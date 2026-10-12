package accounts

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	credentialspkg "github.com/kfadapter/kfadapter/internal/credentials"
	"github.com/kfadapter/kfadapter/internal/provider"
	"github.com/kfadapter/kfadapter/internal/state"
	"github.com/kfadapter/kfadapter/internal/store"
	"github.com/kfadapter/kfadapter/internal/subscription"
)

type fakeClock struct {
	mu       sync.Mutex
	now      time.Time
	ticks    chan time.Time
	observed chan time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), ticks: make(chan time.Time, 1)}
}
func (clock *fakeClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	if clock.observed != nil {
		select {
		case clock.observed <- clock.now:
		default:
		}
	}
	return clock.now
}
func (clock *fakeClock) advance(interval time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(interval)
	clock.mu.Unlock()
}
func (clock *fakeClock) NewTicker(time.Duration) Ticker { return fakeTicker{clock.ticks} }

type fakeTicker struct{ ticks <-chan time.Time }

func (ticker fakeTicker) C() <-chan time.Time { return ticker.ticks }
func (fakeTicker) Stop()                      {}

type fakeDriver struct {
	id      provider.ID
	now     func() time.Time
	mu      sync.Mutex
	inputs  []provider.Snapshot
	refresh func(context.Context, provider.Snapshot) (provider.Snapshot, error)
}

func (driver *fakeDriver) ID() provider.ID { return driver.id }
func (driver *fakeDriver) Login(context.Context, provider.Credentials) (provider.Snapshot, error) {
	return testSnapshot(driver.id, driver.now()), nil
}
func (driver *fakeDriver) Refresh(ctx context.Context, previous provider.Snapshot) (provider.Snapshot, error) {
	driver.mu.Lock()
	driver.inputs = append(driver.inputs, previous.Clone())
	refresh := driver.refresh
	driver.mu.Unlock()
	if refresh != nil {
		return refresh(ctx, previous)
	}
	return previous.Clone(), nil
}
func (driver *fakeDriver) calls() int {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	return len(driver.inputs)
}

func testSnapshot(id provider.ID, now time.Time) provider.Snapshot {
	protocol := provider.Protocol(string(id) + "-native")
	return provider.Snapshot{
		Provider: id, Account: provider.Account{UserID: string(id) + "-user", Display: "•••", Tier: "free"},
		ExpiresAt: now.Add(7 * 24 * time.Hour).UTC(), RefreshState: []byte("original-token"),
		Authorities: map[string]provider.Authority{"default": {Protocol: protocol, Data: []byte("tunnel-authority")}},
		Nodes:       []provider.Node{{ID: string(id) + "-node", AuthorityID: "default", Protocol: protocol, Host: "127.0.0.1", Port: 8080, Name: string(id), Eligible: true}},
	}
}

type fixture struct {
	store       *store.SQLiteStore
	manager     *state.Manager
	coordinator *Coordinator
	now         func() time.Time
	drivers     []*fakeDriver
}

// The fixture uses the real manager, SQLite and subscription publication path;
// only network drivers are fake. Timing tests use the synctest clock.
func newFixture(t *testing.T, ids ...provider.ID) *fixture {
	t.Helper()
	return newFixtureWithClock(t, time.Now, ids...)
}

func newFixtureWithClock(t *testing.T, now func() time.Time, ids ...provider.ID) *fixture {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := store.NewSQLiteStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadOrCreate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Update(t.Context(), func(candidate *state.PersistentState) error {
		return candidate.SetAccessToken("correct horse battery token")
	}); err != nil {
		t.Fatal(err)
	}
	fixture := &fixture{store: store, now: now}
	t.Cleanup(func() {
		if err := fixture.store.Close(t.Context()); err != nil {
			t.Error(err)
		}
	})
	for _, id := range ids {
		fixture.drivers = append(fixture.drivers, &fakeDriver{id: id, now: now})
	}
	fixture.restore(t)
	for _, id := range ids {
		if _, err := fixture.coordinator.Login(t.Context(), id, provider.Credentials{}); err != nil {
			t.Fatal(err)
		}
	}
	return fixture
}

func (fixture *fixture) restore(t *testing.T) {
	t.Helper()
	persistent, err := fixture.store.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	manager, err := state.NewManager(persistent.ActiveSession)
	if err != nil {
		t.Fatal(err)
	}
	fixture.manager = manager
	service, err := subscription.NewService(subscription.ServiceConfig{Store: fixture.store, SocksAddress: "127.0.0.1:10808"})
	if err != nil {
		t.Fatal(err)
	}
	authority, err := persistent.Identity()
	if err != nil {
		t.Fatal(err)
	}
	drivers := make([]provider.Driver, len(fixture.drivers))
	for index, driver := range fixture.drivers {
		drivers[index] = driver
	}
	providers, err := provider.NewRegistry(drivers, nil)
	if err != nil {
		t.Fatal(err)
	}
	fixture.coordinator, err = NewCoordinator(CoordinatorConfig{
		Providers: providers, Manager: manager, SelectorBuilder: selectorBuilder{authority}, Clock: fixture.now,
		CommitSnapshot: func(snapshot *state.RuntimeSnapshot) error {
			persistent, err := fixture.store.Update(t.Context(), func(candidate *state.PersistentState) error {
				candidate.ActiveSession = snapshot.Clone()
				return nil
			})
			if err != nil {
				return err
			}
			if snapshot != nil {
				if err := manager.Commit(snapshot); err != nil {
					return err
				}
			}
			return service.Update(persistent)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}

type selectorBuilder struct{ identity *credentialspkg.Identity }

func (builder selectorBuilder) Build(nodes []state.Node) (map[string]state.NodeRef, error) {
	return state.BuildSelectors(nodes, builder.identity)
}

func (fixture *fixture) supervisor(t *testing.T, every time.Duration) *Supervisor {
	t.Helper()
	supervisor, err := New(Config{Controller: fixture.coordinator, Snapshots: fixture.manager, Now: fixture.now, RefreshEvery: every})
	if err != nil {
		t.Fatal(err)
	}
	return supervisor
}

func startSupervisor(t *testing.T, supervisor *Supervisor) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	finished := make(chan error, 1)
	go func() { finished <- supervisor.Start(ctx) }()
	synctest.Wait()
	t.Cleanup(func() {
		cancel()
		if err := <-finished; !errors.Is(err, context.Canceled) {
			t.Errorf("supervisor shutdown = %v", err)
		}
	})
}

func runDue(t *testing.T, supervisor *Supervisor) {
	t.Helper()
	var workers sync.WaitGroup
	for _, job := range supervisor.due() {
		workers.Go(func() { _ = supervisor.refresh(t.Context(), job.id, job.account, false) })
	}
	workers.Wait()
}

func credentials(t *testing.T, fixture *fixture, id provider.ID) credentialspkg.Credentials {
	t.Helper()
	persistent, err := fixture.store.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	authority, err := persistent.Identity()
	if err != nil {
		t.Fatal(err)
	}
	node, available := persistent.ActiveSession.NodeByID(string(id) + "-node")
	if !available {
		t.Fatal("node unavailable")
	}
	credential, ok := authority.Credentials(node.Route())
	if !ok {
		t.Fatal("node credentials unavailable")
	}
	return credential
}

func TestRejectedProviderDoesNotAffectOthers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fixture := newFixture(t, "alpha", "beta")
		alpha, beta := fixture.drivers[0], fixture.drivers[1]
		alpha.refresh = func(context.Context, provider.Snapshot) (provider.Snapshot, error) {
			return provider.Snapshot{}, provider.ErrSessionRejected
		}
		supervisor := fixture.supervisor(t, 6*time.Hour)
		original := fixture.manager.Current()
		originalCredentials := credentials(t, fixture, "beta")
		if err := supervisor.Trigger(t.Context(), "alpha"); !errors.Is(err, provider.ErrSessionRejected) {
			t.Fatalf("initial rejection = %v", err)
		}
		startSupervisor(t, supervisor)
		for range 72 * 60 {
			time.Sleep(time.Minute)
			synctest.Wait()
		}
		statuses := supervisor.Status()
		if alpha.calls() != 1 || statuses["alpha"].Status != StatusNeedsRelogin || !statuses["alpha"].NextRun.IsZero() {
			t.Fatalf("rejected provider was retried: calls=%d, status=%+v", alpha.calls(), statuses["alpha"])
		}
		if beta.calls() != 12 || statuses["beta"].Status != StatusOK {
			t.Fatalf("healthy provider missed scheduled refreshes: calls=%d, status=%+v", beta.calls(), statuses["beta"])
		}
		current := fixture.manager.Current()
		if !reflect.DeepEqual(current.Providers, original.Providers) {
			t.Fatal("a rejection altered either provider snapshot")
		}
		if got := credentials(t, fixture, "beta"); got != originalCredentials {
			t.Fatal("sibling rejection changed healthy provider node credentials")
		}
		if !state.SessionUsable(current, fixture.now()) {
			t.Fatal("rejected provider snapshots were deleted")
		}
		alpha.refresh = nil
		if err := supervisor.Trigger(t.Context(), "alpha"); err != nil {
			t.Fatal(err)
		}
		if got := supervisor.Status()["alpha"].Status; got != StatusOK {
			t.Fatalf("manual success did not recover rejection: %s", got)
		}
	})
}

func TestTransientFailuresRetainSnapshotAndRecover(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fixture := newFixture(t, "alpha")
		driver := fixture.drivers[0]
		driver.refresh = func(context.Context, provider.Snapshot) (provider.Snapshot, error) {
			return provider.Snapshot{}, errors.New("temporary network failure")
		}
		// Keep failing for a full 48 hours after the persisted hint is stale.
		time.Sleep(8 * 24 * time.Hour)
		supervisor := fixture.supervisor(t, time.Hour)
		original := fixture.manager.Current()
		startSupervisor(t, supervisor)
		for range 48 * 60 {
			time.Sleep(time.Minute)
			synctest.Wait()
			status := supervisor.Status()["alpha"]
			if status.Status == StatusRefreshFailing && status.NextRun.Sub(fixture.now()) > maxBackoff {
				t.Fatalf("retry exceeded 30-minute cap: %s", status.NextRun.Sub(fixture.now()))
			}
			if !reflect.DeepEqual(fixture.manager.Current().Providers, original.Providers) {
				t.Fatal("transient failure altered the retained snapshot")
			}
		}
		if driver.calls() < 90 {
			t.Fatalf("automatic retries gave up: calls=%d", driver.calls())
		}
		driver.mu.Lock()
		driver.refresh = func(_ context.Context, previous provider.Snapshot) (provider.Snapshot, error) {
			previous.ExpiresAt = fixture.now().Add(24 * time.Hour)
			return previous, nil
		}
		driver.mu.Unlock()
		time.Sleep(supervisor.Status()["alpha"].NextRun.Sub(fixture.now()))
		synctest.Wait()
		runDue(t, supervisor)
		status := supervisor.Status()["alpha"]
		if status.Status != StatusOK || status.Attempts != 0 || !status.LastSuccess.Equal(fixture.now()) {
			t.Fatalf("first success did not recover: %+v", status)
		}
		persistent, err := fixture.store.Load(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if persistent.ActiveSession == nil || len(persistent.ActiveSession.Providers) != 1 {
			t.Fatal("retained session disappeared from SQLite")
		}
	})
}

func TestPartialRefreshCommitPersistsRotatedToken(t *testing.T) {
	fixture := newFixture(t, "alpha")
	driver := fixture.drivers[0]
	catalogError := errors.New("catalog unavailable after token rotation")
	driver.refresh = func(context.Context, provider.Snapshot) (provider.Snapshot, error) {
		return provider.Snapshot{Provider: "alpha", RefreshState: []byte("rotated-token")}, catalogError
	}
	supervisor := fixture.supervisor(t, time.Hour)
	previous := fixture.manager.Current().Providers["alpha"]
	if err := supervisor.Trigger(t.Context(), "alpha"); !errors.Is(err, catalogError) {
		t.Fatalf("partial refresh error = %v", err)
	}
	persistent, err := fixture.store.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	retained := persistent.ActiveSession.Providers["alpha"]
	previous.RefreshState = []byte("rotated-token")
	if !reflect.DeepEqual(retained, previous) {
		t.Fatal("partial commit failed to retain catalog/account/authority and persist rotated token")
	}
	driver.refresh = func(_ context.Context, previous provider.Snapshot) (provider.Snapshot, error) {
		if !bytes.Equal(previous.RefreshState, []byte("rotated-token")) {
			return provider.Snapshot{}, errors.New("next attempt received old token")
		}
		return previous, nil
	}
	if err := supervisor.Trigger(t.Context(), "alpha"); err != nil {
		t.Fatal(err)
	}
	if supervisor.Status()["alpha"].Status != StatusOK {
		t.Fatal("partial refresh did not recover")
	}
}

func TestRestartWithStaleSnapshotRefreshesImmediately(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fixture := newFixture(t, "alpha")
		original := fixture.manager.Current().Providers["alpha"]
		time.Sleep(8 * 24 * time.Hour)
		if err := fixture.store.Close(t.Context()); err != nil {
			t.Fatal(err)
		}
		directory := filepath.Dir(fixture.store.Path())
		reopened, err := store.NewSQLiteStore(directory)
		if err != nil {
			t.Fatal(err)
		}
		fixture.store = reopened
		fixture.restore(t)
		if !reflect.DeepEqual(fixture.manager.Current().Providers["alpha"], original) {
			t.Fatal("startup deleted or altered stale provider snapshot")
		}
		supervisor := fixture.supervisor(t, time.Hour)
		refreshed := make(chan struct{}, 1)
		supervisor.onRefresh = func(provider.ID, error) { refreshed <- struct{}{} }
		ctx, cancel := context.WithCancel(t.Context())
		finished := make(chan error, 1)
		go func() { finished <- supervisor.Start(ctx) }()
		synctest.Wait()
		select {
		case <-refreshed:
		default:
			cancel()
			t.Fatal("stale snapshot did not refresh immediately at startup")
		}
		cancel()
		if err := <-finished; !errors.Is(err, context.Canceled) {
			t.Fatalf("supervisor shutdown = %v", err)
		}
		if fixture.drivers[0].calls() != 1 {
			t.Fatalf("startup refresh count = %d", fixture.drivers[0].calls())
		}
		persistent, err := fixture.store.Load(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if persistent.ActiveSession == nil || !reflect.DeepEqual(persistent.ActiveSession.Providers["alpha"], original) {
			t.Fatal("stale snapshot was lost during restart refresh")
		}
	})
}

func TestSupervisorTickRechecksWallClockAfterSleep(t *testing.T) {
	// This test needs a suspended wall clock and an independently queued stale
	// ticker timestamp; advancing synctest time would also deliver fresh ticks.
	clock := newFakeClock()
	fixture := newFixtureWithClock(t, clock.Now, "alpha")
	supervisor, err := New(Config{Controller: fixture.coordinator, Snapshots: fixture.manager, Clock: clock, RefreshEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	oldTick := clock.Now()
	clock.observed = make(chan time.Time, 1)
	refreshed := make(chan struct{}, 1)
	supervisor.onRefresh = func(provider.ID, error) { refreshed <- struct{}{} }
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	finished := make(chan error, 1)
	go func() { finished <- supervisor.Start(ctx) }()
	select {
	case <-clock.observed:
	case <-time.After(5 * time.Second):
		t.Fatal("supervisor did not evaluate startup schedule")
	}
	clock.advance(30 * time.Hour)
	// The queued ticker timestamp predates suspension. Only Clock.Now makes
	// this tick notice the now-overdue provider.
	clock.ticks <- oldTick
	select {
	case <-refreshed:
	case <-time.After(5 * time.Second):
		t.Fatal("stale ticker timestamp skipped the overdue provider")
	}
	supervisor.Stop()
	if err := <-finished; !errors.Is(err, context.Canceled) {
		t.Fatalf("supervisor stop = %v", err)
	}
	if fixture.drivers[0].calls() != 1 {
		t.Fatalf("refresh count after suspension = %d", fixture.drivers[0].calls())
	}
}

func TestManualTransientFailureAfterRejectionKeepsBackoffProgress(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fixture := newFixture(t, "alpha")
		driver := fixture.drivers[0]
		driver.refresh = func(context.Context, provider.Snapshot) (provider.Snapshot, error) {
			return provider.Snapshot{}, provider.ErrSessionRejected
		}
		supervisor := fixture.supervisor(t, time.Hour)
		for range 2 {
			if err := supervisor.Trigger(t.Context(), "alpha"); !errors.Is(err, provider.ErrSessionRejected) {
				t.Fatal(err)
			}
			if status := supervisor.Status()["alpha"]; status.Status != StatusNeedsRelogin || !status.NextRun.IsZero() {
				t.Fatalf("rejection scheduled an automatic retry: %+v", status)
			}
		}
		failure := errors.New("temporary network failure")
		driver.refresh = func(context.Context, provider.Snapshot) (provider.Snapshot, error) {
			return provider.Snapshot{}, failure
		}
		if err := supervisor.Trigger(t.Context(), "alpha"); !errors.Is(err, failure) {
			t.Fatal(err)
		}
		status := supervisor.Status()["alpha"]
		delay := status.NextRun.Sub(fixture.now())
		if status.Status != StatusRefreshFailing || status.Attempts != 3 || delay < 192*time.Second || delay > 288*time.Second {
			t.Fatalf("manual third failure lost backoff progression: %+v, delay %s", status, delay)
		}
	})
}

func TestBackoffJitterAndCap(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fixture := newFixture(t, "alpha", "beta")
		failure := errors.New("temporary network failure")
		for _, driver := range fixture.drivers {
			driver.refresh = func(context.Context, provider.Snapshot) (provider.Snapshot, error) {
				return provider.Snapshot{}, failure
			}
		}
		supervisor := fixture.supervisor(t, time.Hour)
		bases := []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute, maxBackoff}
		assertDelay := func(id provider.ID, base time.Duration, attempts int) {
			t.Helper()
			status := supervisor.Status()[id]
			delay := status.NextRun.Sub(fixture.now())
			minimum := time.Duration(float64(base) * 0.8)
			maximum := min(time.Duration(float64(base)*1.2), maxBackoff)
			if status.Status != StatusRefreshFailing || status.Attempts != attempts || delay < minimum || delay > maximum {
				t.Fatalf("provider %s attempt %d = %+v, delay %s outside [%s, %s]", id, attempts, status, delay, minimum, maximum)
			}
		}
		for attempt := range 100 {
			if err := supervisor.Trigger(t.Context(), "alpha"); !errors.Is(err, failure) {
				t.Fatal(err)
			}
			assertDelay("alpha", bases[min(attempt, len(bases)-1)], attempt+1)
		}
		if err := supervisor.Trigger(t.Context(), "beta"); !errors.Is(err, failure) {
			t.Fatal(err)
		}
		assertDelay("beta", minBackoff, 1)
		if fixture.drivers[0].calls() != 100 || fixture.drivers[1].calls() != 1 {
			t.Fatalf("independent retry counts = %d / %d", fixture.drivers[0].calls(), fixture.drivers[1].calls())
		}
		// Both a successful refresh and a successful login restart the schedule.
		fixture.drivers[0].refresh = nil
		if err := supervisor.Trigger(t.Context(), "alpha"); err != nil {
			t.Fatal(err)
		}
		if status := supervisor.Status()["alpha"]; status.Status != StatusOK || status.Attempts != 0 {
			t.Fatalf("successful refresh did not reset failures: %+v", status)
		}
		fixture.drivers[0].refresh = func(context.Context, provider.Snapshot) (provider.Snapshot, error) {
			return provider.Snapshot{}, failure
		}
		for attempt := range 2 {
			if err := supervisor.Trigger(t.Context(), "alpha"); !errors.Is(err, failure) {
				t.Fatal(err)
			}
			assertDelay("alpha", bases[attempt], attempt+1)
		}
		supervisor.RecordSuccess("alpha")
		if err := supervisor.Trigger(t.Context(), "alpha"); !errors.Is(err, failure) {
			t.Fatal(err)
		}
		assertDelay("alpha", minBackoff, 1)
	})
}

func TestGlobalRefreshCommitsHealthySiblingWithoutCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fixture := newFixture(t, "alpha", "beta")
		alphaFailed, release := make(chan struct{}), make(chan struct{})
		fixture.drivers[0].refresh = func(context.Context, provider.Snapshot) (provider.Snapshot, error) {
			close(alphaFailed)
			return provider.Snapshot{}, provider.ErrSessionRejected
		}
		fixture.drivers[1].refresh = func(ctx context.Context, previous provider.Snapshot) (provider.Snapshot, error) {
			select {
			case <-ctx.Done():
				return provider.Snapshot{}, ctx.Err()
			case <-release:
				previous.RefreshState = []byte("healthy-new-token")
				return previous, nil
			}
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		finished := make(chan error, 1)
		go func() { finished <- fixture.coordinator.Refresh(ctx, "") }()
		select {
		case <-alphaFailed:
		case <-time.After(5 * time.Second):
			t.Fatal("failing provider did not run")
		}
		synctest.Wait()
		select {
		case err := <-finished:
			t.Fatalf("global refresh abandoned an in-flight sibling: %v", err)
		default:
		}
		close(release)
		if err := <-finished; !errors.Is(err, provider.ErrSessionRejected) {
			t.Fatalf("global refresh rejection = %v", err)
		}
		persistent, err := fixture.store.Load(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(persistent.ActiveSession.Providers["beta"].RefreshState, []byte("healthy-new-token")) {
			t.Fatal("a sibling rejection discarded the successful provider commit")
		}
	})
}
