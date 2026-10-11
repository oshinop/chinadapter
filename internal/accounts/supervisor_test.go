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
	"time"

	"github.com/kfadapter/kfadapter/internal/provider"
	"github.com/kfadapter/kfadapter/internal/provider/coordinator"
	"github.com/kfadapter/kfadapter/internal/selector"
	"github.com/kfadapter/kfadapter/internal/state"
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
	clock   *fakeClock
	mu      sync.Mutex
	inputs  []provider.Snapshot
	refresh func(context.Context, provider.Snapshot) (provider.Snapshot, error)
}

func (driver *fakeDriver) ID() provider.ID { return driver.id }
func (driver *fakeDriver) Login(context.Context, provider.Credentials) (provider.Snapshot, error) {
	return testSnapshot(driver.id, driver.clock.Now()), nil
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
		ExpiresAt: now.Add(7 * 24 * time.Hour), RefreshState: []byte("original-token"),
		Authorities: map[string]provider.Authority{"default": {Protocol: protocol, Data: []byte("tunnel-authority")}},
		Nodes:       []provider.Node{{ID: string(id) + "-node", AuthorityID: "default", Protocol: protocol, Host: "127.0.0.1", Port: 8080, Name: string(id), Eligible: true}},
	}
}

type fixture struct {
	store       *state.SQLiteStore
	manager     *state.Manager
	coordinator *coordinator.Coordinator
	clock       *fakeClock
	drivers     []*fakeDriver
}

// The fixture uses the real manager, SQLite and subscription publication path;
// only network drivers and the clock are fake.
func newFixture(t *testing.T, ids ...provider.ID) *fixture {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := state.NewSQLiteStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadOrCreate(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Update(func(candidate *state.PersistentState) error {
		return candidate.SetAccessToken("correct horse battery token")
	}); err != nil {
		t.Fatal(err)
	}
	fixture := &fixture{store: store, clock: newFakeClock()}
	t.Cleanup(func() {
		if err := fixture.store.Close(); err != nil {
			t.Error(err)
		}
	})
	for _, id := range ids {
		fixture.drivers = append(fixture.drivers, &fakeDriver{id: id, clock: fixture.clock})
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
	persistent, err := fixture.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	manager, err := state.NewManagerWithSubscription(persistent.ActiveSession, persistent.Subscription, persistent.AccessTokenVerifier.BindingKey())
	if err != nil {
		t.Fatal(err)
	}
	fixture.manager = manager
	service, err := subscription.NewService(subscription.ServiceConfig{Store: fixture.store, SocksAddress: "127.0.0.1:10808", Now: fixture.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := selector.NewRegistry(persistent.Subscription)
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
	fixture.coordinator, err = coordinator.New(coordinator.Config{
		Providers: providers, Manager: manager, SelectorBuilder: selectorBuilder{registry}, Clock: fixture.clock.Now,
		CommitSnapshot: func(snapshot *state.RuntimeSnapshot) error {
			if snapshot == nil {
				_, err := fixture.store.Update(func(candidate *state.PersistentState) error { candidate.ActiveSession = nil; return nil })
				return err
			}
			ctx := t.Context()
			plan, err := service.PrepareRuntimeCommit(ctx, snapshot.AccountBindingID())
			if err != nil {
				return err
			}
			rollbackManager, err := manager.InstallEpoch(plan.Authority, snapshot.AccountBindingID())
			if err != nil {
				return err
			}
			registry, err := selector.NewRegistry(plan.Authority)
			if err != nil {
				rollbackManager()
				return err
			}
			built, err := registry.Build(snapshot.Nodes)
			if err != nil {
				rollbackManager()
				return err
			}
			next := snapshot.Clone()
			next.Nodes, next.Selectors = built.Nodes, built.Selectors
			rollbackStore, err := service.CommitRuntimeSnapshot(ctx, plan, next)
			if err != nil {
				rollbackManager()
				return err
			}
			if err := manager.Commit(next); err != nil {
				rollbackManager()
				return errors.Join(err, rollbackStore())
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}

type selectorBuilder struct{ registry *selector.Registry }

func (builder selectorBuilder) Build(nodes []state.Node) (map[string]state.NodeRef, error) {
	built, err := builder.registry.Build(nodes)
	return built.Selectors, err
}

func (fixture *fixture) supervisor(t *testing.T, every time.Duration) *Supervisor {
	t.Helper()
	supervisor, err := New(Config{Controller: fixture.coordinator, Snapshots: fixture.manager, Clock: fixture.clock, Rand: func() float64 { return 0.5 }, RefreshEvery: every})
	if err != nil {
		t.Fatal(err)
	}
	return supervisor
}

func runDue(t *testing.T, supervisor *Supervisor) {
	t.Helper()
	var workers sync.WaitGroup
	for _, job := range supervisor.due() {
		workers.Go(func() { _ = supervisor.refresh(t.Context(), job.id, job.account, false) })
	}
	workers.Wait()
}

func credentials(t *testing.T, fixture *fixture, id provider.ID) selector.Credentials {
	t.Helper()
	persistent, err := fixture.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	registry, err := selector.NewRegistry(persistent.Subscription)
	if err != nil {
		t.Fatal(err)
	}
	credential, ok := registry.Credentials(selector.NodeIdentity{NodeID: string(id) + "-node"})
	if !ok {
		t.Fatal("node credentials unavailable")
	}
	return credential
}

func TestRejectedProviderDoesNotAffectOthers(t *testing.T) {
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
	for range 72 * 60 {
		fixture.clock.advance(time.Minute)
		runDue(t, supervisor)
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
	if !state.SessionUsable(current, fixture.clock.Now()) {
		t.Fatal("rejected provider snapshots were deleted")
	}
	alpha.refresh = nil
	if err := supervisor.Trigger(t.Context(), "alpha"); err != nil {
		t.Fatal(err)
	}
	if got := supervisor.Status()["alpha"].Status; got != StatusOK {
		t.Fatalf("manual success did not recover rejection: %s", got)
	}
}

func TestTransientFailuresRetainSnapshotAndRecover(t *testing.T) {
	fixture := newFixture(t, "alpha")
	driver := fixture.drivers[0]
	driver.refresh = func(context.Context, provider.Snapshot) (provider.Snapshot, error) {
		return provider.Snapshot{}, errors.New("temporary network failure")
	}
	// Keep failing for a full 48 hours after the persisted hint is stale.
	fixture.clock.advance(8 * 24 * time.Hour)
	supervisor := fixture.supervisor(t, time.Hour)
	original := fixture.manager.Current()
	for range 48 * 60 {
		fixture.clock.advance(time.Minute)
		runDue(t, supervisor)
		status := supervisor.Status()["alpha"]
		if status.Status == StatusRefreshFailing && status.NextRun.Sub(fixture.clock.Now()) > maxBackoff {
			t.Fatalf("retry exceeded 30-minute cap: %s", status.NextRun.Sub(fixture.clock.Now()))
		}
		if !reflect.DeepEqual(fixture.manager.Current().Providers, original.Providers) {
			t.Fatal("transient failure altered the retained snapshot")
		}
	}
	if driver.calls() < 90 {
		t.Fatalf("automatic retries gave up: calls=%d", driver.calls())
	}
	driver.refresh = func(_ context.Context, previous provider.Snapshot) (provider.Snapshot, error) {
		previous.ExpiresAt = fixture.clock.Now().Add(24 * time.Hour)
		return previous, nil
	}
	fixture.clock.advance(supervisor.Status()["alpha"].NextRun.Sub(fixture.clock.Now()))
	runDue(t, supervisor)
	status := supervisor.Status()["alpha"]
	if status.Status != StatusOK || status.Attempts != 0 || !status.LastSuccess.Equal(fixture.clock.Now()) {
		t.Fatalf("first success did not recover: %+v", status)
	}
	persistent, err := fixture.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if persistent.ActiveSession == nil || len(persistent.ActiveSession.Providers) != 1 {
		t.Fatal("retained session disappeared from SQLite")
	}
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
	persistent, err := fixture.store.Load()
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
	fixture := newFixture(t, "alpha")
	original := fixture.manager.Current().Providers["alpha"]
	fixture.clock.advance(8 * 24 * time.Hour)
	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Dir(fixture.store.Path())
	reopened, err := state.NewSQLiteStore(directory)
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
	select {
	case <-refreshed:
	case <-time.After(5 * time.Second):
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
	persistent, err := fixture.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if persistent.ActiveSession == nil || !reflect.DeepEqual(persistent.ActiveSession.Providers["alpha"], original) {
		t.Fatal("stale snapshot was lost during restart refresh")
	}
}

func TestSupervisorTickRechecksWallClockAfterSleep(t *testing.T) {
	fixture := newFixture(t, "alpha")
	supervisor := fixture.supervisor(t, time.Hour)
	oldTick := fixture.clock.Now()
	fixture.clock.observed = make(chan time.Time, 1)
	refreshed := make(chan struct{}, 1)
	supervisor.onRefresh = func(provider.ID, error) { refreshed <- struct{}{} }
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	finished := make(chan error, 1)
	go func() { finished <- supervisor.Start(ctx) }()
	select {
	case <-fixture.clock.observed:
	case <-time.After(5 * time.Second):
		t.Fatal("supervisor did not evaluate startup schedule")
	}
	fixture.clock.advance(30 * time.Hour)
	// The queued ticker timestamp predates suspension. Only Clock.Now makes
	// this tick notice the now-overdue provider.
	fixture.clock.ticks <- oldTick
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

func TestBackoffJitterAndCap(t *testing.T) {
	for _, random := range []float64{0, 0.5, 0.999999} {
		supervisor := &Supervisor{rand: func() float64 { return random }}
		for attempt := range 100 {
			base := maxBackoff
			if attempt < 5 {
				base = minBackoff << attempt
			}
			delay := supervisor.backoff(attempt + 1)
			if delay < time.Duration(float64(base)*0.8) || delay > min(time.Duration(float64(base)*1.2), maxBackoff) {
				t.Fatalf("backoff attempt %d rand %.6f = %s outside jitter/cap", attempt+1, random, delay)
			}
		}
	}
}

func TestGlobalRefreshCommitsHealthySiblingWithoutCancellation(t *testing.T) {
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
	select {
	case err := <-finished:
		t.Fatalf("global refresh abandoned an in-flight sibling: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if err := <-finished; !errors.Is(err, provider.ErrSessionRejected) {
		t.Fatalf("global refresh rejection = %v", err)
	}
	persistent, err := fixture.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(persistent.ActiveSession.Providers["beta"].RefreshState, []byte("healthy-new-token")) {
		t.Fatal("a sibling rejection discarded the successful provider commit")
	}
}
