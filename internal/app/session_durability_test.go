package app

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/kfadapter/kfadapter/internal/provider"
	"github.com/kfadapter/kfadapter/internal/provider/coordinator"
	"github.com/kfadapter/kfadapter/internal/state"
	"github.com/kfadapter/kfadapter/internal/subscription"
	"github.com/kfadapter/kfadapter/internal/web"
)

type runtimeDriver struct {
	id      provider.ID
	now     time.Time
	refresh func(context.Context, provider.Snapshot) (provider.Snapshot, error)
}

func (driver *runtimeDriver) ID() provider.ID { return driver.id }
func (driver *runtimeDriver) Login(context.Context, provider.Credentials) (provider.Snapshot, error) {
	protocol := provider.Protocol(string(driver.id) + "-native")
	return provider.Snapshot{
		Provider: driver.id, Account: provider.Account{UserID: string(driver.id) + "-user", Display: "•••", Tier: "free"},
		ExpiresAt: driver.now.Add(24 * time.Hour), RefreshState: []byte("original-token"),
		Authorities: map[string]provider.Authority{"default": {Protocol: protocol, Data: []byte("tunnel-authority")}},
		Nodes:       []provider.Node{{ID: string(driver.id) + "-node", AuthorityID: "default", Protocol: protocol, Host: "127.0.0.1", Port: 8080, Name: string(driver.id), Eligible: true}},
	}, nil
}
func (driver *runtimeDriver) Refresh(ctx context.Context, previous provider.Snapshot) (provider.Snapshot, error) {
	if driver.refresh != nil {
		return driver.refresh(ctx, previous)
	}
	return previous, nil
}

type runtimeFixture struct {
	runtime     *Runtime
	store       *state.SQLiteStore
	manager     *state.Manager
	coordinator *coordinator.Coordinator
	drivers     []*runtimeDriver
	now         time.Time
}

func newRuntimeFixture(t *testing.T, dial func(context.Context, string, string) (net.Conn, error)) *runtimeFixture {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := state.NewSQLiteStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadOrCreate(t.Context()); err != nil {
		t.Fatal(err)
	}
	persistent, err := store.Update(t.Context(), func(candidate *state.PersistentState) error {
		return candidate.SetAccessToken("correct horse battery token")
	})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := state.NewManager(nil)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := persistent.Identity()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	credentials, err := NewCredentialCoordinator(nil, authority)
	if err != nil {
		t.Fatal(err)
	}
	mutations := &sync.Mutex{}
	service, err := subscription.NewService(subscription.ServiceConfig{Store: store, SocksAddress: "127.0.0.1:10808"})
	if err != nil {
		t.Fatal(err)
	}
	fixture := &runtimeFixture{store: store, manager: manager, now: now}
	fixture.drivers = []*runtimeDriver{{id: "alpha", now: now}, {id: "beta", now: now}}
	providers, err := provider.NewRegistry([]provider.Driver{fixture.drivers[0], fixture.drivers[1]}, nil)
	if err != nil {
		t.Fatal(err)
	}
	fixture.coordinator, err = coordinator.New(coordinator.Config{
		Providers: providers, Manager: manager, SelectorBuilder: credentials, MutationMu: mutations,
		Clock: func() time.Time { return now },
		CommitSnapshot: func(snapshot *state.RuntimeSnapshot) error {
			return fixture.runtime.CommitControlSnapshotLocked(snapshot)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.runtime, err = NewRuntime(RuntimeConfig{
		Manager: manager, Store: store, Providers: fixture.coordinator, Subscriptions: service,
		Credentials: credentials, MutationMu: mutations, Now: func() time.Time { return now }, DialContext: dial,
		SocksAddress: "127.0.0.1:10808", RefreshEvery: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		fixture.runtime.Stop()
		if err := store.Close(t.Context()); err != nil {
			t.Error(err)
		}
	})
	for _, id := range []string{"alpha", "beta"} {
		if _, err := fixture.runtime.Login(t.Context(), web.LoginInput{Provider: id}); err != nil {
			t.Fatal(err)
		}
	}
	return fixture
}

func completedWithin(t *testing.T, run func() error) {
	t.Helper()
	result := make(chan error, 1)
	go func() { result <- run() }()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("local operation blocked behind provider network I/O")
	}
}

func pipeDial(context.Context, string, string) (net.Conn, error) {
	left, right := net.Pipe()
	_ = right.Close()
	return left, nil
}

func TestRuntimeReadsAndProbeDoNotWaitForProviderNetwork(t *testing.T) {
	fixture := newRuntimeFixture(t, pipeDial)
	entered, release := make(chan struct{}), make(chan struct{})
	fixture.drivers[0].refresh = func(ctx context.Context, previous provider.Snapshot) (provider.Snapshot, error) {
		close(entered)
		select {
		case <-ctx.Done():
			return provider.Snapshot{}, ctx.Err()
		case <-release:
			return previous, nil
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	refreshed := make(chan error, 1)
	go func() { refreshed <- fixture.runtime.Refresh(ctx, "alpha") }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("provider refresh did not start")
	}
	completedWithin(t, func() error { _, err := fixture.runtime.NodeDetails(t.Context(), "alpha-node"); return err })
	completedWithin(t, func() error { _, err := fixture.runtime.Status(t.Context()); return err })
	completedWithin(t, func() error { _, err := fixture.runtime.Probe(t.Context(), "alpha-node"); return err })
	completedWithin(t, func() error { return fixture.runtime.Refresh(t.Context(), "beta") })
	close(release)
	if err := <-refreshed; err != nil {
		t.Fatal(err)
	}
	if len(fixture.manager.Current().Providers) != 2 {
		t.Fatal("concurrent provider commit discarded a sibling")
	}
}

func TestProbeSurvivesUnrelatedProviderRefresh(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	fixture := newRuntimeFixture(t, func(ctx context.Context, network, address string) (net.Conn, error) {
		close(entered)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-release:
			return pipeDial(ctx, network, address)
		}
	})
	probed := make(chan error, 1)
	go func() { _, err := fixture.runtime.Probe(t.Context(), "alpha-node"); probed <- err }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("probe did not start")
	}
	if err := fixture.runtime.Refresh(t.Context(), "beta"); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-probed; err != nil {
		t.Fatalf("unrelated generation update invalidated the probe: %v", err)
	}
	node, found := fixture.manager.Current().NodeByID("alpha-node")
	if !found || node.Health != state.NodeHealthHealthy {
		t.Fatal("probe result was not applied to unchanged node identity")
	}
}

func TestProviderStalenessHintDoesNotRefuseAdmission(t *testing.T) {
	fixture := newRuntimeFixture(t, pipeDial)
	current := fixture.manager.Current()
	node, found := current.NodeByID("alpha-node")
	if !found {
		t.Fatal("fixture node missing")
	}
	future := fixture.now.Add(72 * time.Hour)
	pin, err := fixture.manager.CompactPin(node.Selector, future)
	if err != nil || !fixture.manager.SessionCurrentPin(pin, future) {
		t.Fatalf("elapsed time refused unchanged authority: %v", err)
	}
	if err := fixture.runtime.Logout(t.Context(), "alpha"); err != nil {
		t.Fatal(err)
	}
	if fixture.manager.SessionCurrentPin(pin, future) {
		t.Fatal("logout failed to invalidate the pin")
	}
	if _, err := fixture.manager.CompactPin(node.Selector, future); !errors.Is(err, state.ErrSelectorUnknown) {
		t.Fatalf("logged-out selector admission = %v", err)
	}
}

func TestRuntimeRejectedProviderRemainsLinkedAndRecoversManually(t *testing.T) {
	fixture := newRuntimeFixture(t, pipeDial)
	fixture.drivers[0].refresh = func(context.Context, provider.Snapshot) (provider.Snapshot, error) {
		return provider.Snapshot{}, provider.ErrSessionRejected
	}
	if err := fixture.runtime.Refresh(t.Context(), "alpha"); !errors.Is(err, provider.ErrSessionRejected) {
		t.Fatalf("manual rejection = %v", err)
	}
	status, err := fixture.runtime.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	alpha, beta := status.Accounts["alpha"], status.Accounts["beta"]
	if alpha.RefreshStatus != "needs_relogin" || !alpha.NextRefreshAt.IsZero() || beta.RefreshStatus != "ok" || status.Nodes.Total != 2 {
		t.Fatalf("provider rejection leaked into sibling status or removed nodes: %+v", status)
	}
	if _, err := fixture.runtime.NodeDetails(t.Context(), "alpha-node"); err != nil {
		t.Fatalf("rejected provider lost its retained node details: %v", err)
	}
	fixture.drivers[0].refresh = nil
	if err := fixture.runtime.Refresh(t.Context(), "alpha"); err != nil {
		t.Fatal(err)
	}
	status, err = fixture.runtime.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if status.Accounts["alpha"].RefreshStatus != "ok" || status.Accounts["alpha"].NextRefreshAt.IsZero() {
		t.Fatal("manual success failed to restore automatic scheduling")
	}
}
