package app

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/oshinop/chinadapter/internal/config"
	"github.com/oshinop/chinadapter/internal/lifecycle"
	"github.com/oshinop/chinadapter/internal/provider"
	"github.com/oshinop/chinadapter/internal/state"
	"github.com/oshinop/chinadapter/internal/store"
)

func TestValidateListenInterfaceAddresses(t *testing.T) {
	for _, test := range []struct {
		name, listen string
		addresses    []netip.Addr
		want         bool
	}{
		{"assigned", "192.0.2.10", []netip.Addr{netip.MustParseAddr("192.0.2.10")}, false},
		{"unassigned", "192.0.2.20", []netip.Addr{netip.MustParseAddr("192.0.2.10")}, true},
		{"wildcard4", "0.0.0.0", []netip.Addr{netip.MustParseAddr("127.0.0.1")}, false},
		{"wildcard6", "::", []netip.Addr{netip.MustParseAddr("::1")}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := validateListenInterfaceAddresses(test.listen, test.addresses); (got != nil) != test.want {
				t.Fatalf("error=%v want=%t", got, test.want)
			}
		})
	}
}

func TestNewAdapterRejectsUnassignedListenBeforeCreatingState(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.ListenAddr = "192.0.2.1"
	if err := validateListenInterface(cfg.ListenAddr); err == nil {
		t.Skip("documentation address is assigned on this host")
	}
	if _, err := NewDaemon(cfg, dir, "devel"); err == nil {
		t.Fatal("unassigned listener accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "state.db")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state created before validation: %v", err)
	}
}

func TestAdapterLifecycleShutdown(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.ListenAddr = "127.0.0.1"
	cfg.Management.Port = config.Port(freePort(t))
	cfg.Proxy.Port = config.Port(freePort(t))
	adapter, err := NewDaemon(cfg, dir, "devel")
	if err != nil {
		t.Fatal(err)
	}
	adapter.startupLog = &bytes.Buffer{}
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() { finished <- adapter.Run(ctx) }()
	time.Sleep(40 * time.Millisecond)
	cancel()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatalf("shutdown: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown timed out")
	}
	if adapter.runtime.Healthy() {
		t.Fatal("runtime remained healthy")
	}
}

func TestAdapterSupervisorUsesInternalDrainDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		blocked := make(chan struct{})
		defer close(blocked)
		supervisor, err := newAdapterSupervisor([]lifecycle.Worker{{
			Name: "blocked", Run: func(ctx context.Context) error { <-ctx.Done(); <-blocked; return ctx.Err() },
			Shutdown: func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() },
		}})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() { result <- supervisor.Run(ctx) }()
		cancel()
		synctest.Wait()
		started := time.Now()
		time.Sleep(adapterDrainTimeout - time.Nanosecond)
		synctest.Wait()
		select {
		case err := <-result:
			t.Fatalf("drain ended before deadline: %v", err)
		default:
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		select {
		case err := <-result:
			if err == nil || !strings.Contains(err.Error(), "shutdown exceeded 20s") {
				t.Fatalf("result=%v", err)
			}
		default:
			t.Fatal("deadline not enforced")
		}
		if time.Since(started) != adapterDrainTimeout {
			t.Fatalf("drain elapsed %s, want %s", time.Since(started), adapterDrainTimeout)
		}
	})
}

func TestPersistedProviderSessionRestoresAcrossAdapterRestart(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.ListenAddr = "127.0.0.1"
	cfg.Management.Port = config.Port(freePort(t))
	cfg.Proxy.Port = config.Port(freePort(t))
	store, err := store.NewSQLiteStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.LoadOrCreate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Update(context.Background(), func(candidate *state.PersistentState) error {
		if err := candidate.SetAccessToken("correct horse battery token"); err != nil {
			return err
		}
		authority, err := candidate.Identity()
		if err != nil {
			return err
		}
		ps := provider.Snapshot{Provider: "kuaifan", Account: provider.Account{UserID: "user", Display: "•••", Tier: "free"}, ExpiresAt: time.Now().Add(time.Hour), RefreshState: []byte("refresh"), Authorities: map[string]provider.Authority{"a": {Protocol: "wifiin", Data: []byte("authority")}}, Nodes: []provider.Node{{ID: "node", AuthorityID: "a", Protocol: "wifiin", Host: "127.0.0.1", Port: 80, Name: "node", Eligible: true}}}
		node := state.Node{ID: "node", Selector: "", Provider: "kuaifan", Protocol: "wifiin", AuthorityID: "a", Host: "127.0.0.1", Port: 80, Name: "node", Eligible: true}
		selectors, err := state.BuildSelectors([]state.Node{node}, authority)
		if err != nil {
			return err
		}
		node.Selector = ""
		for selector := range selectors {
			node.Selector = selector
		}
		candidate.ActiveSession = &state.RuntimeSnapshot{Generation: 1, CreatedAt: time.Now(), ExpiresAt: ps.ExpiresAt, Providers: map[provider.ID]provider.Snapshot{"kuaifan": ps}, Nodes: []state.Node{node}, Selectors: selectors}
		return nil
	})
	if err != nil {
		_ = store.Close(context.Background())
		t.Fatal(err)
	}
	_ = store.Close(context.Background())
	adapter, err := NewDaemon(cfg, dir, "devel")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		adapter.runtime.Stop()
		_ = adapter.httpListener.Close()
		_ = adapter.socksListener.Close()
		_ = adapter.store.Close(context.Background())
	}()
	if adapter.manager.State() == state.StateSignedOut {
		t.Fatal("persisted provider session was not restored")
	}
}

func freePort(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return uint16(listener.Addr().(*net.TCPAddr).Port)
}
