package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kfadapter/kfadapter/internal/config"
	"github.com/kfadapter/kfadapter/internal/lifecycle"
	"github.com/kfadapter/kfadapter/internal/provider"
	"github.com/kfadapter/kfadapter/internal/state"
)

func TestHealthcheckUsesConfiguredWildcardListeners(t *testing.T) {
	management, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer management.Close()
	proxy, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	})}
	go func() { _ = server.Serve(management) }()
	defer server.Shutdown(context.Background())
	accepted := make(chan struct{}, 1)
	go func() {
		c, err := proxy.Accept()
		if err == nil {
			close(accepted)
			_ = c.Close()
		}
	}()
	writeWorkingConfig(t, management.Addr().String(), proxy.Addr().String())
	var stdout, stderr bytes.Buffer
	if code := run([]string{"healthcheck"}, &stdout, &stderr); code != 0 {
		t.Fatalf("healthcheck exit=%d stderr=%q", code, stderr.String())
	}
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("healthcheck did not connect to wildcard proxy")
	}
}

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

func TestServeRejectsBareProcessAtSeam(t *testing.T) {
	t.Chdir(t.TempDir())
	previous := requireContainer
	requireContainer = func() error { return errors.New("container required") }
	t.Cleanup(func() { requireContainer = previous })
	if err := os.WriteFile(configPath, []byte("listenAddr: 127.0.0.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := serve(nil); err == nil || !strings.Contains(err.Error(), "container required") {
		t.Fatalf("serve error=%v", err)
	}
}

func TestNewAdapterRejectsUnassignedListenBeforeCreatingState(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.ListenAddr = "192.0.2.1"
	if err := validateListenInterface(cfg.ListenAddr); err == nil {
		t.Skip("documentation address is assigned on this host")
	}
	if _, err := newAdapterAtStateDirectory(cfg, dir); err == nil {
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
	adapter, err := newAdapterAtStateDirectory(cfg, dir)
	if err != nil {
		t.Fatal(err)
	}
	adapter.startupLog = &bytes.Buffer{}
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() { finished <- adapter.runContext(ctx) }()
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
	previous := adapterDrainTimeout
	adapterDrainTimeout = 20 * time.Millisecond
	t.Cleanup(func() { adapterDrainTimeout = previous })
	blocked := make(chan struct{})
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
	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "shutdown exceeded 20ms") {
			t.Fatalf("result=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("deadline not enforced")
	}
	close(blocked)
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
	store, err := state.NewSQLiteStore(dir)
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
	adapter, err := newAdapterAtStateDirectory(cfg, dir)
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

func TestRunRejectsUnknownAndExtraServeArguments(t *testing.T) {
	for _, args := range [][]string{{"unknown"}, {"-x"}, {"serve", "extra"}} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 2 || !strings.HasPrefix(stderr.String(), "usage: kfadapter ") {
			t.Fatalf("args=%v code=%d stderr=%q", args, code, stderr.String())
		}
	}
}

func writeWorkingConfig(t *testing.T, management, proxy string) {
	t.Helper()
	t.Chdir(t.TempDir())
	m := netip.MustParseAddrPort(management)
	p := netip.MustParseAddrPort(proxy)
	body := fmt.Sprintf("listenAddr: %q\nmanagement:\n  port: %d\nproxy:\n  port: %d\n", m.Addr().String(), m.Port(), p.Port())
	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
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
