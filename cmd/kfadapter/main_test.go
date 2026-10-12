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
	"strings"
	"testing"
	"time"
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
