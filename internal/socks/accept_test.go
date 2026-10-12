package socks

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/oshinop/chinadapter/internal/credentials"
	"github.com/oshinop/chinadapter/internal/provider"
	"github.com/oshinop/chinadapter/internal/state"
)

type idleSnapshots struct{}

func (idleSnapshots) CompactPin(string, time.Time) (state.TunnelPin, error) {
	return state.TunnelPin{}, errors.New("unused")
}

func (idleSnapshots) SessionCurrentPin(state.TunnelPin, time.Time) bool { return false }

type stubTransport struct{}

func (stubTransport) Protocol() provider.Protocol { return "stub" }

func (stubTransport) RelayStream(context.Context, provider.RelayRequest) error {
	return errors.New("unused")
}

// transientListener fails the first transient accepts with descriptor
// exhaustion, then delegates to the real listener and signals when it is reached.
type transientListener struct {
	net.Listener
	transient int
	reached   chan struct{}
}

func (l *transientListener) Accept() (net.Conn, error) {
	if l.transient > 0 {
		l.transient--
		return nil, &net.OpError{Op: "accept", Net: "tcp", Err: syscall.EMFILE}
	}
	select {
	case l.reached <- struct{}{}:
	default:
	}
	return l.Listener.Accept()
}

func newAcceptTestServer(t *testing.T) *Server {
	t.Helper()
	authority, err := credentials.New(nil, "00112233445566778899aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	providers, err := provider.NewRegistry(nil, []provider.Transport{stubTransport{}})
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{Snapshots: idleSnapshots{}, Identity: authority, Providers: providers})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

// Descriptor exhaustion is a resource spike, not a closed listener: Serve must
// keep accepting after the transient failures instead of stopping the worker.
func TestServeSurvivesTransientAcceptErrors(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := &transientListener{Listener: base, transient: 2, reached: make(chan struct{}, 1)}
	server := newAcceptTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	select {
	case <-listener.reached:
	case err := <-done:
		t.Fatalf("Serve returned %v after transient accept errors", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not resume accepting after transient errors")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Serve after shutdown = %v, want nil", err)
	}
}

func TestTemporaryAcceptErrorClassification(t *testing.T) {
	transient := []error{
		&net.OpError{Op: "accept", Net: "tcp", Err: syscall.EMFILE},
		&net.OpError{Op: "accept", Net: "tcp", Err: syscall.ENFILE},
		&net.OpError{Op: "accept", Net: "tcp", Err: syscall.ECONNABORTED},
	}
	for _, err := range transient {
		if !temporaryAcceptError(err) {
			t.Fatalf("%v should be retried", err)
		}
	}
	if temporaryAcceptError(net.ErrClosed) {
		t.Fatal("closed listener must not be retried")
	}
	if temporaryAcceptError(errors.New("unexpected listener failure")) {
		t.Fatal("unknown accept failure must not be retried")
	}
}

func TestAcceptBackoffIntervalsCapAndReset(t *testing.T) {
	policy := newAcceptBackOff()
	intervals := []time.Duration{
		5 * time.Millisecond, 10 * time.Millisecond, 20 * time.Millisecond,
		40 * time.Millisecond, 80 * time.Millisecond, 160 * time.Millisecond,
		320 * time.Millisecond, 640 * time.Millisecond, time.Second,
	}
	for attempt := range 100 {
		want := intervals[min(attempt, len(intervals)-1)]
		if delay := policy.NextBackOff(); delay != want {
			t.Fatalf("accept delay %d = %s, want %s", attempt+1, delay, want)
		}
	}
	policy.Reset()
	if delay := policy.NextBackOff(); delay != 5*time.Millisecond {
		t.Fatalf("accept delay after reset = %s, want 5ms", delay)
	}
}
