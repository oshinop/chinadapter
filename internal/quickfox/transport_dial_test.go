package quickfox

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

type closeRecordingConn struct {
	net.Conn
	closed bool
}

func (c *closeRecordingConn) Close() error {
	c.closed = true
	return nil
}

// A relay dial that succeeds just as the caller cancels must not leak the socket.
func TestDialRelayClosesConnectionWhenCancelledAfterDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	connection := &closeRecordingConn{}
	dial := func(context.Context, string, string) (net.Conn, error) {
		cancel()
		return connection, nil
	}
	_, err := dialRelay(ctx, dial, "relay.example", 443, time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("dialRelay error = %v, want context.Canceled", err)
	}
	if !connection.closed {
		t.Fatal("relay connection leaked after cancellation")
	}
}
