package kuaifan

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/kfadapter/kfadapter/internal/provider"
)

type closeRecordingConn struct {
	net.Conn
	closed bool
}

func (c *closeRecordingConn) Close() error {
	c.closed = true
	return nil
}

// A dial that succeeds just as the caller cancels must not leak the socket.
func TestOpenWIFIINClosesUpstreamWhenCancelledAfterDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	upstream := &closeRecordingConn{}
	dial := func(context.Context, string, string) (net.Conn, error) {
		cancel()
		return upstream, nil
	}
	_, _, _, _, err := openWIFIIN(ctx, dial, "node.example", 8080,
		provider.Target{Host: "target.example", Port: 443}, tunnelAuthority{Password: "password", Extension: "|token|cc.fancast.major|order|7|MAC|1.0.46"}, time.Second, false)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("openWIFIIN error = %v, want context.Canceled", err)
	}
	if !upstream.closed {
		t.Fatal("upstream connection leaked after cancellation")
	}
}
