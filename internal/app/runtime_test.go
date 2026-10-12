package app

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/oshinop/chinadapter/internal/state"
)

func TestRuntimeAccessLoginRejectsInvalidToken(t *testing.T) {
	fixture := newRuntimeFixture(t, func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("not used") })
	if err := fixture.runtime.AccessLogin(t.Context(), "wrong local token"); err == nil {
		t.Fatal("invalid access token was accepted")
	} else {
		var public interface{ HTTPStatus() int }
		if !errors.As(err, &public) || public.HTTPStatus() != 401 {
			t.Fatalf("invalid token error=%v", err)
		}
	}
}

func TestRuntimeNodeDetailsRejectsStaleSelectorAuthority(t *testing.T) {
	fixture := newRuntimeFixture(t, func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("not used") })
	current := fixture.manager.Current()
	next := current.Clone()
	next.Generation++
	next.Selectors = map[string]state.NodeRef{}
	if err := fixture.manager.Commit(next); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.runtime.NodeDetails(t.Context(), current.Nodes[0].ID); err == nil || !strings.Contains(err.Error(), "selector authority") {
		t.Fatalf("stale selector error=%v", err)
	}
}

func TestRuntimeCommitRejectsInvalidSnapshotWithoutChangingAggregate(t *testing.T) {
	fixture := newRuntimeFixture(t, func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("not used") })
	before := fixture.manager.Current().Clone()
	if err := fixture.runtime.CommitControlSnapshotLocked(&state.RuntimeSnapshot{Generation: before.Generation + 1}); err == nil {
		t.Fatal("invalid snapshot committed")
	}
	after := fixture.manager.Current()
	if after.Generation != before.Generation || len(after.Nodes) != len(before.Nodes) || len(after.Providers) != len(before.Providers) {
		t.Fatalf("aggregate changed after rejected commit: before=%+v after=%+v", before, after)
	}
}

func TestRuntimeProbePublishesCurrentNodeHealth(t *testing.T) {
	fixture := newRuntimeFixture(t, func(context.Context, string, string) (net.Conn, error) {
		left, right := net.Pipe()
		_ = right.Close()
		return left, nil
	})
	result, err := fixture.runtime.Probe(t.Context(), "alpha-node")
	if err != nil {
		t.Fatal(err)
	}
	if result.NodeID != "alpha-node" || result.Health != string(state.NodeHealthHealthy) {
		t.Fatalf("probe result=%+v", result)
	}
	if node, ok := fixture.manager.Current().NodeByID("alpha-node"); !ok || node.Health != state.NodeHealthHealthy {
		t.Fatalf("node health=%+v ok=%v", node, ok)
	}
}

func TestRuntimeAccountSelectorAuthorityRemainsStableOnRefresh(t *testing.T) {
	fixture := newRuntimeFixture(t, func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("not used") })
	before, err := fixture.runtime.NodeDetails(t.Context(), "alpha-node")
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.runtime.Refresh(t.Context(), "alpha"); err != nil {
		t.Fatal(err)
	}
	after, err := fixture.runtime.NodeDetails(t.Context(), "alpha-node")
	if err != nil {
		t.Fatal(err)
	}
	if before.SocksUsername != after.SocksUsername || before.SocksPassword != after.SocksPassword {
		t.Fatalf("selector credentials changed: before=%+v after=%+v", before, after)
	}
}

func TestRuntimeProblemErrorsKeepPublicClassifications(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fixture := newRuntimeFixture(t, func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		})
		fixture.runtime.now = time.Now
		result, err := fixture.runtime.Probe(t.Context(), "missing")
		var public interface {
			Code() string
			HTTPStatus() int
		}
		if !errors.As(err, &public) || public.Code() != "node_not_found" || public.HTTPStatus() != 404 {
			t.Fatalf("problem=%v", err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan struct{})
		go func() {
			result, err = fixture.runtime.Probe(ctx, "alpha-node")
			close(done)
		}()
		synctest.Wait()
		time.Sleep(defaultProbeTimeout - time.Nanosecond)
		synctest.Wait()
		select {
		case <-done:
			t.Fatal("probe timed out before its deadline")
		default:
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Fatal("probe did not time out at its deadline")
		}
		if !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &public) || public.Code() != "tcp_probe_timeout" || public.HTTPStatus() != 504 {
			t.Fatalf("timeout problem=%v", err)
		}
		if result.Health != string(state.NodeHealthUnhealthy) || result.TCPLatencyMS != int(defaultProbeTimeout/time.Millisecond) {
			t.Fatalf("timeout result=%+v", result)
		}
	})
}
