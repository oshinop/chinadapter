package app

import (
	"context"
	"testing"
	"testing/synctest"

	"github.com/kfadapter/kfadapter/internal/web"
)

func TestEventSubscriptionCancelStopsBackgroundWatcher(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hub := newEventHub(1, 1)
		events, cancel, err := hub.subscribe(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		cancel()
		synctest.Wait()
		select {
		case _, ok := <-events:
			if ok {
				t.Fatal("cancelled event channel remained open")
			}
		default:
			t.Fatal("cancelled event channel did not close")
		}
		waitForHubWatchers(t, hub)
		hub.mu.Lock()
		defer hub.mu.Unlock()
		if len(hub.clients) != 0 {
			t.Fatalf("cancelled subscriber retained: %d", len(hub.clients))
		}
	})
}

func TestEventHubCloseRacesSubscriberCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hub := newEventHub(1, 1)
		_, cancel, err := hub.subscribe(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() {
			cancel()
			close(done)
		}()
		hub.close()
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Fatal("subscriber cancel raced with close")
		}
		waitForHubWatchers(t, hub)
	})
}

func waitForHubWatchers(t *testing.T, hub *eventHub) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		hub.watchers.Wait()
		close(done)
	}()
	synctest.Wait()
	select {
	case <-done:
	default:
		t.Fatal("event watcher leaked")
	}
}

func TestEventHubDropsOldestQueuedEvent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hub := newEventHub(1, 2)
		events, cancel, err := hub.subscribe(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer cancel()
		for _, value := range []string{"oldest", "middle", "latest"} {
			hub.publish(web.Event{Type: "state", Data: value})
		}
		if first, second := <-events, <-events; first.Data != "middle" || second.Data != "latest" {
			t.Fatalf("queued events = %+v %+v", first, second)
		}
		if _, _, err := hub.subscribe(t.Context()); err == nil {
			t.Fatal("client cap not enforced")
		}
	})
}
