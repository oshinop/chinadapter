package lifecycle

import (
	"context"
	"testing"
	"testing/synctest"
	"time"
)

// A worker that cancels the parent and then returns nil is a clean shutdown.
// The parent-done and worker-result branches are both ready, so either can be
// selected; Run must report success whichever one wins.
func TestCleanCancellationNeverReportsWorkerFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		for i := range 2000 {
			parent, cancel := context.WithCancel(context.Background())
			supervisor, err := New([]Worker{{
				Name: "proxy",
				Run: func(context.Context) error {
					cancel()
					return nil
				},
			}}, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if err := supervisor.Run(parent); err != nil {
				t.Fatalf("iteration %d: clean cancellation returned %v", i, err)
			}
			cancel()
		}
	})
}
