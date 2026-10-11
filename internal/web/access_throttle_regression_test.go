package web

import (
	"testing"
	"time"
)

// A non-counted access outcome, such as a 409 setup after initialization, must
// not erase counted failures; otherwise setup becomes a throttle reset probe.
func TestNonCountedAccessOutcomeDoesNotResetFailureWindow(t *testing.T) {
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	store, err := newSessionStore(func() time.Time { return now }, nil, time.Hour, 8, nil)
	if err != nil {
		t.Fatal(err)
	}
	const client = "192.0.2.1"
	attempt := func(successful, countedFailure bool) accessAdmission {
		admission, _ := store.beginAccess(client)
		if admission == accessAdmitted {
			store.finishAccess(client, successful, countedFailure)
		}
		return admission
	}
	for i := range 4 {
		if got := attempt(false, true); got != accessAdmitted {
			t.Fatalf("counted failure %d admission = %v", i+1, got)
		}
	}
	if got := attempt(false, false); got != accessAdmitted {
		t.Fatalf("non-counted outcome admission = %v", got)
	}
	if got := attempt(false, true); got != accessAdmitted {
		t.Fatalf("fifth counted failure admission = %v", got)
	}
	if got, _ := store.beginAccess(client); got != accessRateLimited {
		t.Fatalf("admission after five counted failures = %v, want rate limited", got)
	}
}
