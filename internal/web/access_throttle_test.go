package web

import (
	"fmt"
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

func TestClientIdentityGroupsIPv6By64(t *testing.T) {
	if clientIdentity("[2001:db8:1:2::1]:42") != clientIdentity("[2001:db8:1:2:abcd::2]:43") {
		t.Fatal("IPv6 /64 budget was split")
	}
	if clientIdentity("[2001:db8:1:2::1]:42") == clientIdentity("[2001:db8:1:3::1]:42") {
		t.Fatal("distinct IPv6 /64 budgets merged")
	}
}

func TestAccessTableEvictsOldestUnblockedEntry(t *testing.T) {
	now := time.Now()
	store, err := newSessionStore(func() time.Time { return now }, nil, time.Hour, 8, nil)
	if err != nil {
		t.Fatal(err)
	}
	for index := range 1024 {
		store.accessAttempts[fmt.Sprint(index)] = accessAttempt{createdAt: now.Add(time.Duration(index) * time.Second), windowEnd: now.Add(time.Hour)}
	}
	blocked := store.accessAttempts["0"]
	blocked.blockedTo = now.Add(time.Hour)
	store.accessAttempts["0"] = blocked
	if admission, _ := store.beginAccess("new"); admission != accessAdmitted {
		t.Fatalf("new client admission = %v", admission)
	}
	if _, exists := store.accessAttempts["1"]; exists {
		t.Fatal("oldest unblocked entry was not evicted")
	}
	if _, exists := store.accessAttempts["0"]; !exists {
		t.Fatal("blocked entry was evicted")
	}
	if len(store.accessAttempts) != 1024 {
		t.Fatalf("table size = %d", len(store.accessAttempts))
	}
}
