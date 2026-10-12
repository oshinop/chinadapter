package state

import (
	"testing"
	"time"
)

func TestRuntimeGenerationRemainsMonotonic(t *testing.T) {
	now := time.Now().UTC()
	store, err := NewRuntimeStore(&RuntimeSnapshot{Generation: 1, CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Publish(&RuntimeSnapshot{Generation: 1, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err == nil {
		t.Fatal("accepted non-monotonic runtime generation")
	}
}
