package app

import (
	"bytes"
	"testing"

	"github.com/kfadapter/kfadapter/internal/identity"
	"github.com/kfadapter/kfadapter/internal/state"
)

func TestCredentialCoordinatorInstallsLiveOnlyMap(t *testing.T) {
	authority, err := identity.New(bytes.Repeat([]byte{1}, 32), "00112233445566778899aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewCredentialCoordinator(nil, authority)
	if err != nil {
		t.Fatal(err)
	}
	nodes := []state.Node{{ID: "kuaifan_node", Provider: "kuaifan", Protocol: "wifiin", Host: "127.0.0.1", Port: 80}}
	refs, err := coordinator.Build(nodes)
	if err != nil || len(refs) != 1 {
		t.Fatalf("refs count = %d, %v", len(refs), err)
	}
	if refs, err := coordinator.Build(nil); err != nil || len(refs) != 0 {
		t.Fatal("absent nodes remained in the live credential map")
	}
}
