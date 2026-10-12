package accounts

import (
	"github.com/oshinop/chinadapter/internal/state"
	"testing"
)

type liveBuilder struct{}

func (liveBuilder) Build(nodes []state.Node) (map[string]state.NodeRef, error) {
	refs := make(map[string]state.NodeRef, len(nodes))
	for _, node := range nodes {
		refs[node.Selector] = state.NodeRef{NodeID: node.ID}
	}
	return refs, nil
}
func TestLiveBuilderHasNoRemovedReference(t *testing.T) {
	refs, err := (liveBuilder{}).Build([]state.Node{{ID: "node", Selector: "selector"}})
	if err != nil || refs["selector"].NodeID != "node" || len(refs) != 1 {
		t.Fatalf("refs = %#v, %v", refs, err)
	}
}
