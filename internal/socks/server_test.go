package socks

import (
	"github.com/oshinop/chinadapter/internal/provider"
	"github.com/oshinop/chinadapter/internal/state"
	"testing"
)

func TestCanonicalNodeComparisonRejectsReplacement(t *testing.T) {
	left := state.Node{ID: "quickfox_a", Provider: "quickfox", Protocol: "quickfox-native", Host: "127.0.0.1", Port: 80, AuthorityID: "one"}
	if !sameCanonicalNode(left, left) {
		t.Fatal("identical node rejected")
	}
	replaced := left
	replaced.Host = "127.0.0.2"
	if sameCanonicalNode(left, replaced) {
		t.Fatal("replacement node accepted")
	}
}

func TestPinAuthorityComparisonRejectsAuthorityChange(t *testing.T) {
	left := state.TunnelPin{Authority: provider.Authority{Data: []byte("old")}}
	right := state.TunnelPin{Authority: provider.Authority{Data: []byte("new")}}
	if samePinAuthority(left, right) {
		t.Fatal("different pin accepted")
	}
}
