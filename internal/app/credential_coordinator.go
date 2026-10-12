package app

import (
	"errors"
	"sync/atomic"

	"github.com/kfadapter/kfadapter/internal/identity"
	"github.com/kfadapter/kfadapter/internal/state"
)

// CredentialApplier atomically replaces the live username lookup map in SOCKS.
type CredentialApplier interface {
	SetCredentials(*identity.Identity, *state.RuntimeSnapshot) error
}

// CredentialCoordinator shares one immutable installation identity with the
// provider catalog builder and SOCKS. Provider-account mutations never rotate
// it; only access-token setup or change installs another identity.
type CredentialCoordinator struct {
	socks    CredentialApplier
	identity atomic.Pointer[identity.Identity]
}

func NewCredentialCoordinator(socks CredentialApplier, authority *identity.Identity) (*CredentialCoordinator, error) {
	if authority == nil {
		return nil, errors.New("app: installation identity is required")
	}
	coordinator := &CredentialCoordinator{socks: socks}
	coordinator.identity.Store(authority)
	return coordinator, nil
}
func (coordinator *CredentialCoordinator) Identity() *identity.Identity {
	if coordinator == nil {
		return nil
	}
	return coordinator.identity.Load()
}
func (coordinator *CredentialCoordinator) Build(nodes []state.Node) (map[string]state.NodeRef, error) {
	return state.BuildSelectors(nodes, coordinator.Identity())
}

// Install derives a coherent snapshot map and swaps local credential authority.
// The caller holds the shared short mutation lock, never a provider I/O lock.
func (coordinator *CredentialCoordinator) Install(authority *identity.Identity, snapshot *state.RuntimeSnapshot) (*state.RuntimeSnapshot, error) {
	if coordinator == nil || authority == nil {
		return nil, errors.New("app: installation identity is required")
	}
	next := snapshot.Clone()
	if next != nil {
		var err error
		next.Selectors, err = state.BuildSelectors(next.Nodes, authority)
		if err != nil {
			return nil, err
		}
		for index := range next.Nodes {
			credentials, _ := authority.Credentials(next.Nodes[index].Route())
			next.Nodes[index].Selector = credentials.Username
		}
	}
	if coordinator.socks != nil {
		if err := coordinator.socks.SetCredentials(authority, next); err != nil {
			return nil, err
		}
	}
	coordinator.identity.Store(authority)
	return next, nil
}
