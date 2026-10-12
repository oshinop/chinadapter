package state

import (
	"crypto/subtle"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kfadapter/kfadapter/internal/provider"
)

// RuntimeStore publishes immutable snapshots through an atomic pointer. It
// deep-copies both input and output, so callers cannot mutate a published view.
type RuntimeStore struct {
	snapshot atomic.Pointer[RuntimeSnapshot]
}

// NewRuntimeStore makes an empty store or publishes an initial complete view.
func NewRuntimeStore(initial *RuntimeSnapshot) (*RuntimeStore, error) {
	store := &RuntimeStore{}
	if initial != nil {
		if err := ValidateRuntimeSnapshot(initial); err != nil {
			return nil, err
		}
		store.snapshot.Store(initial.Clone())
	}
	return store, nil
}

// Current returns a private, generation-pinned copy of the current view.
func (s *RuntimeStore) Current() *RuntimeSnapshot {
	if s == nil {
		return nil
	}
	return s.snapshot.Load().Clone()
}

// Publish atomically replaces the view with a deep copy. Generations must be
// strictly monotonic; refresh callers cannot publish partial in-place changes.
func (s *RuntimeStore) Publish(next *RuntimeSnapshot) error {
	if s == nil {
		return fmt.Errorf("nil runtime store")
	}
	if err := ValidateRuntimeSnapshot(next); err != nil {
		return err
	}
	clone := next.Clone()
	for {
		current := s.snapshot.Load()
		if current != nil && clone.Generation <= current.Generation {
			return fmt.Errorf("%w: non-monotonic generation", ErrInvalidSnapshot)
		}
		if s.snapshot.CompareAndSwap(current, clone) {
			return nil
		}
	}
}

// replace is reserved for explicit lifecycle invalidation. It intentionally
// does not relax Publish's generation rules for normal refreshes.
func (s *RuntimeStore) replace(next *RuntimeSnapshot) {
	s.snapshot.Store(next.Clone())
}

// Status is a redacted lifecycle view for API and event consumers.
type Status struct {
	State      ServiceState                   `json:"state"`
	Generation uint64                         `json:"generation,omitempty"`
	CreatedAt  time.Time                      `json:"createdAt,omitempty"`
	ExpiresAt  time.Time                      `json:"expiresAt,omitempty"`
	Accounts   map[provider.ID]AccountSummary `json:"accounts,omitempty"`
	NodeTotal  int                            `json:"nodeTotal"`
	Eligible   int                            `json:"eligible"`
}

// Manager serializes service-state transitions and wraps a RuntimeStore.
type Manager struct {
	runtime *RuntimeStore

	mu            sync.Mutex
	state         ServiceState
	active        Operation
	lease         uint64
	previousState ServiceState
}

// NewManager restores the provider catalog without account-bound credentials.
func NewManager(initial *RuntimeSnapshot) (*Manager, error) {
	store, err := NewRuntimeStore(initial)
	if err != nil {
		return nil, err
	}
	manager := &Manager{runtime: store, state: StateSignedOut}
	if SessionUsable(initial, time.Time{}) {
		manager.state = StateReady
	}
	return manager, nil
}

// Current returns an immutable copy of the current generation.
func (m *Manager) Current() *RuntimeSnapshot {
	if m == nil {
		return nil
	}
	return m.runtime.Current()
}

// TunnelPin is the compact opaque authority and route record retained by one
// SOCKS flow. Only the selected provider transport may decode Authority.Data.
type TunnelPin struct {
	Authority provider.Authority
	ExpiresAt time.Time
	Node      Node
	Ref       NodeRef
}

// CompactPin resolves a live username directly from the atomically published
// snapshot map. The SOCKS server compares the instance password afterwards.
func (m *Manager) CompactPin(selector string, now time.Time) (TunnelPin, error) {
	if m == nil || selector == "" {
		return TunnelPin{}, ErrSelectorUnknown
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state != StateReady && m.state != StateDegraded && m.state != StateSyncing {
		return TunnelPin{}, ErrSelectorUnknown
	}
	current := m.runtime.snapshot.Load()
	if !SessionUsable(current, now) {
		return TunnelPin{}, ErrSelectorUnknown
	}
	node, ref, err := current.ResolveSelector(selector)
	if err != nil {
		return TunnelPin{}, err
	}
	authority, available := current.Authority(node)
	providerSnapshot, providerAvailable := current.Providers[node.Provider]
	if !available || !providerAvailable {
		return TunnelPin{}, ErrSelectorUnknown
	}
	return TunnelPin{Authority: authority, ExpiresAt: providerSnapshot.ExpiresAt, Node: node, Ref: ref}, nil
}

// SessionCurrentPin is the compact final admission check for a SOCKS flow
// after upstream acknowledgement. It is linearizable with state mutation and
// does not require retaining a full runtime snapshot.
func (m *Manager) SessionCurrentPin(pin TunnelPin, now time.Time) bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current := m.runtime.snapshot.Load()
	return (m.state == StateReady || m.state == StateDegraded || m.state == StateSyncing) &&
		current != nil && SessionUsable(current, now) && currentSessionMatchesPin(current, pin)
}

func currentSessionMatchesPin(current *RuntimeSnapshot, pin TunnelPin) bool {
	if current == nil {
		return false
	}
	node, available := current.NodeByID(pin.Node.ID)
	if !available || !node.TunnelEligible() {
		return false
	}
	left, leftErr := provider.NodeKey(node.Route())
	right, rightErr := provider.NodeKey(pin.Node.Route())
	authority, authorityAvailable := current.Authority(node)
	return leftErr == nil && rightErr == nil && left == right && node.AuthorityID == pin.Node.AuthorityID && authorityAvailable &&
		authority.Protocol == pin.Authority.Protocol && subtle.ConstantTimeCompare(authority.Data, pin.Authority.Data) == 1
}

// State returns the current lifecycle state.
func (m *Manager) State() ServiceState {
	if m == nil {
		return StateError
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

// Status returns only non-secret, redacted state.
func (m *Manager) Status() Status {
	if m == nil {
		return Status{State: StateError}
	}
	m.mu.Lock()
	currentState := m.state
	m.mu.Unlock()
	snapshot := m.Current()
	if snapshot == nil {
		return Status{State: currentState}
	}
	status := Status{
		State: currentState, Generation: snapshot.Generation, CreatedAt: snapshot.CreatedAt,
		ExpiresAt: snapshot.ExpiresAt, Accounts: make(map[provider.ID]AccountSummary, len(snapshot.Providers)),
		NodeTotal: len(snapshot.Nodes),
	}
	for id, providerSnapshot := range snapshot.Providers {
		status.Accounts[id] = AccountSummary{Display: providerSnapshot.Account.Display, Tier: providerSnapshot.Account.Tier, SubscriptionActive: providerSnapshot.Account.SubscriptionActive, SubscriptionEndsAt: providerSnapshot.Account.SubscriptionEndsAt}
	}
	for _, node := range snapshot.Nodes {
		if node.TunnelEligible() {
			status.Eligible++
		}
	}
	return status
}

// Begin acquires the exclusive login or refresh lease. The returned function
// must be called exactly once to release the lease.
func (m *Manager) Begin(operation Operation) (func(Outcome), error) {
	if m == nil {
		return nil, ErrNoOperation
	}
	m.mu.Lock()
	if m.active != "" {
		m.mu.Unlock()
		return nil, ErrOperationInProgress
	}
	var target ServiceState
	previous := m.state
	switch operation {
	case OperationLogin:
		switch m.state {
		case StateSignedOut, StateExpired, StateError:
			target = StateAuthenticating
		case StateReady, StateDegraded:
			target = StateSyncing
		default:
			m.mu.Unlock()
			return nil, ErrInvalidTransition
		}
	case OperationRefresh:
		switch m.state {
		case StateReady, StateDegraded:
			target = StateSyncing
		default:
			m.mu.Unlock()
			return nil, ErrInvalidTransition
		}
	default:
		m.mu.Unlock()
		return nil, ErrInvalidTransition
	}
	m.previousState = previous
	m.state = target
	m.active = operation
	m.lease++
	lease := m.lease
	m.mu.Unlock()

	var once sync.Once
	return func(outcome Outcome) {
		once.Do(func() { m.finish(lease, operation, outcome) })
	}, nil
}

func (m *Manager) finish(lease uint64, operation Operation, outcome Outcome) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lease != lease || m.active != operation {
		return
	}
	m.active = ""
	if outcome == OutcomeSucceeded {
		if operation == OperationLogin && m.state == StateAuthenticating {
			m.state = StateSyncing
		}
		return
	}
	current := m.runtime.Current()
	if operation == OperationLogin && SessionUsable(current, time.Now()) && (m.previousState == StateReady || m.previousState == StateDegraded) {
		m.state = m.previousState
		return
	}
	if operation == OperationLogin {
		m.signOutLocked()
		return
	}
	switch {
	case SessionUsable(current, time.Now()):
		m.state = StateDegraded
	default:
		m.state = StateError
	}
}

// Commit publishes a complete provider snapshot after the durable commit.
func (m *Manager) Commit(snapshot *RuntimeSnapshot) error {
	if m == nil || snapshot == nil {
		return ErrInvalidSnapshot
	}
	if err := ValidateRuntimeSnapshot(snapshot); err != nil {
		return err
	}
	if len(snapshot.Providers) == 0 {
		return fmt.Errorf("%w: no provider accounts", ErrInvalidSnapshot)
	}
	hasEligible := false
	for _, node := range snapshot.Nodes {
		if node.TunnelEligible() {
			hasEligible = true
			break
		}
	}
	if !hasEligible {
		return fmt.Errorf("%w: no eligible nodes", ErrInvalidSnapshot)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state != StateAuthenticating && m.state != StateSyncing && m.state != StateReady && m.state != StateDegraded {
		return fmt.Errorf("%w: %s cannot publish", ErrInvalidTransition, m.state)
	}
	if m.runtime.snapshot.Load() != nil && snapshot.Generation <= m.runtime.snapshot.Load().Generation {
		return fmt.Errorf("%w: non-monotonic generation", ErrInvalidSnapshot)
	}
	m.runtime.replace(snapshot)
	if m.state == StateAuthenticating || m.state == StateSyncing {
		m.state = StateReady
	}
	return nil
}

// SignOut removes session material from the current generation while preserving
// the last non-secret node metadata. Previously returned snapshots remain pinned
// for established flows; new flows receive a session-less snapshot and fail.
func (m *Manager) SignOut() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.active = ""
	m.lease++
	m.signOutLocked()
}

// signOutLocked publishes a sessionless, account-redacted snapshot. It must be
// called while m.mu is held.
func (m *Manager) signOutLocked() {
	current := m.runtime.Current()
	if current != nil {
		current.Providers = nil
		m.runtime.replace(current)
	}
	m.state = StateSignedOut
}

// SessionUsable reports whether a validated aggregate retains provider
// accounts. Elapsed time alone never invalidates stored session authority.
// Structural validation belongs at publication, not on every tunnel admission.
func SessionUsable(snapshot *RuntimeSnapshot, _ time.Time) bool {
	return snapshot != nil && len(snapshot.Providers) != 0
}
