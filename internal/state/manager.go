package state

import (
	"crypto/sha256"
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

// AccountBindingStatus reports whether a raw account ID is authorized by the
// durable selector-key binding without exposing that identifier.
type AccountBindingStatus string

const (
	AccountBindingUnbound  AccountBindingStatus = "unbound"
	AccountBindingMatch    AccountBindingStatus = "match"
	AccountBindingMismatch AccountBindingStatus = "mismatch"
)

// Manager serializes service-state transitions and wraps a RuntimeStore.
type Manager struct {
	runtime *RuntimeStore

	mu                   sync.Mutex
	state                ServiceState
	active               Operation
	lease                uint64
	subscription         SubscriptionAuthority
	previousState        ServiceState
	accountBindingKey    []byte
	bindingKeyConfigured bool
}

// NewManager constructs a manager with no durable account-binding authority.
func NewManager(initial *RuntimeSnapshot) (*Manager, error) {
	return NewManagerWithSubscription(initial, SubscriptionAuthority{}, nil)
}

// NewManagerWithSubscription restores persisted subscription authority.
func NewManagerWithSubscription(initial *RuntimeSnapshot, subscription SubscriptionAuthority, bindingKey []byte) (*Manager, error) {
	if len(bindingKey) != 0 && len(bindingKey) != sha256.Size {
		return nil, ErrAccountChanged
	}
	if len(subscription.SelectorKey) != 0 && validateSubscriptionAuthority(subscription) != nil {
		return nil, ErrAccountChanged
	}
	if len(subscription.AccountBinding) != 0 && len(bindingKey) != sha256.Size {
		return nil, ErrAccountChanged
	}
	store, err := NewRuntimeStore(initial)
	if err != nil {
		return nil, err
	}
	manager := &Manager{runtime: store, state: StateSignedOut, subscription: subscription.clone(), accountBindingKey: append([]byte(nil), bindingKey...), bindingKeyConfigured: len(bindingKey) == sha256.Size}
	if initial != nil {
		if SessionUsable(initial, time.Time{}) {
			if !manager.bindingKeyConfigured || len(subscription.AccountBinding) != sha256.Size || !matchesAccountBinding(subscription.AccountBinding, bindingKey, initial.AccountBindingID()) {
				return nil, ErrAccountChanged
			}
			manager.state = StateReady
		} else if len(initial.Nodes) != 0 {
			manager.state = StateSignedOut
		}
	}
	return manager, nil
}

// ConfigureBindingKey installs the verifier-derived account-binding key once.
// It must be called after first-token setup and never accepts raw tokens.
func (m *Manager) ConfigureBindingKey(bindingKey []byte) error {
	if m == nil || len(bindingKey) != sha256.Size {
		return ErrAccountChanged
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.bindingKeyConfigured {
		return ErrBindingKeyAlreadyConfigured
	}
	m.accountBindingKey = append([]byte(nil), bindingKey...)
	m.bindingKeyConfigured = true
	return nil
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

// CompactPin atomically resolves one authenticated selector from the immutable
// snapshot. Authentication is performed by selector.Registry first.
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
	node, ref, err := current.ResolveSelector(selector, now)
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
		current != nil && SessionUsable(current, now) && currentSessionMatchesPin(current, pin, now)
}

// InstallEpoch installs a durable candidate only while an authentication
// operation is active. A same-account refresh retains keys; a cutover rotates both.
func (m *Manager) InstallEpoch(candidate SubscriptionAuthority, userID string) (func(), error) {
	if m == nil || validateSubscriptionAuthority(candidate) != nil {
		return nil, ErrAccountChanged
	}
	m.mu.Lock()
	if (m.state != StateAuthenticating && m.state != StateSyncing) || !m.bindingKeyConfigured || len(m.accountBindingKey) != sha256.Size || len(candidate.AccountBinding) != sha256.Size || !matchesAccountBinding(candidate.AccountBinding, m.accountBindingKey, userID) {
		m.mu.Unlock()
		return nil, ErrAccountChanged
	}
	current := m.subscription
	if len(current.SelectorKey) != 0 {
		if len(current.AccountBinding) == 0 || subtle.ConstantTimeCompare(current.AccountBinding, candidate.AccountBinding) == 1 {
			if !sameSubscriptionCredentials(current, candidate) {
				m.mu.Unlock()
				return nil, ErrAccountChanged
			}
		} else if !rotatedSubscriptionMaterial(current, candidate) {
			m.mu.Unlock()
			return nil, ErrAccountChanged
		}
	}
	previous := current.clone()
	m.subscription = candidate.clone()
	m.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			m.mu.Lock()
			defer m.mu.Unlock()
			if sameSubscriptionAuthority(m.subscription, candidate) {
				m.subscription = previous
			}
		})
	}, nil
}

func sameSubscriptionCredentials(left, right SubscriptionAuthority) bool {
	return subtle.ConstantTimeCompare(left.SelectorKey, right.SelectorKey) == 1 && subtle.ConstantTimeCompare(left.ProxyAuthKey, right.ProxyAuthKey) == 1
}
func sameSubscriptionAuthority(left, right SubscriptionAuthority) bool {
	return sameSubscriptionCredentials(left, right) && subtle.ConstantTimeCompare(left.AccountBinding, right.AccountBinding) == 1
}

// AccountBindingStatus checks the supplied account against durable authority
// without retaining the raw identifier.
func (m *Manager) AccountBindingStatus(userID string) AccountBindingStatus {
	if m == nil {
		return AccountBindingMismatch
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.bindingKeyConfigured || len(m.subscription.SelectorKey) == 0 || len(m.subscription.AccountBinding) == 0 {
		return AccountBindingUnbound
	}
	if matchesAccountBinding(m.subscription.AccountBinding, m.accountBindingKey, userID) {
		return AccountBindingMatch
	}
	return AccountBindingMismatch
}

func currentSessionMatchesPin(current *RuntimeSnapshot, pin TunnelPin, _ time.Time) bool {
	if current == nil {
		return false
	}
	_, available := current.Providers[pin.Node.Provider]
	authority, authorityAvailable := current.Authority(pin.Node)
	return available && authorityAvailable &&
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

// Transition moves between explicit lifecycle states while retaining operation
// serialization. It is useful to expose the authenticating -> syncing phase.
func (m *Manager) Transition(next ServiceState) error {
	if m == nil {
		return ErrInvalidTransition
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !validTransition(m.state, next) {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, m.state, next)
	}
	m.state = next
	return nil
}

func validTransition(from, to ServiceState) bool {
	switch from {
	case StateSignedOut:
		return to == StateAuthenticating
	case StateAuthenticating:
		return to == StateSyncing || to == StateReady || to == StateSignedOut || to == StateError
	case StateSyncing:
		return to == StateReady || to == StateDegraded || to == StateExpired || to == StateError || to == StateSignedOut
	case StateReady:
		return to == StateSyncing || to == StateDegraded || to == StateExpired || to == StateSignedOut
	case StateDegraded:
		return to == StateSyncing || to == StateReady || to == StateExpired || to == StateSignedOut || to == StateError
	case StateExpired:
		return to == StateAuthenticating || to == StateSignedOut
	case StateError:
		return to == StateAuthenticating || to == StateSignedOut
	default:
		return false
	}
}

// Commit publishes a complete newly refreshed snapshot only for the account
// already installed in durable subscription state.
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
	if !m.bindingKeyConfigured || len(m.subscription.SelectorKey) == 0 || len(m.subscription.AccountBinding) != sha256.Size || !matchesAccountBinding(m.subscription.AccountBinding, m.accountBindingKey, snapshot.AccountBindingID()) {
		return ErrAccountChanged
	}
	m.runtime.replace(snapshot)
	if m.state == StateAuthenticating || m.state == StateSyncing {
		m.state = StateReady
	}
	return nil
}

func rotatedSubscriptionMaterial(current, candidate SubscriptionAuthority) bool {
	return subtle.ConstantTimeCompare(current.SelectorKey, candidate.SelectorKey) != 1 &&
		subtle.ConstantTimeCompare(current.ProxyAuthKey, candidate.ProxyAuthKey) != 1
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

// MarkDegraded preserves the current complete generation after a refresh error.
func (m *Manager) MarkDegraded() error { return m.Transition(StateDegraded) }

// SessionUsable reports whether a validated aggregate retains provider
// accounts. Elapsed time alone never invalidates stored session authority.
// Structural validation belongs at publication, not on every tunnel admission.
func SessionUsable(snapshot *RuntimeSnapshot, _ time.Time) bool {
	return snapshot != nil && len(snapshot.Providers) != 0
}
