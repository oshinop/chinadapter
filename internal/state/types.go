// Package state owns the adapter's domain types and immutable runtime view.
package state

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"

	credentialspkg "github.com/oshinop/chinadapter/internal/credentials"
	"github.com/oshinop/chinadapter/internal/provider"
)

const maxRuntimeNodes = 4096

var (
	ErrAccessTokenAlreadyInitialized = errors.New("access token is already initialized")
	ErrInvalidAccessToken            = errors.New("invalid access token")
	ErrInvalidNextAccessToken        = errors.New("invalid next access token")
	ErrStateNotFound                 = errors.New("persistent state not found")
	ErrCorruptState                  = errors.New("persistent state is corrupt")
	ErrStateBusy                     = errors.New("state database is busy")
	ErrInsecureStatePath             = errors.New("state path has insecure ownership or mode")
	ErrInvalidSnapshot               = errors.New("invalid runtime snapshot")
	ErrInvalidTransition             = errors.New("invalid service state transition")
	ErrOperationInProgress           = errors.New("service operation already in progress")
	ErrNoOperation                   = errors.New("no service operation in progress")
	ErrSelectorUnknown               = errors.New("unknown selector")
)

// ServiceState is the externally visible lifecycle state. State transitions are
// serialized by Manager.
type ServiceState string

const (
	StateSignedOut      ServiceState = "signed_out"
	StateAuthenticating ServiceState = "authenticating"
	StateSyncing        ServiceState = "syncing"
	StateReady          ServiceState = "ready"
	StateDegraded       ServiceState = "degraded"
	StateExpired        ServiceState = "expired"
	StateError          ServiceState = "error"
)

// Operation identifies an exclusive control-plane operation.
type Operation string

const (
	OperationLogin   Operation = "login"
	OperationRefresh Operation = "refresh"
)

// Outcome tells a Manager operation lease how it ended.
type Outcome string

const (
	OutcomeSucceeded Outcome = "succeeded"
	OutcomeFailed    Outcome = "failed"
	OutcomeCancelled Outcome = "cancelled"
)

// NodeHealth is intentionally distinct from eligibility. Continuous selection
// health is external to the adapter; this is only its latest explicit observation.
type NodeHealth string

const (
	NodeHealthUnknown     NodeHealth = "unknown"
	NodeHealthHealthy     NodeHealth = "healthy"
	NodeHealthUnhealthy   NodeHealth = "unhealthy"
	NodeHealthUnsupported NodeHealth = "unsupported"
)

// UDPHealth reports the deliberately feature-gated UDP state.
type UDPHealth string

const (
	UDPHealthUnavailable UDPHealth = "unavailable"
	UDPHealthUnknown     UDPHealth = "unknown"
)

// Node is validated, secret-free metadata for one provider-owned upstream.
// AuthorityID resolves only within the matching provider snapshot.
type Node struct {
	ID          string            `json:"id"`
	Selector    string            `json:"selector"`
	Provider    provider.ID       `json:"provider"`
	Protocol    provider.Protocol `json:"protocol"`
	AuthorityID string            `json:"-"`
	Host        string            `json:"host"`
	Port        uint16            `json:"port"`
	Name        string            `json:"name"`
	Group       string            `json:"group"`
	Model       string            `json:"model,omitempty"`
	Weight      int               `json:"weight,omitempty"`
	Auto        bool              `json:"auto,omitempty"`

	Eligible  bool          `json:"eligible"`
	Excluded  bool          `json:"excluded"`
	Health    NodeHealth    `json:"health"`
	UDPHealth UDPHealth     `json:"udpHealth"`
	TCPRTT    time.Duration `json:"tcpRtt,omitempty"`
	ProbedAt  time.Time     `json:"probedAt,omitempty"`
}

// Route contains only the inputs the provider transport uses to reach a node.
func (n Node) Route() provider.Route {
	return provider.Route{Provider: n.Provider, Protocol: n.Protocol, Host: n.Host, Port: n.Port}
}

// TunnelEligible reports whether a generic provider transport can accept the
// node. Protocol-specific validation belongs to that transport.
func (n Node) TunnelEligible() bool {
	return n.Eligible && n.Provider.Valid() && n.Protocol.Valid() && n.AuthorityID != "" && n.Port != 0 && n.Host != ""
}

// SelectorBuilder derives opaque selector references without depending on the
// selector implementation.
type SelectorBuilder interface {
	Build(nodes []Node) (map[string]NodeRef, error)
}

// NodeRef resolves a selector to one live node in an immutable snapshot.
type NodeRef struct {
	NodeID string `json:"nodeId,omitempty"`
}

// AccountSummary deliberately has no raw account identifier. Display must be
// produced with RedactAccount before publication.
type AccountSummary struct {
	Display            string    `json:"display"`
	Tier               string    `json:"tier"`
	SubscriptionActive bool      `json:"subscriptionActive"`
	SubscriptionEndsAt time.Time `json:"subscriptionEndsAt,omitempty"`
}

// NewAccountSummary is the safe construction path for browser-visible account
// metadata. It never retains the supplied raw account identifier.
func NewAccountSummary(account, tier string, subscriptionActive bool, subscriptionEndsAt time.Time) AccountSummary {
	return AccountSummary{Display: RedactAccount(account), Tier: tier, SubscriptionActive: subscriptionActive, SubscriptionEndsAt: subscriptionEndsAt}
}

// RedactAccount returns a safe display form. It never returns the original
// local part and declines to expose malformed account strings.
func RedactAccount(account string) string {
	account = strings.TrimSpace(account)
	at := strings.LastIndexByte(account, '@')
	if at <= 0 || at == len(account)-1 || strings.Count(account, "@") != 1 {
		return "•••"
	}
	local := []rune(account[:at])
	if len(local) == 0 {
		return "•••"
	}
	return string(local[0]) + "•••@" + account[at+1:]
}

// RuntimeSnapshot is one atomic aggregate of independent provider accounts.
// Each provider owns opaque refresh and tunnel authority state.
type RuntimeSnapshot struct {
	Generation uint64                            `json:"generation"`
	CreatedAt  time.Time                         `json:"createdAt"`
	ExpiresAt  time.Time                         `json:"expiresAt"`
	Providers  map[provider.ID]provider.Snapshot `json:"-"`
	Nodes      []Node                            `json:"nodes"`
	Selectors  map[string]NodeRef                `json:"selectors"`
	nodeIndex  map[string]int
}

// Clone deep-copies all mutable runtime fields and opaque provider material.
func (s *RuntimeSnapshot) Clone() *RuntimeSnapshot {
	if s == nil {
		return nil
	}
	clone := *s
	clone.Providers = make(map[provider.ID]provider.Snapshot, len(s.Providers))
	for id, snapshot := range s.Providers {
		clone.Providers[id] = snapshot.Clone()
	}
	clone.Nodes = append([]Node(nil), s.Nodes...)
	clone.IndexNodes()
	clone.Selectors = make(map[string]NodeRef, len(s.Selectors))
	for selector, ref := range s.Selectors {
		clone.Selectors[selector] = ref
	}
	return &clone
}

// IndexNodes rebuilds the node-ID lookup used by NodeByID. Call it after
// constructing or replacing Nodes outside Clone.
func (s *RuntimeSnapshot) IndexNodes() {
	s.nodeIndex = make(map[string]int, len(s.Nodes))
	for index, node := range s.Nodes {
		s.nodeIndex[node.ID] = index
	}
}

// Provider returns an independent snapshot for one configured account.
func (s *RuntimeSnapshot) Provider(id provider.ID) (provider.Snapshot, bool) {
	if s == nil {
		return provider.Snapshot{}, false
	}
	snapshot, available := s.Providers[id]
	if !available {
		return provider.Snapshot{}, false
	}
	return snapshot.Clone(), true
}

// Authority resolves one node's opaque tunnel authority.
func (s *RuntimeSnapshot) Authority(node Node) (provider.Authority, bool) {
	if s == nil {
		return provider.Authority{}, false
	}
	snapshot, available := s.Providers[node.Provider]
	if !available {
		return provider.Authority{}, false
	}
	authority, available := snapshot.Authorities[node.AuthorityID]
	if !available || authority.Protocol != node.Protocol {
		return provider.Authority{}, false
	}
	return authority.Clone(), true
}

// ProviderExpiresAt returns the latest provider expiry in the aggregate.
func ProviderExpiresAt(providers map[provider.ID]provider.Snapshot) time.Time {
	var latest time.Time
	for _, snapshot := range providers {
		if snapshot.ExpiresAt.After(latest) {
			latest = snapshot.ExpiresAt
		}
	}
	return latest
}

// NodeByID returns a copy of the node identified by its opaque ID.
func (s *RuntimeSnapshot) NodeByID(id string) (Node, bool) {
	if s == nil {
		return Node{}, false
	}
	if index, available := s.nodeIndex[id]; available {
		return s.Nodes[index], true
	}
	return Node{}, false
}

// ResolveSelector resolves a username in this pinned immutable snapshot.
func (s *RuntimeSnapshot) ResolveSelector(selector string) (Node, NodeRef, error) {
	if s == nil {
		return Node{}, NodeRef{}, ErrSelectorUnknown
	}
	ref, ok := s.Selectors[selector]
	if !ok || ref.NodeID == "" {
		return Node{}, NodeRef{}, ErrSelectorUnknown
	}
	node, ok := s.NodeByID(ref.NodeID)
	if !ok {
		return Node{}, NodeRef{}, ErrSelectorUnknown
	}
	return node, ref, nil
}

// ValidateRuntimeSnapshot checks provider-neutral aggregate invariants without
// interpreting any driver's opaque refresh or transport authority state.
func ValidateRuntimeSnapshot(snapshot *RuntimeSnapshot) error {
	if snapshot == nil || snapshot.Generation == 0 || snapshot.CreatedAt.IsZero() || snapshot.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: missing generation, creation time, or expiry", ErrInvalidSnapshot)
	}
	if len(snapshot.Nodes) > maxRuntimeNodes || len(snapshot.Selectors) > maxRuntimeNodes {
		return fmt.Errorf("%w: runtime snapshot exceeds selector bounds", ErrInvalidSnapshot)
	}
	for id, providerSnapshot := range snapshot.Providers {
		if providerSnapshot.Provider != id || !providerSnapshot.Valid() {
			return fmt.Errorf("%w: invalid provider snapshot", ErrInvalidSnapshot)
		}
	}
	if len(snapshot.Providers) != 0 && !ProviderExpiresAt(snapshot.Providers).Equal(snapshot.ExpiresAt) {
		return fmt.Errorf("%w: aggregate expiry mismatch", ErrInvalidSnapshot)
	}
	ids := make(map[string]struct{}, len(snapshot.Nodes))
	for _, node := range snapshot.Nodes {
		if err := ValidateNode(node); err != nil {
			return fmt.Errorf("%w: incomplete node", ErrInvalidSnapshot)
		}
		providerSnapshot, providerAvailable := snapshot.Providers[node.Provider]
		if providerAvailable {
			if !nodeMatchesProviderSnapshot(node, providerSnapshot) {
				return fmt.Errorf("%w: node differs from provider snapshot", ErrInvalidSnapshot)
			}
		} else if len(snapshot.Providers) != 0 {
			return fmt.Errorf("%w: node has no provider snapshot", ErrInvalidSnapshot)
		}
		if _, exists := ids[node.ID]; exists {
			return fmt.Errorf("%w: duplicate node id", ErrInvalidSnapshot)
		}
		ids[node.ID] = struct{}{}
	}
	for selector, ref := range snapshot.Selectors {
		if selector == "" || ref.NodeID == "" {
			return fmt.Errorf("%w: invalid selector reference", ErrInvalidSnapshot)
		}
		if _, exists := ids[ref.NodeID]; !exists {
			return fmt.Errorf("%w: selector references absent node", ErrInvalidSnapshot)
		}
	}
	return nil
}

func nodeMatchesProviderSnapshot(node Node, snapshot provider.Snapshot) bool {
	for _, source := range snapshot.Nodes {
		if source.ID == node.ID {
			return source.AuthorityID == node.AuthorityID && source.Protocol == node.Protocol && source.Host == node.Host && source.Port == node.Port &&
				source.Name == node.Name && source.Group == node.Group && source.Model == node.Model && source.Weight == node.Weight &&
				source.Auto == node.Auto && source.Eligible == node.Eligible
		}
	}
	return false
}

// Preferences are durable, non-secret user choices. ExcludedNodeIDs does not
// affect runtime tunnel selection.
type Preferences struct {
	ExcludedNodeIDs map[string]bool
	RevealEndpoints bool
	RefreshPolicy   string
}

func (p Preferences) clone() Preferences {
	clone := p
	clone.ExcludedNodeIDs = make(map[string]bool, len(p.ExcludedNodeIDs))
	for nodeID, excluded := range p.ExcludedNodeIDs {
		clone.ExcludedNodeIDs[nodeID] = excluded
	}
	return clone
}

type Argon2idParameters struct {
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8
}

// AccessTokenVerifier contains only a salted Argon2id verifier. Hash also
// derives installation-scoped credentials; the raw token is never persisted.
type AccessTokenVerifier struct {
	Parameters Argon2idParameters
	Salt       []byte
	Hash       []byte
}

const (
	accessTokenMinBytes  = 16
	accessTokenMaxBytes  = 128
	accessTokenSaltBytes = 16
	accessTokenHashBytes = sha256.Size
)

var productionArgon2idParameters = Argon2idParameters{
	MemoryKiB: 64 * 1024, Iterations: 3, Parallelism: 1,
}

func (v *AccessTokenVerifier) clone() *AccessTokenVerifier {
	if v == nil {
		return nil
	}
	clone := *v
	clone.Salt = append([]byte(nil), v.Salt...)
	clone.Hash = append([]byte(nil), v.Hash...)
	return &clone
}

func validAccessToken(token string) bool {
	token = strings.TrimSpace(token)
	return utf8.ValidString(token) && len(token) >= accessTokenMinBytes && len(token) <= accessTokenMaxBytes
}

func sameArgon2idParameters(left, right Argon2idParameters) bool {
	return left.MemoryKiB == right.MemoryKiB && left.Iterations == right.Iterations && left.Parallelism == right.Parallelism
}

func validateAccessTokenVerifier(verifier *AccessTokenVerifier) error {
	if verifier == nil || !sameArgon2idParameters(verifier.Parameters, productionArgon2idParameters) || len(verifier.Salt) != accessTokenSaltBytes || len(verifier.Hash) != accessTokenHashBytes {
		return ErrInvalidAccessToken
	}
	return nil
}

// NewAccessTokenVerifier derives the production Argon2id verifier for token.
func NewAccessTokenVerifier(token string) (*AccessTokenVerifier, error) {
	token = strings.TrimSpace(token)
	if !validAccessToken(token) {
		return nil, ErrInvalidAccessToken
	}
	salt, err := RandomBytes(accessTokenSaltBytes)
	if err != nil {
		return nil, err
	}
	parameters := productionArgon2idParameters
	hash := argon2.IDKey([]byte(token), salt, parameters.Iterations, parameters.MemoryKiB, parameters.Parallelism, accessTokenHashBytes)
	return &AccessTokenVerifier{Parameters: parameters, Salt: salt, Hash: hash}, nil
}

// VerifyAccessToken performs one Argon2id derivation and a constant-time
// comparison. Invalid and mismatched tokens both return false.
func (v *AccessTokenVerifier) VerifyAccessToken(token string) bool {
	if validateAccessTokenVerifier(v) != nil {
		return false
	}
	token = strings.TrimSpace(token)
	if !validAccessToken(token) {
		return false
	}
	actual := argon2.IDKey([]byte(token), v.Salt, v.Parameters.Iterations, v.Parameters.MemoryKiB, v.Parameters.Parallelism, accessTokenHashBytes)
	defer WipeBytes(actual)
	return subtle.ConstantTimeCompare(actual, v.Hash) == 1
}

// WipeBytes clears transient secret material after use.
func WipeBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

// PersistentState is deliberately closed. It stores an Argon2id verifier but
// never the raw local access token or provider account password. ActiveSession
// is persisted only by store.SQLiteStore.
type PersistentState struct {
	InstallationID      string
	AccessTokenVerifier *AccessTokenVerifier
	Preferences         Preferences
	ActiveSession       *RuntimeSnapshot `json:"-"`
}

func (p PersistentState) Clone() PersistentState {
	p.AccessTokenVerifier = p.AccessTokenVerifier.clone()
	p.Preferences = p.Preferences.clone()
	p.ActiveSession = p.ActiveSession.Clone()
	return p
}

// AccessTokenInitialized reports whether setup has claimed this installation.
func (p PersistentState) AccessTokenInitialized() bool {
	return validateAccessTokenVerifier(p.AccessTokenVerifier) == nil
}

// SetAccessToken initializes the verifier exactly once.
func (p *PersistentState) SetAccessToken(token string) error {
	if p == nil {
		return ErrInvalidAccessToken
	}
	if p.AccessTokenVerifier != nil {
		return ErrAccessTokenAlreadyInitialized
	}
	verifier, err := NewAccessTokenVerifier(token)
	if err != nil {
		return err
	}
	p.AccessTokenVerifier = verifier
	return nil
}

// VerifyAccessToken authenticates a transient access token without retaining it.
func (p PersistentState) VerifyAccessToken(token string) bool {
	return p.AccessTokenVerifier.VerifyAccessToken(token)
}

// NewPersistentState creates an uninitialized installation.
func NewPersistentState() (PersistentState, error) {
	installation, err := randomInstallationID()
	if err != nil {
		return PersistentState{}, err
	}
	return PersistentState{
		InstallationID: installation,
		Preferences:    Preferences{ExcludedNodeIDs: make(map[string]bool)},
	}, nil
}

// Identity derives the immutable local credential authority from the verifier.
func (p PersistentState) Identity() (*credentialspkg.Identity, error) {
	var hash []byte
	if p.AccessTokenInitialized() {
		hash = p.AccessTokenVerifier.Hash
	}
	return credentialspkg.New(hash, p.InstallationID)
}

// ChangeAccessToken rotates only local access authority, not provider sessions.
func (p *PersistentState) ChangeAccessToken(current, next string) error {
	if p == nil || !p.VerifyAccessToken(current) {
		return ErrInvalidAccessToken
	}
	if strings.TrimSpace(current) == strings.TrimSpace(next) {
		return ErrInvalidNextAccessToken
	}
	verifier, err := NewAccessTokenVerifier(next)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidNextAccessToken, err)
	}
	p.AccessTokenVerifier = verifier
	return nil
}

// BuildSelectors derives a live username map without persisting credentials.
func BuildSelectors(nodes []Node, authority *credentialspkg.Identity) (map[string]NodeRef, error) {
	selectors := make(map[string]NodeRef, len(nodes))
	for _, node := range nodes {
		credentials, available := authority.Credentials(node.Route())
		if !available {
			return nil, credentialspkg.ErrInvalidKey
		}
		if _, duplicate := selectors[credentials.Username]; duplicate {
			return nil, fmt.Errorf("%w: duplicate node route", ErrInvalidSnapshot)
		}
		selectors[credentials.Username] = NodeRef{NodeID: node.ID}
	}
	return selectors, nil
}

func validatePreferences(preferences Preferences) error {
	for nodeID, excluded := range preferences.ExcludedNodeIDs {
		if nodeID == "" || !excluded {
			return fmt.Errorf("invalid excluded node preference")
		}
	}
	if preferences.RefreshPolicy != "" {
		interval, err := time.ParseDuration(preferences.RefreshPolicy)
		if err != nil || interval < 15*time.Minute || interval > 24*time.Hour {
			return fmt.Errorf("invalid refresh policy")
		}
	}
	return nil
}

// ValidatePersistentState verifies the aggregate reconstructed from SQLite.
func ValidatePersistentState(p PersistentState) error {
	if !validInstallationID(p.InstallationID) {
		return fmt.Errorf("invalid persistent state")
	}
	if p.AccessTokenVerifier != nil && validateAccessTokenVerifier(p.AccessTokenVerifier) != nil {
		return fmt.Errorf("invalid access token verifier")
	}
	if p.ActiveSession != nil {
		if err := ValidateRuntimeSnapshot(p.ActiveSession); err != nil {
			return fmt.Errorf("invalid active session: %w", err)
		}
	}
	return validatePreferences(p.Preferences)
}

// ValidateNode checks the non-secret structural fields shared by runtime and
// persisted nodes. Provider compatibility remains an eligibility decision.
func ValidateNode(node Node) error {
	if node.ID == "" || !node.Provider.Valid() || !node.Protocol.Valid() || node.AuthorityID == "" || node.Host == "" || node.Port == 0 || strings.IndexByte(string(node.Provider), 0) >= 0 || strings.IndexByte(string(node.Protocol), 0) >= 0 || strings.IndexByte(node.Host, 0) >= 0 {
		return fmt.Errorf("invalid node")
	}
	return nil
}

// RandomBytes returns cryptographically secure randomness for state authority.
func RandomBytes(n int) ([]byte, error) {
	value := make([]byte, n)
	if _, err := rand.Read(value); err != nil {
		return nil, fmt.Errorf("reading random bytes: %w", err)
	}
	return value, nil
}

func randomInstallationID() (string, error) {
	value, err := RandomBytes(16)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func validInstallationID(value string) bool {
	if len(value) != 32 {
		return false
	}
	for index := range len(value) {
		if (value[index] < '0' || value[index] > '9') && (value[index] < 'a' || value[index] > 'f') {
			return false
		}
	}
	return true
}
