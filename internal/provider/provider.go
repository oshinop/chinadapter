// Package provider defines account, lifecycle, node, and transport contracts
// shared by provider implementations and the provider-neutral runtime.
package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	maxIdentifierBytes = 32
	maxFieldBytes      = 4096
	maxStateBytes      = 1 << 20
	maxAuthorities     = 16
	maxNodes           = 4096
)

var (
	ErrUnknownProvider  = errors.New("provider: unknown provider")
	ErrUnknownTransport = errors.New("provider: unknown transport")
	ErrInvalidSnapshot  = errors.New("provider: invalid snapshot")
	ErrInvalidInput     = errors.New("provider: invalid credentials")
	ErrLoginRejected    = errors.New("provider: login rejected")
	ErrAccountExists    = errors.New("provider: account already exists")
	ErrNoSession        = errors.New("provider: no refreshable session")
	ErrAuthorityExpired = errors.New("provider: authority expired")
	// ErrSessionRejected means the upstream explicitly invalidated the stored
	// session. Only explicit rejection codes map here; every other driver error
	// is transient and must never delete provider state.
	ErrSessionRejected = errors.New("provider: session rejected by upstream")
)

// ID is a stable provider implementation identifier, such as "kuaifan".
type ID string

func (id ID) Valid() bool { return validIdentifier(string(id)) }

// Protocol identifies a provider-specific data-plane transport, such as
// "kuaifan-wifiin". SOCKS dispatches exclusively on this value.
type Protocol string

func (protocol Protocol) Valid() bool { return validIdentifier(string(protocol)) }

func validIdentifier(value string) bool {
	if len(value) == 0 || len(value) > maxIdentifierBytes || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}

// Credentials are transient provider login input. Drivers must not retain the
// password after Login returns.
type Credentials struct {
	Account        string
	Password       string
	InstallationID string
}

func (credentials Credentials) Valid() bool {
	return validField(strings.TrimSpace(credentials.Account)) &&
		validField(credentials.Password) && validField(strings.TrimSpace(credentials.InstallationID))
}

// RedactAccount returns a provider-neutral, browser-safe display value.
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

// Account is the browser-safe account view plus the provider's opaque user ID.
// UserID is never serialized by outer presentation layers.
type Account struct {
	UserID             string
	Display            string
	Tier               string
	SubscriptionActive bool
	SubscriptionEndsAt time.Time
}

func (account Account) Valid() bool {
	return validField(account.UserID) && validField(account.Display) && validField(account.Tier) &&
		account.SubscriptionActive == !account.SubscriptionEndsAt.IsZero()
}

// Authority is one opaque, protocol-specific tunnel authority. State persists
// Data without interpreting it; only the matching Transport may decode it.
type Authority struct {
	Protocol Protocol
	Data     []byte
}

func (authority Authority) Valid() bool {
	return authority.Protocol.Valid() && len(authority.Data) > 0 && len(authority.Data) <= maxStateBytes
}

func (authority Authority) Clone() Authority {
	authority.Data = append([]byte(nil), authority.Data...)
	return authority
}

// Node is provider-produced, secret-free upstream metadata.
type Node struct {
	ID          string
	AuthorityID string
	Protocol    Protocol
	Host        string
	Port        uint16
	Name        string
	Group       string
	Model       string
	Weight      int
	Auto        bool
	Eligible    bool
}

func (node Node) Valid() bool {
	return validField(node.ID) && validField(node.AuthorityID) && node.Protocol.Valid() &&
		validField(node.Host) && node.Port != 0 && len(node.Name) <= maxFieldBytes &&
		len(node.Group) <= maxFieldBytes && len(node.Model) <= maxFieldBytes
}

// Snapshot is one provider account's complete refresh result. RefreshState and
// authority Data are opaque to every package except the originating driver and
// matching transport.
type Snapshot struct {
	Provider     ID
	Account      Account
	ExpiresAt    time.Time
	RefreshState []byte
	Authorities  map[string]Authority
	Nodes        []Node
}

// Valid reports whether the complete provider snapshot is structurally sound.
func (snapshot Snapshot) Valid() bool {
	if !snapshot.Provider.Valid() || !snapshot.Account.Valid() || snapshot.ExpiresAt.IsZero() ||
		len(snapshot.RefreshState) == 0 || len(snapshot.RefreshState) > maxStateBytes ||
		len(snapshot.Authorities) == 0 || len(snapshot.Authorities) > maxAuthorities || len(snapshot.Nodes) > maxNodes {
		return false
	}
	for id, authority := range snapshot.Authorities {
		if !validField(id) || !authority.Valid() {
			return false
		}
	}
	seen := make(map[string]struct{}, len(snapshot.Nodes))
	for _, node := range snapshot.Nodes {
		authority, available := snapshot.Authorities[node.AuthorityID]
		if !node.Valid() || !available || authority.Protocol != node.Protocol {
			return false
		}
		if _, duplicate := seen[node.ID]; duplicate {
			return false
		}
		seen[node.ID] = struct{}{}
	}
	return true
}

// UsableAt reports whether the snapshot contains structurally valid authority.
// ExpiresAt is a refresh hint, never an admission or deletion deadline.
func (snapshot Snapshot) UsableAt(_ time.Time) bool {
	return snapshot.Valid()
}

func (snapshot Snapshot) Clone() Snapshot {
	snapshot.RefreshState = append([]byte(nil), snapshot.RefreshState...)
	authorities := snapshot.Authorities
	snapshot.Authorities = make(map[string]Authority, len(authorities))
	for id, authority := range authorities {
		snapshot.Authorities[id] = authority.Clone()
	}
	snapshot.Nodes = append([]Node(nil), snapshot.Nodes...)
	return snapshot
}

// Driver owns one provider's account login, refresh state, and node catalog.
type Driver interface {
	ID() ID
	Login(context.Context, Credentials) (Snapshot, error)
	Refresh(context.Context, Snapshot) (Snapshot, error)
}

func ValidateSnapshot(snapshot Snapshot, expected ID, now time.Time) error {
	if snapshot.Provider != expected || !snapshot.UsableAt(now) {
		return fmt.Errorf("%w: %s", ErrInvalidSnapshot, expected)
	}
	return nil
}

func validField(value string) bool {
	return value != "" && len(value) <= maxFieldBytes && utf8.ValidString(value) && strings.IndexByte(value, 0) < 0
}
