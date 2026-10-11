// Package selector derives and validates opaque per-node SOCKS credentials.
package selector

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/kfadapter/kfadapter/internal/provider"
	"github.com/kfadapter/kfadapter/internal/state"
	"golang.org/x/net/idna"
)

const (
	selectorPrefix = "n_"
	passwordPrefix = "p_"
	selectorBytes  = 12
	passwordBytes  = 18

	// MaxLiveSelectors bounds active selector references in one immutable epoch.
	MaxLiveSelectors = 4096
)

var (
	ErrInvalidIdentity = errors.New("invalid node identity")
	ErrInvalidKey      = errors.New("invalid selector key")
	ErrDuplicateNodeID = errors.New("duplicate node id")
	ErrTooManyNodes    = errors.New("too many live selector nodes")
)

var lookupIDNA = idna.New(idna.MapForLookup(), idna.StrictDomainName(true), idna.ValidateForRegistration(), idna.VerifyDNSLength(true))

// NodeIdentity carries a stable node ID and its route. Only NodeID participates
// in selector derivation; the route remains available to callers that need it.
type NodeIdentity struct {
	NodeID   string
	Provider string
	Host     string
	Port     int
}

// CanonicalIdentity is a normalized route used by provider node-ID builders.
type CanonicalIdentity struct {
	NodeID   string
	Provider string
	Host     string
	Port     uint16
}

func Canonicalize(identity NodeIdentity) (CanonicalIdentity, error) {
	if len(identity.NodeID) > 256 || strings.IndexByte(identity.NodeID, 0) >= 0 {
		return CanonicalIdentity{}, fmt.Errorf("%w: invalid logical node id", ErrInvalidIdentity)
	}
	providerID, err := canonicalProvider(identity.Provider)
	if err != nil {
		return CanonicalIdentity{}, err
	}
	host, err := canonicalHost(identity.Host)
	if err != nil {
		return CanonicalIdentity{}, err
	}
	if identity.Port < 1 || identity.Port > 65535 {
		return CanonicalIdentity{}, fmt.Errorf("%w: port out of range", ErrInvalidIdentity)
	}
	return CanonicalIdentity{NodeID: identity.NodeID, Provider: providerID, Host: host, Port: uint16(identity.Port)}, nil
}

func canonicalProvider(raw string) (string, error) {
	canonical := strings.ToLower(strings.TrimSpace(raw))
	if !provider.ID(canonical).Valid() {
		return "", fmt.Errorf("%w: invalid provider id", ErrInvalidIdentity)
	}
	return canonical, nil
}

func canonicalHost(host string) (string, error) {
	if host == "" || strings.IndexByte(host, 0) >= 0 {
		return "", fmt.Errorf("%w: empty host", ErrInvalidIdentity)
	}
	if address, err := netip.ParseAddr(host); err == nil {
		return address.String(), nil
	}
	ascii, err := lookupIDNA.ToASCII(strings.TrimSuffix(strings.ToLower(host), "."))
	if err != nil {
		return "", fmt.Errorf("%w: IDNA host: %w", ErrInvalidIdentity, err)
	}
	ascii = strings.ToLower(ascii)
	if ascii == "" || strings.ContainsAny(ascii, "\x00/\\@") {
		return "", fmt.Errorf("%w: invalid DNS host", ErrInvalidIdentity)
	}
	return ascii, nil
}

// Credentials are the opaque username/password placed in a SOCKS URL.
type Credentials struct{ Selector, Password string }

func validNodeID(id string) bool { return id != "" && len(id) <= 256 && strings.IndexByte(id, 0) < 0 }

// Derive creates credentials from the complete stable NodeID only.
func Derive(identity NodeIdentity, selectorKey, proxyAuthKey []byte) (Credentials, error) {
	return DeriveNodeID(identity.NodeID, selectorKey, proxyAuthKey)
}

func DeriveNodeID(nodeID string, selectorKey, proxyAuthKey []byte) (Credentials, error) {
	if !validNodeID(nodeID) {
		return Credentials{}, ErrInvalidIdentity
	}
	if len(selectorKey) != sha256.Size || len(proxyAuthKey) != sha256.Size {
		return Credentials{}, ErrInvalidKey
	}
	selectorMAC := mac(selectorKey, []byte("selector\x00"+nodeID))
	selector := selectorPrefix + base64.RawURLEncoding.EncodeToString(selectorMAC[:selectorBytes])
	passwordMAC := mac(proxyAuthKey, []byte("selector-password\x00"+selector))
	return Credentials{Selector: selector, Password: passwordPrefix + base64.RawURLEncoding.EncodeToString(passwordMAC[:passwordBytes])}, nil
}

func mac(key, message []byte) []byte {
	result := hmac.New(sha256.New, key)
	_, _ = result.Write(message)
	return result.Sum(nil)
}

// Registry derives and authenticates exactly one immutable key epoch.
type Registry struct{ selectorKey, proxyAuthKey [sha256.Size]byte }

func NewRegistry(source state.SubscriptionAuthority) (*Registry, error) {
	if len(source.SelectorKey) != sha256.Size || len(source.ProxyAuthKey) != sha256.Size {
		return nil, ErrInvalidKey
	}
	registry := &Registry{}
	copy(registry.selectorKey[:], source.SelectorKey)
	copy(registry.proxyAuthKey[:], source.ProxyAuthKey)
	return registry, nil
}

func (r *Registry) Credentials(identity NodeIdentity) (Credentials, bool) {
	if r == nil {
		return Credentials{}, false
	}
	credential, err := DeriveNodeID(identity.NodeID, r.selectorKey[:], r.proxyAuthKey[:])
	return credential, err == nil
}

func (r *Registry) Authenticate(selector, password string) bool {
	return r.AuthenticateAt(selector, password, time.Now())
}
func (r *Registry) AuthenticateAt(selector, password string, _ time.Time) bool {
	if r == nil || !validSelector(selector) || !validPassword(password) {
		return false
	}
	expectedMAC := mac(r.proxyAuthKey[:], []byte("selector-password\x00"+selector))
	expected := passwordPrefix + base64.RawURLEncoding.EncodeToString(expectedMAC[:passwordBytes])
	return subtle.ConstantTimeCompare([]byte(password), []byte(expected)) == 1
}

func (r *Registry) Resolve(snapshot *state.RuntimeSnapshot, selector, password string, now time.Time) (state.Node, state.NodeRef, error) {
	if !r.AuthenticateAt(selector, password, now) {
		return state.Node{}, state.NodeRef{}, state.ErrSelectorUnknown
	}
	return snapshot.ResolveSelector(selector, now)
}

type BuildResult struct {
	Nodes     []state.Node
	Selectors map[string]state.NodeRef
}

// Build derives live selectors deterministically from current node identities.
func (r *Registry) Build(nodes []state.Node) (BuildResult, error) {
	if r == nil {
		return BuildResult{}, ErrInvalidKey
	}
	if len(nodes) > MaxLiveSelectors {
		return BuildResult{}, ErrTooManyNodes
	}
	selected := make([]state.Node, 0, len(nodes))
	selectors := make(map[string]state.NodeRef, len(nodes))
	ids := make(map[string]struct{}, len(nodes))
	for _, node := range nodes {
		if !validNodeID(node.ID) {
			return BuildResult{}, ErrDuplicateNodeID
		}
		if _, duplicate := ids[node.ID]; duplicate {
			return BuildResult{}, ErrDuplicateNodeID
		}
		ids[node.ID] = struct{}{}
		credential, ok := r.Credentials(NodeIdentity{NodeID: node.ID})
		if !ok {
			return BuildResult{}, ErrInvalidIdentity
		}
		if _, collision := selectors[credential.Selector]; collision {
			return BuildResult{}, ErrDuplicateNodeID
		}
		node.Selector = credential.Selector
		selected = append(selected, node)
		selectors[credential.Selector] = state.NodeRef{NodeID: node.ID}
	}
	return BuildResult{Nodes: selected, Selectors: selectors}, nil
}

func validSelector(selector string) bool {
	if len(selector) != len(selectorPrefix)+base64.RawURLEncoding.EncodedLen(selectorBytes) || !strings.HasPrefix(selector, selectorPrefix) {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(selector[len(selectorPrefix):])
	return err == nil && len(decoded) == selectorBytes
}
func validPassword(password string) bool {
	if len(password) != len(passwordPrefix)+base64.RawURLEncoding.EncodedLen(passwordBytes) || !strings.HasPrefix(password, passwordPrefix) {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(password[len(passwordPrefix):])
	return err == nil && len(decoded) == passwordBytes
}
