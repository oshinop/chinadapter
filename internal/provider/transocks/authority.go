// Package transocks implements the Transocks (穿梭) provider: an HTTPS/JSON
// control plane whose connect calls return ordinary Shadowsocks or Trojan
// tunnel configurations. See docs/transocks-android-4.0.3-analysis.md.
package transocks

import (
	"encoding/json"
	"errors"
	"net"
	"strconv"

	"github.com/oshinop/chinadapter/internal/provider"
)

const (
	ProviderID             provider.ID       = "transocks"
	ShadowsocksProtocol    provider.Protocol = "transocks-ss"
	TrojanProtocol         provider.Protocol = "transocks-trojan"
	shadowsocksAuthorityID                   = "ss"
	trojanAuthorityID                        = "trojan"
	maxAuthorityNodes                        = 4096
	maxAuthorityField                        = 4096
)

// ErrInvalidAuthority identifies malformed opaque control-plane authority.
var (
	ErrInvalidAuthority = errors.New("transocks: invalid tunnel authority")
	// ErrNoProbeAddress reports a line without a catalog detect endpoint.
	ErrNoProbeAddress = errors.New("transocks: line has no probe endpoint")
)

func nodeKey(host string, port uint16) string {
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}

// Tunnel secrets exist only in the two-entry in-memory session cache.
type shadowsocksEntry struct {
	Method   string `json:"method"`
	Password string `json:"password"`
}

type trojanEntry struct {
	Password  string           `json:"password"`
	SNI       string           `json:"sni,omitempty"`
	Verify    bool             `json:"verify"`
	WebSocket *trojanWebSocket `json:"websocket,omitempty"`
}

type trojanWebSocket struct {
	Host string `json:"host,omitempty"`
	Path string `json:"path"`
}

// One authority per protocol retains the account session and stable line pins,
// never a provider-issued endpoint, tunnel password or boostSession. Probes
// holds each line's optional catalog detect endpoint for reachability checks.
type tunnelAuthority struct {
	Session storedSession     `json:"session"`
	Nodes   map[string]int64  `json:"nodes"`
	Probes  map[string]string `json:"probes,omitempty"`
}

func supportedShadowsocksMethod(method string) bool {
	switch method {
	case "chacha20-ietf-poly1305", "aes-128-gcm", "aes-256-gcm":
		return true
	default:
		return false
	}
}

func (entry shadowsocksEntry) valid() bool {
	return supportedShadowsocksMethod(entry.Method) && entry.Password != "" && len(entry.Password) <= maxAuthorityField
}

func (entry trojanEntry) valid() bool {
	if entry.Password == "" || len(entry.Password) > maxAuthorityField || len(entry.SNI) > maxAuthorityField {
		return false
	}
	return entry.WebSocket == nil || len(entry.WebSocket.Host) <= maxAuthorityField && len(entry.WebSocket.Path) <= maxAuthorityField
}

func encodeAuthority(protocol provider.Protocol, session storedSession, nodes map[string]int64, probes map[string]string) (provider.Authority, error) {
	if (protocol != ShadowsocksProtocol && protocol != TrojanProtocol) || !session.valid() || len(nodes) == 0 || len(nodes) > maxAuthorityNodes || len(probes) > len(nodes) {
		return provider.Authority{}, ErrInvalidAuthority
	}
	for key, id := range nodes {
		if key == "" || id <= 0 {
			return provider.Authority{}, ErrInvalidAuthority
		}
	}
	for key, address := range probes {
		if _, pinned := nodes[key]; !pinned || len(address) > maxAuthorityField {
			return provider.Authority{}, ErrInvalidAuthority
		}
	}
	session.Protocols = nil
	data, err := json.Marshal(tunnelAuthority{Session: session, Nodes: nodes, Probes: probes})
	if err != nil {
		return provider.Authority{}, ErrInvalidAuthority
	}
	return provider.Authority{Protocol: protocol, Data: data}, nil
}

// probeAddress returns the pinned line's catalog detect endpoint.
func probeAddress(data []byte, host string, port uint16) (string, error) {
	var authority tunnelAuthority
	if len(data) == 0 || len(data) > maxControlBytes || json.Unmarshal(data, &authority) != nil {
		return "", ErrInvalidAuthority
	}
	address, ok := authority.Probes[nodeKey(host, port)]
	if !ok || address == "" {
		return "", ErrNoProbeAddress
	}
	return address, nil
}

func authorityFor(data []byte, host string, port uint16) (storedSession, int64, error) {
	var authority tunnelAuthority
	if len(data) == 0 || len(data) > maxControlBytes || json.Unmarshal(data, &authority) != nil || !authority.Session.valid() || len(authority.Nodes) > maxAuthorityNodes {
		return storedSession{}, 0, ErrInvalidAuthority
	}
	id := authority.Nodes[nodeKey(host, port)]
	if id <= 0 {
		return storedSession{}, 0, ErrInvalidAuthority
	}
	return authority.Session, id, nil
}
