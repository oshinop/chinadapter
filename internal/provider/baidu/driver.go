// Package baidu implements the Baidu cloud proxy provider: the HTTP CONNECT
// proxy Baidu runs on port 443 of the addresses behind cloudnproxy.baidu.com
// for its own app's zero-rated mobile traffic. It accepts CONNECT to arbitrary
// ports 80/443 when the request carries Baidu's fixed proxy headers, and
// traffic leaves from Chinese addresses. It is a public service: no account.
package baidu

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/oshinop/chinadapter/internal/provider"
)

const (
	ProviderID provider.ID       = "baidu"
	Protocol   provider.Protocol = "baidu-http"

	proxyDomain = "cloudnproxy.baidu.com"
	proxyPort   = 443
	authorityID = "proxy"
	groupName   = "Baidu Proxy"
	maxNodes    = 64

	// The proxy admits CONNECT only with these headers. The token is a fixed
	// value shared by every client of this proxy, not a per-user secret; Baidu
	// can rotate it at any time, which surfaces as a 403 on every node.
	proxyHostHeader = "ascdn.baidu.com"
	proxyToken      = "1951164069"
	proxyUserAgent  = "okhttp/3.11.0 SP-engine/2.71.0 Dalvik/2.1.0 (Linux; U; Android 9) baiduboxapp/13.33.0.11 (Baidu; P1 9)"

	defaultRefreshInterval = 6 * time.Hour
	lookupTimeout          = 10 * time.Second
)

// ErrNoProxies reports that the proxy domain resolved to no IPv4 address.
var ErrNoProxies = errors.New("baidu: proxy domain resolved to no IPv4 address")

type lookupNetIPFunc func(context.Context, string, string) ([]netip.Addr, error)

type DriverConfig struct {
	RefreshInterval time.Duration
	Clock           func() time.Time
	lookup          lookupNetIPFunc
}

type Driver struct {
	refreshInterval time.Duration
	clock           func() time.Time
	lookup          lookupNetIPFunc
}

func NewDriver(config DriverConfig) *Driver {
	driver := &Driver{refreshInterval: config.RefreshInterval, clock: config.Clock, lookup: config.lookup}
	if driver.refreshInterval <= 0 {
		driver.refreshInterval = defaultRefreshInterval
	}
	if driver.clock == nil {
		driver.clock = time.Now
	}
	if driver.lookup == nil {
		driver.lookup = net.DefaultResolver.LookupNetIP
	}
	return driver
}

var _ provider.Driver = (*Driver)(nil)

func (*Driver) ID() provider.ID { return ProviderID }

// Auth declares no credentials: the proxy is a public service.
func (*Driver) Auth() provider.AuthSpec { return provider.AuthSpec{} }

func (driver *Driver) Login(ctx context.Context, credentials provider.Credentials) (provider.Snapshot, error) {
	if provider.ValidateCredentials(driver.Auth(), credentials) != nil {
		return provider.Snapshot{}, provider.ErrInvalidInput
	}
	return driver.snapshot(ctx)
}

// Refresh re-resolves the proxy domain. A failed lookup is transient and
// leaves the previous snapshot in place.
func (driver *Driver) Refresh(ctx context.Context, current provider.Snapshot) (provider.Snapshot, error) {
	if current.Provider != ProviderID || !current.Valid() {
		return provider.Snapshot{}, provider.ErrNoSession
	}
	return driver.snapshot(ctx)
}

type refreshState struct {
	Domain  string   `json:"domain"`
	Proxies []string `json:"proxies"`
}

func (driver *Driver) snapshot(ctx context.Context) (provider.Snapshot, error) {
	lookupCtx, cancel := context.WithTimeout(ctx, lookupTimeout)
	addresses, err := driver.lookup(lookupCtx, "ip4", proxyDomain)
	cancel()
	if err != nil {
		return provider.Snapshot{}, fmt.Errorf("baidu: resolve %s: %w", proxyDomain, err)
	}
	proxies := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		if address = address.Unmap(); address.Is4() && address.IsGlobalUnicast() && !address.IsPrivate() && !slices.Contains(proxies, address) {
			proxies = append(proxies, address)
		}
	}
	if len(proxies) == 0 {
		return provider.Snapshot{}, ErrNoProxies
	}
	slices.SortFunc(proxies, func(left, right netip.Addr) int { return left.Compare(right) })
	proxies = proxies[:min(len(proxies), maxNodes)]
	authority, err := encodeAuthority(proxyAuthority{Host: proxyHostHeader, Token: proxyToken, UserAgent: proxyUserAgent})
	if err != nil {
		return provider.Snapshot{}, err
	}
	nodes := make([]provider.Node, 0, len(proxies))
	state := refreshState{Domain: proxyDomain, Proxies: make([]string, 0, len(proxies))}
	for _, address := range proxies {
		host := address.String()
		id, err := provider.NodeID(provider.Route{Provider: ProviderID, Protocol: Protocol, Host: host, Port: proxyPort})
		if err != nil {
			return provider.Snapshot{}, err
		}
		nodes = append(nodes, provider.Node{
			ID: id, AuthorityID: authorityID, Protocol: Protocol, Host: host, Port: proxyPort,
			Name: host, Group: groupName, Model: "cloudnproxy", Eligible: true,
		})
		state.Proxies = append(state.Proxies, host)
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		return provider.Snapshot{}, err
	}
	now := driver.clock().UTC()
	snapshot := provider.Snapshot{
		Provider:     ProviderID,
		Account:      provider.Account{UserID: "public", Display: "Public service", Tier: "Public"},
		ExpiresAt:    now.Add(driver.refreshInterval),
		RefreshState: encoded,
		Authorities:  map[string]provider.Authority{authorityID: authority},
		Nodes:        nodes,
	}
	if err := provider.ValidateSnapshot(snapshot, ProviderID, now); err != nil {
		return provider.Snapshot{}, err
	}
	return snapshot, nil
}
