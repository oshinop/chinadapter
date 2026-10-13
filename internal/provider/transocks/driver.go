package transocks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/oshinop/chinadapter/internal/provider"
)

var ErrNoUsableNodes = errors.New("transocks: no usable Shadowsocks or Trojan nodes")

type DriverConfig struct {
	Client          *Client
	RefreshInterval time.Duration
	Clock           func() time.Time
}

// Driver discovers protocols once at login, then publishes stable catalog line
// identities. Refresh and relays never retain the login password.
type Driver struct {
	client          *Client
	refreshInterval time.Duration
	clock           func() time.Time
}

func NewDriver(config DriverConfig) (*Driver, error) {
	if config.Client == nil {
		return nil, errors.New("transocks: client is required")
	}
	interval := config.RefreshInterval
	if interval <= 0 || interval > 24*time.Hour {
		interval = time.Hour
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Driver{client: config.Client, refreshInterval: interval, clock: clock}, nil
}

func (*Driver) ID() provider.ID { return ProviderID }

func (*Driver) Auth() provider.AuthSpec { return provider.AccountPasswordAuth("Email or phone") }

func (driver *Driver) Login(ctx context.Context, credentials provider.Credentials) (provider.Snapshot, error) {
	if driver == nil || provider.ValidateCredentials(driver.Auth(), credentials) != nil {
		return provider.Snapshot{}, provider.ErrInvalidInput
	}
	account := credentials.Field(provider.FieldAccount)
	stored, login, err := driver.client.Login(ctx, account, credentials.Field(provider.FieldPassword), credentials.InstallationID)
	if err != nil {
		if errors.Is(err, ErrLoginRejected) {
			return provider.Snapshot{}, fmt.Errorf("%w: %w", provider.ErrLoginRejected, err)
		}
		return provider.Snapshot{}, err
	}
	profile, err := driver.client.MiscInfo(ctx, stored)
	if err != nil {
		return provider.Snapshot{}, err
	}
	if profile.UserID != login.UserID {
		return provider.Snapshot{}, ErrSchema
	}
	snapshot, err := driver.snapshot(ctx, stored, provider.RedactAccount(account), profile, true)
	if err != nil {
		return provider.Snapshot{}, err
	}
	// exp is an absolute Unix epoch in the observed JWT login response. It is
	// only a refresh hint; never an authority admission/deletion deadline.
	if expiry := time.Unix(login.Token.Expiry, 0).UTC(); expiry.After(driver.clock()) && expiry.Before(snapshot.ExpiresAt) {
		snapshot.ExpiresAt = expiry
	}
	return snapshot, nil
}

func (driver *Driver) Refresh(ctx context.Context, current provider.Snapshot) (provider.Snapshot, error) {
	if driver == nil || current.Provider != ProviderID || !current.Valid() {
		return provider.Snapshot{}, provider.ErrNoSession
	}
	stored, err := decodeStoredSession(current.RefreshState)
	if err != nil {
		return provider.Snapshot{}, provider.ErrNoSession
	}
	profile, err := driver.client.MiscInfo(ctx, stored)
	if err != nil {
		return provider.Snapshot{}, err
	}
	if strconv.FormatInt(profile.UserID, 10) != current.Account.UserID {
		return provider.Snapshot{}, provider.ErrNoSession
	}
	return driver.snapshot(ctx, stored, current.Account.Display, profile, false)
}

func decodeStoredSession(data []byte) (storedSession, error) {
	var stored storedSession
	if len(data) == 0 || len(data) > maxControlBytes || json.Unmarshal(data, &stored) != nil || !stored.valid() {
		return storedSession{}, ErrSchema
	}
	return stored, nil
}

func (driver *Driver) snapshot(ctx context.Context, stored storedSession, display string, profile accountPayload, discover bool) (provider.Snapshot, error) {
	now := driver.clock().UTC()
	account, err := profile.account(display, now)
	if err != nil {
		return provider.Snapshot{}, err
	}
	catalog, err := driver.client.Catalog(ctx, stored)
	if err != nil {
		return provider.Snapshot{}, err
	}
	ssLines, trojanLines := make(map[string]int64), make(map[string]int64)
	ssProbes, trojanProbes := make(map[string]string), make(map[string]string)
	protocols := make(map[int64]provider.Protocol, len(catalog.Lines))
	nodes := make([]provider.Node, 0, len(catalog.Lines))
	for _, line := range catalog.Lines {
		if !line.eligible(profile, account) {
			continue
		}
		protocol, known := stored.Protocols[line.ID]
		if observed, ok := driver.client.sessions.protocol(stored, line.ID); ok {
			protocol, known = observed, true
		}
		if discover {
			config, err := driver.client.connectConfig(ctx, stored, line.ID)
			if err != nil {
				return provider.Snapshot{}, err
			}
			protocol, known = config.Protocol, true
		}
		if known {
			protocols[line.ID] = protocol
		} else {
			// New lines are learned on demand. A mismatch fails that connection;
			// the next refresh publishes the observed protocol, never a fallback.
			protocol = ShadowsocksProtocol
		}
		if protocol == "" {
			continue
		}
		node, err := line.node(protocol)
		if err != nil {
			return provider.Snapshot{}, err
		}
		key := nodeKey(node.Host, node.Port)
		lines, probes := ssLines, ssProbes
		if protocol != ShadowsocksProtocol {
			lines, probes = trojanLines, trojanProbes
		}
		lines[key] = line.ID
		if address := line.probeAddress(); address != "" {
			probes[key] = address
		}
		nodes = append(nodes, node)
	}
	if len(nodes) == 0 {
		return provider.Snapshot{}, ErrNoUsableNodes
	}
	stored.Protocols = protocols
	authorities := make(map[string]provider.Authority, 2)
	for _, table := range []struct {
		id       string
		protocol provider.Protocol
		lines    map[string]int64
		probes   map[string]string
	}{{shadowsocksAuthorityID, ShadowsocksProtocol, ssLines, ssProbes}, {trojanAuthorityID, TrojanProtocol, trojanLines, trojanProbes}} {
		if len(table.lines) == 0 {
			continue
		}
		authority, err := encodeAuthority(table.protocol, stored, table.lines, table.probes)
		if err != nil {
			return provider.Snapshot{}, err
		}
		authorities[table.id] = authority
	}
	state, err := json.Marshal(stored)
	if err != nil {
		return provider.Snapshot{}, ErrSchema
	}
	snapshot := provider.Snapshot{Provider: ProviderID, Account: account, ExpiresAt: now.Add(driver.refreshInterval), RefreshState: state, Authorities: authorities, Nodes: nodes}
	if err := provider.ValidateSnapshot(snapshot, ProviderID, now); err != nil {
		return provider.Snapshot{}, err
	}
	return snapshot, nil
}

var _ provider.Driver = (*Driver)(nil)
