package quickfox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/kfadapter/kfadapter/internal/provider"
)

const (
	ProviderID     provider.ID       = "quickfox"
	NativeProtocol provider.Protocol = "quickfox-native"
	standardTier                     = "Standard"
	vipTier                          = "VIP"
	svipTier                         = "SVIP"

	maxCatalogGroups  = 32
	maxCatalogRegions = 512
	maxCatalogLines   = 4096
	maxMetadataBytes  = 512
	authorityID       = "native"
)

type DriverConfig struct {
	Client            *Client
	AuthorityLifetime time.Duration
	Clock             func() time.Time
}

// Driver owns one QuickFox account token and its complete native-relay catalog.
// Login and Refresh publish only user IDs representable by native uint32 tunnels.
type Driver struct {
	client   *Client
	lifetime time.Duration
	clock    func() time.Time
}

func NewDriver(config DriverConfig) (*Driver, error) {
	if config.Client == nil {
		return nil, errors.New("quickfox: client is required")
	}
	lifetime := config.AuthorityLifetime
	if lifetime <= 0 || lifetime > 24*time.Hour {
		lifetime = 24 * time.Hour
	}
	clock := config.Clock
	if clock == nil {
		clock = config.Client.clock
	}
	if clock == nil {
		clock = time.Now
	}
	return &Driver{client: config.Client, lifetime: lifetime, clock: clock}, nil
}

func (*Driver) ID() provider.ID { return ProviderID }

func (driver *Driver) Login(ctx context.Context, credentials provider.Credentials) (provider.Snapshot, error) {
	if driver == nil || !credentials.Valid() {
		return provider.Snapshot{}, provider.ErrInvalidInput
	}
	session, err := driver.client.Login(ctx, credentials.Account, credentials.Password, credentials.InstallationID)
	credentials.Password = ""
	if err != nil {
		if errors.Is(err, ErrLoginRejected) {
			return provider.Snapshot{}, provider.ErrLoginRejected
		}
		return provider.Snapshot{}, err
	}
	catalog, err := driver.retryCatalog(ctx, session.Token, session.DeviceCode)
	if err != nil {
		return provider.Snapshot{}, err
	}
	if catalog.Profile.UserID != session.Profile.UserID {
		return provider.Snapshot{}, ErrSchema
	}
	return driver.snapshot(storedSession{Token: session.Token, UserID: session.Profile.UserID, DeviceCode: session.DeviceCode}, catalog)
}

func (driver *Driver) Refresh(ctx context.Context, current provider.Snapshot) (provider.Snapshot, error) {
	if driver == nil || current.Provider != ProviderID || !current.Valid() {
		return provider.Snapshot{}, provider.ErrNoSession
	}
	stored, err := decodeStoredSession(current.RefreshState)
	if err != nil {
		return provider.Snapshot{}, provider.ErrNoSession
	}
	catalog, err := driver.retryCatalog(ctx, stored.Token, stored.DeviceCode)
	if err != nil {
		return provider.Snapshot{}, err
	}
	if catalog.Profile.UserID != stored.UserID {
		return provider.Snapshot{}, provider.ErrNoSession
	}
	return driver.snapshot(stored, catalog)
}

type storedSession struct {
	Token      string `json:"token"`
	UserID     int64  `json:"userId"`
	DeviceCode string `json:"deviceCode"`
}

type tunnelAuthority struct {
	Token  string `json:"token"`
	UserID int64  `json:"userId"`
	AppID  uint32 `json:"appId"`
}

func (driver *Driver) snapshot(stored storedSession, catalog catalog) (provider.Snapshot, error) {
	// Native tunnel authentication encodes the user ID in a uint32 field.
	if stored.UserID > int64(^uint32(0)) || catalog.Profile.UserID > int64(^uint32(0)) {
		return provider.Snapshot{}, fmt.Errorf("%w: user ID exceeds uint32 maximum", ErrSchema)
	}
	now := driver.clock().UTC()
	account, err := catalog.Profile.account(driver.client.location, now)
	if err != nil || account.UserID != strconv.FormatInt(stored.UserID, 10) {
		return provider.Snapshot{}, ErrSchema
	}
	nodes, err := nodesFromCatalog(catalog.Groups, account.Tier)
	if err != nil {
		return provider.Snapshot{}, err
	}
	stateBytes, err := json.Marshal(stored)
	if err != nil {
		return provider.Snapshot{}, ErrSchema
	}
	authorityBytes, err := json.Marshal(tunnelAuthority{Token: stored.Token, UserID: stored.UserID})
	if err != nil {
		return provider.Snapshot{}, ErrSchema
	}
	snapshot := provider.Snapshot{
		Provider: ProviderID, Account: account, ExpiresAt: now.Add(driver.lifetime), RefreshState: stateBytes,
		Authorities: map[string]provider.Authority{authorityID: {Protocol: NativeProtocol, Data: authorityBytes}}, Nodes: nodes,
	}
	if err := provider.ValidateSnapshot(snapshot, ProviderID, now); err != nil {
		return provider.Snapshot{}, err
	}
	return snapshot, nil
}

func decodeStoredSession(encoded []byte) (storedSession, error) {
	var stored storedSession
	if len(encoded) == 0 || len(encoded) > 1<<20 || json.Unmarshal(encoded, &stored) != nil ||
		!validToken(stored.Token) || stored.UserID <= 0 || !validDeviceCode(stored.DeviceCode) {
		return storedSession{}, ErrSchema
	}
	return stored, nil
}

func decodeTunnelAuthority(encoded []byte) (tunnelAuthority, error) {
	var authority tunnelAuthority
	if len(encoded) == 0 || len(encoded) > 1<<20 || json.Unmarshal(encoded, &authority) != nil ||
		!validToken(authority.Token) || authority.UserID <= 0 || authority.UserID > int64(^uint32(0)) {
		return tunnelAuthority{}, ErrSchema
	}
	return authority, nil
}
