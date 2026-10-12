package kuaifan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/oshinop/chinadapter/internal/provider"
	wireprofile "github.com/oshinop/chinadapter/internal/provider/kuaifan/profile"
)

const (
	ProviderID     provider.ID       = "kuaifan"
	WIFIINProtocol provider.Protocol = "kuaifan-wifiin"
	standardTier                     = "Standard"
	vipTier                          = "VIP"
)

// DriverConfig configures the KuaiFan account driver. It owns both captured
// control profiles; outer packages see one provider account and opaque state.
type DriverConfig struct {
	IOSClient         *Client
	WindowsClient     *Client
	AuthorityLifetime time.Duration
	MaxAttempts       int
	BackoffMin        time.Duration
	BackoffMax        time.Duration
	Clock             func() time.Time
}

// Driver implements provider.Driver for one KuaiFan account.
type Driver struct {
	clients    [2]*Client
	lifetime   time.Duration
	attempts   int
	backoff    time.Duration
	maxBackoff time.Duration
	clock      func() time.Time
}

func NewDriver(config DriverConfig) (*Driver, error) {
	if config.IOSClient == nil || config.WindowsClient == nil ||
		config.IOSClient.Profile() != wireprofile.IOSID || config.WindowsClient.Profile() != wireprofile.WindowsID {
		return nil, provider.ErrNoSession
	}
	lifetime := config.AuthorityLifetime
	if lifetime <= 0 {
		lifetime = 24 * time.Hour
	}
	attempts := config.MaxAttempts
	if attempts <= 0 {
		attempts = 3
	}
	if attempts > 5 {
		attempts = 5
	}
	backoff := config.BackoffMin
	if backoff <= 0 {
		backoff = 250 * time.Millisecond
	}
	maxBackoff := config.BackoffMax
	if maxBackoff <= 0 || maxBackoff > 5*time.Second {
		maxBackoff = 5 * time.Second
	}
	if maxBackoff < backoff {
		return nil, errors.New("kuaifan: invalid backoff bounds")
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Driver{
		clients: [2]*Client{config.IOSClient, config.WindowsClient}, lifetime: lifetime,
		attempts: attempts, backoff: backoff, maxBackoff: maxBackoff, clock: clock,
	}, nil
}

func (*Driver) ID() provider.ID { return ProviderID }

func (driver *Driver) Login(ctx context.Context, credentials provider.Credentials) (provider.Snapshot, error) {
	if driver == nil || !credentials.Valid() {
		return provider.Snapshot{}, provider.ErrInvalidInput
	}
	input := EmailLogin{Account: credentials.Account, Password: credentials.Password, InstallationID: credentials.InstallationID}
	sessions, err := driver.loginBoth(ctx, input)
	input.Password = ""
	credentials.Password = ""
	if err != nil {
		if errors.Is(err, ErrLoginRejected) {
			return provider.Snapshot{}, provider.ErrLoginRejected
		}
		return provider.Snapshot{}, err
	}
	profiles, err := driver.fetchBothProfiles(ctx, sessions, false)
	if err != nil {
		return provider.Snapshot{}, err
	}
	account, err := aggregateProviderAccount(provider.RedactAccount(input.Account), profiles, driver.now().UTC())
	if err != nil {
		return provider.Snapshot{}, err
	}
	stored, _ := updatedDriverState(driverState{}, sessions)
	return driver.snapshot(profiles, account, stored)
}

func (driver *Driver) Refresh(ctx context.Context, current provider.Snapshot) (provider.Snapshot, error) {
	if driver == nil || current.Provider != ProviderID || !current.Valid() {
		return provider.Snapshot{}, provider.ErrNoSession
	}
	stored, err := decodeDriverState(current.RefreshState)
	if err != nil {
		return provider.Snapshot{}, provider.ErrNoSession
	}
	sessions, refreshErr := driver.refreshBoth(ctx, stored)
	stored, refreshed := updatedDriverState(stored, sessions)
	var partial provider.Snapshot
	if refreshed {
		encoded, err := json.Marshal(stored)
		if err != nil {
			return provider.Snapshot{}, fmt.Errorf("kuaifan: encode refresh state: %w", err)
		}
		partial = provider.Snapshot{Provider: ProviderID, RefreshState: encoded}
	}
	if refreshErr != nil {
		return partial, refreshErr
	}
	profiles, err := driver.fetchBothProfiles(ctx, sessions, true)
	if err != nil {
		return partial, err
	}
	account, err := aggregateProviderAccount(current.Account.Display, profiles, driver.now().UTC())
	if err != nil {
		return partial, err
	}
	next, err := driver.snapshot(profiles, account, stored)
	if err != nil {
		return partial, err
	}
	return next, nil
}

func (driver *Driver) now() time.Time { return driver.clock() }
