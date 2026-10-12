package app

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oshinop/chinadapter/internal/accounts"
	"github.com/oshinop/chinadapter/internal/provider"
	"github.com/oshinop/chinadapter/internal/state"
	"github.com/oshinop/chinadapter/internal/store"
	"github.com/oshinop/chinadapter/internal/subscription"
)

const (
	defaultProbeTimeout = 5 * time.Second
	minRefreshPolicy    = 15 * time.Minute
	maxRefreshPolicy    = 24 * time.Hour
)

// ProviderController is the provider-neutral account lifecycle contract.
type ProviderController interface {
	IDs() []provider.ID
	Login(context.Context, provider.ID, provider.Credentials) (provider.Account, error)
	Refresh(context.Context, provider.ID) error
	Logout(context.Context, provider.ID) error
}

// SubscriptionPublisher atomically publishes the immutable persisted catalog.
type SubscriptionPublisher interface {
	Update(state.PersistentState) error
	Metadata() (subscription.Metadata, error)
}

// RuntimeConfig wires production stateful collaborators. Values which can
// reveal account, tunnel, selector, or subscription material are deliberately
// absent from this configuration.
type RuntimeConfig struct {
	Manager       *state.Manager
	Store         *store.SQLiteStore
	Providers     ProviderController
	Subscriptions SubscriptionPublisher
	Accounts      accounts.Lifecycle
	Credentials   *CredentialCoordinator
	MutationMu    *sync.Mutex

	SocksAddress    string
	HTTPAddress     string
	Version         string
	StartedAt       time.Time
	Now             func() time.Time
	DialContext     func(context.Context, string, string) (net.Conn, error)
	ProbeTimeout    time.Duration
	RefreshEvery    time.Duration
	AccountRefresh  func(provider.ID, error)
	ProbeConcurrent int
	EventClients    int
	EventBuffer     int
}

// Runtime is the sole browser-safe facade over state, control,
// durable preferences, and subscription publishing.
type Runtime struct {
	manager       *state.Manager
	store         *store.SQLiteStore
	providers     ProviderController
	accounts      accounts.Lifecycle
	subscriptions SubscriptionPublisher
	credentials   *CredentialCoordinator

	socksAddress string
	httpAddress  string
	version      string
	startedAt    time.Time
	now          func() time.Time
	dial         func(context.Context, string, string) (net.Conn, error)
	probeTimeout time.Duration
	probeSlots   chan struct{}

	mutations    *sync.Mutex
	refreshEvery time.Duration
	alive        atomic.Bool
	events       *eventHub
}

// NewRuntime validates the dependencies needed by every web.Backend method.
func NewRuntime(config RuntimeConfig) (*Runtime, error) {
	if config.Manager == nil || config.Store == nil || config.Providers == nil || config.Subscriptions == nil || config.Credentials == nil {
		return nil, errors.New("app: runtime requires manager, store, provider controller, subscription service, and credential coordinator")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.StartedAt.IsZero() {
		config.StartedAt = config.Now().UTC()
	}
	if config.DialContext == nil {
		dialer := &net.Dialer{}
		config.DialContext = dialer.DialContext
	}
	if config.ProbeTimeout <= 0 || config.ProbeTimeout > 10*time.Second {
		config.ProbeTimeout = defaultProbeTimeout
	}
	if config.ProbeConcurrent <= 0 {
		config.ProbeConcurrent = 8
	}
	if config.ProbeConcurrent > 32 {
		config.ProbeConcurrent = 32
	}
	if config.RefreshEvery < minRefreshPolicy || config.RefreshEvery > maxRefreshPolicy {
		config.RefreshEvery = 23 * time.Hour
	}
	persistent, err := config.Store.Load(context.Background())
	if err != nil {
		return nil, err
	}
	if persistent.Preferences.RefreshPolicy != "" {
		refreshEvery, err := parseRefreshPolicy(persistent.Preferences.RefreshPolicy)
		if err != nil {
			return nil, err
		}
		config.RefreshEvery = refreshEvery
	}
	mutationMu := config.MutationMu
	if mutationMu == nil {
		mutationMu = &sync.Mutex{}
	}
	runtime := &Runtime{
		manager: config.Manager, store: config.Store, providers: config.Providers,
		subscriptions: config.Subscriptions, credentials: config.Credentials,
		socksAddress: config.SocksAddress, httpAddress: config.HTTPAddress,
		version:   config.Version,
		startedAt: config.StartedAt.UTC(), now: config.Now, dial: config.DialContext,
		probeTimeout: config.ProbeTimeout, probeSlots: make(chan struct{}, config.ProbeConcurrent), mutations: mutationMu,
		refreshEvery: config.RefreshEvery,
		events:       newEventHub(config.EventClients, config.EventBuffer),
	}
	if config.Accounts == nil {
		supervisor, err := accounts.New(accounts.Config{
			Controller: config.Providers, Snapshots: config.Manager, RefreshEvery: config.RefreshEvery, Now: config.Now,
			OnRefresh: func(id provider.ID, err error) {
				runtime.publish("refresh", refreshEvent{State: string(runtime.manager.State()), Complete: err == nil})
				if config.AccountRefresh != nil {
					config.AccountRefresh(id, err)
				}
			},
		})
		if err != nil {
			return nil, err
		}
		config.Accounts = supervisor
	}
	runtime.accounts = config.Accounts
	runtime.alive.Store(true)
	return runtime, nil
}

// Healthy implements web.Liveness. It intentionally answers only process
// liveness; a signed-out or degraded account is still healthy.
func (r *Runtime) Healthy() bool { return r != nil && r.alive.Load() }

// Stop makes the facade unavailable, then wipes only the in-memory session
// before it closes browser events. Durable control authority remains available
// to the next process; existing relays retain only snapshots they pinned before
// this call and are drained by the process supervisor.
func (r *Runtime) Stop() {
	if r == nil {
		return
	}
	r.alive.Store(false)
	r.accounts.Stop()
	r.mutations.Lock()
	r.manager.SignOut()
	r.mutations.Unlock()
	r.events.close()
}

// RefreshEvery returns the bounded, in-memory refresh cadence.
func (r *Runtime) RefreshEvery() time.Duration {
	if r == nil || !r.alive.Load() {
		return 0
	}
	return r.refreshEvery
}

// RunAccounts runs the independent provider schedules as a lifecycle worker.
func (r *Runtime) RunAccounts(ctx context.Context) error {
	return r.accounts.Start(ctx)
}

func parseRefreshPolicy(value string) (time.Duration, error) {
	interval, err := time.ParseDuration(value)
	if err != nil || interval < minRefreshPolicy || interval > maxRefreshPolicy {
		return 0, errors.New("app: refresh policy must be between 15m and 24h")
	}
	return interval, nil
}
