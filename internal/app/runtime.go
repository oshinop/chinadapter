package app

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kfadapter/kfadapter/internal/accounts"
	"github.com/kfadapter/kfadapter/internal/provider"
	"github.com/kfadapter/kfadapter/internal/state"
	"github.com/kfadapter/kfadapter/internal/subscription"
	"github.com/kfadapter/kfadapter/internal/web"
)

const (
	defaultProbeTimeout = 5 * time.Second
	minRefreshPolicy    = 15 * time.Minute
	maxRefreshPolicy    = 24 * time.Hour
)

var errRuntimeStopped = errors.New("app: runtime stopped")

// ErrProbeBusy is returned immediately when all bounded direct-probe slots are
// in use. Callers must retry later rather than creating an unbounded dial queue.
var ErrProbeBusy = errors.New("app: probe capacity reached")

// ErrStaleProbe means a refresh or node replacement invalidated the pinned
// probe target before its result could be applied.
var ErrStaleProbe = errors.New("app: stale probe")

// accessError is a browser-safe access-token failure. It retains the internal
// cause for Go callers while exposing only a stable public classification.
type accessError struct {
	cause  error
	code   string
	status int
}

func (e *accessError) Error() string {
	switch e.code {
	case "access_initialized":
		return "access token already initialized"
	case "access_invalid":
		return "access token rejected"
	case "access_next_invalid":
		return "next access token rejected"
	default:
		return "access unavailable"
	}
}

func (e *accessError) Unwrap() error   { return e.cause }
func (e *accessError) Code() string    { return e.code }
func (e *accessError) HTTPStatus() int { return e.status }

func classifyAccessSetupError(cause error) error {
	switch {
	case errors.Is(cause, state.ErrAccessTokenAlreadyInitialized):
		return &accessError{cause: cause, code: "access_initialized", status: http.StatusConflict}
	case errors.Is(cause, state.ErrInvalidNextAccessToken):
		return &accessError{cause: cause, code: "access_next_invalid", status: http.StatusBadRequest}
	case errors.Is(cause, state.ErrInvalidAccessToken):
		return &accessError{cause: cause, code: "access_invalid", status: http.StatusUnauthorized}
	default:
		return &accessError{cause: cause, code: "access_unavailable", status: http.StatusServiceUnavailable}
	}
}

func invalidAccessError() error {
	return &accessError{cause: state.ErrInvalidAccessToken, code: "access_invalid", status: http.StatusUnauthorized}
}

type staleProbeError struct{}

func (staleProbeError) Error() string   { return "probe result is stale" }
func (staleProbeError) Unwrap() error   { return ErrStaleProbe }
func (staleProbeError) Code() string    { return "stale_probe" }
func (staleProbeError) HTTPStatus() int { return http.StatusConflict }

type probeProblem struct {
	cause  error
	code   string
	status int
}

func (e *probeProblem) Error() string {
	switch e.code {
	case "probe_busy":
		return "probe capacity reached"
	case "node_not_found":
		return "node not found"
	case "node_ineligible":
		return "node is not eligible"
	case "node_snapshot_unavailable":
		return "node snapshot unavailable"
	case "tcp_probe_timeout":
		return "TCP reachability check timed out"
	default:
		return "TCP reachability check failed"
	}
}

func (e *probeProblem) Unwrap() error   { return e.cause }
func (e *probeProblem) Code() string    { return e.code }
func (e *probeProblem) HTTPStatus() int { return e.status }

func tcpProbeProblem(cause, contextError error) error {
	if errors.Is(cause, context.DeadlineExceeded) || errors.Is(contextError, context.DeadlineExceeded) {
		return &probeProblem{cause: cause, code: "tcp_probe_timeout", status: http.StatusGatewayTimeout}
	}
	return &probeProblem{cause: cause, code: "tcp_probe_failed", status: http.StatusBadGateway}
}

// loginError exposes only a stable browser-safe problem classification. The
// wrapped cause remains available to Go callers for errors.Is, but its text is
// never suitable for transport or diagnostics.
type loginError struct {
	cause  error
	code   string
	status int
}

func (e *loginError) Error() string {
	switch e.code {
	case "login_rejected":
		return "login rejected"
	case "account_exists":
		return "provider account already exists"
	case "operation_in_progress":
		return "login operation in progress"
	default:
		return "login unavailable"
	}
}

func (e *loginError) Unwrap() error   { return e.cause }
func (e *loginError) Code() string    { return e.code }
func (e *loginError) HTTPStatus() int { return e.status }

func classifyLoginError(cause error) error {
	switch {
	case errors.Is(cause, provider.ErrLoginRejected):
		return &loginError{cause: cause, code: "login_rejected", status: http.StatusUnauthorized}
	case errors.Is(cause, provider.ErrAccountExists):
		return &loginError{cause: cause, code: "account_exists", status: http.StatusConflict}
	case errors.Is(cause, state.ErrOperationInProgress):
		return &loginError{cause: cause, code: "operation_in_progress", status: http.StatusConflict}
	default:
		return &loginError{cause: cause, code: "login_unavailable", status: http.StatusServiceUnavailable}
	}
}

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
	Store         *state.SQLiteStore
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
	store         *state.SQLiteStore
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

// AccessStatus reports only whether an access-token verifier is configured.
// Browser-session fields are added by web and never stored here.
func (r *Runtime) AccessStatus(ctx context.Context) (web.AccessStatus, error) {
	if r == nil {
		return web.AccessStatus{}, errors.New("app: runtime unavailable")
	}
	if !r.alive.Load() {
		return web.AccessStatus{}, errRuntimeStopped
	}
	persistent, err := r.store.Load(ctx)
	if err != nil {
		return web.AccessStatus{}, err
	}
	return web.AccessStatus{Initialized: persistent.AccessTokenInitialized()}, nil
}

// AccessSetup commits the first verifier and installs local credential authority.
func (r *Runtime) AccessSetup(ctx context.Context, token string) error {
	if r == nil {
		return classifyAccessSetupError(errors.New("runtime unavailable"))
	}
	if !r.alive.Load() {
		return classifyAccessSetupError(errRuntimeStopped)
	}
	r.mutations.Lock()
	defer r.mutations.Unlock()
	if !r.alive.Load() {
		return classifyAccessSetupError(errRuntimeStopped)
	}
	persistent, err := r.store.Update(ctx, func(candidate *state.PersistentState) error {
		return candidate.SetAccessToken(token)
	})
	if err != nil {
		return classifyAccessSetupError(err)
	}
	if persistent.AccessTokenVerifier == nil {
		return classifyAccessSetupError(errors.New("access verifier was not persisted"))
	}
	authority, err := persistent.Identity()
	if err != nil {
		return classifyAccessSetupError(err)
	}
	if _, err := r.credentials.Install(authority, persistent.ActiveSession); err != nil {
		return classifyAccessSetupError(err)
	}
	if err := r.subscriptions.Update(persistent); err != nil {
		return classifyAccessSetupError(err)
	}
	r.publishState()
	return nil
}

// AccessLogin verifies a submitted access token against the durable Argon2id
// verifier. Verification is constant-time within state and returns one public
// failure for unset, malformed, and mismatched tokens.
func (r *Runtime) AccessLogin(ctx context.Context, token string) error {
	if r == nil {
		return classifyAccessSetupError(errors.New("runtime unavailable"))
	}
	if !r.alive.Load() {
		return classifyAccessSetupError(errRuntimeStopped)
	}
	r.mutations.Lock()
	defer r.mutations.Unlock()
	if !r.alive.Load() {
		return classifyAccessSetupError(errRuntimeStopped)
	}
	persistent, err := r.store.Load(ctx)
	if err != nil {
		return classifyAccessSetupError(err)
	}
	if !persistent.VerifyAccessToken(token) {
		return invalidAccessError()
	}
	return nil
}

// AccessChangeToken rotates installation credentials without touching provider
// account authority. SQLite revokes persisted browser sessions in the same write.
func (r *Runtime) AccessChangeToken(ctx context.Context, current, next string) error {
	if r == nil || !r.alive.Load() {
		return classifyAccessSetupError(errRuntimeStopped)
	}
	r.mutations.Lock()
	defer r.mutations.Unlock()
	if !r.alive.Load() {
		return classifyAccessSetupError(errRuntimeStopped)
	}
	persistent, err := r.store.Update(ctx, func(candidate *state.PersistentState) error {
		if err := candidate.ChangeAccessToken(current, next); err != nil {
			return err
		}
		if candidate.ActiveSession != nil {
			authority, err := candidate.Identity()
			if err != nil {
				return err
			}
			candidate.ActiveSession.Generation++
			candidate.ActiveSession.Selectors, err = state.BuildSelectors(candidate.ActiveSession.Nodes, authority)
			if err != nil {
				return err
			}
			for index := range candidate.ActiveSession.Nodes {
				credentials, _ := authority.Credentials(candidate.ActiveSession.Nodes[index].Route())
				candidate.ActiveSession.Nodes[index].Selector = credentials.Username
			}
		}
		return nil
	})
	if err != nil {
		return classifyAccessSetupError(err)
	}
	if persistent.ActiveSession != nil {
		if err := r.manager.Commit(persistent.ActiveSession); err != nil {
			return classifyAccessSetupError(err)
		}
	}
	authority, err := persistent.Identity()
	if err != nil {
		return classifyAccessSetupError(err)
	}
	if _, err := r.credentials.Install(authority, persistent.ActiveSession); err != nil {
		return classifyAccessSetupError(err)
	}
	if err := r.subscriptions.Update(persistent); err != nil {
		return classifyAccessSetupError(err)
	}
	r.publishState()
	return nil
}

func browserAccount(providerID, display, tier string, subscriptionActive bool, subscriptionEndsAt time.Time) web.Account {
	account := web.Account{Provider: providerID, Display: display, Tier: tier, SubscriptionActive: subscriptionActive}
	if subscriptionActive && !subscriptionEndsAt.IsZero() {
		expires := subscriptionEndsAt.UTC()
		account.SubscriptionEndsAt = &expires
	}
	return account
}

// Status returns only redacted state and local listener information.
func (r *Runtime) Status(context.Context) (web.Status, error) {
	if r == nil {
		return web.Status{}, errors.New("app: runtime unavailable")
	}
	if !r.alive.Load() {
		return web.Status{}, errRuntimeStopped
	}
	status := r.manager.Status()
	metadata, err := r.subscriptionMetadata()
	if err != nil {
		return web.Status{}, err
	}
	schedules := r.accounts.Status()
	var lastRefreshAt, nextRefreshAt time.Time
	for _, schedule := range schedules {
		if schedule.LastSuccess.After(lastRefreshAt) {
			lastRefreshAt = schedule.LastSuccess
		}
		if !schedule.NextRun.IsZero() && (nextRefreshAt.IsZero() || schedule.NextRun.Before(nextRefreshAt)) {
			nextRefreshAt = schedule.NextRun
		}
		if schedule.Status != accounts.StatusOK {
			status.State = state.StateDegraded
		}
	}
	result := web.Status{
		State:        string(status.State),
		Version:      r.version,
		Deployment:   web.Deployment{Mode: "container", StartedAt: r.startedAt},
		ControlPlane: web.ControlPlaneStatus{LastRefreshAt: lastRefreshAt, NextRefreshAt: nextRefreshAt},
		DataPlane:    web.DataPlaneStatus{SocksAddress: r.socksAddress, UDPMode: "provider_transport"},
		Nodes:        web.NodeCounts{Total: status.NodeTotal, Eligible: status.Eligible},
		Subscription: metadata,
	}
	for _, id := range r.providers.IDs() {
		result.Providers = append(result.Providers, string(id))
	}
	if len(status.Accounts) != 0 {
		result.Accounts = make(map[string]web.Account, len(status.Accounts))
		for id, account := range status.Accounts {
			view := browserAccount(string(id), account.Display, account.Tier, account.SubscriptionActive, account.SubscriptionEndsAt)
			schedule := schedules[id]
			view.RefreshStatus, view.LastRefreshAt, view.NextRefreshAt = schedule.Status, schedule.LastSuccess, schedule.NextRun
			result.Accounts[string(id)] = view
		}
	}
	if current := r.manager.Current(); current != nil {
		for _, node := range current.Nodes {
			if !node.TunnelEligible() {
				continue
			}
			if node.Health == state.NodeHealthHealthy {
				result.Nodes.Healthy++
			}
		}
	}
	return result, nil
}

// Nodes maps immutable state into the routine browser-safe node summary.
func (r *Runtime) Nodes(context.Context) ([]web.Node, error) {
	if r == nil {
		return nil, errors.New("app: runtime unavailable")
	}
	if !r.alive.Load() {
		return nil, errRuntimeStopped
	}
	current := r.manager.Current()
	if current == nil {
		return []web.Node{}, nil
	}
	result := make([]web.Node, 0, len(current.Nodes))
	for _, node := range current.Nodes {
		if !node.TunnelEligible() {
			continue
		}
		latency := 0
		if node.TCPRTT > 0 {
			latency = int(node.TCPRTT.Round(time.Millisecond) / time.Millisecond)
		}
		result = append(result, web.Node{
			ID: node.ID, Name: node.Name, Group: node.Group, Provider: string(node.Provider),
			Health: string(node.Health), TCPLatencyMS: latency, UDPHealth: string(node.UDPHealth),
			Eligible: node.Eligible,
		})
	}
	return result, nil
}

// NodeDetails returns the selected node's upstream route and the local SOCKS
// credentials currently authorized for it. Credentials are derived only after
// the active runtime snapshot and selector authority agree.
func (r *Runtime) NodeDetails(_ context.Context, nodeID string) (web.NodeDetails, error) {
	if r == nil {
		return web.NodeDetails{}, errors.New("app: runtime unavailable")
	}
	if !r.alive.Load() {
		return web.NodeDetails{}, errRuntimeStopped
	}
	current := r.manager.Current()
	if !state.SessionUsable(current, r.now()) {
		return web.NodeDetails{}, errors.New("app: no usable node snapshot")
	}
	node, found := current.NodeByID(nodeID)
	if !found || !node.TunnelEligible() {
		return web.NodeDetails{}, errors.New("app: node not found")
	}
	ref, found := current.Selectors[node.Selector]
	if !found || ref.NodeID != node.ID {
		return web.NodeDetails{}, errors.New("app: node selector authority is stale")
	}
	registry := r.credentials.Identity()
	if registry == nil {
		return web.NodeDetails{}, errors.New("app: node selector authority is unavailable")
	}
	credentials, authorized := registry.Credentials(node.Route())
	if !authorized || credentials.Username != node.Selector {
		return web.NodeDetails{}, errors.New("app: node selector authority is stale")
	}
	latency := 0
	if node.TCPRTT > 0 {
		latency = int(node.TCPRTT.Round(time.Millisecond) / time.Millisecond)
	}
	return web.NodeDetails{
		ID: node.ID, Name: node.Name, Group: node.Group, Provider: string(node.Provider),
		UpstreamHost: node.Host, UpstreamPort: int(node.Port),
		SocksAddress: r.socksAddress, SocksUsername: credentials.Username, SocksPassword: credentials.Password,
		Health: string(node.Health), TCPLatencyMS: latency,
	}, nil
}

// Login passes only protected installation randomness and transient credentials
// into the selected provider driver. No host identifier is consulted.
func (r *Runtime) Login(ctx context.Context, input web.LoginInput) (web.Account, error) {
	if r == nil {
		return web.Account{}, classifyLoginError(errors.New("runtime unavailable"))
	}
	if !r.alive.Load() {
		return web.Account{}, classifyLoginError(errRuntimeStopped)
	}
	id := provider.ID(input.Provider)
	if !id.Valid() {
		return web.Account{}, classifyLoginError(provider.ErrUnknownProvider)
	}
	persistent, err := r.store.Load(ctx)
	if err != nil {
		return web.Account{}, classifyLoginError(err)
	}
	account, err := r.providers.Login(ctx, id, provider.Credentials{
		Account: input.Account, Password: input.Password, InstallationID: persistent.InstallationID,
	})
	input.Password = ""
	if err != nil {
		r.publish("state", lifecycleEvent{State: string(r.manager.State())})
		return web.Account{}, classifyLoginError(err)
	}
	current := r.manager.Current()
	if current == nil {
		return web.Account{}, classifyLoginError(errors.New("login did not publish a complete provider session"))
	}
	if _, available := current.Providers[id]; !available {
		return web.Account{}, classifyLoginError(errors.New("login did not publish the selected provider"))
	}
	result := browserAccount(string(id), account.Display, account.Tier, account.SubscriptionActive, account.SubscriptionEndsAt)
	r.accounts.RecordSuccess(id)
	schedule := r.accounts.Status()[id]
	result.RefreshStatus, result.LastRefreshAt, result.NextRefreshAt = schedule.Status, schedule.LastSuccess, schedule.NextRun
	r.publishState()
	return result, nil
}

// Logout clears durable provider authority before invalidating new tunnel
// setup in state.Manager. Retained snapshot references remain available to
// existing relays until their drain.
func (r *Runtime) Logout(ctx context.Context, providerID string) error {
	if r == nil {
		return errors.New("app: runtime unavailable")
	}
	if !r.alive.Load() {
		return errRuntimeStopped
	}
	id := provider.ID(providerID)
	if !id.Valid() {
		return provider.ErrUnknownProvider
	}
	if err := r.providers.Logout(ctx, id); err != nil {
		return err
	}
	_ = r.accounts.Status()
	r.publishState()
	return nil
}

// Refresh verifies a complete durable provider catalog commit.
func (r *Runtime) Refresh(ctx context.Context, providerID string) error {
	if r == nil {
		return errors.New("app: runtime unavailable")
	}
	if !r.alive.Load() {
		return errRuntimeStopped
	}
	id := provider.ID(providerID)
	if providerID != "" && !id.Valid() {
		return provider.ErrUnknownProvider
	}
	before := r.manager.Current()
	if err := r.accounts.Trigger(ctx, id); err != nil {
		r.publish("refresh", refreshEvent{State: string(r.manager.State()), Complete: false})
		return err
	}
	current := r.manager.Current()
	if current == nil || before == nil || current.Generation <= before.Generation || !state.SessionUsable(current, r.now()) {
		return errors.New("app: refresh did not commit a new complete generation")
	}
	r.publish("refresh", refreshEvent{State: string(r.manager.State()), Complete: true})
	return nil
}

// Probe measures only one bounded direct TCP connection to the selected
// upstream node. It never starts SOCKS authentication or sends a destination.
func (r *Runtime) Probe(ctx context.Context, nodeID string) (web.ProbeResult, error) {
	if r == nil {
		return web.ProbeResult{}, errors.New("app: runtime unavailable")
	}
	if !r.alive.Load() {
		return web.ProbeResult{}, errRuntimeStopped
	}
	current := r.manager.Current()
	if !state.SessionUsable(current, r.now()) {
		return web.ProbeResult{}, &probeProblem{cause: provider.ErrNoSession, code: "node_snapshot_unavailable", status: http.StatusConflict}
	}
	node, found := current.NodeByID(nodeID)
	if !found {
		return web.ProbeResult{}, &probeProblem{cause: errors.New("node not found"), code: "node_not_found", status: http.StatusNotFound}
	}
	if !node.TunnelEligible() {
		return web.ProbeResult{}, &probeProblem{cause: errors.New("node ineligible"), code: "node_ineligible", status: http.StatusConflict}
	}
	target := probeTarget{id: node.ID, selector: node.Selector, provider: string(node.Provider), host: node.Host, port: node.Port}
	select {
	case r.probeSlots <- struct{}{}:
		defer func() { <-r.probeSlots }()
	default:
		return web.ProbeResult{}, &probeProblem{cause: ErrProbeBusy, code: "probe_busy", status: http.StatusTooManyRequests}
	}

	probeCtx, cancel := context.WithTimeout(ctx, r.probeTimeout)
	defer cancel()
	started := r.now()
	connection, dialErr := r.dial(probeCtx, "tcp", net.JoinHostPort(node.Host, strconv.Itoa(int(node.Port))))
	finished := r.now().UTC()
	latency := finished.Sub(started)
	if latency < 0 {
		latency = 0
	}
	if connection != nil {
		_ = connection.Close()
	}
	health := state.NodeHealthHealthy
	if dialErr != nil {
		health = state.NodeHealthUnhealthy
	}
	result := web.ProbeResult{NodeID: nodeID, Health: string(health), ProbedAt: finished}
	if latency > 0 {
		result.TCPLatencyMS = int(latency.Round(time.Millisecond) / time.Millisecond)
	}

	r.mutations.Lock()
	if !r.alive.Load() {
		r.mutations.Unlock()
		return web.ProbeResult{}, errRuntimeStopped
	}
	latest := r.manager.Current()
	if !target.matches(latest) || !state.SessionUsable(latest, r.now()) {
		r.mutations.Unlock()
		return result, staleProbeError{}
	}
	updated, updateErr := r.updateProbe(latest, nodeID, health, latency, finished)
	r.mutations.Unlock()
	if updateErr != nil {
		return result, updateErr
	}
	if updated != nil {
		r.publish("probe", probeEvent{NodeID: nodeID, Health: string(health), TCPLatencyMS: result.TCPLatencyMS, ProbedAt: finished})
		r.publishState()
	}
	if dialErr != nil {
		return result, tcpProbeProblem(dialErr, probeCtx.Err())
	}
	return result, nil
}

type probeTarget struct {
	id       string
	selector string
	provider string
	host     string
	port     uint16
}

func (target probeTarget) matches(snapshot *state.RuntimeSnapshot) bool {
	if snapshot == nil {
		return false
	}
	node, found := snapshot.NodeByID(target.id)
	return found && node.ID == target.id && node.Selector == target.selector && string(node.Provider) == target.provider && node.Host == target.host && node.Port == target.port
}

func (r *Runtime) updateProbe(current *state.RuntimeSnapshot, nodeID string, health state.NodeHealth, latency time.Duration, observed time.Time) (*state.RuntimeSnapshot, error) {
	if !state.SessionUsable(current, observed) {
		return nil, errors.New("app: no active node snapshot")
	}
	next := current.Clone()
	next.Generation++
	for index := range next.Nodes {
		if next.Nodes[index].ID == nodeID {
			next.Nodes[index].Health = health
			next.Nodes[index].TCPRTT = latency
			next.Nodes[index].ProbedAt = observed
			break
		}
	}
	if err := r.manager.Commit(next); err != nil {
		return nil, err
	}
	return next, nil
}

// CommitControlSnapshotLocked publishes a provider result under the shared
// short mutation lock held by the coordinator, never around network I/O.
func (r *Runtime) CommitControlSnapshotLocked(snapshot *state.RuntimeSnapshot) error {
	if r == nil {
		return errors.New("app: runtime unavailable")
	}
	if !r.alive.Load() {
		return errRuntimeStopped
	}
	ctx := context.Background()
	previousIdentity := r.credentials.Identity()
	previousSnapshot := r.manager.Current()
	rebuilt, err := r.credentials.Install(previousIdentity, snapshot)
	if err != nil {
		return err
	}
	var previous state.PersistentState
	persistent, err := r.store.Update(ctx, func(candidate *state.PersistentState) error {
		previous = candidate.Clone()
		candidate.ActiveSession = rebuilt
		return nil
	})
	if err != nil {
		_, restoreErr := r.credentials.Install(previousIdentity, previousSnapshot)
		return errors.Join(err, restoreErr)
	}
	if rebuilt != nil {
		if err := r.manager.Commit(rebuilt); err != nil {
			_, restoreErr := r.credentials.Install(previousIdentity, previousSnapshot)
			return errors.Join(err, restoreErr, r.store.Save(ctx, previous))
		}
	}
	return r.subscriptions.Update(persistent)
}

func parseRefreshPolicy(value string) (time.Duration, error) {
	interval, err := time.ParseDuration(value)
	if err != nil || interval < minRefreshPolicy || interval > maxRefreshPolicy {
		return 0, errors.New("app: refresh policy must be between 15m and 24h")
	}
	return interval, nil
}

// Diagnostics returns a closed, redacted report. It intentionally omits
// account identifiers, node endpoints, selectors, capabilities, credentials,
// provider extensions, and all persistent-state content.
func (r *Runtime) Diagnostics(context.Context) (any, error) {
	if r == nil {
		return nil, errors.New("app: runtime unavailable")
	}
	if !r.alive.Load() {
		return nil, errRuntimeStopped
	}
	status := r.manager.Status()
	return struct {
		Version       string    `json:"version"`
		State         string    `json:"state"`
		Generation    uint64    `json:"generation"`
		StartedAt     time.Time `json:"startedAt"`
		RefreshPolicy string    `json:"refreshPolicy"`
		UDPMode       string    `json:"udpMode"`
		Redacted      bool      `json:"redacted"`
	}{
		Version: r.version, State: string(status.State), Generation: status.Generation,
		StartedAt: r.startedAt, RefreshPolicy: r.RefreshEvery().String(), UDPMode: "disabled_unverified", Redacted: true,
	}, nil
}

// Subscribe implements web.EventSource using a bounded, lossy per-client hub.
func (r *Runtime) Subscribe(ctx context.Context) (<-chan web.Event, func(), error) {
	if r == nil || !r.Healthy() {
		return nil, nil, errors.New("app: event source unavailable")
	}
	return r.events.subscribe(ctx)
}

func (r *Runtime) subscriptionMetadata() (web.SubscriptionMetadata, error) {
	if r == nil || !r.alive.Load() {
		return web.SubscriptionMetadata{}, errRuntimeStopped
	}
	metadata, err := r.subscriptions.Metadata()
	if err != nil {
		return web.SubscriptionMetadata{}, err
	}
	return web.SubscriptionMetadata{Active: metadata.Active, NodeCount: metadata.NodeCount}, nil
}

func (r *Runtime) publishState() {
	if r == nil {
		return
	}
	status := r.manager.Status()
	r.publish("state", lifecycleEvent{State: string(status.State)})
}

func (r *Runtime) publish(kind string, data any) {
	if r != nil {
		r.events.publish(web.Event{Type: kind, Data: data})
	}
}

type lifecycleEvent struct {
	State string `json:"state"`
}

type refreshEvent struct {
	State    string `json:"state"`
	Complete bool   `json:"complete"`
}

type probeEvent struct {
	NodeID       string    `json:"nodeId"`
	Health       string    `json:"health"`
	TCPLatencyMS int       `json:"tcpLatencyMs,omitempty"`
	ProbedAt     time.Time `json:"probedAt"`
}
