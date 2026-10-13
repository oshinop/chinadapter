package app

import (
	"context"
	"errors"
	"time"

	"github.com/oshinop/chinadapter/internal/provider"
	"github.com/oshinop/chinadapter/internal/state"
	"github.com/oshinop/chinadapter/internal/web"
)

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
	account, err := r.providers.Login(ctx, id, provider.Credentials{InstallationID: persistent.InstallationID, Fields: input.Fields})
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

// Subscribe implements web.EventSource using a bounded, lossy per-client hub.
func (r *Runtime) Subscribe(ctx context.Context) (<-chan web.Event, func(), error) {
	if r == nil || !r.Healthy() {
		return nil, nil, errors.New("app: event source unavailable")
	}
	return r.events.subscribe(ctx)
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
