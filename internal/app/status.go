package app

import (
	"context"
	"errors"
	"time"

	"github.com/oshinop/chinadapter/internal/accounts"
	"github.com/oshinop/chinadapter/internal/state"
	"github.com/oshinop/chinadapter/internal/web"
)

const udpMode = "provider_transport"

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
		DataPlane:    web.DataPlaneStatus{SocksAddress: r.socksAddress, UDPMode: udpMode},
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
		StartedAt: r.startedAt, RefreshPolicy: r.RefreshEvery().String(), UDPMode: udpMode, Redacted: true,
	}, nil
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
