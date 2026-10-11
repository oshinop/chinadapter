// Package coordinator serializes provider account lifecycle operations and
// publishes one atomic provider-neutral runtime aggregate.
package coordinator

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/kfadapter/kfadapter/internal/provider"
	"github.com/kfadapter/kfadapter/internal/state"
)

// Config wires provider drivers to generic state publication.
type Config struct {
	Providers       *provider.Registry
	Manager         *state.Manager
	SelectorBuilder state.SelectorBuilder
	CommitSnapshot  func(*state.RuntimeSnapshot) error
	Clock           func() time.Time
	MutationMu      *sync.Mutex
}

// Coordinator owns one independent account per registered provider.
type Coordinator struct {
	providers *provider.Registry
	manager   *state.Manager
	builder   state.SelectorBuilder
	commit    func(*state.RuntimeSnapshot) error
	clock     func() time.Time
	mutations *sync.Mutex
	locks     map[provider.ID]*sync.Mutex
}

func New(config Config) (*Coordinator, error) {
	if config.Providers == nil || config.Manager == nil || config.SelectorBuilder == nil || config.CommitSnapshot == nil {
		return nil, errors.New("provider coordinator: incomplete configuration")
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.MutationMu == nil {
		config.MutationMu = &sync.Mutex{}
	}
	locks := make(map[provider.ID]*sync.Mutex)
	for _, id := range config.Providers.IDs() {
		locks[id] = &sync.Mutex{}
	}
	return &Coordinator{providers: config.Providers, manager: config.Manager, builder: config.SelectorBuilder, commit: config.CommitSnapshot, clock: config.Clock, mutations: config.MutationMu, locks: locks}, nil
}

func (coordinator *Coordinator) IDs() []provider.ID {
	if coordinator == nil {
		return nil
	}
	return coordinator.providers.IDs()
}

func (coordinator *Coordinator) Login(ctx context.Context, id provider.ID, credentials provider.Credentials) (provider.Account, error) {
	driver, err := coordinator.providers.Driver(id)
	if err != nil {
		return provider.Account{}, err
	}
	lock := coordinator.locks[id]
	lock.Lock()
	defer lock.Unlock()
	if current := coordinator.manager.Current(); current != nil {
		if _, exists := current.Providers[id]; exists {
			return provider.Account{}, provider.ErrAccountExists
		}
	}
	next, err := driver.Login(ctx, credentials)
	credentials.Password = ""
	if err != nil {
		return provider.Account{}, err
	}
	if err := provider.ValidateSnapshot(next, id, coordinator.now()); err != nil {
		return provider.Account{}, err
	}
	if err := coordinator.commitProvider(id, next, state.OperationLogin); err != nil {
		return provider.Account{}, err
	}
	return next.Account, nil
}

// Refresh commits each selected provider independently. One failure never
// cancels another provider or discards another provider's successful refresh.
func (coordinator *Coordinator) Refresh(ctx context.Context, id provider.ID) error {
	current := coordinator.manager.Current()
	if current == nil || len(current.Providers) == 0 {
		return provider.ErrNoSession
	}
	ids, err := refreshIDs(current.Providers, id)
	if err != nil {
		return err
	}
	if len(ids) == 1 {
		return coordinator.refresh(ctx, ids[0])
	}
	results := make(chan error, len(ids))
	for _, providerID := range ids {
		go func() { results <- coordinator.refresh(ctx, providerID) }()
	}
	var failures []error
	for range ids {
		if err := <-results; err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (coordinator *Coordinator) refresh(ctx context.Context, id provider.ID) error {
	driver, err := coordinator.providers.Driver(id)
	if err != nil {
		return err
	}
	lock := coordinator.locks[id]
	lock.Lock()
	defer lock.Unlock()
	previous, available := coordinator.manager.Current().Provider(id)
	if !available {
		return provider.ErrNoSession
	}
	next, refreshErr := driver.Refresh(ctx, previous)
	if refreshErr != nil {
		if next.Provider == id && len(next.RefreshState) != 0 {
			// Only the rotated refresh token is durable on a partial result.
			// Catalog, account and tunnel authority remain the last good view.
			previous.RefreshState = append([]byte(nil), next.RefreshState...)
			if err := provider.ValidateSnapshot(previous, id, coordinator.now()); err != nil {
				return errors.Join(refreshErr, err)
			}
			if err := coordinator.commitProvider(id, previous, state.OperationRefresh); err != nil {
				return errors.Join(refreshErr, err)
			}
		}
		return refreshErr
	}
	if err := provider.ValidateSnapshot(next, id, coordinator.now()); err != nil {
		return err
	}
	return coordinator.commitProvider(id, next, state.OperationRefresh)
}

// commitProvider rebases on concurrent changes to other providers and probes.
// The shared mutation lock protects the generation compare-and-swap and final
// publication, but is never held while a driver performs network I/O.
func (coordinator *Coordinator) commitProvider(id provider.ID, next provider.Snapshot, operation state.Operation) error {
	coordinator.mutations.Lock()
	defer coordinator.mutations.Unlock()
	complete, err := coordinator.manager.Begin(operation)
	if err != nil {
		return err
	}
	outcome := state.OutcomeFailed
	defer func() { complete(outcome) }()
	providers := coordinator.currentProviders()
	providers[id] = next.Clone()
	if err := coordinator.publish(providers); err != nil {
		return err
	}
	outcome = state.OutcomeSucceeded
	return nil
}

// Logout is the only operation that removes a provider's stored session.
func (coordinator *Coordinator) Logout(_ context.Context, id provider.ID) error {
	lock, available := coordinator.locks[id]
	if !available {
		return provider.ErrUnknownProvider
	}
	lock.Lock()
	defer lock.Unlock()
	coordinator.mutations.Lock()
	defer coordinator.mutations.Unlock()
	providers := coordinator.currentProviders()
	if _, available := providers[id]; !available {
		return provider.ErrNoSession
	}
	complete, err := coordinator.manager.Begin(state.OperationRefresh)
	if err != nil {
		return err
	}
	outcome := state.OutcomeFailed
	defer func() { complete(outcome) }()
	delete(providers, id)
	if len(providers) == 0 {
		if err := coordinator.commit(nil); err != nil {
			return err
		}
		coordinator.manager.SignOut()
	} else if err := coordinator.publish(providers); err != nil {
		return err
	}
	outcome = state.OutcomeSucceeded
	return nil
}

func refreshIDs(providers map[provider.ID]provider.Snapshot, requested provider.ID) ([]provider.ID, error) {
	if requested.Valid() {
		if _, available := providers[requested]; !available {
			return nil, provider.ErrNoSession
		}
		return []provider.ID{requested}, nil
	}
	if requested != "" {
		return nil, provider.ErrUnknownProvider
	}
	ids := make([]provider.ID, 0, len(providers))
	for id := range providers {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(left, right int) bool { return ids[left] < ids[right] })
	return ids, nil
}

func (coordinator *Coordinator) publish(providers map[provider.ID]provider.Snapshot) error {
	now := coordinator.now().UTC()
	if len(providers) == 0 {
		return provider.ErrNoSession
	}
	current := coordinator.manager.Current()
	generation := uint64(1)
	if current != nil {
		generation = current.Generation + 1
	}
	nodes, err := runtimeNodes(providers)
	if err != nil {
		return err
	}
	builtNodes, selectors, err := coordinator.buildSelectors(nodes)
	if err != nil {
		return fmt.Errorf("provider coordinator: build selectors: %w", err)
	}
	snapshot := &state.RuntimeSnapshot{
		Generation: generation, CreatedAt: now, ExpiresAt: state.ProviderExpiresAt(providers),
		Providers: cloneProviders(providers), Nodes: builtNodes, Selectors: selectors,
	}
	latest := coordinator.manager.Current()
	if (current == nil) != (latest == nil) || current != nil && current.Generation != latest.Generation {
		return fmt.Errorf("%w: generation changed before provider commit", state.ErrInvalidSnapshot)
	}
	return coordinator.commit(snapshot)
}

func runtimeNodes(providers map[provider.ID]provider.Snapshot) ([]state.Node, error) {
	ids := make([]provider.ID, 0, len(providers))
	for id := range providers {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(left, right int) bool { return ids[left] < ids[right] })
	total := 0
	for _, id := range ids {
		total += len(providers[id].Nodes)
	}
	nodes := make([]state.Node, 0, total)
	seen := make(map[string]struct{}, total)
	for _, id := range ids {
		snapshot := providers[id]
		if snapshot.Provider != id || !snapshot.Valid() {
			return nil, provider.ErrInvalidSnapshot
		}
		for _, source := range snapshot.Nodes {
			if !source.Eligible {
				continue
			}
			if _, duplicate := seen[source.ID]; duplicate {
				return nil, fmt.Errorf("provider coordinator: duplicate node id %s", source.ID)
			}
			seen[source.ID] = struct{}{}
			nodes = append(nodes, state.Node{
				ID: source.ID, Provider: id, Protocol: source.Protocol, AuthorityID: source.AuthorityID,
				Host: source.Host, Port: source.Port, Name: source.Name, Group: source.Group, Model: source.Model,
				Weight: source.Weight, Auto: source.Auto, Eligible: source.Eligible,
				Health: state.NodeHealthUnknown, UDPHealth: state.UDPHealthUnknown,
			})
		}
	}
	return nodes, nil
}

func cloneProviders(source map[provider.ID]provider.Snapshot) map[provider.ID]provider.Snapshot {
	clone := make(map[provider.ID]provider.Snapshot, len(source))
	for id, snapshot := range source {
		clone[id] = snapshot.Clone()
	}
	return clone
}

func (coordinator *Coordinator) currentProviders() map[provider.ID]provider.Snapshot {
	current := coordinator.manager.Current()
	if current == nil {
		return make(map[provider.ID]provider.Snapshot)
	}
	return cloneProviders(current.Providers)
}

func (coordinator *Coordinator) buildSelectors(nodes []state.Node) ([]state.Node, map[string]state.NodeRef, error) {
	selectors, err := coordinator.builder.Build(nodes)
	if err != nil {
		return nil, nil, err
	}
	byID := make(map[string]int, len(nodes))
	for index := range nodes {
		byID[nodes[index].ID] = index
	}
	for name, reference := range selectors {
		index, exists := byID[reference.NodeID]
		if !exists {
			return nil, nil, provider.ErrInvalidSnapshot
		}
		nodes[index].Selector = name
	}
	return nodes, selectors, nil
}

func (coordinator *Coordinator) now() time.Time { return coordinator.clock() }
