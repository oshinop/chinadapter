// Package accounts renews linked provider sessions independently. Stored
// authority is durable until logout; deadlines are scheduling hints only.
package accounts

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v5"

	"github.com/oshinop/chinadapter/internal/provider"
	"github.com/oshinop/chinadapter/internal/state"
)

const (
	StatusOK             = "ok"
	StatusRefreshFailing = "refresh_failing"
	StatusNeedsRelogin   = "needs_relogin"

	safetyMargin = 30 * time.Minute
	minBackoff   = time.Minute
	maxBackoff   = 30 * time.Minute
)

// Status is a redacted, independent provider refresh schedule.
type Status struct {
	Status      string    `json:"status"`
	LastSuccess time.Time `json:"lastSuccess,omitzero"`
	Attempts    int       `json:"attempts"`
	NextRun     time.Time `json:"nextRun,omitzero"`
}

// Lifecycle is the small account supervision contract used by the app facade.
type Lifecycle interface {
	Status() map[provider.ID]Status
	Start(context.Context) error
	Stop()
	Trigger(context.Context, provider.ID) error
	RecordSuccess(provider.ID)
}

// Controller is implemented by the provider coordinator.
type Controller interface {
	Refresh(context.Context, provider.ID) error
}

// SnapshotSource returns immutable snapshots of the currently linked accounts.
type SnapshotSource interface {
	Current() *state.RuntimeSnapshot
}

// Ticker and Clock allow deterministic scheduling without sleeping in tests.
type Ticker interface {
	C() <-chan time.Time
	Stop()
}

type Clock interface {
	Now() time.Time
	NewTicker(time.Duration) Ticker
}

type wallClock struct{ now func() time.Time }

func (clock wallClock) Now() time.Time { return clock.now() }
func (wallClock) NewTicker(interval time.Duration) Ticker {
	return wallTicker{time.NewTicker(interval)}
}

type wallTicker struct{ *time.Ticker }

func (ticker wallTicker) C() <-chan time.Time { return ticker.Ticker.C }

// Config injects the coordinator, immutable state and clock.
type Config struct {
	Controller   Controller
	Snapshots    SnapshotSource
	RefreshEvery time.Duration
	Clock        Clock
	Now          func() time.Time
	OnRefresh    func(provider.ID, error)
}

type account struct {
	operation sync.Mutex
	status    Status                     // guarded by Supervisor.mu
	running   bool                       // guarded by Supervisor.mu
	backoff   backoff.ExponentialBackOff // guarded by Supervisor.mu
}

// Supervisor serializes work within each provider, never across providers.
// A rejected account retains its last-good snapshot and has no automatic retry
// until a successful manual refresh or login calls RecordSuccess.
type Supervisor struct {
	controller Controller
	snapshots  SnapshotSource
	clock      Clock
	onRefresh  func(provider.ID, error)

	mu       sync.Mutex
	every    time.Duration
	accounts map[provider.ID]*account
	cancel   context.CancelFunc
	done     chan struct{}
}

func New(config Config) (*Supervisor, error) {
	if config.Controller == nil || config.Snapshots == nil || config.RefreshEvery <= 0 {
		return nil, errors.New("accounts: incomplete configuration")
	}
	if config.Clock == nil {
		if config.Now == nil {
			config.Now = time.Now
		}
		config.Clock = wallClock{now: config.Now}
	}
	supervisor := &Supervisor{
		controller: config.Controller, snapshots: config.Snapshots, clock: config.Clock,
		onRefresh: config.OnRefresh, every: config.RefreshEvery,
		accounts: make(map[provider.ID]*account),
	}
	supervisor.reconcile()
	return supervisor, nil
}

// Status returns private copies of the redacted per-provider state.
func (supervisor *Supervisor) Status() map[provider.ID]Status {
	supervisor.reconcile()
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	result := make(map[provider.ID]Status, len(supervisor.accounts))
	for id, account := range supervisor.accounts {
		result[id] = account.status
	}
	return result
}

// Start runs until cancellation. Each tick reads the current wall clock rather
// than the ticker timestamp, so suspension cannot skip overdue providers.
// Due providers run concurrently and are drained before Start returns.
func (supervisor *Supervisor) Start(ctx context.Context) error {
	supervisor.mu.Lock()
	if supervisor.cancel != nil {
		supervisor.mu.Unlock()
		return errors.New("accounts: already started")
	}
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	supervisor.cancel, supervisor.done = cancel, done
	supervisor.mu.Unlock()
	var workers sync.WaitGroup
	defer func() {
		cancel()
		workers.Wait()
		supervisor.mu.Lock()
		supervisor.cancel = nil
		close(done)
		supervisor.mu.Unlock()
	}()
	ticker := supervisor.clock.NewTicker(time.Minute)
	defer ticker.Stop()
	runDue := func() {
		for _, job := range supervisor.due() {
			workers.Go(func() { _ = supervisor.refresh(ctx, job.id, job.account, false) })
		}
	}
	runDue()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C():
			runDue()
		}
	}
}

// Stop cancels and drains the automatic worker without deleting any snapshot.
func (supervisor *Supervisor) Stop() {
	supervisor.mu.Lock()
	cancel, done := supervisor.cancel, supervisor.done
	supervisor.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

// Trigger refreshes one linked provider immediately, including rejected
// sessions. An empty ID refreshes all linked accounts without sibling cancel.
func (supervisor *Supervisor) Trigger(ctx context.Context, id provider.ID) error {
	supervisor.reconcile()
	supervisor.mu.Lock()
	if id != "" {
		account := supervisor.accounts[id]
		supervisor.mu.Unlock()
		if account == nil {
			return provider.ErrNoSession
		}
		return supervisor.refresh(ctx, id, account, true)
	}
	jobs := make([]job, 0, len(supervisor.accounts))
	for id, account := range supervisor.accounts {
		jobs = append(jobs, job{id: id, account: account})
	}
	supervisor.mu.Unlock()
	if len(jobs) == 0 {
		return provider.ErrNoSession
	}
	results := make(chan error, len(jobs))
	for _, job := range jobs {
		go func() { results <- supervisor.refresh(ctx, job.id, job.account, true) }()
	}
	var failures []error
	for range jobs {
		if err := <-results; err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

// RecordSuccess enrolls a newly logged-in account or resets its failure state.
func (supervisor *Supervisor) RecordSuccess(id provider.ID) {
	supervisor.reconcile()
	current, available := supervisor.snapshots.Current().Provider(id)
	if !available {
		return
	}
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	if account := supervisor.accounts[id]; account != nil {
		now := supervisor.clock.Now().UTC()
		account.backoff.Reset()
		account.status = Status{Status: StatusOK, LastSuccess: now, NextRun: refreshAt(now, current.ExpiresAt, supervisor.every)}
	}
}

func (supervisor *Supervisor) reconcile() {
	current := supervisor.snapshots.Current()
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	for id := range supervisor.accounts {
		if current == nil {
			delete(supervisor.accounts, id)
		} else if _, exists := current.Providers[id]; !exists {
			delete(supervisor.accounts, id)
		}
	}
	if current == nil {
		return
	}
	for id, snapshot := range current.Providers {
		if _, exists := supervisor.accounts[id]; exists {
			continue
		}
		lastSuccess := current.CreatedAt.UTC()
		supervisor.accounts[id] = &account{
			status: Status{
				Status: StatusOK, LastSuccess: lastSuccess,
				NextRun: refreshAt(lastSuccess, snapshot.ExpiresAt, supervisor.every),
			},
			backoff: backoff.ExponentialBackOff{
				InitialInterval: minBackoff, RandomizationFactor: 0.2,
				Multiplier: 2, MaxInterval: maxBackoff,
			},
		}
	}
}

type job struct {
	id      provider.ID
	account *account
}

func (supervisor *Supervisor) due() []job {
	supervisor.reconcile()
	now := supervisor.clock.Now()
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	var jobs []job
	for id, account := range supervisor.accounts {
		if account.running || account.status.Status == StatusNeedsRelogin || account.status.NextRun.IsZero() || now.Before(account.status.NextRun) {
			continue
		}
		account.running = true
		jobs = append(jobs, job{id: id, account: account})
	}
	return jobs
}

func (supervisor *Supervisor) refresh(ctx context.Context, id provider.ID, account *account, manual bool) error {
	account.operation.Lock()
	defer account.operation.Unlock()
	if err := ctx.Err(); err != nil {
		supervisor.clearRunning(id, account)
		return err
	}
	// A manual refresh may have recovered a queued automatic job already.
	supervisor.mu.Lock()
	currentAccount := supervisor.accounts[id]
	skip := currentAccount != account || !manual && (account.status.Status == StatusNeedsRelogin || supervisor.clock.Now().Before(account.status.NextRun))
	supervisor.mu.Unlock()
	if skip {
		supervisor.clearRunning(id, account)
		return nil
	}
	err := supervisor.controller.Refresh(ctx, id)
	now := supervisor.clock.Now().UTC()
	current, linked := supervisor.snapshots.Current().Provider(id)
	supervisor.mu.Lock()
	if supervisor.accounts[id] == account && linked {
		account.running = false
		switch {
		case err == nil:
			account.backoff.Reset()
			account.status = Status{Status: StatusOK, LastSuccess: now, NextRun: refreshAt(now, current.ExpiresAt, supervisor.every)}
		case errors.Is(err, provider.ErrSessionRejected):
			// Rejection still counts as a failed attempt if a later manual retry
			// fails transiently before a successful refresh or login resets it.
			_ = account.backoff.NextBackOff()
			account.status.Status = StatusNeedsRelogin
			account.status.Attempts++
			account.status.NextRun = time.Time{}
		default:
			account.status.Status = StatusRefreshFailing
			account.status.Attempts++
			// MaxInterval bounds the base interval; cap the randomized delay too.
			account.status.NextRun = now.Add(min(account.backoff.NextBackOff(), maxBackoff))
		}
	}
	supervisor.mu.Unlock()
	if supervisor.onRefresh != nil {
		supervisor.onRefresh(id, err)
	}
	return err
}

func (supervisor *Supervisor) clearRunning(id provider.ID, account *account) {
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	if supervisor.accounts[id] == account {
		account.running = false
	}
}

func refreshAt(lastSuccess, expiresAt time.Time, every time.Duration) time.Time {
	due := lastSuccess.Add(every)
	if !expiresAt.IsZero() {
		due = minTime(due, expiresAt.Add(-safetyMargin))
	}
	return due
}

func minTime(left, right time.Time) time.Time {
	if left.Before(right) {
		return left
	}
	return right
}
