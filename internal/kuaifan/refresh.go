package kuaifan

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	wireprofile "github.com/kfadapter/kfadapter/internal/kuaifan/profile"
	"github.com/kfadapter/kfadapter/internal/provider"
	"github.com/kfadapter/kfadapter/internal/selector"
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
	return driver.snapshot(profiles, account)
}

func (driver *Driver) Refresh(ctx context.Context, current provider.Snapshot) (provider.Snapshot, error) {
	if driver == nil || current.Provider != ProviderID || !current.Valid() {
		return provider.Snapshot{}, provider.ErrNoSession
	}
	stored, err := decodeDriverState(current.RefreshState)
	if err != nil {
		return provider.Snapshot{}, provider.ErrNoSession
	}
	sessions, err := driver.refreshBoth(ctx, stored)
	if err != nil {
		return provider.Snapshot{}, err
	}
	profiles, err := driver.fetchBothProfiles(ctx, sessions, true)
	if err != nil {
		return provider.Snapshot{}, err
	}
	account, err := aggregateProviderAccount(current.Account.Display, profiles, driver.now().UTC())
	if err != nil {
		return provider.Snapshot{}, err
	}
	return driver.snapshot(profiles, account)
}

func (driver *Driver) loginBoth(ctx context.Context, input EmailLogin) ([2]LoginSession, error) {
	return parallelSessions(ctx, driver.clients, func(child context.Context, client *Client) (LoginSession, error) {
		copyInput := input
		session, err := client.Login(child, copyInput)
		copyInput.Password = ""
		if err != nil {
			return LoginSession{}, err
		}
		if client.requiresPostLoginRefresh() {
			return client.RefreshSession(child, session)
		}
		return session, nil
	})
}

type driverState struct {
	IOS     storedLoginSession `json:"ios"`
	Windows storedLoginSession `json:"windows"`
}

type storedLoginSession struct {
	UserID int32  `json:"userId"`
	Token  string `json:"token"`
}

func (driver *Driver) refreshBoth(ctx context.Context, current driverState) ([2]LoginSession, error) {
	return parallelSessions(ctx, driver.clients, func(child context.Context, client *Client) (LoginSession, error) {
		stored := current.IOS
		if client.Profile() == wireprofile.WindowsID {
			stored = current.Windows
		}
		if stored.UserID <= 0 || stored.Token == "" {
			return LoginSession{}, provider.ErrNoSession
		}
		configuration, err := retry(child, driver, func() (ClientConfig, error) { return client.FetchClientConfig(child) })
		if err != nil {
			return LoginSession{}, err
		}
		session := LoginSession{UserID: stored.UserID, Token: stored.Token, APIBase: configuration.APIBase}
		return retry(child, driver, func() (LoginSession, error) { return client.RefreshSession(child, session) })
	})
}

func parallelSessions(ctx context.Context, clients [2]*Client, call func(context.Context, *Client) (LoginSession, error)) ([2]LoginSession, error) {
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		index   int
		session LoginSession
		err     error
	}
	results := make(chan result, len(clients))
	for index, client := range clients {
		go func() {
			session, err := call(child, client)
			results <- result{index: index, session: session, err: err}
		}()
	}
	var sessions [2]LoginSession
	var firstErr error
	for range clients {
		result := <-results
		if result.err != nil && firstErr == nil {
			firstErr = result.err
			cancel()
		}
		sessions[result.index] = result.session
	}
	if firstErr != nil {
		return [2]LoginSession{}, firstErr
	}
	if sessions[0].UserID <= 0 || sessions[0].UserID != sessions[1].UserID {
		return [2]LoginSession{}, ErrSchema
	}
	return sessions, nil
}

type completeProfile struct {
	client    *Client
	session   LoginSession
	authority Authority
	lines     Lines
}

func (driver *Driver) fetchBothProfiles(ctx context.Context, sessions [2]LoginSession, retryRequests bool) ([2]completeProfile, error) {
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		index   int
		profile completeProfile
		err     error
	}
	results := make(chan result, len(driver.clients))
	for index, client := range driver.clients {
		go func() {
			authority, lines, err := driver.fetchAuthorityAndLines(child, client, sessions[index], retryRequests)
			if err != nil {
				cancel()
			}
			results <- result{index: index, profile: completeProfile{client: client, session: sessions[index], authority: authority, lines: lines}, err: err}
		}()
	}
	var profiles [2]completeProfile
	for range driver.clients {
		result := <-results
		if result.err != nil {
			return [2]completeProfile{}, result.err
		}
		profiles[result.index] = result.profile
	}
	return profiles, nil
}

func (driver *Driver) fetchAuthorityAndLines(ctx context.Context, client *Client, session LoginSession, retryRequests bool) (Authority, Lines, error) {
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		authority *Authority
		lines     *Lines
		err       error
	}
	results := make(chan result, 2)
	go func() {
		var authority Authority
		var err error
		if retryRequests {
			authority, err = retry(child, driver, func() (Authority, error) { return client.FetchAuthority(child, session) })
		} else {
			authority, err = client.FetchAuthority(child, session)
		}
		if err != nil {
			cancel()
			results <- result{err: err}
			return
		}
		results <- result{authority: &authority}
	}()
	go func() {
		var lines Lines
		var err error
		if retryRequests {
			lines, err = retry(child, driver, func() (Lines, error) { return client.FetchLines(child, session) })
		} else {
			lines, err = client.FetchLines(child, session)
		}
		if err != nil {
			cancel()
			results <- result{err: err}
			return
		}
		results <- result{lines: &lines}
	}()
	var authority Authority
	var lines Lines
	for range 2 {
		result := <-results
		if result.err != nil {
			return Authority{}, Lines{}, result.err
		}
		if result.authority != nil {
			authority = *result.authority
		}
		if result.lines != nil {
			lines = *result.lines
		}
	}
	if authority.ProviderToken == "" || session.Token == "" || len(lines.Lines) == 0 {
		return Authority{}, Lines{}, ErrSchema
	}
	return authority, lines, nil
}

func aggregateProviderAccount(display string, profiles [2]completeProfile, now time.Time) (provider.Account, error) {
	if display == "" || profiles[0].session.UserID <= 0 || profiles[0].session.UserID != profiles[1].session.UserID {
		return provider.Account{}, ErrSchema
	}
	active := profiles[0].session.Profile.IsVIP && profiles[1].session.Profile.IsVIP
	subscriptionEndsAt := time.Time{}
	if active {
		subscriptionEndsAt = profiles[0].session.Profile.VIPEndsAt
		if other := profiles[1].session.Profile.VIPEndsAt; subscriptionEndsAt.IsZero() || !other.IsZero() && other.Before(subscriptionEndsAt) {
			subscriptionEndsAt = other
		}
		if subscriptionEndsAt.IsZero() {
			return provider.Account{}, ErrSchema
		}
		active = subscriptionEndsAt.After(now)
	}
	tier := standardTier
	if active {
		tier = vipTier
	} else {
		subscriptionEndsAt = time.Time{}
	}
	return provider.Account{
		UserID: formatUserID(profiles[0].session.UserID), Display: display, Tier: tier,
		SubscriptionActive: active, SubscriptionEndsAt: subscriptionEndsAt,
	}, nil
}

type tunnelAuthority struct {
	Password  string `json:"password"`
	Method    string `json:"method"`
	Extension string `json:"extension"`
}

func (driver *Driver) snapshot(profiles [2]completeProfile, account provider.Account) (provider.Snapshot, error) {
	stateBytes, err := json.Marshal(driverState{
		IOS:     storedLoginSession{UserID: profiles[0].session.UserID, Token: profiles[0].session.Token},
		Windows: storedLoginSession{UserID: profiles[1].session.UserID, Token: profiles[1].session.Token},
	})
	if err != nil {
		return provider.Snapshot{}, ErrSchema
	}
	authorities := make(map[string]provider.Authority, len(profiles))
	for _, profile := range profiles {
		encoded, err := json.Marshal(tunnelAuthority{
			Password: profile.authority.EncryptKey, Method: profile.authority.EncryptType, Extension: profile.authority.ProviderExtension,
		})
		if err != nil {
			return provider.Snapshot{}, ErrSchema
		}
		authorities[string(profile.client.Profile())] = provider.Authority{Protocol: WIFIINProtocol, Data: encoded}
	}
	iosNodes, err := nodesFromLines(profiles[0].lines, wireprofile.IOSID)
	if err != nil {
		return provider.Snapshot{}, err
	}
	windowsNodes, err := nodesFromLines(profiles[1].lines, wireprofile.WindowsID)
	if err != nil {
		return provider.Snapshot{}, err
	}
	now := driver.now().UTC()
	snapshot := provider.Snapshot{
		Provider: ProviderID, Account: account, ExpiresAt: now.Add(driver.lifetime), RefreshState: stateBytes,
		Authorities: authorities, Nodes: mergeProfileNodes(iosNodes, windowsNodes),
	}
	if err := provider.ValidateSnapshot(snapshot, ProviderID, now); err != nil {
		return provider.Snapshot{}, err
	}
	return snapshot, nil
}

func decodeDriverState(encoded []byte) (driverState, error) {
	var state driverState
	if len(encoded) == 0 || len(encoded) > 1<<20 || json.Unmarshal(encoded, &state) != nil ||
		state.IOS.UserID <= 0 || state.Windows.UserID != state.IOS.UserID || state.IOS.Token == "" || state.Windows.Token == "" {
		return driverState{}, ErrSchema
	}
	return state, nil
}

func decodeTunnelAuthority(encoded []byte) (tunnelAuthority, error) {
	var authority tunnelAuthority
	if len(encoded) == 0 || len(encoded) > 1<<20 || json.Unmarshal(encoded, &authority) != nil ||
		authority.Password == "" || authority.Method != "aes-256-cfb" || authority.Extension == "" {
		return tunnelAuthority{}, ErrSchema
	}
	return authority, nil
}

func mergeProfileNodes(ios, windows []provider.Node) []provider.Node {
	merged := make([]provider.Node, 0, len(ios)+len(windows))
	seen := make(map[string]struct{}, len(ios)+len(windows))
	for _, profileNodes := range [][]provider.Node{ios, windows} {
		for _, node := range profileNodes {
			if _, duplicate := seen[node.ID]; duplicate {
				continue
			}
			seen[node.ID] = struct{}{}
			merged = append(merged, node)
		}
	}
	return merged
}

func nodesFromLines(lines Lines, profileID wireprofile.ID) ([]provider.Node, error) {
	if profileID != wireprofile.IOSID && profileID != wireprofile.WindowsID {
		return nil, ErrSchema
	}
	groups := make(map[string]string, len(lines.Groups))
	for _, group := range lines.Groups {
		groups[group.ID] = group.Name
	}
	seen := make(map[string]struct{}, len(lines.Lines))
	nodes := make([]provider.Node, 0, len(lines.Lines))
	for _, line := range lines.Lines {
		if !line.Eligible {
			continue
		}
		identity, err := selector.Canonicalize(selector.NodeIdentity{Provider: string(ProviderID), Host: line.Host, Port: int(line.Port)})
		if err != nil {
			return nil, fmt.Errorf("%w: canonical node identity", ErrSchema)
		}
		id := nodeID(identity, line.GroupID)
		if _, duplicate := seen[id]; duplicate {
			continue
		}
		seen[id] = struct{}{}
		groupName := line.GroupName
		if groupName == "" {
			groupName = groups[line.GroupID]
		}
		nodes = append(nodes, provider.Node{
			ID: id, AuthorityID: string(profileID), Protocol: WIFIINProtocol, Host: identity.Host, Port: identity.Port,
			Name: line.Label, Group: groupName, Model: line.Model, Weight: line.Weight, Auto: line.Auto, Eligible: line.Eligible,
		})
	}
	return nodes, nil
}

func nodeID(identity selector.CanonicalIdentity, groupID string) string {
	payload := []byte(groupID + "\x00" + identity.Host + "\x00" + fmt.Sprintf("%d", identity.Port))
	sum := sha256.Sum256(payload)
	return "kuaifan_" + base64.RawURLEncoding.EncodeToString(sum[:12])
}

func (driver *Driver) now() time.Time { return driver.clock() }

func retry[T any](ctx context.Context, driver *Driver, call func() (T, error)) (T, error) {
	var zero T
	for attempt := range driver.attempts {
		select {
		case <-ctx.Done():
			return zero, ctx.Err()
		default:
		}
		value, err := call()
		if err == nil || !retryable(err) || attempt+1 == driver.attempts {
			return value, err
		}
		delay := retryDelay(driver, attempt)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return zero, ctx.Err()
		case <-timer.C:
		}
	}
	return zero, nil
}

func retryable(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, ErrLoginRejected) || errors.Is(err, ErrBusinessStatus) || errors.Is(err, ErrSchema) ||
		errors.Is(err, ErrInvalidEnvelope) || errors.Is(err, ErrInvalidPadding) || errors.Is(err, ErrMalformedCiphertext) ||
		errors.Is(err, ErrResponseTooLarge) || errors.Is(err, ErrUnsupportedCipher) || errors.Is(err, ErrInvalidLine) {
		return false
	}
	var status *httpStatusError
	if errors.As(err, &status) {
		return status.status == http.StatusRequestTimeout || status.status == http.StatusTooManyRequests || status.status >= http.StatusInternalServerError && status.status <= 599
	}
	var networkErr net.Error
	return errors.As(err, &networkErr) && (networkErr.Timeout() || networkErr.Temporary()) //nolint:staticcheck // Temporary is the errno-level signal net.OpError exposes; P1 replaces this classifier.
}

func retryDelay(driver *Driver, attempt int) time.Duration {
	base := driver.backoff
	for range attempt {
		if base >= driver.maxBackoff/2 {
			base = driver.maxBackoff
			break
		}
		base *= 2
	}
	jitter, err := wireprofile.RandomInt(driver.clients[0].random, int(base/time.Millisecond)+1)
	if err != nil {
		return base
	}
	return time.Duration(jitter) * time.Millisecond
}
