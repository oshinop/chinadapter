// Package web provides the loopback browser control plane. It intentionally
// depends only on consumer-owned interfaces so cmd can wire control, state,
// SOCKS, and subscription implementations without an import cycle.
package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/mail"
	"net/netip"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/kfadapter/kfadapter/internal/endpoint"
	"github.com/kfadapter/kfadapter/internal/identity"
)

var (
	errContentType   = errors.New("content type must be application/json")
	errBodyTooLarge  = errors.New("request body is too large")
	errMalformedJSON = errors.New("request body must be one JSON object")
)

type publicProblemError interface {
	error
	Code() string
	HTTPStatus() int
}

// Config defines the HTTP listener and optional DNS hostname accepted by the
// browser boundary.
type Config struct {
	Listen      string
	Hostname    string
	SocksListen string
	Version     string
	StartedAt   time.Time
	Now         func() time.Time
	Random      io.Reader
	SessionTTL  time.Duration
	MaxSessions int
	// MaxConnections bounds all accepted local HTTP connections. Zero defaults
	// to 128; values above 1024 are rejected.
	MaxConnections int
	// ReadTimeout bounds request headers plus JSON body delivery. WriteTimeout
	// bounds regular responses; SSE refreshes and clears a per-write deadline so
	// its idle lifetime is not limited by that server-wide bound.
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	// ProviderRequestTimeout is the per-request provider transport budget.
	ProviderRequestTimeout time.Duration
	JSONBodyLimit          int
	SSEMaxEventBytes       int
	SSEHeartbeat           time.Duration
}

// BrowserSessionPersistence stores only opaque browser-session and CSRF
// secrets. It never receives provider credentials or local access tokens.
type BrowserSessionPersistence interface {
	RestoreBrowserSessions(context.Context, time.Time, int, func(tokenHash []byte, csrf string, expiresAt time.Time) error) error
	SaveBrowserSession(context.Context, string, string, time.Time, int) error
	DeleteBrowserSession(context.Context, []byte) error
	DeleteAllBrowserSessions(context.Context) error
}

// Dependencies are injected by cmd. Backend implementations normally adapt
// control/state/SOCKS services; this package never receives their secrets.
type Dependencies struct {
	Backend       Backend
	Subscriptions SubscriptionService
	Liveness      Liveness
	Sessions      BrowserSessionPersistence
}

// Liveness reports process component health for the unauthenticated /healthz
// endpoint. It must not inspect or disclose account/upstream readiness.
type Liveness interface {
	Healthy() bool
}

// Backend is the browser-safe facade over control, state, and SOCKS services.
// NodeDetails may return only locally derived SOCKS credentials; provider and subscription authority stays hidden.
type Backend interface {
	AccessStatus(context.Context) (AccessStatus, error)
	AccessSetup(context.Context, string) error
	AccessLogin(context.Context, string) error
	AccessChangeToken(context.Context, string, string) error
	Status(context.Context) (Status, error)
	Nodes(context.Context) ([]Node, error)
	NodeDetails(context.Context, string) (NodeDetails, error)
	Login(context.Context, LoginInput) (Account, error)
	Logout(context.Context, string) error
	Refresh(context.Context, string) error
	Probe(context.Context, string) (ProbeResult, error)
	Diagnostics(context.Context) (any, error)
}

// EventSource is an optional Backend capability. Subscribe must return a
// bounded source owned by the state layer and a cancellation function.
type EventSource interface {
	Subscribe(context.Context) (<-chan Event, func(), error)
}

// SubscriptionService is the browser-safe facade over the state-backed
// subscription service. It exposes a stable account-bound URL only after the
// API has authenticated the browser session.
type SubscriptionService interface {
	Metadata(context.Context) (SubscriptionMetadata, error)
	SubscriptionURL(context.Context, string, string) (SubscriptionURL, error)
	ServeSubscription(http.ResponseWriter, *http.Request, string, string)
}

// AccessStatus is deliberately limited to initialization state. The API adds
// browser-session authentication information without exposing verifier data.
type AccessStatus struct {
	Initialized bool `json:"initialized"`
}

// SubscriptionURL is a reusable, account-bound subscription endpoint.
type SubscriptionURL struct {
	URL string `json:"url"`
}

// Status is the browser-safe operational state.
type Status struct {
	State        string               `json:"state"`
	Version      string               `json:"version,omitempty"`
	Deployment   Deployment           `json:"deployment"`
	Providers    []string             `json:"providers"`
	Accounts     map[string]Account   `json:"accounts,omitempty"`
	ControlPlane ControlPlaneStatus   `json:"controlPlane"`
	DataPlane    DataPlaneStatus      `json:"dataPlane"`
	Nodes        NodeCounts           `json:"nodes"`
	Subscription SubscriptionMetadata `json:"subscription"`
}

type Deployment struct {
	Mode      string    `json:"mode,omitempty"`
	StartedAt time.Time `json:"startedAt,omitzero"`
}

type Account struct {
	Provider           string     `json:"provider"`
	Display            string     `json:"display,omitempty"`
	Tier               string     `json:"tier"`
	SubscriptionActive bool       `json:"subscriptionActive"`
	SubscriptionEndsAt *time.Time `json:"subscriptionEndsAt,omitempty"`
	RefreshStatus      string     `json:"refreshStatus,omitempty"`
	LastRefreshAt      time.Time  `json:"lastRefreshAt,omitzero"`
	NextRefreshAt      time.Time  `json:"nextRefreshAt,omitzero"`
}

// LoginInput carries provider credentials transiently to the runtime.
type LoginInput struct {
	Provider string
	Account  string
	Password string
}

type ControlPlaneStatus struct {
	LastRefreshAt time.Time `json:"lastRefreshAt,omitzero"`
	NextRefreshAt time.Time `json:"nextRefreshAt,omitzero"`
}

type DataPlaneStatus struct {
	SocksAddress string `json:"socksAddress,omitempty"`
	UDPMode      string `json:"udpMode"`
}

type NodeCounts struct {
	Total    int `json:"total"`
	Eligible int `json:"eligible"`
	Healthy  int `json:"healthy"`
}

// Node is deliberately limited to browser-safe node presentation data.
type Node struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Group        string `json:"group"`
	Provider     string `json:"provider"`
	Health       string `json:"health"`
	TCPLatencyMS int    `json:"tcpLatencyMs,omitempty"`
	UDPHealth    string `json:"udpHealth"`
	Eligible     bool   `json:"eligible"`
}

// NodeDetails is an authenticated, on-demand local SOCKS connection profile.
// Its credentials are derived locally and are never provider tunnel secrets.
type NodeDetails struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Group         string `json:"group"`
	Provider      string `json:"provider"`
	UpstreamHost  string `json:"upstreamHost"`
	UpstreamPort  int    `json:"upstreamPort"`
	SocksAddress  string `json:"socksAddress"`
	SocksUsername string `json:"socksUsername"`
	SocksPassword string `json:"socksPassword"`
	Health        string `json:"health"`
	TCPLatencyMS  int    `json:"tcpLatencyMs"`
}

// ProbeResult reports the latest bounded TCP probe for one node.
type ProbeResult struct {
	NodeID       string    `json:"nodeId"`
	Health       string    `json:"health"`
	TCPLatencyMS int       `json:"tcpLatencyMs,omitempty"`
	ProbedAt     time.Time `json:"probedAt"`
}

// SubscriptionMetadata intentionally excludes subscription URLs and selector
// credentials. It matches the metadata shown by the Subscription screen.
type SubscriptionMetadata struct {
	Active    bool `json:"active"`
	NodeCount int  `json:"nodeCount"`
}

// Event is a coarse, browser-safe SSE event. Data is validated and bounded by
// the server before it is placed on the wire.
type Event struct {
	Type string
	Data any
}

type API struct {
	config        Config
	backend       Backend
	subscriptions SubscriptionService
	liveness      Liveness
	listenIP      netip.Addr
	listenPort    string
	hostname      string
	socksIP       netip.Addr
	socksPort     string
	sessions      *sessionStore
	accessMu      sync.RWMutex
	handler       http.Handler
}

// NewAPI creates the browser handler for the configured listener.
func NewAPI(config Config, dependencies Dependencies) (*API, error) {
	if config.Listen == "" {
		config.Listen = "127.0.0.1:10809"
	}
	listenIP, listenPort, err := canonicalNumericAddress(config.Listen)
	if err != nil {
		return nil, errors.New("listen must be a canonical numeric IP address and port")
	}
	if config.SocksListen == "" {
		config.SocksListen = "127.0.0.1:10808"
	}
	socksIP, socksPort, err := canonicalNumericAddress(config.SocksListen)
	if err != nil {
		return nil, errors.New("SOCKS listen must be a canonical numeric IP address and port")
	}
	if config.Hostname != "" {
		if err := endpoint.ValidateHostname(config.Hostname); err != nil {
			return nil, fmt.Errorf("hostname %w", err)
		}
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.JSONBodyLimit <= 0 {
		config.JSONBodyLimit = defaultJSONLimit
	}
	if config.ReadTimeout == 0 {
		config.ReadTimeout = 10 * time.Second
	} else if config.ReadTimeout < 0 || config.ReadTimeout > 30*time.Second {
		return nil, errors.New("invalid HTTP read timeout")
	}
	if config.WriteTimeout == 0 {
		config.WriteTimeout = 15 * time.Second
	} else if config.WriteTimeout < 0 || config.WriteTimeout > 30*time.Second {
		return nil, errors.New("invalid HTTP write timeout")
	}
	if config.SSEMaxEventBytes <= 0 {
		config.SSEMaxEventBytes = 4 << 10
	}
	if config.SSEHeartbeat <= 0 {
		config.SSEHeartbeat = 15 * time.Second
	}
	if config.MaxConnections == 0 {
		config.MaxConnections = 128
	} else if config.MaxConnections < 1 || config.MaxConnections > 1024 {
		return nil, errors.New("invalid HTTP connection limit")
	}
	if config.StartedAt.IsZero() {
		config.StartedAt = config.Now().UTC()
	}
	sessions, err := newSessionStore(config.Now, config.Random, config.SessionTTL, config.MaxSessions, dependencies.Sessions)
	if err != nil {
		return nil, fmt.Errorf("restore browser sessions: %w", err)
	}
	api := &API{
		config: config, backend: dependencies.Backend, subscriptions: dependencies.Subscriptions,
		liveness: dependencies.Liveness, listenIP: listenIP, listenPort: listenPort, hostname: config.Hostname,
		socksIP: socksIP, socksPort: socksPort,
		sessions: sessions,
	}
	api.handler = api.newHandler()
	return api, nil
}

// ServeHTTP is intentionally free of request logging. In particular, invalid
// subscription paths are never formatted into a log message.
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodHead {
		w = headResponseWriter{w}
	}
	if !requestHostAllowed(a.listenIP, a.listenPort, a.hostname, r.Host) {
		setSecurityHeaders(w.Header())
		setNoStore(w.Header())
		a.writeProblem(w, http.StatusBadRequest, "invalid_host", "Invalid Host")
		return
	}
	setSecurityHeaders(w.Header())
	if a.serveSubscription(w, r) {
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/") && strings.Contains(r.URL.Path, "//") {
		setNoStore(w.Header())
		a.writeProblem(w, http.StatusNotFound, "not_found", "Not Found")
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/api/") && r.URL.Path != "/api" {
		a.serveAsset(w, r)
		return
	}
	a.handler.ServeHTTP(w, r)
}

func (a *API) health(w http.ResponseWriter, r *http.Request) {
	setNoStore(w.Header())
	if a.liveness != nil && !a.liveness.Healthy() {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		if r.Method != http.MethodHead {
			_, _ = io.WriteString(w, "unhealthy\n")
		}
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = io.WriteString(w, "ok\n")
	}
}

func (a *API) accessStatus(w http.ResponseWriter, r *http.Request) {
	if a.backend == nil {
		a.backendUnavailable(w)
		return
	}
	status, err := a.backend.AccessStatus(r.Context())
	if err != nil {
		a.writeAccessError(w, err)
		return
	}
	response := struct {
		Initialized   bool       `json:"initialized"`
		Authenticated bool       `json:"authenticated"`
		CSRFToken     string     `json:"csrfToken,omitempty"`
		ExpiresAt     *time.Time `json:"expiresAt,omitempty"`
	}{Initialized: status.Initialized}
	if _, session, authenticated := a.authenticate(r); authenticated {
		response.Authenticated = true
		response.CSRFToken = session.csrf
		expiresAt := session.expiresAt
		response.ExpiresAt = &expiresAt
	}
	a.writeJSON(w, http.StatusOK, response)
}

func (a *API) access(w http.ResponseWriter, r *http.Request, setup bool) {
	if a.backend == nil {
		a.backendUnavailable(w)
		return
	}
	if !originAllowed(r.Header.Get("Origin"), "http://"+r.Host) {
		a.writeProblem(w, http.StatusForbidden, "invalid_origin", "Invalid Origin")
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := readJSONBody(w, r, accessTokenLimit, &body); err != nil {
		a.writeBodyError(w, err)
		return
	}
	body.Token = strings.TrimSpace(body.Token)
	client := clientIdentity(r.RemoteAddr)
	admission, retry := a.sessions.beginAccess(client)
	switch admission {
	case accessBusy:
		w.Header().Set("Retry-After", "1")
		a.writeProblem(w, http.StatusTooManyRequests, "access_in_progress", "Access request in progress")
		return
	case accessRateLimited:
		retryAfterHeader(w.Header(), retry)
		a.writeProblem(w, http.StatusTooManyRequests, "access_rate_limited", "Too Many Requests")
		return
	case accessAdmitted:
		// Admitted requests continue below.
	}
	successful, countedFailure := false, false
	defer func() { a.sessions.finishAccess(client, successful, countedFailure) }()
	if !validAccessToken(body.Token) {
		countedFailure = true
		a.writeProblem(w, http.StatusUnauthorized, "invalid_access_token", "Authentication required")
		return
	}
	a.accessMu.RLock()
	defer a.accessMu.RUnlock()
	var err error
	if setup {
		err = a.backend.AccessSetup(r.Context(), body.Token)
	} else {
		err = a.backend.AccessLogin(r.Context(), body.Token)
	}
	if err != nil {
		countedFailure = accessFailureCounts(err)
		a.writeAccessError(w, err)
		return
	}
	successful = true
	token, session, err := a.sessions.create(r.Context())
	if err != nil {
		a.writeProblem(w, http.StatusServiceUnavailable, "session_unavailable", "Session unavailable")
		return
	}
	status := http.StatusOK
	if setup {
		status = http.StatusCreated
	}
	setSessionCookie(w, token, session.expiresAt)
	a.writeJSON(w, status, struct {
		Initialized   bool      `json:"initialized"`
		Authenticated bool      `json:"authenticated"`
		CSRFToken     string    `json:"csrfToken"`
		ExpiresAt     time.Time `json:"expiresAt"`
	}{Initialized: true, Authenticated: true, CSRFToken: session.csrf, ExpiresAt: session.expiresAt})
}

func (a *API) changeAccessToken(w http.ResponseWriter, r *http.Request, token string, session browserSession) {
	if a.backend == nil {
		a.backendUnavailable(w)
		return
	}
	var body struct {
		Current string `json:"current"`
		Next    string `json:"next"`
	}
	if err := readJSONBody(w, r, accessTokenLimit, &body); err != nil {
		a.writeBodyError(w, err)
		return
	}
	body.Current, body.Next = strings.TrimSpace(body.Current), strings.TrimSpace(body.Next)
	client := clientIdentity(r.RemoteAddr)
	admission, retry := a.sessions.beginAccess(client)
	switch admission {
	case accessBusy:
		w.Header().Set("Retry-After", "1")
		a.writeProblem(w, http.StatusTooManyRequests, "access_in_progress", "Access request in progress")
		return
	case accessRateLimited:
		retryAfterHeader(w.Header(), retry)
		a.writeProblem(w, http.StatusTooManyRequests, "access_rate_limited", "Too Many Requests")
		return
	case accessAdmitted:
	}
	successful, countedFailure := false, false
	defer func() { a.sessions.finishAccess(client, successful, countedFailure) }()
	if !validAccessToken(body.Current) {
		countedFailure = true
		a.writeProblem(w, http.StatusUnauthorized, "invalid_access_token", "Authentication required")
		return
	}
	// The write lock includes verifier rotation, revocation and the replacement
	// caller session; concurrent access logins cannot mint an old-token session.
	a.accessMu.Lock()
	defer a.accessMu.Unlock()
	if !a.sessions.matches(r.Context(), token, session) {
		a.writeProblem(w, http.StatusUnauthorized, "not_authenticated", "Authentication required")
		return
	}
	if err := a.backend.AccessChangeToken(r.Context(), body.Current, body.Next); err != nil {
		countedFailure = accessFailureCounts(err)
		a.writeAccessError(w, err)
		return
	}
	successful = true
	if err := a.sessions.revokeAll(r.Context()); err != nil {
		a.writeProblem(w, http.StatusServiceUnavailable, "session_unavailable", "Session unavailable")
		return
	}
	newToken, newSession, err := a.sessions.create(r.Context())
	if err != nil {
		a.writeProblem(w, http.StatusServiceUnavailable, "session_unavailable", "Session unavailable")
		return
	}
	setSessionCookie(w, newToken, newSession.expiresAt)
	a.writeJSON(w, http.StatusOK, struct {
		Initialized   bool      `json:"initialized"`
		Authenticated bool      `json:"authenticated"`
		CSRFToken     string    `json:"csrfToken"`
		ExpiresAt     time.Time `json:"expiresAt"`
	}{Initialized: true, Authenticated: true, CSRFToken: newSession.csrf, ExpiresAt: newSession.expiresAt})
}

func (a *API) status(w http.ResponseWriter, r *http.Request) {
	if a.backend == nil {
		a.backendUnavailable(w)
		return
	}
	status, err := a.backend.Status(r.Context())
	if err != nil {
		a.writeBackendError(w, err, "status_unavailable", http.StatusServiceUnavailable)
		return
	}
	for id, account := range status.Accounts {
		status.Accounts[id] = *redactAccount(&account)
	}
	status.Version = firstNonEmpty(status.Version, a.config.Version)
	if status.Deployment.StartedAt.IsZero() {
		status.Deployment.StartedAt = a.config.StartedAt
	}
	if a.subscriptions != nil {
		metadata, err := a.subscriptions.Metadata(r.Context())
		if err != nil {
			a.writeBackendError(w, err, "subscription_unavailable", http.StatusServiceUnavailable)
			return
		}
		status.Subscription = metadata
	}
	status.DataPlane.SocksAddress = a.socksAddress(r)
	a.writeJSON(w, http.StatusOK, status)
}

func (a *API) nodes(w http.ResponseWriter, r *http.Request) {
	if a.backend == nil {
		a.backendUnavailable(w)
		return
	}
	nodes, err := a.backend.Nodes(r.Context())
	if err != nil {
		a.writeBackendError(w, err, "nodes_unavailable", http.StatusServiceUnavailable)
		return
	}
	a.writeJSON(w, http.StatusOK, struct {
		Nodes []Node `json:"nodes"`
	}{Nodes: nodes})
}

func (a *API) nodeDetails(w http.ResponseWriter, r *http.Request, id string) {
	if a.backend == nil {
		a.backendUnavailable(w)
		return
	}
	if !validResourceID(id) {
		a.writeProblem(w, http.StatusNotFound, "not_found", "Not Found")
		return
	}
	details, err := a.backend.NodeDetails(r.Context(), id)
	if err != nil {
		a.writeBackendError(w, err, "node_details_unavailable", http.StatusServiceUnavailable)
		return
	}
	details.SocksAddress = a.socksAddress(r)
	a.writeJSON(w, http.StatusOK, details)
}

func (a *API) login(w http.ResponseWriter, r *http.Request, token string) {
	if a.backend == nil {
		a.backendUnavailable(w)
		return
	}
	var body struct {
		Provider string `json:"provider"`
		Account  string `json:"account"`
		Password string `json:"password"`
	}
	if err := readJSONBody(w, r, a.config.JSONBodyLimit, &body); err != nil {
		a.writeBodyError(w, err)
		return
	}
	if !validProviderID(body.Provider) || !validEmail(body.Account) || body.Password == "" {
		a.writeProblem(w, http.StatusBadRequest, "invalid_login", "Invalid login")
		return
	}
	admission, retry := a.sessions.beginLogin(r.Context(), token)
	switch admission {
	case loginBusy:
		w.Header().Set("Retry-After", "1")
		a.writeProblem(w, http.StatusTooManyRequests, "login_in_progress", "Login already in progress")
		return
	case loginRateLimited:
		retryAfterHeader(w.Header(), retry)
		a.writeProblem(w, http.StatusTooManyRequests, "login_rate_limited", "Too Many Requests")
		return
	case loginSessionInactive:
		a.writeProblem(w, http.StatusUnauthorized, "not_authenticated", "Authentication required")
		return
	case loginAdmitted:
		// Admitted requests continue below.
	}
	ctx := r.Context()
	successful, countedFailure := false, false
	defer func() { a.sessions.finishLogin(ctx, token, successful, countedFailure) }()
	if !a.extendProviderWriteDeadline(w) {
		return
	}
	account, err := a.backend.Login(ctx, LoginInput{Provider: body.Provider, Account: body.Account, Password: body.Password})
	if err != nil {
		countedFailure = loginFailureCounts(err)
		a.writeBackendError(w, err, "login_failed", http.StatusUnauthorized)
		return
	}
	successful = true
	a.writeJSON(w, http.StatusOK, redactAccount(&account))
}

func (a *API) accountLogout(w http.ResponseWriter, r *http.Request) {
	if a.backend == nil {
		a.backendUnavailable(w)
		return
	}
	var body struct {
		Provider string `json:"provider"`
	}
	if err := readJSONBody(w, r, a.config.JSONBodyLimit, &body); err != nil {
		a.writeBodyError(w, err)
		return
	}
	if !validProviderID(body.Provider) {
		a.writeProblem(w, http.StatusBadRequest, "invalid_provider", "Invalid provider")
		return
	}
	if err := a.backend.Logout(r.Context(), body.Provider); err != nil {
		a.writeBackendError(w, err, "logout_failed", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) lock(w http.ResponseWriter, r *http.Request, token string) {
	if err := a.requireEmptyJSON(w, r); err != nil {
		a.writeBodyError(w, err)
		return
	}
	if err := a.revokeBrowserSession(r.Context(), token); err != nil {
		a.writeProblem(w, http.StatusServiceUnavailable, "session_unavailable", "Session unavailable")
		return
	}
	clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) revokeBrowserSession(ctx context.Context, token string) error {
	return a.sessions.revoke(ctx, token)
}

func (a *API) refresh(w http.ResponseWriter, r *http.Request) {
	if a.backend == nil {
		a.backendUnavailable(w)
		return
	}
	var body struct {
		Provider string `json:"provider"`
	}
	if err := readJSONBody(w, r, a.config.JSONBodyLimit, &body); err != nil {
		a.writeBodyError(w, err)
		return
	}
	if body.Provider != "" && !validProviderID(body.Provider) {
		a.writeProblem(w, http.StatusBadRequest, "invalid_provider", "Invalid provider")
		return
	}
	if !a.extendProviderWriteDeadline(w) {
		return
	}
	if err := a.backend.Refresh(r.Context(), body.Provider); err != nil {
		a.writeBackendError(w, err, "refresh_failed", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// Kuaifan refresh has three sequential request stages, each with three attempts;
// profiles and linked providers run concurrently. Login fits within this bound.
func (a *API) extendProviderWriteDeadline(w http.ResponseWriter) bool {
	timeout := a.config.ProviderRequestTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	budget := 9*timeout + 10*time.Second
	if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(budget)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		a.backendUnavailable(w)
		return false
	}
	return true
}

func (a *API) probe(w http.ResponseWriter, r *http.Request, id string) {
	if a.backend == nil {
		a.backendUnavailable(w)
		return
	}
	if !validResourceID(id) {
		a.writeProblem(w, http.StatusNotFound, "not_found", "Not Found")
		return
	}
	if err := a.requireEmptyJSON(w, r); err != nil {
		a.writeBodyError(w, err)
		return
	}
	result, err := a.backend.Probe(r.Context(), id)
	if err != nil {
		a.writeBackendError(w, err, "probe_failed", http.StatusServiceUnavailable)
		return
	}
	a.writeJSON(w, http.StatusOK, result)
}

func (a *API) subscriptionMetadata(w http.ResponseWriter, r *http.Request) {
	if a.subscriptions == nil {
		a.writeProblem(w, http.StatusServiceUnavailable, "subscription_unavailable", "Subscription unavailable")
		return
	}
	metadata, err := a.subscriptions.Metadata(r.Context())
	if err != nil {
		a.writeBackendError(w, err, "subscription_unavailable", http.StatusServiceUnavailable)
		return
	}
	a.writeJSON(w, http.StatusOK, metadata)
}

func (a *API) subscriptionURL(w http.ResponseWriter, r *http.Request) {
	if a.subscriptions == nil {
		a.writeProblem(w, http.StatusServiceUnavailable, "subscription_unavailable", "Subscription unavailable")
		return
	}
	subscriptionURL, err := a.subscriptions.SubscriptionURL(r.Context(), a.baseURL(r.Host), a.socksAddress(r))
	if err != nil {
		a.writeBackendError(w, err, "subscription_unavailable", http.StatusServiceUnavailable)
		return
	}
	a.writeJSON(w, http.StatusOK, subscriptionURL)
}

func (a *API) diagnostics(w http.ResponseWriter, r *http.Request) {
	if a.backend == nil {
		a.backendUnavailable(w)
		return
	}
	if err := a.requireEmptyJSON(w, r); err != nil {
		a.writeBodyError(w, err)
		return
	}
	diagnostic, err := a.backend.Diagnostics(r.Context())
	if err != nil {
		a.writeBackendError(w, err, "diagnostics_unavailable", http.StatusServiceUnavailable)
		return
	}
	redacted := redactDiagnostic(diagnostic)
	encoded, err := json.Marshal(redacted)
	if err != nil {
		a.writeProblem(w, http.StatusInternalServerError, "diagnostics_unavailable", "Diagnostics unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\"kfadapter-diagnostics.json\"")
	w.Header().Set("Content-Length", fmt.Sprint(len(encoded)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(encoded)
}

func (a *API) writeSSE(w http.ResponseWriter, flusher http.Flusher, payload string) bool {
	controller := http.NewResponseController(w)
	if err := controller.SetWriteDeadline(time.Now().Add(a.config.WriteTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return false
	}
	defer func() { _ = controller.SetWriteDeadline(time.Time{}) }()
	if _, err := io.WriteString(w, payload); err != nil {
		return false
	}
	flusher.Flush()
	return true
}

func (a *API) events(w http.ResponseWriter, r *http.Request, token string, session browserSession) {
	if !a.sessions.matches(r.Context(), token, session) {
		a.writeProblem(w, http.StatusUnauthorized, "not_authenticated", "Authentication required")
		return
	}
	source, ok := a.backend.(EventSource)
	if !ok {
		a.writeProblem(w, http.StatusServiceUnavailable, "events_unavailable", "Events unavailable")
		return
	}
	streamContext, stopStream := context.WithCancel(r.Context())
	defer stopStream()
	events, cancel, err := source.Subscribe(streamContext)
	if err != nil {
		a.writeBackendError(w, err, "events_unavailable", http.StatusServiceUnavailable)
		return
	}
	defer cancel()
	flusher, ok := w.(http.Flusher)
	if !ok {
		a.writeProblem(w, http.StatusInternalServerError, "streaming_unavailable", "Streaming unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	if !a.writeSSE(w, flusher, "retry: 1000\n\n") {
		return
	}
	heartbeat := time.NewTicker(a.config.SSEHeartbeat)
	defer heartbeat.Stop()
	checkEvery := a.config.SSEHeartbeat
	if checkEvery > 15*time.Second {
		checkEvery = 15 * time.Second
	}
	sessionCheck := time.NewTicker(checkEvery)
	defer sessionCheck.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-session.done:
			return
		case <-sessionCheck.C:
			if !a.sessions.matches(r.Context(), token, session) {
				return
			}
		case <-heartbeat.C:
			if !a.writeSSE(w, flusher, ": keepalive\n\n") {
				return
			}
		case event, open := <-events:
			if !open {
				return
			}
			if !a.sessions.matches(r.Context(), token, session) {
				return
			}
			if event.Type == "" || strings.ContainsAny(event.Type, "\r\n") {
				continue
			}
			payload, err := json.Marshal(redactDiagnostic(event.Data))
			if err != nil || len(payload) > a.config.SSEMaxEventBytes {
				continue
			}
			if !a.writeSSE(w, flusher, fmt.Sprintf("event: %s\ndata: %s\n\n", event.Type, payload)) {
				return
			}
		}
	}
}

func (a *API) authenticate(r *http.Request) (string, browserSession, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return "", browserSession{}, false
	}
	session, ok := a.sessions.valid(r.Context(), cookie.Value)
	return cookie.Value, session, ok
}

func (a *API) requireEmptyJSON(w http.ResponseWriter, r *http.Request) error {
	var body struct{}
	return readJSONBody(w, r, a.config.JSONBodyLimit, &body)
}

func (a *API) writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (a *API) writeProblem(w http.ResponseWriter, status int, code, title string) {
	w.Header().Set("Content-Type", "application/problem+json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Type   string `json:"type"`
		Code   string `json:"code"`
		Status int    `json:"status"`
		Title  string `json:"title"`
	}{Type: "urn:kfadapter:problem:" + code, Code: code, Status: status, Title: title})
}

func (a *API) writeBodyError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errContentType):
		a.writeProblem(w, http.StatusUnsupportedMediaType, "invalid_content_type", "Unsupported Content Type")
	case errors.Is(err, errBodyTooLarge):
		a.writeProblem(w, http.StatusRequestEntityTooLarge, "body_too_large", "Request body too large")
	default:
		a.writeProblem(w, http.StatusBadRequest, "invalid_json", "Invalid JSON")
	}
}

func (a *API) writeBackendError(w http.ResponseWriter, err error, fallback string, status int) {
	var public publicProblemError
	if errors.As(err, &public) {
		code := public.Code()
		if code == "" {
			code = fallback
		}
		publicStatus := public.HTTPStatus()
		if publicStatus >= 400 && publicStatus <= 599 {
			status = publicStatus
		}
		a.writeProblem(w, status, code, problemTitle(status))
		return
	}
	a.writeProblem(w, status, fallback, problemTitle(status))
}

func (a *API) writeAccessError(w http.ResponseWriter, err error) {
	var public publicProblemError
	if errors.As(err, &public) {
		switch public.HTTPStatus() {
		case http.StatusConflict:
			a.writeProblem(w, http.StatusConflict, "access_initialized", "Conflict")
			return
		case http.StatusBadRequest:
			a.writeProblem(w, http.StatusBadRequest, "invalid_next_access_token", "Invalid next access token")
			return
		case http.StatusUnauthorized:
			a.writeProblem(w, http.StatusUnauthorized, "invalid_access_token", "Authentication required")
			return
		}
	}
	a.writeProblem(w, http.StatusServiceUnavailable, "access_unavailable", "Service unavailable")
}

func accessFailureCounts(err error) bool {
	var public publicProblemError
	return errors.As(err, &public) && public.HTTPStatus() == http.StatusUnauthorized
}

func loginFailureCounts(err error) bool {
	var public publicProblemError
	return !errors.As(err, &public) || public.Code() == "login_rejected"
}

func (a *API) backendUnavailable(w http.ResponseWriter) {
	a.writeProblem(w, http.StatusServiceUnavailable, "service_unavailable", "Service unavailable")
}

func (a *API) baseURL(requestHost string) string {
	if hostname, ok := a.advertisedHostname(requestHost); ok {
		if a.listenPort == "80" {
			return "http://" + hostname
		}
		return "http://" + net.JoinHostPort(hostname, a.listenPort)
	}
	return "http://" + requestHost
}

func (a *API) advertisedHostname(requestHost string) (string, bool) {
	return acceptedHostname(a.listenIP, a.listenPort, a.hostname, requestHost)
}

func (a *API) socksAddress(r *http.Request) string {
	if hostname, ok := a.advertisedHostname(r.Host); ok {
		return net.JoinHostPort(hostname, a.socksPort)
	}
	if !a.socksIP.IsUnspecified() {
		return a.config.SocksListen
	}
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil && a.listenPort == "80" {
		host = r.Host
	}
	if requestIP, err := netip.ParseAddr(host); err == nil && requestIP.Is4() == a.socksIP.Is4() {
		return net.JoinHostPort(host, a.socksPort)
	}
	return a.config.SocksListen
}

func requestHostAllowed(listenIP netip.Addr, listenPort, hostname, requestHost string) bool {
	requestIP, requestPort, err := canonicalNumericAddress(requestHost)
	if err == nil && requestPort == listenPort && (requestIP == listenIP || listenIP.IsUnspecified() && requestIP.Is4() == listenIP.Is4()) {
		return true
	}
	_, ok := acceptedHostname(listenIP, listenPort, hostname, requestHost)
	return ok
}

func acceptedHostname(listenIP netip.Addr, listenPort, configuredHostname, requestHost string) (string, bool) {
	if configuredHostname != "" && hostnameMatches(configuredHostname, listenPort, requestHost) {
		return configuredHostname, true
	}
	if (listenIP.IsUnspecified() || listenIP.IsLoopback()) && hostnameMatches("localhost", listenPort, requestHost) {
		return "localhost", true
	}
	return "", false
}

func hostnameMatches(hostname, listenPort, requestHost string) bool {
	return strings.EqualFold(requestHost, net.JoinHostPort(hostname, listenPort)) ||
		listenPort == "80" && strings.EqualFold(requestHost, hostname)
}

func canonicalNumericAddress(hostport string) (netip.Addr, string, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil || host == "" || port == "" {
		return netip.Addr{}, "", errors.New("host and port are required")
	}
	parsedPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil || parsedPort == 0 || strconv.FormatUint(parsedPort, 10) != port {
		return netip.Addr{}, "", errors.New("port must be canonical")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.String() != host {
		return netip.Addr{}, "", errors.New("address must be canonical")
	}
	return ip, port, nil
}

func subscriptionPath(requestPath string) (string, bool) {
	return identity.ParseSubscriptionPath(requestPath)
}

func validProviderID(value string) bool {
	if len(value) == 0 || len(value) > 32 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}

func validEmail(value string) bool {
	parsed, err := mail.ParseAddress(value)
	return err == nil && parsed.Address == value && strings.Contains(value, "@") && !strings.ContainsAny(value, "\r\n")
}

func validResourceID(value string) bool {
	return value != "" && value == path.Base(value) && !strings.ContainsAny(value, "\r\n") && len(value) <= 256
}

func validAccessToken(token string) bool {
	return utf8.ValidString(token) && len(token) >= 16 && len(token) <= 128
}

func redactAccount(account *Account) *Account {
	if account == nil {
		return nil
	}
	clone := *account
	clone.Display = maskAccount(clone.Display)
	return &clone
}

func maskAccount(account string) string {
	if account == "" {
		return ""
	}
	if strings.Contains(account, "•••") {
		return account
	}
	at := strings.IndexByte(account, '@')
	if at > 0 {
		return string([]rune(account[:at])[0]) + "•••" + account[at:]
	}
	runes := []rune(account)
	if len(runes) == 0 {
		return ""
	}
	return string(runes[0]) + "•••"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func problemTitle(status int) string {
	return http.StatusText(status)
}

func writeEmptyNotFound(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", "0")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusNotFound)
}
