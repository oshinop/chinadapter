// Package web provides the loopback browser control plane. It intentionally
// depends only on consumer-owned interfaces so app can wire control, state,
// SOCKS, and subscription implementations without an import cycle.
package web

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"sync"
	"time"

	adapterconfig "github.com/oshinop/chinadapter/internal/config"
)

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

// BrowserSessionPersistence stores only hashed browser-session identities and
// expiry. It never receives provider credentials or local access tokens.
type BrowserSessionPersistence interface {
	RestoreBrowserSessions(context.Context, time.Time, int, func(tokenHash []byte, expiresAt time.Time) error) error
	SaveBrowserSession(context.Context, string, time.Time, int) error
	DeleteBrowserSession(context.Context, []byte) error
	DeleteAllBrowserSessions(context.Context) error
}

// Dependencies are injected by app. Backend implementations normally adapt
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
	ParseSubscriptionPath(string) (string, bool)
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
	ProviderAuth map[string]AuthSpec  `json:"providerAuth"`
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

// AuthSpec lists the credential fields a provider needs to be added. An empty
// Fields list marks a public service added without credentials.
type AuthSpec struct {
	Fields []AuthField `json:"fields"`
}

// AuthField is one credential input the console renders for a provider.
type AuthField struct {
	Key    string `json:"key"`
	Label  string `json:"label"`
	Secret bool   `json:"secret"`
}

// LoginInput carries provider credential field values transiently to the
// runtime. Its keys are the provider's AuthSpec field keys.
type LoginInput struct {
	Provider string
	Fields   map[string]string
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
	Protocol     string `json:"protocol"`
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
		if err := adapterconfig.ValidateHostname(config.Hostname); err != nil {
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
