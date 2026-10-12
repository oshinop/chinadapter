package kuaifan

import (
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const (
	defaultAPIHost = "ws.kuaifan.co"
	defaultAPIBase = "https://" + defaultAPIHost

	maxControlFieldBytes     = 4096
	maxResponseFields        = 128
	maxAuthorityAuthKeyBytes = 8192
	maxGroups                = 512
	maxLines                 = 4096
	maxGroupIDBytes          = 128
	maxLineMetadataBytes     = 256
	maxGroupObjectFields     = 16
	maxLineObjectFields      = 32
	maxLocalizedNameEntries  = 8
	maxLocalizedNameFields   = 4
	maxLocaleBytes           = 32
	maxUnixMilli             = int64(253402300799999)
)

var (
	ErrUnapprovedAPIBase = errors.New("control: API base is not approved HTTPS")
	ErrInsecureTLS       = errors.New("control: insecure TLS transport")
	ErrHTTPStatus        = errors.New("control: unexpected HTTP status")
	ErrBusinessStatus    = errors.New("control: unexpected business status")
	ErrLoginRejected     = errors.New("control: login rejected")
	ErrSchema            = errors.New("control: response schema is invalid")
	ErrUnsupportedCipher = errors.New("control: unsupported authority cipher")
	ErrInvalidLine       = errors.New("control: invalid line")
)

// Config configures a HTTPS-only control-plane client. AllowedAPIHosts is an
// administrator-controlled hostname allowlist. An empty list permits only the
// documented bootstrap host.
type Config struct {
	AllowedAPIHosts []string
	BootstrapBase   string
	Language        string
	Location        *time.Location
	Clock           func() time.Time
	Random          io.Reader
	RequestTimeout  time.Duration

	// httpClient is available only to same-package behavioral tests. Production
	// callers always receive a dedicated TLS-validating client.
	httpClient *http.Client
}

// Client sends encrypted requests and validates every response according to
// one immutable provider profile. It contains no account, token, or authority
// state.
type Client struct {
	profile        providerProfile
	httpClient     *http.Client
	allowedHosts   map[string]struct{}
	bootstrapBase  *url.URL
	language       string
	location       *time.Location
	clock          func() time.Time
	random         io.Reader
	requestTimeout time.Duration
	normalCodec    Codec
	authorityCodec Codec
}

// lockedReader permits concurrent authority and line requests to share an
// injected entropy source safely. crypto/rand.Reader is safe already, but
// callers may supply a deterministic fixture reader.
type lockedReader struct {
	mu     sync.Mutex
	reader io.Reader
}

func (r *lockedReader) Read(data []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reader.Read(data)
}

// NewIOSClient creates an iOS control-profile client.
func NewIOSClient(cfg Config) (*Client, error) { return newClient(cfg, iosClientProfile{}) }

// NewWindowsClient creates a Windows control-profile client.
func NewWindowsClient(cfg Config) (*Client, error) { return newClient(cfg, windowsClientProfile{}) }

func newClient(cfg Config, profile providerProfile) (*Client, error) {
	allowed, err := normalizedAllowlist(cfg.AllowedAPIHosts)
	if err != nil {
		return nil, err
	}
	bootstrap := cfg.BootstrapBase
	if bootstrap == "" {
		bootstrap = defaultAPIBase
	}
	base, err := parseApprovedBase(bootstrap, allowed)
	if err != nil {
		return nil, err
	}
	client := cfg.httpClient
	if client == nil {
		client = hardenedHTTPClient()
	}
	if transport, ok := client.Transport.(*http.Transport); ok && transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify {
		return nil, ErrInsecureTLS
	}
	// Redirects would otherwise let a valid approved initial URL cross the
	// HTTPS/allowlist boundary. A copy avoids changing a caller-owned client.
	clone := *client
	clone.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	language := cfg.Language
	if language == "" {
		language = "zh-CN"
	}
	location := cfg.Location
	if location == nil {
		location = time.FixedZone("Asia/Shanghai", 8*60*60)
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	randomness := cfg.Random
	if randomness == nil {
		randomness = rand.Reader
	}
	randomness = &lockedReader{reader: randomness}
	deadline := cfg.RequestTimeout
	if deadline <= 0 || deadline > 15*time.Second {
		deadline = 15 * time.Second
	}
	return &Client{
		profile:        profile,
		httpClient:     &clone,
		allowedHosts:   allowed,
		bootstrapBase:  base,
		language:       language,
		location:       location,
		clock:          clock,
		random:         randomness,
		requestTimeout: deadline,
		normalCodec:    NormalCodec(),
		authorityCodec: AuthorityCodec(),
	}, nil
}
