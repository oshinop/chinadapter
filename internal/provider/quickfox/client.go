package quickfox

import (
	"context"
	"crypto/md5" // #nosec G501 -- QuickFox's password protocol requires MD5 compatibility.
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kfadapter/kfadapter/internal/provider"
)

var (
	ErrHTTPStatus    = errors.New("quickfox: unexpected HTTP status")
	ErrBusinessCode  = errors.New("quickfox: unexpected business code")
	ErrLoginRejected = errors.New("quickfox: login rejected")
	ErrSchema        = errors.New("quickfox: invalid response schema")
	ErrCrypto        = errors.New("quickfox: invalid encrypted envelope")
	ErrInvalidLine   = errors.New("quickfox: invalid line")
)

type httpStatusError struct{ status int }

func (err *httpStatusError) Error() string {
	return fmt.Sprintf("quickfox: unexpected HTTP status %d", err.status)
}

func (err *httpStatusError) Unwrap() error { return ErrHTTPStatus }

type businessCodeError struct{ code int }

func (err *businessCodeError) Error() string {
	return fmt.Sprintf("%s: %d", ErrBusinessCode, err.code)
}

func (err *businessCodeError) Unwrap() error { return ErrBusinessCode }

// Config configures the fixed-origin QuickFox HTTPS client.
type Config struct {
	Location       *time.Location
	Clock          func() time.Time
	Random         io.Reader
	RequestTimeout time.Duration

	// Test-only seams are unexported so production callers cannot weaken the
	// fixed HTTPS origin or TLS-validating transport.
	httpClient *http.Client
	apiBase    string
}

// Client implements QuickFox's encrypted HTTPS control protocol without
// retaining account credentials or session authority.
// Control response envelopes are limited to 1 MiB, including streamed replies.
type Client struct {
	httpClient     *http.Client
	apiBase        *url.URL
	location       *time.Location
	clock          func() time.Time
	random         io.Reader
	requestTimeout time.Duration
}

func NewClient(config Config) (*Client, error) {
	base := config.apiBase
	if base == "" {
		base = defaultAPIBase
	}
	parsed, err := url.Parse(base)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" {
		return nil, errors.New("quickfox: invalid API origin")
	}
	if config.httpClient == nil && (parsed.Scheme != "https" || parsed.Host != "api.quick-fox.com") {
		return nil, errors.New("quickfox: API origin is fixed")
	}
	if config.httpClient != nil && parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("quickfox: invalid API origin")
	}
	client := config.httpClient
	if client == nil {
		dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
		client = &http.Client{Transport: &http.Transport{
			DialContext: dialer.DialContext, ForceAttemptHTTP2: true, MaxIdleConns: 100,
			IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 10 * time.Second,
			ExpectContinueTimeout: time.Second, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		}}
	}
	if transport, ok := client.Transport.(*http.Transport); ok && transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify {
		return nil, errors.New("quickfox: insecure TLS transport")
	}
	clone := *client
	clone.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	location := config.Location
	if location == nil {
		location = time.FixedZone("Asia/Shanghai", 8*60*60)
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	randomness := config.Random
	if randomness == nil {
		randomness = rand.Reader
	}
	timeout := config.RequestTimeout
	if timeout <= 0 || timeout > 15*time.Second {
		timeout = 15 * time.Second
	}
	return &Client{httpClient: &clone, apiBase: parsed, location: location, clock: clock, random: randomness, requestTimeout: timeout}, nil
}

type loginPayload struct {
	DeleteTokenID any            `json:"delTokenId"`
	Email         string         `json:"email"`
	Password      string         `json:"password"`
	IdentityType  int            `json:"identityType"`
	Platform      string         `json:"platform"`
	DeviceCode    string         `json:"deviceCode"`
	Version       string         `json:"version"`
	OldDeviceCode string         `json:"oldDeviceCode"`
	DeviceInfo    string         `json:"deviceInfo"`
	DeviceToken   string         `json:"deviceToken"`
	WiFiMAC       string         `json:"wifiMac"`
	MAC           string         `json:"mac"`
	SystemVersion string         `json:"systemVersion"`
	VerifyOnline  int            `json:"isVerifyOnline"`
	NetSafeData   map[string]any `json:"netSafeData"`
}

type session struct {
	Token      string
	DeviceCode string
	Profile    accountPayload
}

func (c *Client) Login(ctx context.Context, account, password, installationID string) (session, error) {
	account = strings.TrimSpace(account)
	deviceCode, err := deviceCode(installationID)
	if err != nil || !validControlString(account) || password == "" || len(password) > maxControlFieldSize {
		return session{}, provider.ErrInvalidInput
	}
	digest := md5.Sum([]byte(password)) // #nosec G401 -- required by the observed QuickFox login protocol.
	payload := loginPayload{
		DeleteTokenID: nil, Email: account, Password: hex.EncodeToString(digest[:]), IdentityType: 1,
		Platform: "pc", DeviceCode: deviceCode, Version: clientVersion, OldDeviceCode: "", DeviceInfo: "",
		DeviceToken: "", WiFiMAC: "", MAC: "", SystemVersion: "Windows 11", VerifyOnline: 0,
		NetSafeData: map[string]any{},
	}
	var response loginResponse
	if err := c.do(ctx, http.MethodPost, "/user/login", payload, "", deviceCode, &response); err != nil {
		var rejection *businessCodeError
		if errors.As(err, &rejection) {
			return session{}, fmt.Errorf("%w: %d", ErrLoginRejected, rejection.code)
		}
		return session{}, err
	}
	if !validToken(response.Token) {
		return session{}, ErrSchema
	}
	if _, err := response.account(c.location, c.clock().UTC()); err != nil {
		return session{}, err
	}
	return session{Token: response.Token, DeviceCode: deviceCode, Profile: response.accountPayload}, nil
}

func (c *Client) Profile(ctx context.Context, token, deviceCode string) (accountPayload, error) {
	if !validToken(token) || !validDeviceCode(deviceCode) {
		return accountPayload{}, ErrSchema
	}
	var profile accountPayload
	if err := c.do(ctx, http.MethodGet, "/user/info", nil, token, deviceCode, &profile); err != nil {
		return accountPayload{}, err
	}
	if _, err := profile.account(c.location, c.clock().UTC()); err != nil {
		return accountPayload{}, err
	}
	return profile, nil
}

func (c *Client) Catalog(ctx context.Context, token, deviceCode string) (catalog, error) {
	profile, err := c.Profile(ctx, token, deviceCode)
	if err != nil {
		return catalog{}, err
	}
	var response catalog
	if err := c.do(ctx, http.MethodPost, "/line/socksServerPoolList", map[string]any{"lineTypeId": 2, "type": 1}, token, deviceCode, &response); err != nil {
		return catalog{}, err
	}
	if len(response.Groups) == 0 || len(response.Groups) > maxCatalogGroups || response.Profile.UserID != 0 && response.Profile.UserID != profile.UserID {
		return catalog{}, ErrSchema
	}
	response.Profile = profile
	return response, nil
}
