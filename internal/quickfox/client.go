package quickfox

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5" // #nosec G501 -- QuickFox's password protocol requires MD5 compatibility.
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultAPIBase      = "https://api.quick-fox.com"
	clientVersion       = "3.59.6"
	platformType        = "2"
	requestKey          = "6PNkQ8aleI5MNgj6"
	responseKey         = "5bj6PNkQ8aleI5MN"
	apiIV               = "PNkQ8aleI5MNgj6r"
	maxRequestBytes     = 64 << 10
	maxResponseBytes    = 16 << 20
	maxControlFieldSize = 4096
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
		return session{}, ErrLoginRejected
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
		if errors.Is(err, ErrBusinessCode) {
			return session{}, ErrLoginRejected
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

type catalog struct {
	Profile accountPayload `json:"userInfo"`
	Groups  []lineGroup    `json:"lineList"`
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

type envelope struct {
	Code    *int            `json:"code"`
	Data    json.RawMessage `json:"data"`
	Success *bool           `json:"success"`
}

func (c *Client) do(ctx context.Context, method, path string, payload any, token, deviceCode string, target any) error {
	if c == nil || ctx == nil || !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#") || !validDeviceCode(deviceCode) {
		return ErrSchema
	}
	var body io.Reader
	if method != http.MethodGet {
		plaintext, err := json.Marshal(payload)
		if err != nil || len(plaintext) > maxRequestBytes {
			return ErrSchema
		}
		ciphertext, err := encryptCBC(plaintext, []byte(requestKey))
		if err != nil {
			return err
		}
		encoded, err := json.Marshal(struct {
			Data string `json:"data"`
		}{Data: base64.StdEncoding.EncodeToString(ciphertext)})
		if err != nil {
			return ErrSchema
		}
		body = bytes.NewReader(encoded)
	}
	requestContext, cancel := context.WithTimeout(ctx, c.requestTimeout)
	defer cancel()
	endpoint := *c.apiBase
	endpoint.Path = path
	request, err := http.NewRequestWithContext(requestContext, method, endpoint.String(), body)
	if err != nil {
		return ErrSchema
	}
	nonce := make([]byte, 16)
	if _, err := io.ReadFull(c.random, nonce); err != nil {
		return fmt.Errorf("quickfox: request nonce: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("version", clientVersion)
	request.Header.Set("platformType", platformType)
	request.Header.Set("nonce", hex.EncodeToString(nonce))
	request.Header.Set("proxyChannel", "")
	request.Header.Set("channel", "official")
	request.Header.Set("lang", "zh_CN")
	request.Header.Set("deviceCode", deviceCode)
	if token != "" {
		request.Header.Set("token", token)
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("quickfox: control request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return &httpStatusError{status: response.StatusCode}
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("quickfox: read response: %w", err)
	}
	if len(encoded) == 0 || len(encoded) > maxResponseBytes {
		return ErrSchema
	}
	var wrapped envelope
	if json.Unmarshal(encoded, &wrapped) != nil || wrapped.Code == nil || wrapped.Success == nil || len(wrapped.Data) == 0 {
		return ErrSchema
	}
	if *wrapped.Code != http.StatusOK || !*wrapped.Success {
		return ErrBusinessCode
	}
	decoded, err := decodeData(wrapped.Data)
	if err != nil {
		return err
	}
	if len(decoded) == 0 || len(decoded) > maxResponseBytes || json.Unmarshal(decoded, target) != nil {
		return ErrSchema
	}
	return nil
}

func decodeData(raw json.RawMessage) ([]byte, error) {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil, ErrSchema
	}
	if raw[0] != '"' {
		return append([]byte(nil), raw...), nil
	}
	var encoded string
	if json.Unmarshal(raw, &encoded) != nil || encoded == "" {
		return nil, ErrSchema
	}
	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(ciphertext) > maxResponseBytes {
		return nil, ErrCrypto
	}
	for _, key := range []string{responseKey, requestKey} {
		plaintext, decryptErr := decryptCBC(ciphertext, []byte(key))
		if decryptErr == nil && json.Valid(plaintext) {
			return plaintext, nil
		}
	}
	return nil, ErrCrypto
}

func encryptCBC(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrCrypto
	}
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	padded := make([]byte, len(plaintext)+padding)
	copy(padded, plaintext)
	for index := len(plaintext); index < len(padded); index++ {
		padded[index] = byte(padding)
	}
	cipher.NewCBCEncrypter(block, []byte(apiIV)).CryptBlocks(padded, padded)
	return padded, nil
}

func decryptCBC(ciphertext, key []byte) ([]byte, error) {
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, ErrCrypto
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrCrypto
	}
	plaintext := append([]byte(nil), ciphertext...)
	cipher.NewCBCDecrypter(block, []byte(apiIV)).CryptBlocks(plaintext, plaintext)
	padding := int(plaintext[len(plaintext)-1])
	if padding == 0 || padding > aes.BlockSize || padding > len(plaintext) {
		return nil, ErrCrypto
	}
	for _, value := range plaintext[len(plaintext)-padding:] {
		if int(value) != padding {
			return nil, ErrCrypto
		}
	}
	return plaintext[:len(plaintext)-padding], nil
}

func validControlString(value string) bool {
	return value != "" && len(value) <= maxControlFieldSize && strings.IndexByte(value, 0) < 0
}
