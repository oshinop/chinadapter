package transocks

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/oshinop/chinadapter/internal/provider"
)

const maxControlBytes = 1 << 20

var (
	ErrHTTPStatus    = errors.New("transocks: unexpected HTTP status")
	ErrBusinessCode  = errors.New("transocks: unexpected business code")
	ErrLoginRejected = errors.New("transocks: login rejected")
	ErrSchema        = errors.New("transocks: invalid response schema")
)

var defaultAPIOrigins = [...]string{
	"https://abscf2.fobwifi.com",
	"https://b.kolavpn.xyz",
	"https://b.kolavpn.win",
	"https://b.transmoon.xyz",
}

type businessCodeError struct{ code int }

func (err *businessCodeError) Error() string { return fmt.Sprintf("%s: %d", ErrBusinessCode, err.code) }
func (err *businessCodeError) Unwrap() error { return ErrBusinessCode }

// Config configures the TLS-validating control-plane client. Production origins
// are fixed; the unexported HTTP seams are only for package fixtures.
type Config struct {
	RequestTimeout time.Duration
	httpClient     *http.Client
	apiBases       []string
}

// Client sends bounded HTTPS/JSON requests and retains no account or token.
// Network failures and HTTP 5xx responses fail over to the next official origin;
// application errors do not repeat mutating connect or login calls.
type Client struct {
	httpClient     *http.Client
	apiBases       []*url.URL
	requestTimeout time.Duration
	origin         atomic.Uint32
	sessions       *SessionManager
}

func NewClient(config Config) (*Client, error) {
	origins := config.apiBases
	if len(origins) == 0 {
		origins = defaultAPIOrigins[:]
	}
	if len(origins) > len(defaultAPIOrigins) {
		return nil, errors.New("transocks: too many API origins")
	}
	bases := make([]*url.URL, 0, len(origins))
	for _, origin := range origins {
		base, err := url.Parse(origin)
		if err != nil || base.Host == "" || base.User != nil || base.Path != "" || base.RawQuery != "" || base.Fragment != "" ||
			(base.Scheme != "https" && (config.httpClient == nil || base.Scheme != "http")) {
			return nil, errors.New("transocks: invalid API origin")
		}
		if config.httpClient == nil {
			allowed := false
			for _, official := range defaultAPIOrigins {
				allowed = allowed || origin == official
			}
			if !allowed {
				return nil, errors.New("transocks: API origins are fixed")
			}
		}
		bases = append(bases, base)
	}
	client := config.httpClient
	if client == nil {
		dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
		client = &http.Client{Transport: &http.Transport{
			DialContext: dialer.DialContext, ForceAttemptHTTP2: true, MaxIdleConns: 16,
			IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 10 * time.Second,
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		}}
	}
	if transport, ok := client.Transport.(*http.Transport); ok && transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify {
		return nil, errors.New("transocks: insecure TLS transport")
	}
	clone := *client
	clone.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	timeout := config.RequestTimeout
	if timeout <= 0 || timeout > 30*time.Second {
		timeout = 15 * time.Second
	}
	result := &Client{httpClient: &clone, apiBases: bases, requestTimeout: timeout}
	result.sessions = NewSessionManager(result)
	return result, nil
}

type installationMetadata struct {
	Device      string `json:"device"`
	MAC         string `json:"mac"`
	UUID        string `json:"uuid"`
	Language    string `json:"langue"`
	PackageName string `json:"package_name"`
	AppVersion  string `json:"app_version"`
	Org         string `json:"org"`
	Channel     string `json:"channel"`
	WidthHeight string `json:"width_height"`
	Realname    bool   `json:"realname"`
	Model       string `json:"model"`
}

// These are synthetic installation identities, not hardware identifiers. The
// namespace keeps the two observed identity fields independent and stable.
func metadataFor(installationID string) (installationMetadata, error) {
	installationID = strings.TrimSpace(installationID)
	if !validControlField(installationID) {
		return installationMetadata{}, provider.ErrInvalidInput
	}
	mac := sha256.Sum256([]byte("chinadapter/transocks/mac\x00" + installationID))
	uuid := sha256.Sum256([]byte("chinadapter/transocks/uuid\x00" + installationID))
	hexMAC := hex.EncodeToString(mac[:16])
	return installationMetadata{
		Device: "Android", MAC: hexMAC[:8] + "-" + hexMAC[8:12] + "-" + hexMAC[12:16] + "-" + hexMAC[16:20] + "-" + hexMAC[20:],
		UUID: hex.EncodeToString(uuid[:16]), Language: "zh", PackageName: "com.fobwifi.transocks", AppVersion: "4.0.3",
		Org: "transocks_mix", Channel: "official", WidthHeight: "1080x1920", Realname: true, Model: "chinadapter",
	}, nil
}

func (metadata installationMetadata) valid() bool {
	if metadata.Device != "Android" || metadata.Language != "zh" || metadata.PackageName != "com.fobwifi.transocks" ||
		metadata.AppVersion != "4.0.3" || metadata.Org != "transocks_mix" || metadata.Channel != "official" ||
		metadata.WidthHeight != "1080x1920" || !metadata.Realname || metadata.Model != "chinadapter" || len(metadata.MAC) != 36 || len(metadata.UUID) != 32 {
		return false
	}
	if metadata.MAC[8] != '-' || metadata.MAC[13] != '-' || metadata.MAC[18] != '-' || metadata.MAC[23] != '-' {
		return false
	}
	_, macErr := hex.DecodeString(strings.ReplaceAll(metadata.MAC, "-", ""))
	_, uuidErr := hex.DecodeString(metadata.UUID)
	return macErr == nil && uuidErr == nil
}

func (metadata installationMetadata) query() url.Values {
	return url.Values{
		"device": {metadata.Device}, "mac": {metadata.MAC}, "uuid": {metadata.UUID}, "langue": {metadata.Language},
		"package_name": {metadata.PackageName}, "app_version": {metadata.AppVersion}, "org": {metadata.Org},
		"channel": {metadata.Channel}, "width_height": {metadata.WidthHeight}, "realname": {strconv.FormatBool(metadata.Realname)}, "model": {metadata.Model},
	}
}

type storedSession struct {
	Token     string                      `json:"token"`
	TokenType string                      `json:"token_type"`
	Metadata  installationMetadata        `json:"metadata"`
	Protocols map[int64]provider.Protocol `json:"protocols,omitempty"`
}

func (stored storedSession) valid() bool {
	return validHeaderValue(stored.Token) && validHeaderValue(stored.TokenType) && stored.Metadata.valid()
}

func validControlField(value string) bool {
	return value != "" && len(value) <= maxAuthorityField && utf8.ValidString(value) && strings.IndexByte(value, 0) < 0
}

func validHeaderValue(value string) bool {
	if !validControlField(value) {
		return false
	}
	for _, character := range value {
		if character <= ' ' || character >= 127 {
			return false
		}
	}
	return true
}

type loginResponse struct {
	accountPayload
	Token struct {
		AccessToken string `json:"access_token"`
		Type        string `json:"token_type"`
		Expiry      int64  `json:"exp"`
	} `json:"token"`
}

type loginPayload struct {
	installationMetadata
	AuthBy   string `json:"auth_by"`
	AuthType string `json:"auth_type"`
	Email    string `json:"email,omitempty"`
	Phone    string `json:"phone,omitempty"`
	CC       string `json:"cc,omitempty"`
	Password string `json:"password"`
	Autokick int    `json:"autokick"`
}

func loginPayloadFor(account, password string, metadata installationMetadata) (loginPayload, error) {
	payload := loginPayload{installationMetadata: metadata, AuthBy: "email", AuthType: "jwt", Password: password}
	if strings.Contains(account, "@") {
		payload.Email = account
		return payload, nil
	}
	cc, phone, err := splitPhone(account)
	if err != nil {
		return loginPayload{}, err
	}
	payload.AuthBy, payload.CC, payload.Phone = "mobile", cc, phone
	return payload, nil
}

func splitPhone(account string) (string, string, error) {
	digits := strings.TrimPrefix(account, "+")
	if len(digits) < 5 || len(digits) > 15 {
		return "", "", provider.ErrInvalidInput
	}
	for _, digit := range digits {
		if digit < '0' || digit > '9' {
			return "", "", provider.ErrInvalidInput
		}
	}
	if account[0] != '+' {
		if len(digits) == 11 && digits[0] == '1' {
			return "+86", digits, nil
		}
		return "", "", provider.ErrInvalidInput
	}
	for length := 1; length <= 3; length++ {
		code := digits[:length]
		if knownCallingCode(code) && len(digits)-length >= 4 {
			return "+" + code, digits[length:], nil
		}
	}
	return "", "", provider.ErrInvalidInput
}

// E.164 country calling codes are prefix-free. Split only assigned country
// codes, not a guessed fixed length; the app sends cc with its leading '+'.
func knownCallingCode(code string) bool {
	switch code {
	case "1", "7", "20", "27", "30", "31", "32", "33", "34", "36", "39", "40", "41", "43", "44", "45", "46", "47", "48", "49", "51", "52", "53", "54", "55", "56", "57", "58", "60", "61", "62", "63", "64", "65", "66", "81", "82", "84", "86", "90", "91", "92", "93", "94", "95", "98",
		"211", "212", "213", "216", "218", "220", "221", "222", "223", "224", "225", "226", "227", "228", "229", "230", "231", "232", "233", "234", "235", "236", "237", "238", "239", "240", "241", "242", "243", "244", "245", "246", "247", "248", "249", "250", "251", "252", "253", "254", "255", "256", "257", "258", "260", "261", "262", "263", "264", "265", "266", "267", "268", "269", "290", "291", "297", "298", "299",
		"350", "351", "352", "353", "354", "355", "356", "357", "358", "359", "370", "371", "372", "373", "374", "375", "376", "377", "378", "379", "380", "381", "382", "383", "385", "386", "387", "389", "420", "421", "423",
		"500", "501", "502", "503", "504", "505", "506", "507", "508", "509", "590", "591", "592", "593", "594", "595", "596", "597", "598", "599", "670", "672", "673", "674", "675", "676", "677", "678", "679", "680", "681", "682", "683", "685", "686", "687", "688", "689", "690", "691", "692",
		"850", "852", "853", "855", "856", "880", "886", "960", "961", "962", "963", "964", "965", "966", "967", "968", "970", "971", "972", "973", "974", "975", "976", "977", "992", "993", "994", "995", "996", "998":
		return true
	default:
		return false
	}
}

func (client *Client) Login(ctx context.Context, account, password, installationID string) (storedSession, loginResponse, error) {
	metadata, err := metadataFor(installationID)
	account = strings.TrimSpace(account)
	if err != nil || !validControlField(account) || !validControlField(password) {
		return storedSession{}, loginResponse{}, provider.ErrInvalidInput
	}
	payload, err := loginPayloadFor(account, password, metadata)
	if err != nil {
		return storedSession{}, loginResponse{}, err
	}
	var response loginResponse
	if err := client.do(ctx, http.MethodPost, "/api/1/login", nil, payload, storedSession{}, &response); err != nil {
		return storedSession{}, loginResponse{}, err
	}
	if response.Token.Type == "" {
		response.Token.Type = "Bearer"
	}
	stored := storedSession{Token: response.Token.AccessToken, TokenType: response.Token.Type, Metadata: metadata}
	if !stored.valid() || response.UserID <= 0 {
		return storedSession{}, loginResponse{}, ErrSchema
	}
	return stored, response, nil
}

func (client *Client) MiscInfo(ctx context.Context, stored storedSession) (accountPayload, error) {
	var response accountPayload
	if !stored.valid() {
		return response, ErrSchema
	}
	err := client.do(ctx, http.MethodGet, "/api/1/user/misc-info", stored.Metadata.query(), nil, stored, &response)
	return response, err
}

func (client *Client) Catalog(ctx context.Context, stored storedSession) (catalog, error) {
	var response catalog
	if !stored.valid() {
		return response, ErrSchema
	}
	query := stored.Metadata.query()
	query.Set("requestAll", "true")
	if err := client.do(ctx, http.MethodGet, "/api/2/line", query, nil, stored, &response); err != nil {
		return catalog{}, err
	}
	if err := response.validate(); err != nil {
		return catalog{}, err
	}
	return response, nil
}

type connectRequest struct {
	installationMetadata
	Proto          string   `json:"proto"`
	Methods        []string `json:"methods"`
	AvailableProto []string `json:"available_proto"`
	LineCount      int      `json:"lineCount,omitempty"`
}

func (client *Client) Connect(ctx context.Context, stored storedSession, lineID int64) (connectResponse, error) {
	if !stored.valid() || lineID <= 0 {
		return connectResponse{}, ErrSchema
	}
	request := connectRequest{installationMetadata: stored.Metadata, Proto: "SS", Methods: []string{"chacha20-ietf-poly1305"}, AvailableProto: []string{"SS", "Trojan"}}
	var response connectResponse
	err := client.do(ctx, http.MethodPost, "/api/2/line/connect/"+strconv.FormatInt(lineID, 10), nil, request, stored, &response)
	return response, err
}

func (client *Client) do(ctx context.Context, method, path string, query url.Values, payload any, stored storedSession, result any) error {
	var body []byte
	if payload != nil {
		var err error
		body, err = json.Marshal(payload)
		if err != nil || len(body) > maxControlBytes {
			return ErrSchema
		}
	}
	start := int(client.origin.Load()) % len(client.apiBases)
	var last error
	for attempt := range len(client.apiBases) {
		index := (start + attempt) % len(client.apiBases)
		endpoint := *client.apiBases[index]
		endpoint.Path, endpoint.RawQuery = path, query.Encode()
		attemptCtx, cancel := context.WithTimeout(ctx, client.requestTimeout)
		request, err := http.NewRequestWithContext(attemptCtx, method, endpoint.String(), bytes.NewReader(body))
		if err != nil {
			cancel()
			return ErrSchema
		}
		request.Header.Set("Accept", "application/json")
		if payload != nil {
			request.Header.Set("Content-Type", "application/json")
		}
		if stored.Token != "" {
			request.Header.Set("Authorization", stored.TokenType+" "+stored.Token)
		}
		response, err := client.httpClient.Do(request)
		if err != nil {
			cancel()
			var urlErr *url.Error
			if errors.As(err, &urlErr) {
				err = urlErr.Err
			}
			last = fmt.Errorf("transocks: control request: %w", err)
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, maxControlBytes+1))
		response.Body.Close()
		cancel()
		if readErr != nil {
			last = fmt.Errorf("transocks: control response: %w", readErr)
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue
		}
		if len(data) > maxControlBytes {
			return ErrSchema
		}
		var envelope struct {
			Code *int `json:"code"`
		}
		jsonErr := json.Unmarshal(data, &envelope)
		if jsonErr == nil && envelope.Code != nil && *envelope.Code != 0 {
			switch *envelope.Code {
			case 20001, 40015:
				return fmt.Errorf("%w: code %d", provider.ErrSessionRejected, *envelope.Code)
			case 40001:
				if path == "/api/1/login" {
					return fmt.Errorf("%w: code %d", ErrLoginRejected, *envelope.Code)
				}
			case 40003:
				// "Out of devices": login uses autokick=0 and never evicts the
				// user's other sessions.
				if path == "/api/1/login" {
					return fmt.Errorf("%w: code %d", provider.ErrDeviceLimit, *envelope.Code)
				}
			}
			return &businessCodeError{code: *envelope.Code}
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			last = fmt.Errorf("%w: %d", ErrHTTPStatus, response.StatusCode)
			if response.StatusCode >= 500 {
				continue
			}
			return last
		}
		if jsonErr != nil || envelope.Code == nil || json.Unmarshal(data, result) != nil {
			return ErrSchema
		}
		client.origin.Store(uint32(index))
		return nil
	}
	return last
}
