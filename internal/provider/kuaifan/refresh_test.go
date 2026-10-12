package kuaifan

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/kfadapter/kfadapter/internal/provider"
	wireprofile "github.com/kfadapter/kfadapter/internal/provider/kuaifan/profile"
)

func TestDriverLoginAggregatesProfilesAndRoutesOpaqueAuthorities(t *testing.T) {
	const (
		iosVIP     = int64(1790000000000)
		windowsVIP = iosVIP - 1000
	)
	iosAuthority := encodedAuthority(t, "1", "ios-tunnel", "ios-order")
	windowsAuthority := encodedAuthority(t, "1", wireprofile.WindowsTunnelPassword, "windows-order")
	var mu sync.Mutex
	calls := make(map[string]int)
	iosClient, windowsClient := testControlClients(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		windows := request.Header.Get("User-Agent") == wireprofile.WindowsUserAgent
		mu.Lock()
		calls[request.URL.Path]++
		mu.Unlock()
		switch request.URL.Path {
		case "/v4/client/conf.do":
			return encryptedHTTPResponse(t, envelope(map[string]any{"domain": map[string]any{"ws": "api.example"}})), nil
		case "/v4/user/login.do":
			token, vipEnd := "ios-login", iosVIP
			if windows {
				token, vipEnd = "windows-login", windowsVIP
			}
			return encryptedHTTPResponse(t, map[string]any{"status": 119, "msg": "", "fields": map[string]any{"token": token, "userId": 1, "isVip": true, "vipEndTime": vipEnd}}), nil
		case "/v4/user/refresh.do":
			token, vipEnd := "ios-login", iosVIP
			if windows {
				token, vipEnd = "windows-login", windowsVIP
			}
			return encryptedHTTPResponse(t, envelope(map[string]any{"token": token, "userId": 1, "isVip": true, "vipEndTime": vipEnd})), nil
		case "/v4/invpn/getAuthority.do":
			authKey, token, order := iosAuthority, "ios-provider", "ios-order"
			if windows {
				authKey, token, order = windowsAuthority, "windows-provider", "windows-order"
			}
			return encryptedHTTPResponse(t, envelope(map[string]any{"authKey": string(authKey), "token": token, "cpOrderNo": order})), nil
		case "/v4/invpn/getLines.do":
			host := "ios-only.example"
			if windows {
				host = "windows-only.example"
			}
			return encryptedHTTPResponse(t, envelope(map[string]any{
				"groups": []any{map[string]any{"id": "g", "name": "group"}},
				"lines": []any{
					map[string]any{"host": "common.example", "port": 11000, "provider": "WIFIIN", "password": wireprofile.WindowsTunnelPassword, "groupId": "g"},
					map[string]any{"host": host, "port": 11000, "provider": "WIFIIN", "password": wireprofile.WindowsTunnelPassword, "groupId": "g"},
				},
			})), nil
		default:
			return nil, errors.New("unexpected route")
		}
	}))
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)
	driver, err := NewDriver(DriverConfig{IOSClient: iosClient, WindowsClient: windowsClient, Clock: func() time.Time { return now }, MaxAttempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := driver.Login(context.Background(), provider.Credentials{
		Account: "alice@example.test", Password: "password", InstallationID: "00112233445566778899aabbccddeeff",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.Valid() || snapshot.Provider != ProviderID || snapshot.Account.Display != "a•••@example.test" ||
		snapshot.Account.Tier != vipTier || !snapshot.Account.SubscriptionActive || snapshot.Account.SubscriptionEndsAt.UnixMilli() != windowsVIP || !snapshot.ExpiresAt.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("aggregate snapshot = %#v", snapshot)
	}
	profiles := make(map[string]string, len(snapshot.Nodes))
	for _, node := range snapshot.Nodes {
		profiles[node.Host] = node.AuthorityID
		if node.Protocol != WIFIINProtocol {
			t.Fatalf("node protocol = %q", node.Protocol)
		}
	}
	if !reflect.DeepEqual(profiles, map[string]string{"common.example": "ios", "ios-only.example": "ios", "windows-only.example": "windows"}) {
		t.Fatalf("profile routing = %#v", profiles)
	}
	iosTunnel, err := decodeTunnelAuthority(snapshot.Authorities["ios"].Data)
	if err != nil {
		t.Fatal(err)
	}
	windowsTunnel, err := decodeTunnelAuthority(snapshot.Authorities["windows"].Data)
	if err != nil {
		t.Fatal(err)
	}
	if iosTunnel.Password != "ios-tunnel" || windowsTunnel.Password != wireprofile.WindowsTunnelPassword || iosTunnel.Extension == windowsTunnel.Extension {
		t.Fatalf("opaque profile authorities = %#v / %#v", iosTunnel, windowsTunnel)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls["/v4/client/conf.do"] != 2 || calls["/v4/user/login.do"] != 2 || calls["/v4/user/refresh.do"] != 1 || calls["/v4/invpn/getAuthority.do"] != 2 || calls["/v4/invpn/getLines.do"] != 2 {
		t.Fatalf("request calls = %#v", calls)
	}
}

func TestDriverRefreshReturnsCompleteReplacementWithoutMutatingCurrent(t *testing.T) {
	current := provider.Snapshot{
		Provider:     ProviderID,
		Account:      provider.Account{UserID: "1", Display: "a•••@example.test", Tier: vipTier, SubscriptionActive: true, SubscriptionEndsAt: time.UnixMilli(1784661133000)},
		ExpiresAt:    time.Now().Add(time.Hour),
		RefreshState: []byte(`{"ios":{"userId":1,"token":"ios-old"},"windows":{"userId":1,"token":"windows-old"}}`),
		Authorities:  map[string]provider.Authority{"ios": {Protocol: WIFIINProtocol, Data: []byte(`{"password":"old","method":"aes-256-cfb","extension":"|old|package|order|1|MAC|1"}`)}},
		Nodes:        []provider.Node{{ID: "old", AuthorityID: "ios", Protocol: WIFIINProtocol, Host: "old.example", Port: 11000, Eligible: true}},
	}
	before := current.Clone()
	authKey := encodedAuthority(t, "1", "new-tunnel", "new-order")
	iosClient, windowsClient := testControlClients(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/v4/client/conf.do":
			return encryptedHTTPResponse(t, envelope(map[string]any{})), nil
		case "/v4/user/refresh.do":
			return encryptedHTTPResponse(t, envelope(validRefreshFields("new-login"))), nil
		case "/v4/invpn/getAuthority.do":
			return encryptedHTTPResponse(t, envelope(map[string]any{"authKey": string(authKey), "token": "new-provider", "cpOrderNo": "new-order"})), nil
		case "/v4/invpn/getLines.do":
			return encryptedHTTPResponse(t, envelope(validLineFields("new.example", "group"))), nil
		default:
			return nil, errors.New("unexpected route")
		}
	}))
	driver, err := NewDriver(DriverConfig{IOSClient: iosClient, WindowsClient: windowsClient, MaxAttempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	next, err := driver.Refresh(context.Background(), current)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(current, before) {
		t.Fatalf("Refresh mutated caller snapshot: before=%#v after=%#v", before, current)
	}
	if !next.Valid() || len(next.Nodes) != 1 || next.Nodes[0].Host != "new.example" || next.Account.Display != current.Account.Display {
		t.Fatalf("replacement snapshot = %#v", next)
	}
	stored, err := decodeDriverState(next.RefreshState)
	if err != nil || stored.IOS.Token != "new-login" || stored.Windows.Token != "new-login" {
		t.Fatalf("replacement refresh state = %#v, %v", stored, err)
	}
}

func TestDriverRejectedLoginIsNotRetried(t *testing.T) {
	var mu sync.Mutex
	calls := make(map[string]int)
	iosClient, windowsClient := testControlClients(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		mu.Lock()
		calls[request.URL.Path]++
		mu.Unlock()
		switch request.URL.Path {
		case "/v4/client/conf.do":
			return encryptedHTTPResponse(t, envelope(map[string]any{})), nil
		case "/v4/user/login.do":
			return encryptedHTTPResponse(t, map[string]any{"status": 401, "msg": "rejected", "fields": map[string]any{}}), nil
		default:
			return nil, errors.New("login rejection fetched provider state")
		}
	}))
	driver, err := NewDriver(DriverConfig{IOSClient: iosClient, WindowsClient: windowsClient, MaxAttempts: 5})
	if err != nil {
		t.Fatal(err)
	}
	_, err = driver.Login(context.Background(), provider.Credentials{Account: "a@example.test", Password: "secret", InstallationID: "00112233445566778899aabbccddeeff"})
	if !errors.Is(err, provider.ErrLoginRejected) {
		t.Fatalf("Login error = %v, want provider.ErrLoginRejected", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls["/v4/user/login.do"] != 2 || calls["/v4/client/conf.do"] != 2 {
		t.Fatalf("rejected login retried: %#v", calls)
	}
}

func TestAggregateProviderAccountMapsInactiveAccessToStandard(t *testing.T) {
	now := time.Date(2026, 7, 22, 6, 0, 0, 0, time.UTC)
	profiles := [2]completeProfile{
		{session: LoginSession{UserID: 1, Profile: AccountProfile{IsVIP: true, VIPEndsAt: now.Add(time.Hour)}}},
		{session: LoginSession{UserID: 1, Profile: AccountProfile{IsVIP: false}}},
	}
	account, err := aggregateProviderAccount("a•••@example.test", profiles, now)
	if err != nil {
		t.Fatal(err)
	}
	if account.Tier != standardTier || account.SubscriptionActive || !account.SubscriptionEndsAt.IsZero() {
		t.Fatalf("standard account = %#v", account)
	}
}

func TestNodesFromLinesUsesCanonicalIdentityAndProfileAuthority(t *testing.T) {
	groups := []Group{{ID: "group", Name: "group"}}
	left, err := nodesFromLines(Lines{Groups: groups, Lines: []Line{{Host: "Node.Example.", Port: 11000, Provider: "wifiin", GroupID: "group", Eligible: true}}}, wireprofile.IOSID)
	if err != nil {
		t.Fatal(err)
	}
	right, err := nodesFromLines(Lines{Groups: groups, Lines: []Line{{Host: "node.example", Port: 11000, Provider: "WIFIIN", GroupID: "group", Eligible: true}}}, wireprofile.IOSID)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 1 || len(right) != 1 || left[0].ID != right[0].ID || left[0].Host != "node.example" || left[0].AuthorityID != "ios" || left[0].Protocol != WIFIINProtocol {
		t.Fatalf("canonical nodes = %#v / %#v", left, right)
	}
}

func TestNodesFromLinesDropsTransportIneligibleLines(t *testing.T) {
	nodes, err := nodesFromLines(Lines{
		Groups: []Group{{ID: "group", Name: "group"}},
		Lines: []Line{
			{Host: "eligible.example", Port: 11000, Provider: "wifiin", GroupID: "group", Eligible: true},
			{Host: "unsupported.example", Port: 11000, Provider: "other", GroupID: "group", Eligible: false},
		},
	}, wireprofile.IOSID)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].Host != "eligible.example" {
		t.Fatalf("eligible nodes = %#v", nodes)
	}
}

func TestNodesFromLinesDeduplicatesSharedEndpointAcrossLabels(t *testing.T) {
	nodes, err := nodesFromLines(Lines{
		Groups: []Group{{ID: "video", Name: "Video"}, {ID: "direct", Name: "Direct"}},
		Lines: []Line{
			{Host: "shared.example", Port: 11000, Provider: "WIFIIN", GroupID: "video", Eligible: true},
			{Host: "shared.example", Port: 11000, Provider: "WIFIIN", GroupID: "direct", Eligible: true},
		},
	}, wireprofile.WindowsID)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].AuthorityID != "windows" {
		t.Fatalf("shared endpoint nodes = %#v", nodes)
	}
}

func TestRetryDoesNotRetryInvalidResponseEnvelopes(t *testing.T) {
	trailing, err := NormalCodec().Encode([]byte(`{"status":1,"msg":"","fields":{}} {}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		response  func() *http.Response
		wantCause error
	}{
		{name: "malformed", response: func() *http.Response {
			return &http.Response{StatusCode: http.StatusOK, Body: ioNopString("not-base64"), Header: make(http.Header)}
		}, wantCause: ErrMalformedCiphertext},
		{name: "trailing JSON", response: func() *http.Response {
			return &http.Response{StatusCode: http.StatusOK, ContentLength: int64(len(trailing)), Body: io.NopCloser(bytes.NewReader(trailing)), Header: make(http.Header)}
		}, wantCause: ErrTrailingJSON},
		{name: "wrong status type", response: func() *http.Response {
			return encryptedHTTPResponse(t, map[string]any{"status": "1", "msg": "", "fields": map[string]any{}})
		}},
		{name: "wrong fields type", response: func() *http.Response {
			return encryptedHTTPResponse(t, map[string]any{"status": 1, "msg": "", "fields": "not-an-object"})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			client := testControlClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return test.response(), nil
			}))
			driver := retryTestDriver(client)
			_, err := retry(context.Background(), driver, func() (ClientConfig, error) {
				return client.FetchClientConfig(context.Background())
			})
			if !errors.Is(err, ErrInvalidEnvelope) || test.wantCause != nil && !errors.Is(err, test.wantCause) {
				t.Fatalf("retry error = %v", err)
			}
			if calls != 1 {
				t.Fatalf("invalid response attempts = %d, want 1", calls)
			}
		})
	}
}

func TestRetryRetriesOnlyRetryableHTTPStatuses(t *testing.T) {
	for _, test := range []struct {
		status   int
		attempts int
	}{
		{status: http.StatusUnauthorized, attempts: 1},
		{status: http.StatusForbidden, attempts: 1},
		{status: http.StatusNotFound, attempts: 1},
		{status: http.StatusRequestTimeout, attempts: 3},
		{status: http.StatusTooManyRequests, attempts: 3},
		{status: http.StatusInternalServerError, attempts: 3},
	} {
		t.Run(http.StatusText(test.status), func(t *testing.T) {
			calls := 0
			client := testControlClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: test.status, Body: ioNopString(""), Header: make(http.Header)}, nil
			}))
			_, err := retry(context.Background(), retryTestDriver(client), func() (ClientConfig, error) {
				return client.FetchClientConfig(context.Background())
			})
			var status *httpStatusError
			if !errors.Is(err, ErrHTTPStatus) || !errors.As(err, &status) || status.status != test.status || calls != test.attempts {
				t.Fatalf("status %d error = %v after %d calls, want %d", test.status, err, calls, test.attempts)
			}
		})
	}
}

func TestRetryStopsWhenContextIsCancelled(t *testing.T) {
	client := testControlClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("network is not used")
	}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	_, err := retry(ctx, retryTestDriver(client), func() (struct{}, error) {
		calls++
		cancel()
		return struct{}{}, temporaryTransportError{}
	})
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("cancelled retry = %v after %d calls", err, calls)
	}
}

func TestRetryRetriesTemporaryTransportFailures(t *testing.T) {
	client := testControlClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("network is not used")
	}))
	calls := 0
	_, err := retry(context.Background(), retryTestDriver(client), func() (struct{}, error) {
		calls++
		return struct{}{}, temporaryTransportError{}
	})
	var typed temporaryTransportError
	if !errors.As(err, &typed) || calls != 3 {
		t.Fatalf("temporary retry = %v after %d calls", err, calls)
	}
}

func TestRetryBackoffJitterAndCap(t *testing.T) {
	driver := &Driver{backoff: 250 * time.Millisecond, maxBackoff: 5 * time.Second}
	bases := []time.Duration{250 * time.Millisecond, 500 * time.Millisecond, time.Second, 2 * time.Second, 4 * time.Second, 5 * time.Second}
	for range 100 {
		policy := newRetryBackOff(driver)
		for attempt := range 100 {
			base := bases[min(attempt, len(bases)-1)]
			delay := policy.NextBackOff()
			minimum, maximum := base/2, min(base+base/2, driver.maxBackoff)
			if delay < minimum || delay > maximum {
				t.Fatalf("retry delay %d = %s outside [%s, %s]", attempt+1, delay, minimum, maximum)
			}
		}
		policy.Reset()
		if delay := policy.NextBackOff(); delay < 125*time.Millisecond || delay > 375*time.Millisecond {
			t.Fatalf("reset delay = %s, want initial interval jitter", delay)
		}
	}
}

func TestRetryPreservesFinalResultAndError(t *testing.T) {
	for _, attempts := range []int{1, 3, 5} {
		for _, failure := range []error{ErrSchema, temporaryTransportError{}} {
			driver := &Driver{attempts: attempts, backoff: time.Millisecond, maxBackoff: time.Millisecond}
			calls := 0
			value, err := retry(t.Context(), driver, func() (int, error) {
				calls++
				return 42, failure
			})
			wantCalls := attempts
			if !retryable(failure) {
				wantCalls = 1
			}
			if value != 42 || !errors.Is(err, failure) || reflect.TypeOf(err) != reflect.TypeOf(failure) || calls != wantCalls {
				t.Fatalf("retry with %d attempts and %v = %d, %v after %d calls, want original result/error after %d", attempts, failure, value, err, calls, wantCalls)
			}
		}
	}
}

func TestRetryCancelledParentMakesNoRequest(t *testing.T) {
	ctx, cancel := context.WithCancelCause(t.Context())
	cancel(errors.New("parent stopped"))
	calls := 0
	value, err := retry(ctx, &Driver{attempts: 3, backoff: time.Millisecond, maxBackoff: time.Millisecond}, func() (int, error) {
		calls++
		return 42, nil
	})
	if value != 0 || !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatalf("cancelled parent = %d, %v after %d calls", value, err, calls)
	}
}

type temporaryTransportError struct{}

func (temporaryTransportError) Error() string   { return "temporary transport failure" }
func (temporaryTransportError) Timeout() bool   { return true }
func (temporaryTransportError) Temporary() bool { return true }

func retryTestDriver(client *Client) *Driver {
	return &Driver{clients: [2]*Client{client, client}, attempts: 3, backoff: time.Millisecond, maxBackoff: time.Millisecond}
}

func encodedAuthority(t *testing.T, userID, password, orderID string) []byte {
	t.Helper()
	authKey, err := AuthorityCodec().EncodeJSON(map[string]any{
		"userId": userID, "encryptKey": password, "encryptType": "aes-256-cfb", "orderId": orderID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return authKey
}

func testControlClient(t *testing.T, transport http.RoundTripper) *Client {
	t.Helper()
	client, err := NewIOSClient(testControlConfig(transport))
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func testControlClients(t *testing.T, transport http.RoundTripper) (*Client, *Client) {
	t.Helper()
	iosClient, err := NewIOSClient(testControlConfig(transport))
	if err != nil {
		t.Fatal(err)
	}
	windowsClient, err := NewWindowsClient(testControlConfig(transport))
	if err != nil {
		t.Fatal(err)
	}
	return iosClient, windowsClient
}

func testControlConfig(transport http.RoundTripper) Config {
	return Config{
		httpClient: &http.Client{Transport: transport}, BootstrapBase: "https://bootstrap.example",
		AllowedAPIHosts: []string{"bootstrap.example", "api.example"}, Random: bytes.NewReader(bytes.Repeat([]byte{0}, 256)),
	}
}

func envelope(fields map[string]any) map[string]any {
	return map[string]any{"status": 1, "msg": "", "fields": fields}
}

func validRefreshFields(token string) map[string]any {
	return map[string]any{"userId": 1, "token": token, "isVip": true, "vipEndTime": int64(1784661133000)}
}

func validLineFields(host, groupID string) map[string]any {
	return map[string]any{
		"groups": []any{map[string]any{"id": groupID, "name": "group"}},
		"lines":  []any{map[string]any{"text": "line", "host": host, "port": 11000, "provider": "WIFIIN", "password": wireprofile.WindowsTunnelPassword, "groupId": groupID}},
	}
}

func ioNopString(value string) io.ReadCloser { return io.NopCloser(bytes.NewBufferString(value)) }
