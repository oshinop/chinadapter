package web

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/oshinop/chinadapter/internal/credentials"
)

const (
	testHost         = "127.0.0.1:10809"
	testOrigin       = "http://127.0.0.1:10809"
	validTestToken   = "access-token-12345"
	invalidTestToken = "invalid-token-123"
)

func testConfig() Config {
	return Config{Listen: testHost}
}

type publicError struct {
	status int
}

func (e publicError) Error() string   { return "public access error" }
func (e publicError) Code() string    { return "access_error" }
func (e publicError) HTTPStatus() int { return e.status }

type fakeBackend struct {
	mu                   sync.Mutex
	accessInitialized    bool
	accessToken          string
	accessSetupCalls     int
	accessLoginCalls     int
	accessSetupStarted   chan<- struct{}
	accessSetupRelease   <-chan struct{}
	nodes                []Node
	nodeDetails          NodeDetails
	nodeDetailsCalls     int
	nodeDetailsID        string
	accountLoginCalls    int
	accountLoginProvider string
	accountLoginStarted  chan<- struct{}
	accountLoginRelease  <-chan struct{}
	logoutCalls          int
	logoutProvider       string
	refreshProvider      string
	events               chan Event
	subscribed           chan struct{}
}

func (f *fakeBackend) AccessStatus(context.Context) (AccessStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return AccessStatus{Initialized: f.accessInitialized}, nil
}

func (f *fakeBackend) AccessSetup(_ context.Context, token string) error {
	f.mu.Lock()
	f.accessSetupCalls++
	started, release := f.accessSetupStarted, f.accessSetupRelease
	f.mu.Unlock()
	if started != nil {
		started <- struct{}{}
	}
	if release != nil {
		<-release
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.accessInitialized {
		return publicError{status: http.StatusConflict}
	}
	f.accessInitialized = true
	f.accessToken = token
	return nil
}

func (f *fakeBackend) AccessLogin(_ context.Context, token string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.accessLoginCalls++
	if !f.accessInitialized || subtle.ConstantTimeCompare([]byte(f.accessToken), []byte(token)) != 1 {
		return publicError{status: http.StatusUnauthorized}
	}
	return nil
}

func (f *fakeBackend) AccessChangeToken(_ context.Context, current, next string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.accessInitialized || subtle.ConstantTimeCompare([]byte(f.accessToken), []byte(current)) != 1 {
		return publicError{status: http.StatusUnauthorized}
	}
	if !validAccessToken(next) || current == next {
		return publicError{status: http.StatusBadRequest}
	}
	f.accessToken = next
	return nil
}

func (f *fakeBackend) Status(context.Context) (Status, error) {
	return Status{State: "ready", Providers: []string{"kuaifan"}, Accounts: map[string]Account{"kuaifan": {Provider: "kuaifan", Display: "person@example.com", Tier: "Standard"}}}, nil
}
func (f *fakeBackend) Nodes(context.Context) ([]Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Node(nil), f.nodes...), nil
}
func (f *fakeBackend) NodeDetails(_ context.Context, id string) (NodeDetails, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nodeDetailsCalls++
	f.nodeDetailsID = id
	return f.nodeDetails, nil
}
func (f *fakeBackend) Login(_ context.Context, input LoginInput) (Account, error) {
	f.mu.Lock()
	f.accountLoginCalls++
	f.accountLoginProvider = input.Provider
	started, release := f.accountLoginStarted, f.accountLoginRelease
	f.mu.Unlock()
	if started != nil {
		started <- struct{}{}
	}
	if release != nil {
		<-release
	}
	if input.Account == "fail@example.com" {
		return Account{}, errors.New("rejected")
	}
	return Account{Provider: input.Provider, Display: input.Account}, nil
}
func (f *fakeBackend) Logout(_ context.Context, provider string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logoutCalls++
	f.logoutProvider = provider
	return nil
}
func (f *fakeBackend) Refresh(_ context.Context, provider string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refreshProvider = provider
	return nil
}
func (f *fakeBackend) Probe(context.Context, string) (ProbeResult, error) {
	return ProbeResult{Health: "healthy", ProbedAt: time.Now().UTC()}, nil
}
func (f *fakeBackend) Diagnostics(context.Context) (any, error) {
	return map[string]any{"safe": "value"}, nil
}
func (f *fakeBackend) Subscribe(context.Context) (<-chan Event, func(), error) {
	f.mu.Lock()
	if f.events == nil {
		f.events = make(chan Event, 1)
	}
	events, subscribed := f.events, f.subscribed
	f.mu.Unlock()
	if subscribed != nil {
		subscribed <- struct{}{}
	}
	return events, func() {}, nil
}

type fakeSubscriptions struct {
	binding  string
	metadata SubscriptionMetadata
	mu       sync.Mutex
	urlCalls int
}

func newFakeSubscriptions() *fakeSubscriptions {
	return &fakeSubscriptions{
		binding:  "07112233-4455-8677-8899-aabbccddeeff",
		metadata: SubscriptionMetadata{Active: true, NodeCount: 1},
	}
}

func (s *fakeSubscriptions) Metadata(context.Context) (SubscriptionMetadata, error) {
	return s.metadata, nil
}
func (s *fakeSubscriptions) SubscriptionURL(_ context.Context, baseURL, _ string) (SubscriptionURL, error) {
	s.mu.Lock()
	s.urlCalls++
	s.mu.Unlock()
	return SubscriptionURL{URL: strings.TrimRight(baseURL, "/") + "/sub/" + s.binding}, nil
}
func (s *fakeSubscriptions) ServeSubscription(w http.ResponseWriter, _ *http.Request, binding, _ string) {
	if binding != s.binding {
		writeEmptyNotFound(w)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("subscription"))
}

func (s *fakeSubscriptions) ParseSubscriptionPath(requestPath string) (string, bool) {
	return credentials.ParseSubscriptionPath(requestPath)
}

func newTestAPI(t *testing.T, backend *fakeBackend, subscriptions *fakeSubscriptions) *API {
	t.Helper()
	api, err := NewAPI(testConfig(), Dependencies{Backend: backend, Subscriptions: subscriptions})
	if err != nil {
		t.Fatal(err)
	}
	return api
}

func TestAPIWildcardAndHostnamePolicy(t *testing.T) {
	const wildcardHost = "0.0.0.0:10809"
	api, err := NewAPI(Config{Listen: wildcardHost, Hostname: "adapter.example.com"}, Dependencies{Backend: &fakeBackend{}})
	if err != nil {
		t.Fatal(err)
	}
	const remoteHost = "192.0.2.10:10809"
	if got, want := api.baseURL(remoteHost), "http://"+remoteHost; got != want {
		t.Fatalf("subscription base URL = %q, want %q", got, want)
	}

	for _, host := range []string{wildcardHost, testHost, remoteHost, "localhost:10809", "LOCALHOST:10809", "adapter.example.com:10809", "ADAPTER.EXAMPLE.COM:10809"} {
		request := httptest.NewRequest(http.MethodGet, "http://"+host+"/healthz", nil)
		request.Host = host
		response := httptest.NewRecorder()
		api.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("Host %q = %d: %s", host, response.Code, response.Body.String())
		}
	}
	for _, host := range []string{"192.0.2.10:10810", "[::1]:10809"} {
		request := httptest.NewRequest(http.MethodGet, "http://"+host+"/healthz", nil)
		request.Host = host
		response := httptest.NewRecorder()
		api.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("invalid Host %q = %d", host, response.Code)
		}
	}

	if got := api.baseURL("LOCALHOST:10809"); got != "http://localhost:10809" {
		t.Fatalf("localhost base URL = %q", got)
	}
	localhostRequest := httptest.NewRequest(http.MethodGet, "http://localhost:10809/", nil)
	if got := api.socksAddress(localhostRequest); got != "localhost:10808" {
		t.Fatalf("localhost SOCKS address = %q", got)
	}
	loopback, err := NewAPI(Config{Listen: testHost}, Dependencies{})
	if err != nil {
		t.Fatal(err)
	}
	loopbackRequest := httptest.NewRequest(http.MethodGet, "http://localhost:10809/healthz", nil)
	loopbackResponse := httptest.NewRecorder()
	loopback.ServeHTTP(loopbackResponse, loopbackRequest)
	if loopbackResponse.Code != http.StatusOK {
		t.Fatalf("loopback listener rejected implicit localhost: %d", loopbackResponse.Code)
	}
	specific, err := NewAPI(Config{Listen: "192.0.2.10:10809"}, Dependencies{})
	if err != nil {
		t.Fatal(err)
	}
	specificRequest := httptest.NewRequest(http.MethodGet, "http://localhost:10809/healthz", nil)
	specificResponse := httptest.NewRecorder()
	specific.ServeHTTP(specificResponse, specificRequest)
	if specificResponse.Code != http.StatusBadRequest {
		t.Fatalf("non-loopback listener accepted implicit localhost: %d", specificResponse.Code)
	}

	setup := func(origin string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "http://"+remoteHost+"/api/v1/access/setup", strings.NewReader(`{"token":"`+validTestToken+`"}`))
		request.Host = remoteHost
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", origin)
		response := httptest.NewRecorder()
		api.ServeHTTP(response, request)
		return response
	}
	if crossOrigin := setup("http://evil.test"); crossOrigin.Code != http.StatusForbidden || !strings.Contains(crossOrigin.Body.String(), `"code":"invalid_origin"`) {
		t.Fatalf("cross-origin setup = %d: %s", crossOrigin.Code, crossOrigin.Body.String())
	}
	if sameHostOrigin := setup("http://" + remoteHost + "/"); sameHostOrigin.Code != http.StatusCreated {
		t.Fatalf("same-host Origin = %d: %s", sameHostOrigin.Code, sameHostOrigin.Body.String())
	}
}

func TestAPIEndpointConfiguration(t *testing.T) {
	for _, listen := range []string{"127.0.0.1:10809", "192.0.2.10:10809", "[2001:db8::1]:10809"} {
		if _, err := NewAPI(Config{Listen: listen}, Dependencies{}); err != nil {
			t.Fatalf("NewAPI(%q): %v", listen, err)
		}
	}
	for _, config := range []Config{
		{Listen: "localhost:10809"},
		{Listen: "127.0.0.1:010809"},
		{Listen: testHost, Hostname: "http://adapter.example.com"},
		{Listen: testHost, Hostname: "adapter.example.com:10809"},
	} {
		if _, err := NewAPI(config, Dependencies{}); err == nil {
			t.Fatalf("NewAPI(%#v) accepted invalid endpoint policy", config)
		}
	}
}

func TestAPIDerivesWildcardSocksAddressFromReachedHost(t *testing.T) {
	api, err := NewAPI(Config{Listen: "0.0.0.0:10809", SocksListen: "0.0.0.0:10808", Hostname: "adapter.example.com"}, Dependencies{})
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"192.0.2.10", "198.51.100.20"} {
		numeric := httptest.NewRequest(http.MethodGet, "http://"+host+":10809/", nil)
		if got := api.socksAddress(numeric); got != host+":10808" {
			t.Fatalf("numeric reached address = %q", got)
		}
	}
	hostname := httptest.NewRequest(http.MethodGet, "http://adapter.example.com:10809/", nil)
	if got := api.socksAddress(hostname); got != "adapter.example.com:10808" {
		t.Fatalf("hostname SOCKS address = %q", got)
	}
	if got := api.baseURL("ADAPTER.EXAMPLE.COM:10809"); got != "http://adapter.example.com:10809" {
		t.Fatalf("hostname base URL = %q", got)
	}
	numeric := httptest.NewRequest(http.MethodGet, "http://192.0.2.10:10809/", nil)
	specific, err := NewAPI(Config{Listen: "0.0.0.0:10809", SocksListen: "192.0.2.20:10808"}, Dependencies{})
	if err != nil {
		t.Fatal(err)
	}
	if got := specific.socksAddress(numeric); got != "192.0.2.20:10808" {
		t.Fatalf("specific SOCKS address = %q", got)
	}
}

func TestAPIAdvertisesHostnameUsedByRequest(t *testing.T) {
	subscriptions := newFakeSubscriptions()
	api, err := NewAPI(Config{Listen: "0.0.0.0:10809", SocksListen: "0.0.0.0:10808", Hostname: "adapter.example.com"}, Dependencies{Backend: &fakeBackend{}, Subscriptions: subscriptions})
	if err != nil {
		t.Fatal(err)
	}
	cookie := establish(t, api)

	statusRequest := httptest.NewRequest(http.MethodGet, "http://adapter.example.com:10809/api/v1/status", nil)
	statusRequest.Host = "adapter.example.com:10809"
	statusRequest.AddCookie(cookie)
	statusResponse := httptest.NewRecorder()
	api.ServeHTTP(statusResponse, statusRequest)
	if statusResponse.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", statusResponse.Code, statusResponse.Body.String())
	}
	var status Status
	if err := json.Unmarshal(statusResponse.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.DataPlane.SocksAddress != "adapter.example.com:10808" {
		t.Fatalf("advertised SOCKS address = %q", status.DataPlane.SocksAddress)
	}

	urlRequest := httptest.NewRequest(http.MethodGet, "http://ADAPTER.EXAMPLE.COM:10809/api/v1/subscription/url", nil)
	urlRequest.Host = "ADAPTER.EXAMPLE.COM:10809"
	urlRequest.AddCookie(cookie)
	urlResponse := httptest.NewRecorder()
	api.ServeHTTP(urlResponse, urlRequest)
	if urlResponse.Code != http.StatusOK {
		t.Fatalf("subscription URL = %d: %s", urlResponse.Code, urlResponse.Body.String())
	}
	var subscriptionURL SubscriptionURL
	if err := json.Unmarshal(urlResponse.Body.Bytes(), &subscriptionURL); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(subscriptionURL.URL, "http://adapter.example.com:10809/sub/") {
		t.Fatalf("advertised subscription URL = %q", subscriptionURL.URL)
	}
}

func TestAPIAdvertisesImplicitLocalhost(t *testing.T) {
	subscriptions := newFakeSubscriptions()
	api, err := NewAPI(Config{Listen: "0.0.0.0:10809", SocksListen: "0.0.0.0:10808"}, Dependencies{Backend: &fakeBackend{}, Subscriptions: subscriptions})
	if err != nil {
		t.Fatal(err)
	}
	cookie := establish(t, api)

	statusRequest := httptest.NewRequest(http.MethodGet, "http://LOCALHOST:10809/api/v1/status", nil)
	statusRequest.Host = "LOCALHOST:10809"
	statusRequest.AddCookie(cookie)
	statusResponse := httptest.NewRecorder()
	api.ServeHTTP(statusResponse, statusRequest)
	if statusResponse.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", statusResponse.Code, statusResponse.Body.String())
	}
	var status Status
	if err := json.Unmarshal(statusResponse.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.DataPlane.SocksAddress != "localhost:10808" {
		t.Fatalf("advertised SOCKS address = %q", status.DataPlane.SocksAddress)
	}

	urlRequest := httptest.NewRequest(http.MethodGet, "http://localhost:10809/api/v1/subscription/url", nil)
	urlRequest.Host = "localhost:10809"
	urlRequest.AddCookie(cookie)
	urlResponse := httptest.NewRecorder()
	api.ServeHTTP(urlResponse, urlRequest)
	if urlResponse.Code != http.StatusOK {
		t.Fatalf("subscription URL = %d: %s", urlResponse.Code, urlResponse.Body.String())
	}
	var subscriptionURL SubscriptionURL
	if err := json.Unmarshal(urlResponse.Body.Bytes(), &subscriptionURL); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(subscriptionURL.URL, "http://localhost:10809/sub/") {
		t.Fatalf("advertised subscription URL = %q", subscriptionURL.URL)
	}
}

func TestAccessSetupLoginStatusAndReload(t *testing.T) {
	backend := &fakeBackend{}
	api := newTestAPI(t, backend, newFakeSubscriptions())

	initial := request(api, http.MethodGet, "/api/v1/access/status", "", nil, "")
	assertAccessStatus(t, initial, false, false)
	if initial.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("access status cache control = %q", initial.Header().Get("Cache-Control"))
	}

	setup := request(api, http.MethodPost, "/api/v1/access/setup", `{"token":"  `+validTestToken+`  "}`, nil, testOrigin)
	if setup.Code != http.StatusCreated {
		t.Fatalf("setup = %d: %s", setup.Code, setup.Body.String())
	}
	cookie := sessionFromResponse(t, setup)
	assertAccessStatus(t, setup, true, true)
	backend.mu.Lock()
	storedToken := backend.accessToken
	backend.mu.Unlock()
	if storedToken != validTestToken {
		t.Fatalf("setup token was not trimmed: %q", storedToken)
	}

	reloaded := request(api, http.MethodGet, "/api/v1/access/status", "", cookie, "")
	assertAccessStatus(t, reloaded, true, true)

	conflict := request(api, http.MethodPost, "/api/v1/access/setup", `{"token":"`+validTestToken+`"}`, nil, testOrigin)
	if conflict.Code != http.StatusConflict || !strings.Contains(conflict.Body.String(), "access_initialized") {
		t.Fatalf("repeated setup = %d: %s", conflict.Code, conflict.Body.String())
	}
	invalid := request(api, http.MethodPost, "/api/v1/access/login", `{"token":"`+invalidTestToken+`"}`, nil, testOrigin)
	if invalid.Code != http.StatusUnauthorized || !strings.Contains(invalid.Body.String(), "invalid_access_token") || strings.Contains(invalid.Body.String(), invalidTestToken) {
		t.Fatalf("invalid login = %d: %s", invalid.Code, invalid.Body.String())
	}
	login := request(api, http.MethodPost, "/api/v1/access/login", `{"token":"`+validTestToken+`"}`, nil, testOrigin)
	if login.Code != http.StatusOK {
		t.Fatalf("access login = %d: %s", login.Code, login.Body.String())
	}
	sessionFromResponse(t, login)
}

func TestAccessTokenValidationBounds(t *testing.T) {
	for _, test := range []struct {
		token string
		valid bool
	}{
		{token: strings.Repeat("a", 16), valid: true},
		{token: strings.Repeat("a", 128), valid: true},
		{token: strings.Repeat("a", 15), valid: false},
		{token: strings.Repeat("a", 129), valid: false},
		{token: string([]byte{0xff}) + strings.Repeat("a", 16), valid: false},
	} {
		if got := validAccessToken(test.token); got != test.valid {
			t.Fatalf("validAccessToken(%q) = %t, want %t", test.token, got, test.valid)
		}
	}
}

func TestAccessSetupFirstClaimIsAtomic(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		backend := &fakeBackend{}
		started := make(chan struct{}, 2)
		release := make(chan struct{})
		backend.accessSetupStarted = started
		backend.accessSetupRelease = release
		api := newTestAPI(t, backend, newFakeSubscriptions())

		responses := make(chan *httptest.ResponseRecorder, 2)
		for _, remote := range []string{"192.0.2.1:10001", "192.0.2.2:10002"} {
			go func(remote string) {
				req := httptest.NewRequest(http.MethodPost, "http://"+testHost+"/api/v1/access/setup", strings.NewReader(`{"token":"`+validTestToken+`"}`))
				req.Host = testHost
				req.RemoteAddr = remote
				req.Header.Set("Origin", testOrigin)
				req.Header.Set("Content-Type", "application/json")
				response := httptest.NewRecorder()
				api.ServeHTTP(response, req)
				responses <- response
			}(remote)
		}
		synctest.Wait()
		for range 2 {
			select {
			case <-started:
			default:
				t.Fatal("concurrent setup did not reach backend")
			}
		}
		close(release)
		synctest.Wait()
		statuses := map[int]int{}
		for range 2 {
			select {
			case response := <-responses:
				statuses[response.Code]++
			default:
				t.Fatal("concurrent setup did not finish")
			}
		}
		if statuses[http.StatusCreated] != 1 || statuses[http.StatusConflict] != 1 {
			t.Fatalf("atomic setup statuses = %#v", statuses)
		}
		backend.mu.Lock()
		calls, initialized := backend.accessSetupCalls, backend.accessInitialized
		backend.mu.Unlock()
		if calls != 2 || !initialized {
			t.Fatalf("first claim backend state calls=%d initialized=%t", calls, initialized)
		}
	})
}

func TestAccessThrottleAndPreSessionChecks(t *testing.T) {
	backend := &fakeBackend{}
	api := newTestAPI(t, backend, newFakeSubscriptions())
	if response := request(api, http.MethodPost, "/api/v1/access/setup", `{"token":"`+validTestToken+`"}`, nil, "http://evil.test"); response.Code != http.StatusForbidden {
		t.Fatalf("cross-origin setup = %d", response.Code)
	}
	nonJSONRequest := httptest.NewRequest(http.MethodPost, "http://"+testHost+"/api/v1/access/login", strings.NewReader(`{"token":"`+validTestToken+`"}`))
	nonJSONRequest.Host = testHost
	nonJSONRequest.Header.Set("Origin", testOrigin)
	nonJSON := httptest.NewRecorder()
	api.ServeHTTP(nonJSON, nonJSONRequest)
	if nonJSON.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("non-JSON login = %d", nonJSON.Code)
	}
	establish(t, api)
	for attempt := range 5 {
		response := request(api, http.MethodPost, "/api/v1/access/login", `{"token":"`+invalidTestToken+`"}`, nil, testOrigin)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("invalid access login %d = %d", attempt, response.Code)
		}
	}
	limited := request(api, http.MethodPost, "/api/v1/access/login", `{"token":"`+invalidTestToken+`"}`, nil, testOrigin)
	if limited.Code != http.StatusTooManyRequests || limited.Header().Get("Retry-After") == "" {
		t.Fatalf("access throttle = %d %#v", limited.Code, limited.Header())
	}
}

func TestAccountLogoutPreservesBrowserAccess(t *testing.T) {
	backend := &fakeBackend{}
	api := newTestAPI(t, backend, newFakeSubscriptions())
	cookie := establish(t, api)

	crossOrigin := rawRequest(api, http.MethodPost, "/api/v1/auth/logout", `{"provider":"kuaifan"}`, cookie, testOrigin, "cross-site")
	if crossOrigin.Code != http.StatusForbidden || !strings.Contains(crossOrigin.Body.String(), `"code":"invalid_origin"`) {
		t.Fatalf("cross-origin account logout = %d: %s", crossOrigin.Code, crossOrigin.Body.String())
	}
	backend.mu.Lock()
	logoutCalls := backend.logoutCalls
	backend.mu.Unlock()
	if logoutCalls != 0 {
		t.Fatalf("cross-origin account logout backend calls = %d", logoutCalls)
	}

	logout := request(api, http.MethodPost, "/api/v1/auth/logout", `{"provider":"kuaifan"}`, cookie, testOrigin)
	if logout.Code != http.StatusNoContent || logout.Header().Get("Cache-Control") != "no-store" || logout.Header().Get("Set-Cookie") != "" {
		t.Fatalf("account logout = %d %#v", logout.Code, logout.Header())
	}
	backend.mu.Lock()
	logoutCalls = backend.logoutCalls
	logoutProvider := backend.logoutProvider
	backend.mu.Unlock()
	if logoutCalls != 1 || logoutProvider != "kuaifan" {
		t.Fatalf("account logout backend = calls:%d provider:%q", logoutCalls, logoutProvider)
	}
	accessStatus := request(api, http.MethodGet, "/api/v1/access/status", "", cookie, "")
	assertAccessStatus(t, accessStatus, true, true)
	status := request(api, http.MethodGet, "/api/v1/status", "", cookie, "")
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"providers":["kuaifan"]`) || !strings.Contains(status.Body.String(), `"accounts":{"kuaifan"`) || !strings.Contains(status.Body.String(), `"tier":"Standard","subscriptionActive":false`) || strings.Contains(status.Body.String(), "person@example.com") || strings.Contains(status.Body.String(), "subscriptionEndsAt") {
		t.Fatalf("provider status after account logout = %d: %s", status.Code, status.Body.String())
	}
}

func TestAuthenticatedMutationsAccountLoginAndAccessLock(t *testing.T) {
	backend := &fakeBackend{}
	api := newTestAPI(t, backend, newFakeSubscriptions())
	cookie := establish(t, api)

	crossOrigin := rawRequest(api, http.MethodPost, "/api/v1/control/refresh", `{"provider":"kuaifan"}`, cookie, testOrigin, "cross-site")
	if crossOrigin.Code != http.StatusForbidden || !strings.Contains(crossOrigin.Body.String(), `"code":"invalid_origin"`) {
		t.Fatalf("cross-origin mutation = %d: %s", crossOrigin.Code, crossOrigin.Body.String())
	}
	refreshed := request(api, http.MethodPost, "/api/v1/control/refresh", `{"provider":"kuaifan"}`, cookie, testOrigin)
	if refreshed.Code != http.StatusAccepted {
		t.Fatalf("refresh = %d: %s", refreshed.Code, refreshed.Body.String())
	}
	accountLogin := request(api, http.MethodPost, "/api/v1/auth/login", `{"provider":"kuaifan","account":"person@example.com","password":"password"}`, cookie, testOrigin)
	if accountLogin.Code != http.StatusOK || strings.Contains(accountLogin.Body.String(), "person@example.com") {
		t.Fatalf("account login = %d: %s", accountLogin.Code, accountLogin.Body.String())
	}
	backend.mu.Lock()
	loginProvider, refreshProvider := backend.accountLoginProvider, backend.refreshProvider
	backend.mu.Unlock()
	if loginProvider != "kuaifan" || refreshProvider != "kuaifan" {
		t.Fatalf("provider-keyed mutations routed login=%q refresh=%q", loginProvider, refreshProvider)
	}
	otherLogin := request(api, http.MethodPost, "/api/v1/access/login", `{"token":"`+validTestToken+`"}`, nil, testOrigin)
	if otherLogin.Code != http.StatusOK {
		t.Fatalf("second access login = %d: %s", otherLogin.Code, otherLogin.Body.String())
	}
	otherCookie := sessionFromResponse(t, otherLogin)
	lock := request(api, http.MethodPost, "/api/v1/access/logout", `{}`, cookie, testOrigin)
	if lock.Code != http.StatusNoContent || lock.Header().Get("Cache-Control") != "no-store" || !strings.Contains(lock.Header().Get("Set-Cookie"), "Max-Age=0") {
		t.Fatalf("access lock = %d %#v", lock.Code, lock.Header())
	}
	backend.mu.Lock()
	logoutCalls := backend.logoutCalls
	backend.mu.Unlock()
	if logoutCalls != 0 {
		t.Fatalf("access lock invoked provider logout %d times", logoutCalls)
	}
	if response := request(api, http.MethodGet, "/api/v1/status", "", cookie, ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("revoked status = %d", response.Code)
	}
	if response := request(api, http.MethodGet, "/api/v1/status", "", otherCookie, ""); response.Code != http.StatusOK {
		t.Fatalf("other session status = %d", response.Code)
	}
	legacy := request(api, http.MethodDelete, "/api/v1/auth/session", "", nil, "")
	if legacy.Code != http.StatusNotFound || legacy.Body.Len() != 0 || legacy.Header().Get("Content-Length") != "0" {
		t.Fatalf("removed legacy auth-session route = %d %#v %q", legacy.Code, legacy.Header(), legacy.Body.String())
	}
}

func TestAccessLockCompletesDuringProviderLogin(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started := make(chan struct{}, 1)
		release := make(chan struct{})
		backend := &fakeBackend{accountLoginStarted: started, accountLoginRelease: release}
		api := newTestAPI(t, backend, newFakeSubscriptions())
		cookie := establish(t, api)

		loginResponses := make(chan *httptest.ResponseRecorder, 1)
		go func() {
			loginResponses <- request(api, http.MethodPost, "/api/v1/auth/login", `{"provider":"kuaifan","account":"person@example.com","password":"password"}`, cookie, testOrigin)
		}()
		synctest.Wait()
		select {
		case <-started:
		default:
			t.Fatal("provider login did not reach the backend")
		}

		logoutResponses := make(chan *httptest.ResponseRecorder, 1)
		go func() {
			logoutResponses <- request(api, http.MethodPost, "/api/v1/access/logout", `{}`, cookie, testOrigin)
		}()
		synctest.Wait()
		select {
		case logout := <-logoutResponses:
			if logout.Code != http.StatusNoContent || !strings.Contains(logout.Header().Get("Set-Cookie"), "Max-Age=0") {
				t.Fatalf("access lock = %d %#v", logout.Code, logout.Header())
			}
		default:
			t.Fatal("access lock waited for provider login")
		}
		if response := request(api, http.MethodGet, "/api/v1/status", "", cookie, ""); response.Code != http.StatusUnauthorized {
			t.Fatalf("revoked session status = %d", response.Code)
		}
		select {
		case response := <-loginResponses:
			t.Fatalf("provider login completed before release: %d", response.Code)
		default:
		}
		close(release)
		synctest.Wait()
		select {
		case response := <-loginResponses:
			if response.Code != http.StatusOK {
				t.Fatalf("provider login = %d: %s", response.Code, response.Body.String())
			}
		default:
			t.Fatal("provider login did not complete after release")
		}
		backend.mu.Lock()
		calls := backend.accountLoginCalls
		backend.mu.Unlock()
		if calls != 1 {
			t.Fatalf("provider login calls = %d", calls)
		}
	})
}

func TestNodeDetailsRequiresAuthenticationAndUsesExactRoute(t *testing.T) {
	const nodeID = "node-alpha"
	backend := &fakeBackend{nodeDetails: NodeDetails{ID: nodeID}}
	api := newTestAPI(t, backend, newFakeSubscriptions())

	unauthenticated := request(api, http.MethodGet, "/api/v1/nodes/"+nodeID+"/details", "", nil, "")
	if unauthenticated.Code != http.StatusUnauthorized || unauthenticated.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unauthenticated node details = %d %#v", unauthenticated.Code, unauthenticated.Header())
	}
	backend.mu.Lock()
	detailCalls := backend.nodeDetailsCalls
	backend.mu.Unlock()
	if detailCalls != 0 {
		t.Fatalf("unauthenticated node details backend calls = %d", detailCalls)
	}

	cookie := establish(t, api)
	wrongMethod := request(api, http.MethodPost, "/api/v1/nodes/"+nodeID+"/details", `{}`, cookie, testOrigin)
	if wrongMethod.Code != http.StatusMethodNotAllowed || wrongMethod.Header().Get("Allow") != "GET, HEAD" || wrongMethod.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("node details wrong method = %d %#v", wrongMethod.Code, wrongMethod.Header())
	}
	badPath := request(api, http.MethodGet, "/api/v1/nodes//details", "", cookie, "")
	if badPath.Code != http.StatusNotFound || badPath.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("node details bad path = %d %#v", badPath.Code, badPath.Header())
	}

	response := request(api, http.MethodGet, "/api/v1/nodes/"+nodeID+"/details", "", cookie, "")
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("node details = %d %#v", response.Code, response.Header())
	}
	backend.mu.Lock()
	detailCalls, detailID := backend.nodeDetailsCalls, backend.nodeDetailsID
	backend.mu.Unlock()
	if detailCalls != 1 || detailID != nodeID {
		t.Fatalf("node details backend dispatch calls=%d id=%q", detailCalls, detailID)
	}
}

func TestNodesOmitLegacyEndpointAndExcludedFields(t *testing.T) {
	expected := Node{
		ID: "node-alpha", Name: "Alpha", Group: "Core", Provider: "WIFIIN", Health: "healthy",
		TCPLatencyMS: 17, UDPHealth: "healthy", Eligible: true,
	}
	backend := &fakeBackend{nodes: []Node{expected}}
	api := newTestAPI(t, backend, newFakeSubscriptions())
	cookie := establish(t, api)

	response := request(api, http.MethodGet, "/api/v1/nodes", "", cookie, "")
	if response.Code != http.StatusOK {
		t.Fatalf("nodes = %d: %s", response.Code, response.Body.String())
	}
	var payload struct {
		Nodes []Node `json:"nodes"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Nodes) != 1 || payload.Nodes[0] != expected {
		t.Fatalf("nodes response = %#v", payload.Nodes)
	}
	var raw struct {
		Nodes []map[string]json.RawMessage `json:"nodes"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw.Nodes) != 1 {
		t.Fatalf("raw nodes response = %#v", raw.Nodes)
	}
	for _, field := range []string{"endpoint", "excluded", "activeConnections"} {
		if _, present := raw.Nodes[0][field]; present {
			t.Fatalf("routine node exposed removed %s field: %s", field, response.Body.String())
		}
	}
}

func TestNodeDetailsReturnsOnlyLocalCredentials(t *testing.T) {
	expected := NodeDetails{
		ID: "node-alpha", Name: "Alpha", Group: "Core", Provider: "WIFIIN",
		UpstreamHost: "upstream.example.test", UpstreamPort: 443,
		SocksAddress: "127.0.0.1:10808", SocksUsername: "local-selector", SocksPassword: "local-password",
		Health: "healthy", TCPLatencyMS: 17,
	}
	backend := &fakeBackend{nodeDetails: expected}
	api := newTestAPI(t, backend, newFakeSubscriptions())
	cookie := establish(t, api)

	response := request(api, http.MethodGet, "/api/v1/nodes/"+expected.ID+"/details", "", cookie, "")
	if response.Code != http.StatusOK {
		t.Fatalf("node details = %d: %s", response.Code, response.Body.String())
	}
	var details NodeDetails
	if err := json.Unmarshal(response.Body.Bytes(), &details); err != nil {
		t.Fatal(err)
	}
	if details != expected {
		t.Fatalf("node details response = %#v", details)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) != 11 {
		t.Fatalf("node details response fields = %#v", raw)
	}
	for _, field := range []string{"loginToken", "providerToken", "tunnelPassword", "tunnelMethod", "providerExtension", "selector", "endpoint", "excluded", "activeConnections"} {
		if _, present := raw[field]; present {
			t.Fatalf("node details exposed provider field %s: %s", field, response.Body.String())
		}
	}
}

func TestStatusUsesReachedLANAddress(t *testing.T) {
	api, err := NewAPI(Config{Listen: "0.0.0.0:10809", SocksListen: "0.0.0.0:10808"}, Dependencies{Backend: &fakeBackend{}, Subscriptions: newFakeSubscriptions()})
	if err != nil {
		t.Fatal(err)
	}
	cookie := establish(t, api)
	statusRequest := httptest.NewRequest(http.MethodGet, "http://192.0.2.10:10809/api/v1/status", nil)
	statusRequest.Host = "192.0.2.10:10809"
	statusRequest.AddCookie(cookie)
	response := httptest.NewRecorder()
	api.ServeHTTP(response, statusRequest)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	var raw struct {
		DataPlane map[string]json.RawMessage `json:"dataPlane"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	var socksAddress string
	if err := json.Unmarshal(raw.DataPlane["socksAddress"], &socksAddress); err != nil || socksAddress != "192.0.2.10:10808" {
		t.Fatalf("status SOCKS address = %q, %v", socksAddress, err)
	}
	for _, field := range []string{"activeTcp", "activeUdpAssociations"} {
		if _, present := raw.DataPlane[field]; present {
			t.Fatalf("status exposed removed %s field: %s", field, response.Body.String())
		}
	}
}

func TestStableSubscriptionURLAndRemovedRoutes(t *testing.T) {
	backend := &fakeBackend{}
	subscriptions := newFakeSubscriptions()
	api := newTestAPI(t, backend, subscriptions)
	cookie := establish(t, api)

	first := request(api, http.MethodGet, "/api/v1/subscription/url", "", cookie, "")
	second := request(api, http.MethodGet, "/api/v1/subscription/url", "", cookie, "")
	if first.Code != http.StatusOK || second.Code != http.StatusOK || first.Body.String() != second.Body.String() {
		t.Fatalf("stable URL responses = %d/%d %q/%q", first.Code, second.Code, first.Body.String(), second.Body.String())
	}
	var result SubscriptionURL
	if err := json.NewDecoder(first.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	expected := testOrigin + "/sub/" + subscriptions.binding
	if result.URL != expected {
		t.Fatalf("stable URL = %#v", result)
	}
	metadata := request(api, http.MethodGet, "/api/v1/subscription", "", cookie, "")
	status := request(api, http.MethodGet, "/api/v1/status", "", cookie, "")
	if strings.Contains(metadata.Body.String(), result.URL) || strings.Contains(status.Body.String(), result.URL) {
		t.Fatalf("ordinary endpoint exposed subscription URL: metadata=%s status=%s", metadata.Body.String(), status.Body.String())
	}
	for _, legacy := range []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/v1/local-session"},
		{http.MethodPost, "/api/v1/subscription/reveal"},
		{http.MethodPost, "/api/v1/subscription/rotation"},
		{http.MethodPost, "/api/v1/subscription/rotation/old/commit"},
		{http.MethodGet, "/api/v1/settings"},
		{http.MethodPut, "/api/v1/settings"},
		{http.MethodPut, "/api/v1/nodes/node-alpha/preference"},
	} {
		response := request(api, legacy.method, legacy.path, `{}`, nil, testOrigin)
		if response.Code != http.StatusNotFound {
			t.Fatalf("legacy route %s %s = %d", legacy.method, legacy.path, response.Code)
		}
	}
	for _, route := range []string{
		"/sub",
		"/sub/short",
		"/sub/" + strings.Repeat("A", 42),
		"/sub/" + strings.Repeat("!", 43),
		"/sub/" + subscriptions.binding + "/subscription",
		"/sub/" + subscriptions.binding + "/",
		"/sub/" + subscriptions.binding + "/other",
	} {
		response := request(api, http.MethodGet, route, "", nil, "")
		if response.Code != http.StatusNotFound || response.Body.Len() != 0 || response.Header().Get("Content-Length") != "0" || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("invalid subscription route %s = %d %#v %q", route, response.Code, response.Header(), response.Body.String())
		}
	}
	served := request(api, http.MethodGet, "/sub/"+subscriptions.binding, "", nil, "")
	if served.Code != http.StatusOK || served.Body.String() != "subscription" {
		t.Fatalf("stable external subscription = %d %q", served.Code, served.Body.String())
	}
}

// Wait makes preceding writes visible, but advancing time does not order a
// body read before the next heartbeat write. Protect both sides of the recorder.
type sseRecorder struct {
	*httptest.ResponseRecorder
	mu sync.Mutex
}

func (r *sseRecorder) Write(body []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ResponseRecorder.Write(body)
}

func (r *sseRecorder) WriteString(body string) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ResponseRecorder.WriteString(body)
}

func (r *sseRecorder) body() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.Body.String()
}

func TestSSESurvivesAccessMigration(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		backend := &fakeBackend{events: make(chan Event), subscribed: make(chan struct{}, 1)}
		api := newTestAPI(t, backend, newFakeSubscriptions())
		cookie := establish(t, api)
		context, cancel := context.WithCancel(context.Background())
		defer cancel()
		req := httptest.NewRequest(http.MethodGet, "http://"+testHost+"/api/v1/events", nil).WithContext(context)
		req.Host = testHost
		req.Header.Set("Origin", testOrigin)
		req.AddCookie(cookie)
		response := &sseRecorder{ResponseRecorder: httptest.NewRecorder()}
		done := make(chan struct{})
		go func() {
			api.ServeHTTP(response, req)
			close(done)
		}()
		synctest.Wait()
		select {
		case <-backend.subscribed:
		default:
			t.Fatal("SSE did not subscribe")
		}
		backend.events <- Event{Type: "state", Data: map[string]any{"state": "ready"}}
		synctest.Wait()
		time.Sleep(api.config.SSEHeartbeat - time.Nanosecond)
		synctest.Wait()
		if strings.Contains(response.body(), ": keepalive") {
			t.Fatal("SSE heartbeat sent before its interval")
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		if got := strings.Count(response.body(), ": keepalive\n\n"); got != 1 {
			t.Fatalf("SSE heartbeat count = %d, want 1", got)
		}
		cancel()
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Fatal("SSE did not close after cancellation")
		}
		if !strings.Contains(response.body(), "event: state") {
			t.Fatalf("SSE payload = %q", response.body())
		}
	})
}

func TestAPIMutationsRejectCrossOrigin(t *testing.T) {
	api := newTestAPI(t, &fakeBackend{}, newFakeSubscriptions())
	cookie := establish(t, api)
	for _, route := range api.routes() {
		if route.method != http.MethodPost {
			continue
		}
		path := strings.ReplaceAll(route.path, "{id}", "node-alpha")
		for _, test := range []struct {
			name, origin, fetchSite string
		}{
			{name: "fetch-site", origin: testOrigin, fetchSite: "cross-site"},
			{name: "origin", origin: "http://evil.test"},
		} {
			t.Run(path+"/"+test.name, func(t *testing.T) {
				response := rawRequest(api, route.method, path, `{}`, cookie, test.origin, test.fetchSite)
				if response.Code != http.StatusForbidden || !strings.HasPrefix(response.Header().Get("Content-Type"), "application/problem+json") || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Content-Type-Options") != "nosniff" {
					t.Fatalf("cross-origin rejection = %d %#v", response.Code, response.Header())
				}
				var problem struct {
					Code   string `json:"code"`
					Status int    `json:"status"`
					Title  string `json:"title"`
				}
				if err := json.NewDecoder(response.Body).Decode(&problem); err != nil {
					t.Fatal(err)
				}
				if problem.Code != "invalid_origin" || problem.Status != http.StatusForbidden || problem.Title != "Invalid Origin" {
					t.Fatalf("cross-origin problem = %#v", problem)
				}
			})
		}
	}
}

func TestAPIMutationCrossOriginProtection(t *testing.T) {
	api := newTestAPI(t, &fakeBackend{}, newFakeSubscriptions())
	cookie := establish(t, api)
	for _, test := range []struct {
		name, origin, fetchSite string
		want                    int
	}{
		{name: "same-origin-fetch-site", fetchSite: "same-origin", want: http.StatusAccepted},
		{name: "same-origin-origin", origin: testOrigin, want: http.StatusAccepted},
		{name: "non-browser", want: http.StatusAccepted},
		{name: "cross-site", origin: testOrigin, fetchSite: "cross-site", want: http.StatusForbidden},
		{name: "same-site", origin: testOrigin, fetchSite: "same-site", want: http.StatusForbidden},
		{name: "mismatched-origin", origin: "http://evil.test", want: http.StatusForbidden},
		{name: "mismatched-port", origin: "http://127.0.0.1:10810", want: http.StatusForbidden},
		{name: "null-origin", origin: "null", want: http.StatusForbidden},
		{name: "cross-origin-scheme-fetch-site", origin: "https://" + testHost, fetchSite: "cross-site", want: http.StatusForbidden},
		{name: "same-host-scheme-fallback", origin: "https://" + testHost, want: http.StatusAccepted},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := rawRequest(api, http.MethodPost, "/api/v1/control/refresh", `{"provider":"kuaifan"}`, cookie, test.origin, test.fetchSite)
			if response.Code != test.want {
				t.Fatalf("mutation = %d: %s", response.Code, response.Body.String())
			}
			if test.want == http.StatusForbidden && !strings.Contains(response.Body.String(), `"code":"invalid_origin"`) {
				t.Fatalf("cross-origin problem = %s", response.Body.String())
			}
		})
	}
	if response := request(api, http.MethodPost, "/api/v1/control/refresh", `{"provider":"kuaifan"}`, nil, ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("non-browser without session = %d", response.Code)
	}
	if response := request(api, http.MethodPost, "/api/v1/control/refresh", "", cookie, ""); response.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("non-browser without JSON content type = %d", response.Code)
	}
}

func TestSSERequiresExactOriginEvenWithSameOriginFetchSite(t *testing.T) {
	api := newTestAPI(t, &fakeBackend{}, newFakeSubscriptions())
	cookie := establish(t, api)
	for _, origin := range []string{"", "http://evil.test", testOrigin + "/", "https://" + testHost} {
		response := rawRequest(api, http.MethodGet, "/api/v1/events", "", cookie, origin, "same-origin")
		if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), `"code":"invalid_origin"`) {
			t.Fatalf("SSE Origin %q = %d: %s", origin, response.Code, response.Body.String())
		}
	}
	if response := rawRequest(api, http.MethodGet, "/api/v1/status", "", cookie, "http://evil.test", "cross-site"); response.Code != http.StatusOK {
		t.Fatalf("safe status = %d: %s", response.Code, response.Body.String())
	}
}

func establish(t *testing.T, api *API) *http.Cookie {
	t.Helper()
	response := request(api, http.MethodPost, "/api/v1/access/setup", `{"token":"`+validTestToken+`"}`, nil, testOrigin)
	if response.Code != http.StatusCreated {
		t.Fatalf("setup = %d: %s", response.Code, response.Body.String())
	}
	return sessionFromResponse(t, response)
}

func sessionFromResponse(t *testing.T, response *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie = %#v", cookies)
	}
	assertAccessStatus(t, response, true, true)
	return cookies[0]
}

func assertAccessStatus(t *testing.T, response *httptest.ResponseRecorder, initialized, authenticated bool) {
	t.Helper()
	if response.Code != http.StatusOK && response.Code != http.StatusCreated {
		t.Fatalf("access status response = %d: %s", response.Code, response.Body.String())
	}
	var body struct {
		Initialized   bool       `json:"initialized"`
		Authenticated bool       `json:"authenticated"`
		ExpiresAt     *time.Time `json:"expiresAt"`
	}
	decoder := json.NewDecoder(bytes.NewReader(response.Body.Bytes()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Initialized != initialized || body.Authenticated != authenticated || (body.ExpiresAt != nil) != authenticated {
		t.Fatalf("access status = %#v", body)
	}
}

func request(api *API, method, route, body string, cookie *http.Cookie, origin string) *httptest.ResponseRecorder {
	return rawRequest(api, method, route, body, cookie, origin, "")
}

func rawRequest(api *API, method, route, body string, cookie *http.Cookie, origin, fetchSite string) *httptest.ResponseRecorder {
	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	} else {
		reader = strings.NewReader("")
	}
	req := httptest.NewRequest(method, "http://"+testHost+route, reader)
	req.Host = testHost
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if fetchSite != "" {
		req.Header.Set("Sec-Fetch-Site", fetchSite)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	api.ServeHTTP(response, req)
	return response
}
