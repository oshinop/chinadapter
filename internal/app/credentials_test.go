package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kfadapter/kfadapter/internal/accounts"
	credentialspkg "github.com/kfadapter/kfadapter/internal/credentials"
	"github.com/kfadapter/kfadapter/internal/provider"
	"github.com/kfadapter/kfadapter/internal/socks"
	"github.com/kfadapter/kfadapter/internal/state"
	"github.com/kfadapter/kfadapter/internal/store"
	"github.com/kfadapter/kfadapter/internal/subscription"
	"github.com/kfadapter/kfadapter/internal/web"
)

const stableToken = "correct horse battery token"
const changedToken = "changed horse battery token"

// Only provider network I/O is replaced. Persistence, catalog publication,
// browser session security, subscription rendering and RFC 1929 are real.
type stableDriver struct {
	id     provider.ID
	now    time.Time
	rename bool
}

func (driver *stableDriver) ID() provider.ID { return driver.id }
func (driver *stableDriver) Login(_ context.Context, credentials provider.Credentials) (provider.Snapshot, error) {
	protocol := provider.Protocol(string(driver.id) + "-native")
	route := provider.Route{Provider: driver.id, Protocol: protocol, Host: string(driver.id) + ".example.test", Port: 11000}
	id, err := provider.NodeID(route)
	if err != nil {
		return provider.Snapshot{}, err
	}
	return provider.Snapshot{Provider: driver.id, Account: provider.Account{UserID: credentials.Account, Display: "•••", Tier: "free"}, ExpiresAt: driver.now.Add(24 * time.Hour), RefreshState: []byte("renewable-refresh-state"), Authorities: map[string]provider.Authority{"default": {Protocol: protocol, Data: []byte(credentials.Account)}}, Nodes: []provider.Node{{ID: id, Protocol: protocol, AuthorityID: "default", Host: route.Host, Port: route.Port, Name: string(driver.id) + " line", Group: "original region", Model: "original model", Eligible: true}}}, nil
}
func (driver *stableDriver) Refresh(_ context.Context, previous provider.Snapshot) (provider.Snapshot, error) {
	next := previous.Clone()
	if driver.rename {
		for index := range next.Nodes {
			next.Nodes[index].Name = "renamed line"
			next.Nodes[index].Group = "renamed region"
			next.Nodes[index].Model = "renamed model"
		}
	}
	return next, nil
}

type stableHarness struct {
	runtime *Runtime
	store   *store.SQLiteStore
	service *subscription.Service
	socks   *socks.Server
	api     *web.API
	drivers map[provider.ID]*stableDriver
}

func newStableHarness(t *testing.T, directory string) *stableHarness {
	t.Helper()
	if directory == "" {
		directory = t.TempDir()
		if err := os.Chmod(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	store, err := store.NewSQLiteStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	persistent, err := store.LoadOrCreate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !persistent.AccessTokenInitialized() {
		persistent, err = store.Update(t.Context(), func(candidate *state.PersistentState) error { return candidate.SetAccessToken(stableToken) })
		if err != nil {
			t.Fatal(err)
		}
	}
	authority, err := persistent.Identity()
	if err != nil {
		t.Fatal(err)
	}
	manager, err := state.NewManager(persistent.ActiveSession)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	drivers := map[provider.ID]*stableDriver{"kuaifan": {id: "kuaifan", now: now}, "quickfox": {id: "quickfox", now: now}}
	registry, err := provider.NewRegistry([]provider.Driver{drivers["kuaifan"], drivers["quickfox"]}, nil)
	if err != nil {
		t.Fatal(err)
	}
	socksServer, err := socks.New(socks.Config{Snapshots: manager, Identity: authority, InitialSnapshot: persistent.ActiveSession, Providers: registry})
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := NewCredentialCoordinator(socksServer, authority)
	if err != nil {
		t.Fatal(err)
	}
	service, err := subscription.NewService(subscription.ServiceConfig{Store: store, SocksAddress: "127.0.0.1:10808"})
	if err != nil {
		t.Fatal(err)
	}
	mutations := &sync.Mutex{}
	harness := &stableHarness{store: store, service: service, socks: socksServer, drivers: drivers}
	controller, err := accounts.NewCoordinator(accounts.CoordinatorConfig{Providers: registry, Manager: manager, SelectorBuilder: credentials, MutationMu: mutations, CommitSnapshot: func(snapshot *state.RuntimeSnapshot) error {
		return harness.runtime.CommitControlSnapshotLocked(snapshot)
	}})
	if err != nil {
		t.Fatal(err)
	}
	harness.runtime, err = NewRuntime(RuntimeConfig{Manager: manager, Store: store, Providers: controller, Subscriptions: service, Credentials: credentials, MutationMu: mutations, SocksAddress: "127.0.0.1:10808", RefreshEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	harness.api, err = web.NewAPI(web.Config{Listen: "0.0.0.0:10809", Hostname: "adapter.example.com", SocksListen: "0.0.0.0:10808"}, web.Dependencies{Backend: harness.runtime, Subscriptions: web.NewSubscriptionAdapter(service), Sessions: store})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		harness.runtime.Stop()
		if err := store.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	return harness
}
func stableRequest(api *web.API, method, path, body string, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "http://127.0.0.1:10809"+path, strings.NewReader(body))
	if cookie != nil {
		request.AddCookie(cookie)
	}
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", "http://127.0.0.1:10809")
		request.Header.Set("X-CSRF-Token", csrf)
	}
	response := httptest.NewRecorder()
	api.ServeHTTP(response, request)
	return response
}
func stableSession(t *testing.T, response *httptest.ResponseRecorder) (*http.Cookie, string) {
	t.Helper()
	if response.Code != http.StatusOK {
		t.Fatalf("access status = %d", response.Code)
	}
	var body struct {
		CSRFToken string `json:"csrfToken"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || body.CSRFToken == "" {
		t.Fatal("replacement session missing")
	}
	return cookies[0], body.CSRFToken
}
func stableCapture(t *testing.T, harness *stableHarness) (string, map[string]credentialspkg.Credentials) {
	t.Helper()
	subscriptionURL, err := harness.service.SubscriptionURL("http://127.0.0.1:10809")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(subscriptionURL)
	if err != nil {
		t.Fatal(err)
	}
	response := stableRequest(harness.api, http.MethodGet, parsed.Path, "", nil, "")
	if response.Code != http.StatusOK {
		t.Fatalf("subscription status = %d", response.Code)
	}
	decoded, err := base64.StdEncoding.DecodeString(response.Body.String())
	if err != nil {
		t.Fatal(err)
	}
	result := make(map[string]credentialspkg.Credentials)
	for _, line := range strings.Fields(string(decoded)) {
		uri, err := url.Parse(line)
		if err != nil {
			t.Fatal(err)
		}
		password, _ := uri.User.Password()
		credentials := credentialspkg.Credentials{Username: uri.User.Username(), Password: password}
		if !credentialspkg.ValidUUID(password) {
			t.Fatal("instance password is not UUIDv8")
		}
		result[credentials.Username] = credentials
	}
	for _, node := range harness.runtime.manager.Current().Nodes {
		details, err := harness.runtime.NodeDetails(t.Context(), node.ID)
		if err != nil {
			t.Fatal(err)
		}
		if result[details.SocksUsername] != (credentialspkg.Credentials{Username: details.SocksUsername, Password: details.SocksPassword}) {
			t.Fatal("node-details and subscription credentials disagree")
		}
	}
	return subscriptionURL, result
}
func stableLogin(t *testing.T, harness *stableHarness, id, account string) {
	t.Helper()
	if _, err := harness.runtime.Login(t.Context(), web.LoginInput{Provider: id, Account: account}); err != nil {
		t.Fatal(err)
	}
}

func TestStableCredentialsAcrossAccountCatalogAndRestart(t *testing.T) {
	harness := newStableHarness(t, "")
	stableLogin(t, harness, "kuaifan", "first-account")
	stableLogin(t, harness, "quickfox", "second-account")
	originalURL, original := stableCapture(t, harness)
	steps := []struct {
		name string
		run  func()
	}{
		{"logout", func() {
			if err := harness.runtime.Logout(t.Context(), "kuaifan"); err != nil {
				t.Fatal(err)
			}
		}},
		{"login", func() { stableLogin(t, harness, "kuaifan", "first-account") }},
		{"account-swap", func() {
			if err := harness.runtime.Logout(t.Context(), "kuaifan"); err != nil {
				t.Fatal(err)
			}
			stableLogin(t, harness, "kuaifan", "replacement-account")
		}},
		{"provider-remove", func() {
			if err := harness.runtime.Logout(t.Context(), "quickfox"); err != nil {
				t.Fatal(err)
			}
		}},
		{"provider-add", func() { stableLogin(t, harness, "quickfox", "second-account") }},
		{"store-reopen", func() {
			directory := strings.TrimSuffix(harness.store.Path(), "/state.db")
			harness.runtime.Stop()
			if err := harness.store.Close(t.Context()); err != nil {
				t.Fatal(err)
			}
			harness = newStableHarness(t, directory)
		}},
		{"label-refresh", func() {
			harness.drivers["kuaifan"].rename = true
			if err := harness.runtime.Refresh(t.Context(), "kuaifan"); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			step.run()
			currentURL, current := stableCapture(t, harness)
			if currentURL != originalURL {
				t.Fatal("subscription URL rotated")
			}
			for username, credentials := range current {
				if original[username] != credentials {
					t.Fatal("node credentials rotated")
				}
			}
			snapshot := harness.runtime.manager.Current()
			if len(current) != len(snapshot.Nodes) {
				t.Fatal("absent or duplicate nodes rendered")
			}
			if step.name == "logout" || step.name == "provider-remove" {
				if len(current) != 1 {
					t.Fatal("logged-out provider remained in subscription")
				}
				for username, credentials := range original {
					if _, exists := current[username]; !exists && stableSOCKSAuth(t, harness.socks, credentials) {
						t.Fatal("absent node still authenticates")
					}
				}
			} else if len(current) != len(original) {
				t.Fatal("returning node credentials did not return")
			}
		})
	}
}

// Authenticate over RFC 1929 without issuing CONNECT or contacting a provider.
func stableSOCKSAuth(t *testing.T, server *socks.Server, credentials credentialspkg.Credentials) bool {
	t.Helper()
	client, adapter := net.Pipe()
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.HandleConn(t.Context(), adapter) }()
	defer func() { _ = client.Close(); <-done }()
	if _, err := client.Write([]byte{5, 1, 2}); err != nil {
		t.Fatal(err)
	}
	var answer [2]byte
	if _, err := io.ReadFull(client, answer[:]); err != nil || answer != [2]byte{5, 2} {
		t.Fatal("SOCKS negotiation failed")
	}
	packet := []byte{1, byte(len(credentials.Username))}
	packet = append(packet, credentials.Username...)
	packet = append(packet, byte(len(credentials.Password)))
	packet = append(packet, credentials.Password...)
	if _, err := client.Write(packet); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(client, answer[:]); err != nil {
		t.Fatal(err)
	}
	return answer == [2]byte{1, 0}
}

func TestAccessTokenChangeRevokesURLPasswordAndBrowserSessions(t *testing.T) {
	harness := newStableHarness(t, "")
	stableLogin(t, harness, "kuaifan", "first-account")
	oldURL, oldCredentials := stableCapture(t, harness)
	loginBody := fmt.Sprintf(`{"token":%q}`, stableToken)
	caller, csrf := stableSession(t, stableRequest(harness.api, http.MethodPost, "/api/v1/access/login", loginBody, nil, ""))
	other, _ := stableSession(t, stableRequest(harness.api, http.MethodPost, "/api/v1/access/login", loginBody, nil, ""))
	response := stableRequest(harness.api, http.MethodPost, "/api/v1/access/token", fmt.Sprintf(`{"current":%q,"next":%q}`, stableToken, changedToken), caller, csrf)
	replacement, _ := stableSession(t, response)
	for _, cookie := range []*http.Cookie{caller, other} {
		if stableRequest(harness.api, http.MethodGet, "/api/v1/status", "", cookie, "").Code != http.StatusUnauthorized {
			t.Fatal("old browser session survived token change")
		}
	}
	if stableRequest(harness.api, http.MethodGet, "/api/v1/status", "", replacement, "").Code != http.StatusOK {
		t.Fatal("caller replacement session invalid")
	}
	oldPath, _ := url.Parse(oldURL)
	revoked := stableRequest(harness.api, http.MethodGet, oldPath.Path, "", nil, "")
	if revoked.Code != http.StatusNotFound || revoked.Body.Len() != 0 || revoked.Header().Get("Content-Length") != "0" || revoked.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("old URL did not return uniform empty 404")
	}
	newURL, newCredentials := stableCapture(t, harness)
	if newURL == oldURL {
		t.Fatal("URL did not rotate")
	}
	var oldPassword string
	for _, credentials := range oldCredentials {
		oldPassword = credentials.Password
		if stableSOCKSAuth(t, harness.socks, credentials) {
			t.Fatal("old SOCKS credentials accepted")
		}
	}
	for _, credentials := range newCredentials {
		if !stableSOCKSAuth(t, harness.socks, credentials) {
			t.Fatal("new SOCKS credentials rejected")
		}
		mixed := credentials
		mixed.Password = oldPassword
		if stableSOCKSAuth(t, harness.socks, mixed) {
			t.Fatal("old password accepted with new username")
		}
	}
	loaded, err := harness.store.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if loaded.VerifyAccessToken(stableToken) || !loaded.VerifyAccessToken(changedToken) {
		t.Fatal("verifier did not rotate")
	}
}
