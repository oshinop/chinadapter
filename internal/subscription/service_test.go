package subscription

import (
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oshinop/chinadapter/internal/provider"
	"github.com/oshinop/chinadapter/internal/state"
)

func catalogService(t *testing.T) (*Service, state.PersistentState) {
	t.Helper()
	persistent, err := state.NewPersistentState()
	if err != nil {
		t.Fatal(err)
	}
	if err := persistent.SetAccessToken("subscription fixture access token"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	source := provider.Node{ID: "kuaifan_node", Protocol: "kuaifan-wifiin", AuthorityID: "ios", Host: "node.example.test", Port: 11000, Name: "Node 01 # / 测试", Group: "Region", Eligible: true}
	persistent.ActiveSession = &state.RuntimeSnapshot{Generation: 1, CreatedAt: now, ExpiresAt: now.Add(time.Hour), Providers: map[provider.ID]provider.Snapshot{"kuaifan": {Provider: "kuaifan", Account: provider.Account{UserID: "fixture", Display: "•••", Tier: "free"}, ExpiresAt: now.Add(time.Hour), RefreshState: []byte("refresh"), Authorities: map[string]provider.Authority{"ios": {Protocol: source.Protocol, Data: []byte("authority")}}, Nodes: []provider.Node{source}}}, Nodes: []state.Node{{ID: source.ID, Provider: "kuaifan", Protocol: source.Protocol, AuthorityID: source.AuthorityID, Host: source.Host, Port: source.Port, Name: source.Name, Group: source.Group, Eligible: true}}}
	service := &Service{socksAddress: "127.0.0.1:10808", responseSlots: make(chan struct{}, subscriptionResponseConcurrency)}
	if err := service.Update(persistent); err != nil {
		t.Fatal(err)
	}
	return service, persistent
}

func TestConcurrentSubscriptionAuthorities(t *testing.T) {
	service, _ := catalogService(t)
	// Permit all 50 renderers to overlap in this isolation test. The production
	// admission bound is tested separately without changing its eight slots.
	service.responseSlots = make(chan struct{}, 50)
	subscriptionURL, err := service.SubscriptionURL("http://127.0.0.1:10809")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(subscriptionURL)
	if err != nil {
		t.Fatal(err)
	}
	hosts := []string{"127.0.0.1:10809", "192.0.2.10:10809", "adapter.example.com:10809"}
	start := make(chan struct{})
	var workers sync.WaitGroup
	for index := range 50 {
		workers.Go(func() {
			<-start
			host := hosts[index%len(hosts)]
			request := httptest.NewRequest(http.MethodGet, "http://"+host+parsed.Path, nil)
			request.Host = host
			name, _, err := net.SplitHostPort(request.Host)
			if err != nil {
				t.Error(err)
				return
			}
			authority := net.JoinHostPort(name, "10808")
			response := httptest.NewRecorder()
			service.HandleSubscription(response, request, authority)
			if response.Code != http.StatusOK {
				t.Errorf("subscription status = %d", response.Code)
				return
			}
			decoded, err := base64.StdEncoding.DecodeString(response.Body.String())
			if err != nil {
				t.Error(err)
				return
			}
			for _, line := range strings.Fields(string(decoded)) {
				uri, err := url.Parse(line)
				if err != nil {
					t.Error(err)
					return
				}
				if uri.Host != authority {
					t.Error("response used another request's authority")
				}
			}
		})
	}
	close(start)
	workers.Wait()
}

func TestSubscriptionSaturationPrecedesStrictPathValidation(t *testing.T) {
	service, _ := catalogService(t)
	subscriptionURL, err := service.SubscriptionURL("http://127.0.0.1:10809")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(subscriptionURL)
	if err != nil {
		t.Fatal(err)
	}
	for range cap(service.responseSlots) {
		service.responseSlots <- struct{}{}
	}
	for _, path := range []string{parsed.Path, "/sub/invalid", "/sub", parsed.Path + "/"} {
		response := httptest.NewRecorder()
		service.HandleSubscription(response, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:10809"+path, nil), "")
		if response.Code != http.StatusServiceUnavailable || response.Body.Len() != 0 || response.Header().Get("Content-Length") != "0" || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Retry-After") != "1" {
			t.Fatal("saturation leaked path validity")
		}
	}
	for range cap(service.responseSlots) {
		<-service.responseSlots
	}
	for _, path := range []string{"/sub/invalid", "/sub", parsed.Path + "/", "/sub/00000000-0000-4000-8000-000000000000", strings.ToUpper(parsed.Path), "/sub/%30" + parsed.Path[6:]} {
		response := httptest.NewRecorder()
		service.HandleSubscription(response, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:10809"+path, nil), "")
		if response.Code != http.StatusNotFound || response.Body.Len() != 0 || response.Header().Get("Content-Length") != "0" || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("strict path did not return uniform empty 404")
		}
	}
}

func TestSubscriptionRendersFiltersAndEscapingWithoutMutation(t *testing.T) {
	service, persistent := catalogService(t)
	authority, err := persistent.Identity()
	if err != nil {
		t.Fatal(err)
	}
	original := persistent.ActiveSession.Nodes[0]
	body, count, err := Render(persistent.ActiveSession.Nodes, Filter{Provider: "kuaifan", Group: "Region", Name: "node"}, "[2001:db8::1]:10808", authority)
	if err != nil || count != 1 {
		t.Fatal("matching filter did not render")
	}
	decoded, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(strings.TrimSpace(string(decoded)))
	if err != nil {
		t.Fatal(err)
	}
	credentials, ok := authority.Credentials(original.Route())
	password, _ := uri.User.Password()
	if !ok || uri.Scheme != "socks5" || uri.Host != "[2001:db8::1]:10808" || uri.Fragment != original.Name || uri.User.Username() != credentials.Username || password != credentials.Password {
		t.Fatal("URI escaping or credentials incorrect")
	}
	if persistent.ActiveSession.Nodes[0] != original {
		t.Fatal("renderer mutated its input")
	}
	for _, filter := range []Filter{{Provider: "quickfox"}, {Group: "missing"}, {Name: "missing"}} {
		if _, _, err := Render(persistent.ActiveSession.Nodes, filter, "127.0.0.1:10808", authority); !errors.Is(err, ErrNoEligibleLinks) {
			t.Fatal("empty filter selection did not fail closed")
		}
	}
	originalURL, err := service.SubscriptionURL("http://127.0.0.1:10809")
	if err != nil {
		t.Fatal(err)
	}
	persistent.ActiveSession = nil
	if err := service.Update(persistent); err != nil {
		t.Fatal(err)
	}
	if currentURL, err := service.SubscriptionURL("http://127.0.0.1:10809"); err != nil || currentURL != originalURL {
		t.Fatal("empty catalog rotated URL")
	}
}
