package web

import (
	"net/http"
	"strings"
	"testing"
)

func TestAccessTokenChangeRequiresSessionAndSameOrigin(t *testing.T) {
	backend := &fakeBackend{}
	api := newTestAPI(t, backend, newFakeSubscriptions())
	cookie := establish(t, api)
	body := `{"current":"` + validTestToken + `","next":"replacement-token-12345"}`
	for _, test := range []struct {
		name              string
		cookie            bool
		origin, fetchSite string
		want              int
	}{
		{name: "session", origin: testOrigin, want: http.StatusUnauthorized},
		{name: "cross-site", cookie: true, origin: testOrigin, fetchSite: "cross-site", want: http.StatusForbidden},
		{name: "cross-origin", cookie: true, origin: "http://evil.test", want: http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			var sessionCookie *http.Cookie
			if test.cookie {
				sessionCookie = cookie
			}
			response := rawRequest(api, http.MethodPost, "/api/v1/access/token", body, sessionCookie, test.origin, test.fetchSite)
			if response.Code != test.want {
				t.Fatalf("mutation security = %d", response.Code)
			}
			if test.want == http.StatusForbidden && !strings.Contains(response.Body.String(), `"code":"invalid_origin"`) {
				t.Fatalf("cross-origin problem = %s", response.Body.String())
			}
		})
	}
	if backend.accessToken != validTestToken {
		t.Fatal("unauthorized token mutation reached backend")
	}
}

func TestAccessTokenChangeThrottlesOnlyCurrentFailures(t *testing.T) {
	api := newTestAPI(t, &fakeBackend{}, newFakeSubscriptions())
	cookie := establish(t, api)
	invalidNext := `{"current":"` + validTestToken + `","next":"short"}`
	for range 5 {
		response := request(api, http.MethodPost, "/api/v1/access/token", invalidNext, cookie, testOrigin)
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "invalid_next_access_token") {
			t.Fatalf("invalid next = %d", response.Code)
		}
	}
	wrongCurrent := `{"current":"` + invalidTestToken + `","next":"replacement-token-12345"}`
	for range 5 {
		response := request(api, http.MethodPost, "/api/v1/access/token", wrongCurrent, cookie, testOrigin)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("wrong current = %d", response.Code)
		}
	}
	limited := request(api, http.MethodPost, "/api/v1/access/token", wrongCurrent, cookie, testOrigin)
	if limited.Code != http.StatusTooManyRequests || limited.Header().Get("Retry-After") == "" {
		t.Fatalf("token change throttle = %d", limited.Code)
	}
}

func TestAccessTokenChangeRevokesSessionsAndEventLifetime(t *testing.T) {
	persistence := &fakeBrowserSessionPersistence{}
	api := newPersistentTestAPI(t, testConfig().Now, &fakeBackend{}, persistence)
	caller := establish(t, api)
	session, exists := api.sessions.valid(t.Context(), caller.Value)
	if !exists {
		t.Fatal("caller session missing")
	}
	other := request(api, http.MethodPost, "/api/v1/access/login", `{"token":"`+validTestToken+`"}`, nil, testOrigin)
	otherCookie := sessionFromResponse(t, other)
	changed := request(api, http.MethodPost, "/api/v1/access/token", `{"current":"`+validTestToken+`","next":"replacement-token-12345"}`, caller, testOrigin)
	replacement := sessionFromResponse(t, changed)
	if changed.Code != http.StatusOK || replacement.Value == caller.Value {
		t.Fatal("caller session was not replaced")
	}
	select {
	case <-session.done:
	default:
		t.Fatal("revoked event lifetime still open")
	}
	for _, cookie := range []*http.Cookie{caller, otherCookie} {
		if request(api, http.MethodGet, "/api/v1/status", "", cookie, "").Code != http.StatusUnauthorized {
			t.Fatal("revoked browser session still valid")
		}
	}
	if request(api, http.MethodGet, "/api/v1/status", "", replacement, "").Code != http.StatusOK {
		t.Fatal("replacement session invalid")
	}
	persistence.mu.Lock()
	count := len(persistence.sessions)
	_, rawStored := persistence.sessions[replacement.Value]
	persistence.mu.Unlock()
	if count != 1 || rawStored {
		t.Fatal("session persistence is not a single hashed replacement")
	}
}
