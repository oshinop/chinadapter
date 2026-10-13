package transocks

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oshinop/chinadapter/internal/provider"
)

func fixtureClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := NewClient(Config{httpClient: server.Client(), apiBases: []string{server.URL}})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func fixtureSession(t *testing.T) storedSession {
	t.Helper()
	metadata, err := metadataFor("fixture-installation")
	if err != nil {
		t.Fatal(err)
	}
	return storedSession{Token: "fixture-token", TokenType: "Bearer", Metadata: metadata}
}

func TestClientLoginForms(t *testing.T) {
	for _, test := range []struct{ name, account, authBy, email, phone, cc string }{
		{"email", "fixture@example.invalid", "email", "fixture@example.invalid", "", ""},
		{"bare mobile", "13800000000", "mobile", "", "13800000000", "+86"},
		{"international mobile", "+8613800000000", "mobile", "", "13800000000", "+86"},
		{"one digit calling code", "+12025550123", "mobile", "", "2025550123", "+1"},
		{"three digit calling code", "+85251234567", "mobile", "", "51234567", "+852"},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := fixtureClient(t, func(w http.ResponseWriter, request *http.Request) {
				if request.Method != http.MethodPost || request.URL.Path != "/api/1/login" || request.Header.Get("Authorization") != "" || request.Header.Get("Content-Type") != "application/json" {
					t.Error("unexpected login request")
				}
				var payload loginPayload
				if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
					t.Error(err)
					return
				}
				if !payload.valid() || payload.AuthBy != test.authBy || payload.AuthType != "jwt" || payload.Email != test.email || payload.Phone != test.phone || payload.CC != test.cc || payload.Password != "unchanged-password" || payload.Autokick != 0 {
					t.Error("login fields differ")
				}
				fmt.Fprint(w, `{"code":0,"user_id":42,"expired":true,"token":{"access_token":"fixture-token","token_type":"","exp":2000000000}}`)
			})
			stored, response, err := client.Login(context.Background(), test.account, "unchanged-password", "fixture-installation")
			if err != nil {
				t.Fatal(err)
			}
			if !stored.valid() || stored.TokenType != "Bearer" || stored.Token != "fixture-token" || response.UserID != 42 {
				t.Fatal("login response mapping differs")
			}
		})
	}
}

func TestClientLoginAndSessionCodes(t *testing.T) {
	for _, test := range []struct {
		code int
		want error
	}{
		{40001, ErrLoginRejected}, {40003, provider.ErrDeviceLimit}, {20001, provider.ErrSessionRejected}, {40015, provider.ErrSessionRejected},
		{20000, ErrBusinessCode}, {20010, ErrBusinessCode}, {20012, ErrBusinessCode}, {40022, ErrBusinessCode},
	} {
		t.Run(fmt.Sprint(test.code), func(t *testing.T) {
			client := fixtureClient(t, func(w http.ResponseWriter, request *http.Request) {
				fmt.Fprintf(w, `{"code":%d,"error":"untrusted server detail"}`, test.code)
			})
			_, _, err := client.Login(context.Background(), "fixture@example.invalid", "password", "installation")
			if !errors.Is(err, test.want) {
				t.Fatalf("wrong classification: %v", err)
			}
			if strings.Contains(err.Error(), "untrusted server detail") {
				t.Fatal("server detail leaked")
			}
			if test.code != 20001 && test.code != 40015 && errors.Is(err, provider.ErrSessionRejected) {
				t.Fatal("non-auth code erased session")
			}
		})
	}
}

func TestClientResponseBoundsAndEnvelope(t *testing.T) {
	for _, test := range []struct {
		name, body string
		status     int
		want       error
	}{
		{"missing code", `{"user_id":42}`, 200, ErrSchema},
		{"null code", `{"code":null}`, 200, ErrSchema},
		{"malformed", `{"code":0`, 200, ErrSchema},
		{"oversized", strings.Repeat("x", maxControlBytes+1), 200, ErrSchema},
		{"http auth without explicit code", `{"code":0}`, 401, ErrHTTPStatus},
		{"auth rejection with http error", `{"code":40015}`, 401, provider.ErrSessionRejected},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := fixtureClient(t, func(w http.ResponseWriter, request *http.Request) {
				w.WriteHeader(test.status)
				fmt.Fprint(w, test.body)
			})
			_, err := client.MiscInfo(context.Background(), fixtureSession(t))
			if !errors.Is(err, test.want) {
				t.Fatalf("wrong response classification: %v", err)
			}
		})
	}
}

func TestClientOriginFailoverAndStickiness(t *testing.T) {
	var firstCalls, secondCalls atomic.Int32
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		firstCalls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		secondCalls.Add(1)
		if request.Header.Get("Authorization") != "Bearer fixture-token" || request.URL.Query().Get("org") != "transocks_mix" || request.URL.Query().Get("uuid") == "" || request.URL.Query().Get("langue") != "zh" {
			t.Error("missing request authority or installation metadata")
		}
		fmt.Fprint(w, `{"code":0,"user_id":42,"expired":true}`)
	}))
	defer second.Close()
	client, err := NewClient(Config{httpClient: first.Client(), apiBases: []string{first.URL, second.URL}})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := client.MiscInfo(context.Background(), fixtureSession(t)); err != nil {
			t.Fatal(err)
		}
	}
	if firstCalls.Load() != 1 || secondCalls.Load() != 2 {
		t.Fatal("successful origin was not retained")
	}
}

func TestClientBusinessFailureDoesNotFailOver(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) { calls.Add(1); fmt.Fprint(w, `{"code":40022}`) }))
	defer server.Close()
	client, err := NewClient(Config{httpClient: server.Client(), apiBases: []string{server.URL, server.URL}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Connect(context.Background(), fixtureSession(t), 1); !errors.Is(err, ErrBusinessCode) {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("mutating business rejection was repeated")
	}
}

func TestClientRejectsRedirectsAndInsecureTLS(t *testing.T) {
	client := fixtureClient(t, func(w http.ResponseWriter, request *http.Request) {
		http.Redirect(w, request, "https://untrusted.invalid/", http.StatusFound)
	})
	if _, err := client.MiscInfo(context.Background(), fixtureSession(t)); !errors.Is(err, ErrHTTPStatus) {
		t.Fatal(err)
	}
	_, err := NewClient(Config{httpClient: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}})
	if err == nil {
		t.Fatal("accepted hostname-verification bypass")
	}
}

func TestInstallationMetadataAndInvalidAccounts(t *testing.T) {
	first, err := metadataFor("installation-one")
	if err != nil {
		t.Fatal(err)
	}
	again, _ := metadataFor("installation-one")
	other, _ := metadataFor("installation-two")
	if first != again || first.MAC == other.MAC || first.UUID == other.UUID || !first.valid() {
		t.Fatal("identity is not installation-specific and stable")
	}
	for _, input := range []string{"", "abc", "12345", "+99912345678", "+86138x0000000", "+86", "22025550123"} {
		if _, _, err := splitPhone(input); !errors.Is(err, provider.ErrInvalidInput) {
			t.Fatalf("accepted invalid account shape %q", input)
		}
	}
	client := fixtureClient(t, func(w http.ResponseWriter, request *http.Request) { t.Error("invalid input issued request") })
	if _, _, err := client.Login(context.Background(), "abc", "password", "install"); !errors.Is(err, provider.ErrInvalidInput) {
		t.Fatal(err)
	}
	if _, err := client.Connect(context.Background(), fixtureSession(t), -1); !errors.Is(err, ErrSchema) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.MiscInfo(ctx, fixtureSession(t)); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

var fixtureNow = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
