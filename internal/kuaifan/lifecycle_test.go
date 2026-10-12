package kuaifan

import (
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	wireprofile "github.com/kfadapter/kfadapter/internal/kuaifan/profile"
	"github.com/kfadapter/kfadapter/internal/provider"
)

func TestRetryRetriesPerRequestTimeouts(t *testing.T) {
	client := testControlClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("network is not used")
	}))
	calls := 0
	value, err := retry(context.Background(), retryTestDriver(client), func() (int, error) {
		calls++
		if calls < 3 {
			return 0, context.DeadlineExceeded
		}
		return 42, nil
	})
	if err != nil || calls != 3 || value != 42 {
		t.Fatalf("request timeout retry = %d, %v after %d calls", value, err, calls)
	}
}

func TestRetryStopsAtParentDeadline(t *testing.T) {
	client := testControlClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("network is not used")
	}))
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	calls := 0
	_, err := retry(ctx, retryTestDriver(client), func() (struct{}, error) {
		calls++
		<-ctx.Done()
		return struct{}{}, ctx.Err()
	})
	if !errors.Is(err, context.DeadlineExceeded) || calls != 1 {
		t.Fatalf("parent deadline retry = %v after %d calls", err, calls)
	}
}

func TestKuaifanIOSRejectionKeepsWindowsNodes(t *testing.T) {
	for _, rejectedRoute := range []string{"/v4/user/refresh.do", "/v4/invpn/getAuthority.do", "/v4/invpn/getLines.do"} {
		t.Run(rejectedRoute, func(t *testing.T) {
			current := lifecycleSnapshot()
			before := current.Clone()
			authKey := encodedAuthority(t, "1", "new-tunnel", "new-order")
			var reject atomic.Bool
			reject.Store(true)
			iosClient, windowsClient := testControlClients(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
				windows := request.Header.Get("User-Agent") == wireprofile.WindowsUserAgent
				if !windows && request.URL.Path == rejectedRoute && reject.Load() {
					// Inject a classified rejection at the transport seam. No live
					// refresh-side business rejection code is confirmed yet.
					return nil, provider.ErrSessionRejected
				}
				return lifecycleResponse(t, request, authKey), nil
			}))
			driver := lifecycleDriver(t, iosClient, windowsClient)
			next, err := driver.Refresh(context.Background(), current)
			if err != nil {
				t.Fatal(err)
			}
			if !next.Valid() || len(next.Nodes) != 1 || next.Nodes[0].Host != "windows.example" || next.Nodes[0].AuthorityID != "windows" || len(next.Authorities) != 1 {
				t.Fatalf("surviving profile snapshot = %#v", next)
			}
			if _, ok := next.Authorities["windows"]; !ok {
				t.Fatal("surviving Windows authority is missing")
			}
			stored, err := decodeDriverState(next.RefreshState)
			wantIOS := "ios-new"
			if rejectedRoute == "/v4/user/refresh.do" {
				wantIOS = "ios-old"
			}
			if err != nil || stored.IOS.Token != wantIOS || stored.Windows.Token != "windows-new" {
				t.Fatalf("retained profile refresh state = %#v, %v", stored, err)
			}
			if !reflect.DeepEqual(current, before) {
				t.Fatal("rejection mutated the caller's snapshot")
			}
			reject.Store(false)
			recovered, err := driver.Refresh(context.Background(), next)
			if err != nil || !recovered.Valid() || len(recovered.Nodes) != 2 || len(recovered.Authorities) != 2 {
				t.Fatalf("recovered profile snapshot = %#v, %v", recovered, err)
			}
		})
	}
}

func TestKuaifanBothFailedProfilesReportExplicitRejection(t *testing.T) {
	iosClient, windowsClient := testControlClients(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("network is not used")
	}))
	for _, otherErr := range []error{provider.ErrSessionRejected, context.DeadlineExceeded} {
		_, err := parallelSessions(context.Background(), [2]*Client{iosClient, windowsClient}, true, func(_ context.Context, client *Client) (LoginSession, error) {
			if client.Profile() == wireprofile.IOSID {
				return LoginSession{}, provider.ErrSessionRejected
			}
			return LoginSession{}, otherErr
		})
		if !errors.Is(err, provider.ErrSessionRejected) {
			t.Fatalf("both failed profiles = %v, want explicit rejection", err)
		}
	}
}

func TestKuaifanPartialRefreshRetainsRotatedTokens(t *testing.T) {
	current := lifecycleSnapshot()
	before := current.Clone()
	authKey := encodedAuthority(t, "1", "new-tunnel", "new-order")
	var failCatalog atomic.Bool
	failCatalog.Store(true)
	var mu sync.Mutex
	seenTokens := make(map[string]string)
	iosClient, windowsClient := testControlClients(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		windows := request.Header.Get("User-Agent") == wireprofile.WindowsUserAgent
		if request.URL.Path == "/v4/user/refresh.do" {
			encoded, err := io.ReadAll(request.Body)
			if err != nil {
				return nil, err
			}
			var fields map[string]any
			if err := NormalCodec().DecodeJSON(encoded, &fields); err != nil {
				return nil, err
			}
			profile := "ios"
			if windows {
				profile = "windows"
			}
			mu.Lock()
			seenTokens[profile], _ = fields["token"].(string)
			mu.Unlock()
		}
		if windows && request.URL.Path == "/v4/invpn/getLines.do" && failCatalog.Load() {
			return nil, ErrSchema
		}
		return lifecycleResponse(t, request, authKey), nil
	}))
	driver := lifecycleDriver(t, iosClient, windowsClient)
	partial, err := driver.Refresh(context.Background(), current)
	if !errors.Is(err, ErrSchema) || errors.Is(err, context.Canceled) {
		t.Fatalf("catalog failure = %v, want original schema error", err)
	}
	stored, err := decodeDriverState(partial.RefreshState)
	if err != nil || partial.Provider != ProviderID || stored.IOS.Token != "ios-new" || stored.Windows.Token != "windows-new" || partial.Authorities != nil || partial.Nodes != nil {
		t.Fatalf("partial rotated state = %#v, %v", partial, err)
	}
	if !reflect.DeepEqual(current, before) {
		t.Fatal("partial refresh mutated the previous snapshot")
	}
	// The coordinator merges only this opaque state into the previous snapshot.
	current.RefreshState = partial.RefreshState
	failCatalog.Store(false)
	next, err := driver.Refresh(context.Background(), current)
	if err != nil || !next.Valid() {
		t.Fatalf("next refresh = %#v, %v", next, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if seenTokens["ios"] != "ios-new" || seenTokens["windows"] != "windows-new" {
		t.Fatalf("next refresh did not use rotated tokens: %#v", seenTokens)
	}
}

func TestKuaifanCatalogFailureDrainsWorkersWithoutMaskingCause(t *testing.T) {
	var started sync.WaitGroup
	started.Add(4)
	var active atomic.Int32
	iosClient, windowsClient := testControlClients(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		active.Add(1)
		defer active.Add(-1)
		started.Done()
		if request.Header.Get("User-Agent") == wireprofile.IOSUserAgent && request.URL.Path == "/v4/invpn/getAuthority.do" {
			started.Wait()
			return nil, ErrSchema
		}
		<-request.Context().Done()
		return nil, request.Context().Err()
	}))
	driver := lifecycleDriver(t, iosClient, windowsClient)
	sessions := [2]LoginSession{
		{UserID: 1, Token: "ios-old", APIBase: mustBase(t, "https://bootstrap.example")},
		{UserID: 1, Token: "windows-old", APIBase: mustBase(t, "https://bootstrap.example")},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := driver.fetchBothProfiles(ctx, sessions, false)
	if !errors.Is(err, ErrSchema) || errors.Is(err, context.Canceled) || active.Load() != 0 {
		t.Fatalf("parallel catalog failure = %v with %d active workers", err, active.Load())
	}
}

func TestKuaifanBusinessStatusRemainsTransient(t *testing.T) {
	iosClient, windowsClient := testControlClients(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/v4/client/conf.do" {
			return encryptedHTTPResponse(t, envelope(map[string]any{})), nil
		}
		return encryptedHTTPResponse(t, map[string]any{"status": 401, "fields": map[string]any{}}), nil
	}))
	partial, err := lifecycleDriver(t, iosClient, windowsClient).Refresh(context.Background(), lifecycleSnapshot())
	if !errors.Is(err, ErrBusinessStatus) || errors.Is(err, provider.ErrSessionRejected) || !reflect.DeepEqual(partial, provider.Snapshot{}) {
		t.Fatalf("unconfirmed refresh rejection = %#v, %v", partial, err)
	}
}

func lifecycleSnapshot() provider.Snapshot {
	return provider.Snapshot{
		Provider:     ProviderID,
		Account:      provider.Account{UserID: "1", Display: "a•••@example.test", Tier: standardTier},
		ExpiresAt:    time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC),
		RefreshState: []byte(`{"ios":{"userId":1,"token":"ios-old"},"windows":{"userId":1,"token":"windows-old"}}`),
		Authorities:  map[string]provider.Authority{"ios": {Protocol: WIFIINProtocol, Data: []byte("old")}},
		Nodes:        []provider.Node{{ID: "old", AuthorityID: "ios", Protocol: WIFIINProtocol, Host: "old.example", Port: 11000, Eligible: true}},
	}
}

func lifecycleDriver(t *testing.T, iosClient, windowsClient *Client) *Driver {
	t.Helper()
	driver, err := NewDriver(DriverConfig{
		IOSClient: iosClient, WindowsClient: windowsClient, MaxAttempts: 1,
		Clock: func() time.Time { return time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return driver
}

func lifecycleResponse(t *testing.T, request *http.Request, authKey []byte) *http.Response {
	t.Helper()
	windows := request.Header.Get("User-Agent") == wireprofile.WindowsUserAgent
	profile := "ios"
	if windows {
		profile = "windows"
	}
	switch request.URL.Path {
	case "/v4/client/conf.do":
		return encryptedHTTPResponse(t, envelope(map[string]any{}))
	case "/v4/user/refresh.do":
		return encryptedHTTPResponse(t, envelope(validRefreshFields(profile+"-new")))
	case "/v4/invpn/getAuthority.do":
		return encryptedHTTPResponse(t, envelope(map[string]any{"authKey": string(authKey), "token": profile + "-provider", "cpOrderNo": "new-order"}))
	case "/v4/invpn/getLines.do":
		return encryptedHTTPResponse(t, envelope(validLineFields(profile+".example", "group")))
	default:
		t.Errorf("unexpected lifecycle route %q", request.URL.Path)
		return &http.Response{StatusCode: http.StatusNotFound, Body: ioNopString(""), Header: make(http.Header)}
	}
}
