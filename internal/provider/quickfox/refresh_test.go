package quickfox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/kfadapter/kfadapter/internal/provider"
)

func TestQuickFoxTransientTimeoutIsRetriedAndSucceeds(t *testing.T) {
	for _, timedOutRoute := range []string{"/user/info", "/line/socksServerPoolList"} {
		t.Run(timedOutRoute, func(t *testing.T) {
			calls := make(map[string]int)
			driver := refreshTestDriver(t, controlRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				calls[request.URL.Path]++
				if request.URL.Path == timedOutRoute && calls[request.URL.Path] == 1 {
					<-request.Context().Done()
					return nil, request.Context().Err()
				}
				return catalogHTTPResponse(t, request.URL.Path), nil
			}))
			current := refreshTestSnapshot(t, driver)
			before := current.Clone()
			next, err := driver.Refresh(context.Background(), current)
			if err != nil || !next.Valid() || calls[timedOutRoute] != 2 || len(next.Nodes) != 2 {
				t.Fatalf("timeout recovery = %#v, %v after %#v calls", next, err, calls)
			}
			if !reflect.DeepEqual(current, before) || !bytes.Equal(next.RefreshState, current.RefreshState) {
				t.Fatal("transient timeout changed the stored token or caller snapshot")
			}
		})
	}
}

func TestQuickFoxRejectedTokenIsSessionRejectionAndNotRetried(t *testing.T) {
	calls := 0
	driver := refreshTestDriver(t, controlRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		// Live QuickFox answer for a token it no longer accepts: envelope code
		// 401, no success field, and data echoing a token.
		encoded, err := json.Marshal(map[string]any{
			"code": http.StatusUnauthorized, "message": "token失效，请重新登录",
			"data": map[string]any{"token": "0123456789abcdef0123456789abcdef"},
		})
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(encoded)), Header: make(http.Header)}, nil
	}))
	next, err := driver.Refresh(context.Background(), refreshTestSnapshot(t, driver))
	if !errors.Is(err, provider.ErrSessionRejected) || calls != 1 || !reflect.DeepEqual(next, provider.Snapshot{}) {
		t.Fatalf("rejected token = %#v, %v after %d calls", next, err, calls)
	}
}

func TestQuickFoxBusinessCodeRemainsTransient(t *testing.T) {
	for _, code := range []int{http.StatusForbidden, http.StatusInternalServerError} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			calls := 0
			driver := refreshTestDriver(t, controlRoundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				encoded, err := json.Marshal(map[string]any{"code": code, "success": false, "data": nil})
				if err != nil {
					return nil, err
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(encoded)), Header: make(http.Header)}, nil
			}))
			_, err := driver.Refresh(context.Background(), refreshTestSnapshot(t, driver))
			if !errors.Is(err, ErrBusinessCode) || errors.Is(err, provider.ErrSessionRejected) || calls != 1 {
				t.Fatalf("unconfirmed business rejection = %v after %d calls", err, calls)
			}
		})
	}
}

func TestQuickFoxRetryClassifiesHTTPStatuses(t *testing.T) {
	for _, test := range []struct {
		status int
		want   bool
	}{
		{status: http.StatusUnauthorized},
		{status: http.StatusForbidden},
		{status: http.StatusNotFound},
		{status: http.StatusRequestTimeout, want: true},
		{status: http.StatusTooManyRequests, want: true},
		{status: http.StatusInternalServerError, want: true},
		{status: http.StatusBadGateway, want: true},
	} {
		if got := retryable(&httpStatusError{status: test.status}); got != test.want {
			t.Errorf("retryable HTTP %d = %t, want %t", test.status, got, test.want)
		}
	}
}

func TestQuickFoxCatalogRetryIsBounded(t *testing.T) {
	calls := 0
	driver := refreshTestDriver(t, controlRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, context.DeadlineExceeded
	}))
	next, err := driver.Refresh(context.Background(), refreshTestSnapshot(t, driver))
	if !errors.Is(err, context.DeadlineExceeded) || calls != 3 || !reflect.DeepEqual(next, provider.Snapshot{}) {
		t.Fatalf("bounded retry = %#v, %v after %d calls", next, err, calls)
	}
}

func TestQuickFoxCatalogRetryStopsOnParentCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	driver := refreshTestDriver(t, controlRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		cancel()
		return nil, context.DeadlineExceeded
	}))
	_, err := driver.Refresh(ctx, refreshTestSnapshot(t, driver))
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("cancelled retry = %v after %d calls", err, calls)
	}
}

type controlRoundTripFunc func(*http.Request) (*http.Response, error)

func (call controlRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return call(request)
}

func refreshTestDriver(t *testing.T, transport http.RoundTripper) *Driver {
	t.Helper()
	client, err := NewClient(Config{
		Clock:  func() time.Time { return time.Date(2026, 7, 22, 6, 0, 0, 0, time.UTC) },
		Random: bytes.NewReader(bytes.Repeat([]byte{0x5a}, 512)), RequestTimeout: time.Millisecond,
		httpClient: &http.Client{Transport: transport}, apiBase: "https://api.quick-fox.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	driver, err := NewDriver(DriverConfig{Client: client})
	if err != nil {
		t.Fatal(err)
	}
	return driver
}

func refreshTestSnapshot(t *testing.T, driver *Driver) provider.Snapshot {
	t.Helper()
	snapshot, err := driver.snapshot(storedSession{
		Token: "0123456789abcdef0123456789abcdef", UserID: 15904241, DeviceCode: "00112233-4455-4677-8899-aabbccddeeff",
	}, catalogFixture())
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func catalogHTTPResponse(t *testing.T, path string) *http.Response {
	t.Helper()
	responseWriter := httptest.NewRecorder()
	fixture := catalogFixture()
	if path == "/user/info" {
		writeEncryptedResponse(t, responseWriter, fixture.Profile)
	} else {
		writeEncryptedResponse(t, responseWriter, fixture)
	}
	return responseWriter.Result()
}
