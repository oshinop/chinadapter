package kuaifan

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	wireprofile "github.com/kfadapter/kfadapter/internal/provider/kuaifan/profile"
)

func TestWindowsLineValidationRetainsUnsupportedWSAsIneligible(t *testing.T) {
	t.Parallel()
	fields := windowsRawFields(t, map[string]any{
		"groups": []any{map[string]any{"id": "g", "name": "group"}},
		"lines": []any{
			map[string]any{"host": "wifiin.example", "port": 11000, "provider": "WIFIIN", "password": wireprofile.WindowsTunnelPassword, "groupId": "g"},
			map[string]any{"host": "ws.example", "port": 12000, "provider": "WS", "groupId": "g"},
		},
	})
	lines, err := validateLinesForProfile(fields, "zh-CN", windowsClientProfile{})
	if err != nil {
		t.Fatal(err)
	}
	if len(lines.Lines) != 2 || !lines.Lines[0].Eligible || lines.Lines[1].Eligible {
		t.Fatalf("Windows line eligibility = %#v", lines.Lines)
	}
}

func TestConstructorsKeepProfileBoundary(t *testing.T) {
	t.Parallel()
	ios, err := NewIOSClient(Config{})
	if err != nil {
		t.Fatal(err)
	}
	windows, err := NewWindowsClient(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if ios.Profile() != wireprofile.IOSID || windows.Profile() != wireprofile.WindowsID {
		t.Fatalf("profiles = %q / %q", ios.Profile(), windows.Profile())
	}
}

func TestWindowsRequestWireNonces(t *testing.T) {
	t.Parallel()
	type wireRequest struct {
		route  string
		fields map[string]any
	}
	requests := make(chan wireRequest, 5)
	codec := NormalCodec()
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		var fields map[string]any
		if err := codec.DecodeJSON(body, &fields); err != nil {
			t.Error(err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		requests <- wireRequest{route: request.URL.Path, fields: fields}
		responseFields := map[string]any{}
		switch request.URL.Path {
		case "/v4/user/login.do", "/v4/user/refresh.do":
			responseFields = map[string]any{"userId": 7, "token": "login", "isVip": false, "vipEndTime": 0}
		case "/v4/invpn/getAuthority.do":
			responseFields = map[string]any{"token": "provider", "cpOrderNo": "order"}
		case "/v4/invpn/getLines.do":
			responseFields = map[string]any{"groups": []any{}, "lines": []any{}}
		}
		response, err := codec.EncodeJSON(envelope(responseFields))
		if err != nil {
			t.Error(err)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		if _, err := writer.Write(response); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	httpClient := hardenedHTTPClient()
	defer httpClient.CloseIdleConnections()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	httpClient.Transport.(*http.Transport).TLSClientConfig.RootCAs = roots
	client, err := NewWindowsClient(Config{
		BootstrapBase: server.URL, AllowedAPIHosts: []string{"127.0.0.1"}, Language: "en-US",
		httpClient: httpClient, Clock: func() time.Time { return time.Unix(1700000000, 0) },
		Random: bytes.NewReader(make([]byte, 64)),
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := client.Login(context.Background(), EmailLogin{
		Account: "user@example.test", Password: "password", InstallationID: "00112233445566778899aabbccddeeff",
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err = client.RefreshSession(context.Background(), session)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.FetchAuthority(context.Background(), session); err != nil {
		t.Fatal(err)
	}
	if _, err := client.FetchLines(context.Background(), session); err != nil {
		t.Fatal(err)
	}
	for range 5 {
		request := <-requests
		nonce, ok := request.fields["nonce"].(string)
		if !ok || len(nonce) != 8 {
			t.Fatalf("%s nonce shape = %q", request.route, nonce)
		}
		value, err := strconv.Atoi(nonce)
		if err != nil || value < 0 || value > 99999999 {
			t.Fatalf("%s nonce is not eight decimal digits: %q", request.route, nonce)
		}
		switch request.route {
		case "/v4/user/login.do", "/v4/invpn/getAuthority.do":
			if nonce != wireprofile.WindowsFixedNonce {
				t.Fatalf("%s recovered nonce = %q, want %q", request.route, nonce, wireprofile.WindowsFixedNonce)
			}
		case "/v4/user/refresh.do", "/v4/invpn/getLines.do":
			if value < 10000000 {
				t.Fatalf("%s generated Windows nonce lost its leading digit: %q", request.route, nonce)
			}
		}
		if request.fields["lang"] != "en-US" {
			t.Fatalf("%s language = %v", request.route, request.fields["lang"])
		}
	}
}

func TestRequestEnvelopePreservesProfileFields(t *testing.T) {
	t.Parallel()
	fields := map[string]any{"lang": "en-US", "nonce": "07531556", "time": "profile-time"}
	got, err := requestEnvelope(fields, "zh-CN", "default-time", bytes.NewReader(nil))
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range fields {
		if got[key] != want {
			t.Errorf("%s = %v, want %v", key, got[key], want)
		}
	}
}

func TestUnknownLineProvidersAreIneligible(t *testing.T) {
	t.Parallel()
	for _, profile := range []providerProfile{iosClientProfile{}, windowsClientProfile{}} {
		t.Run(fmt.Sprint(profile.id()), func(t *testing.T) {
			fields := windowsRawFields(t, map[string]any{
				"groups": []any{map[string]any{"id": "g", "name": "group"}},
				"lines": []any{
					map[string]any{"host": "wifiin.example", "port": 11000, "provider": "WIFIIN", "password": wireprofile.WindowsTunnelPassword, "groupId": "g"},
					map[string]any{"host": "other.example", "port": 12000, "provider": "FUTURE", "groupId": "g"},
				},
			})
			lines, err := validateLinesForProfile(fields, "zh-CN", profile)
			if err != nil || len(lines.Lines) != 2 || !lines.Lines[0].Eligible || lines.Lines[1].Eligible {
				t.Fatalf("line eligibility = %#v, %v", lines, err)
			}
		})
	}
}

func windowsRawFields(t *testing.T, values map[string]any) map[string]json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	return fields
}
