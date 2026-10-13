package kuaifan

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/oshinop/chinadapter/internal/provider"
	wireprofile "github.com/oshinop/chinadapter/internal/provider/kuaifan/profile"
)

func TestWindowsAuthorityUsesDecryptedUserAndRejectsMalformedMaterial(t *testing.T) {
	for _, test := range []struct {
		name    string
		key     any
		encoded string
		want    error
	}{
		{name: "numeric user", key: map[string]any{"userId": 1}},
		{name: "string user", key: map[string]any{"userId": "1"}},
		{name: "mismatched user", key: map[string]any{"userId": 2}, want: ErrSchema},
		{name: "missing user", key: map[string]any{}, want: ErrSchema},
		{name: "zero user", key: map[string]any{"userId": 0}, want: ErrSchema},
		{name: "fractional user", key: map[string]any{"userId": 1.5}, want: ErrSchema},
		{name: "invalid ciphertext", encoded: "not-base64", want: ErrMalformedCiphertext},
	} {
		t.Run(test.name, func(t *testing.T) {
			authKey := test.encoded
			if test.key != nil {
				encoded, err := AuthorityCodec().EncodeJSON(test.key)
				if err != nil {
					t.Fatal(err)
				}
				authKey = string(encoded)
			}
			_, client := testControlClients(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
				return encryptedHTTPResponse(t, envelope(map[string]any{"authKey": authKey, "token": "authority-token"})), nil
			}))
			base, _ := url.Parse("https://api.example")
			authority, err := client.FetchAuthority(t.Context(), LoginSession{UserID: 1, Token: "session-token", APIBase: base})
			if test.want != nil {
				if !errors.Is(err, test.want) {
					t.Fatalf("authority error = %v, want %v", err, test.want)
				}
				return
			}
			if err != nil || authority.UserID != "1" || authority.ProviderToken != "authority-token" || authority.EncryptKey != "" || authority.ProviderExtension != "" {
				t.Fatal("beta authority must extract only its own credential fields")
			}
		})
	}
}

func TestSPEEDINAuthorityUsesCanonicalPasswordsAndCurrentSessionToken(t *testing.T) {
	profile := completeProfile{
		session:   LoginSession{UserID: 1, Token: "rotated-session-token"},
		authority: Authority{UserID: "1", ProviderToken: "different-authority-token"},
		lines: Lines{Lines: []Line{
			{Host: "Node.Example.", Port: 11000, Provider: "SPEEDIN", Method: "aes-128-gcm", Password: "first-password", Eligible: true},
			{Host: "node.example", Port: 11000, Provider: "SPEEDIN", Method: "aes-128-gcm", Password: "first-password", Eligible: true},
			{Host: "2001:db8::1", Port: 12000, Provider: "SPEEDIN", Method: "aes-128-gcm", Password: "second-password", Eligible: true},
			{Host: "ineligible.example", Port: 11000},
		}},
	}
	encoded, err := speedinAuthorityFromProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := decodeSPEEDINAuthority(encoded.Data)
	if err != nil || encoded.Protocol != SPEEDINProtocol || authority.UserID != 1 || authority.Token != profile.session.Token || authority.OS != "WINDOWS" || authority.Method != "aes-128-gcm" || !reflect.DeepEqual(authority.Passwords, map[string]string{
		speedinNodeKey("node.example", 11000): "first-password",
		speedinNodeKey("2001:db8::1", 12000):  "second-password",
	}) {
		t.Fatal("SPEEDIN authority credentials are not bound to canonical selected nodes and current session")
	}
	profile.lines.Lines[1].Password = "conflicting-password"
	if _, err := speedinAuthorityFromProfile(profile); !errors.Is(err, ErrInvalidLine) {
		t.Fatalf("canonical endpoint with conflicting passwords error = %v", err)
	}
	profile.lines.Lines[1].Password = strings.Repeat("x", maxControlFieldBytes+1)
	profile.lines.Lines = profile.lines.Lines[1:2]
	if _, err := speedinAuthorityFromProfile(profile); !errors.Is(err, ErrInvalidAuthority) {
		t.Fatalf("oversized password error = %v", err)
	}
}

func TestLegacyWindowsWIFIINRefreshStateMigratesAtomically(t *testing.T) {
	current := lifecycleSnapshot()
	current.Authorities["windows"] = provider.Authority{Protocol: WIFIINProtocol, Data: []byte(`{"password":"wifiin1234","method":"aes-256-cfb","extension":"legacy"}`)}
	current.Nodes = append(current.Nodes, provider.Node{ID: "legacy-windows", AuthorityID: "windows", Protocol: WIFIINProtocol, Host: "windows.example", Port: 11000, Eligible: true})
	before := current.Clone()
	authKey := encodedAuthority(t, "1", "ios-password", "ios-order")
	ios, windows := testControlClients(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return lifecycleResponse(t, request, authKey), nil
	}))
	next, err := lifecycleDriver(t, ios, windows).Refresh(context.Background(), current)
	if err != nil || !next.Valid() || next.Authorities["windows"].Protocol != SPEEDINProtocol || !reflect.DeepEqual(current, before) {
		t.Fatalf("legacy migration failed or mutated prior generation: %v", err)
	}
	windowsAuthority, err := decodeSPEEDINAuthority(next.Authorities["windows"].Data)
	if err != nil || windowsAuthority.Token != "windows-new" {
		t.Fatal("migration did not adopt the current refreshed session token")
	}
	for _, node := range next.Nodes {
		if node.AuthorityID == string(wireprofile.WindowsID) && (node.Protocol != SPEEDINProtocol || node.ID == "legacy-windows") {
			t.Fatal("legacy Windows node identity survived migration")
		}
	}
	// A failed beta catalog fetch cannot publish a partially migrated catalog.
	ios, windows = testControlClients(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("User-Agent") == wireprofile.WindowsUserAgent && request.URL.Path == "/v4/invpn/getLines.do" {
			return nil, ErrSchema
		}
		return lifecycleResponse(t, request, authKey), nil
	}))
	partial, err := lifecycleDriver(t, ios, windows).Refresh(context.Background(), current)
	if !errors.Is(err, ErrSchema) || partial.Valid() || partial.Nodes != nil || partial.Authorities != nil || !reflect.DeepEqual(current, before) {
		t.Fatal("failed migration published a replacement or mutated the prior generation")
	}
}

func TestDualProfileLoginRejectsDifferentUserIDs(t *testing.T) {
	ios, windows := testControlClients(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/v4/client/conf.do" {
			return encryptedHTTPResponse(t, envelope(map[string]any{})), nil
		}
		userID := 1
		if request.Header.Get("User-Agent") == wireprofile.WindowsUserAgent {
			userID = 2
		}
		return encryptedHTTPResponse(t, envelope(map[string]any{"userId": userID, "token": "session", "isVip": false, "vipEndTime": 0})), nil
	}))
	_, err := lifecycleDriver(t, ios, windows).Login(t.Context(), provider.Credentials{InstallationID: "00112233445566778899aabbccddeeff", Fields: map[string]string{provider.FieldAccount: "person@example.test", provider.FieldPassword: "password"}})
	if !errors.Is(err, ErrSchema) {
		t.Fatalf("different profile account IDs error = %v", err)
	}
}
