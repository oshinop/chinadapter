package transocks

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/oshinop/chinadapter/internal/provider"
)

func fixtureSSConfig(host string, port int, password string) tunnelConfig {
	return tunnelConfig{Proto: new(0), Host: "detect.invalid", ProxyIP: "192.0.2.99", SS: &ssConfig{Server: host, Port: port, Method: "chacha20-ietf-poly1305", Password: password}}
}

func fixtureTrojanConfig(websocket bool) tunnelConfig {
	remote := trojanRemoteConfig{RemoteAddr: "TROJAN.EXAMPLE.INVALID.", RemotePort: 443, Passwords: []string{"trojan-first-password", "not-selected-password"}}
	remote.SSL.SNI, remote.SSL.Verify = "sni.example.invalid", new(true)
	remote.WebSocket.Enabled, remote.WebSocket.Host, remote.WebSocket.Path = websocket, "ws.example.invalid", "/proxy?mode=1"
	data, _ := json.Marshal(remote)
	return tunnelConfig{Proto: new(5), Host: "detect.invalid", ProxyIP: "192.0.2.99", InJSON: string(data)}
}

func TestCatalogParsingAndEligibility(t *testing.T) {
	// Preserve live capitalization and nullable metadata; auto choices are
	// catalog entries, not physical tunnel endpoints.
	var catalog catalog
	err := json.Unmarshal([]byte(`{"code":0,"lines":[{"id":-1,"name":"Auto","isFree":true,"detectPort":null},{"id":21,"name":"Shanghai","enName":"Shanghai","category":"VIP","location":"Shanghai","domain":"detect.example.invalid","iPAddr":"192.0.2.10","detectPort":80,"isFree":false},{"id":22,"name":"Free","category":null,"location":null,"isFree":true}]}`), &catalog)
	if err != nil || catalog.validate() != nil {
		t.Fatal("valid catalog was rejected", err)
	}
	if catalog.Lines[1].IPAddr != "192.0.2.10" || catalog.Lines[1].DetectPort == nil || *catalog.Lines[1].DetectPort != 80 || catalog.Lines[0].DetectPort != nil || catalog.Lines[1].group() != "VIP / Shanghai" {
		t.Fatal("catalog fields differ")
	}
	profile := accountPayload{Expired: new(true), IsRealname: new(true), PasswordSetup: new(true)}
	account := provider.Account{}
	if catalog.Lines[0].eligible(profile, account) || catalog.Lines[1].eligible(profile, account) || !catalog.Lines[2].eligible(profile, account) {
		t.Fatal("free/paid/auto eligibility differs")
	}
	account.SubscriptionActive = true
	if !catalog.Lines[1].eligible(profile, account) {
		t.Fatal("paid line not admitted for membership")
	}
	profile.IsRealname = new(false)
	if catalog.Lines[2].eligible(profile, account) {
		t.Fatal("realname gate ignored")
	}
	profile.RealnameGraceState = new(1)
	if !catalog.Lines[2].eligible(profile, account) {
		t.Fatal("realname grace ignored")
	}
	profile.PasswordSetup, profile.Email = new(false), "fixture@example.invalid"
	if catalog.Lines[2].eligible(profile, account) {
		t.Fatal("password-setup gate ignored")
	}
	catalog.Lines = append(catalog.Lines, catalog.Lines[1])
	if !errors.Is(catalog.validate(), ErrSchema) {
		t.Fatal("duplicate line id accepted")
	}
}

func TestConfigMapsActualEndpointAndProtocol(t *testing.T) {
	config, err := parseTunnelConfig(fixtureSSConfig("SS.EXAMPLE.INVALID.", 12345, "ss-password"))
	if err != nil {
		t.Fatal(err)
	}
	if config.Host != "ss.example.invalid" || config.Port != 12345 || config.Protocol != ShadowsocksProtocol || config.SS.Password != "ss-password" {
		t.Fatal("SS endpoint or authority mapping differs")
	}
	for _, websocket := range []bool{false, true} {
		config, err := parseTunnelConfig(fixtureTrojanConfig(websocket))
		if err != nil {
			t.Fatal(err)
		}
		entry := config.Trojan
		if config.Host != "trojan.example.invalid" || config.Port != 443 || config.Protocol != TrojanProtocol || entry.Password != "trojan-first-password" || entry.SNI != "sni.example.invalid" || !entry.Verify {
			t.Fatal("Trojan endpoint or authority mapping differs")
		}
		if websocket {
			if entry.WebSocket == nil || entry.WebSocket.Host != "ws.example.invalid" || entry.WebSocket.Path != "/proxy?mode=1" {
				t.Fatal("WebSocket mapping differs")
			}
		} else if entry.WebSocket != nil {
			t.Fatal("disabled WebSocket was enabled")
		}
	}
	for _, proto := range []int{1, 2, 3, 6, -1, 9} {
		config := fixtureSSConfig("ss.example.invalid", 12345, "ss-password")
		config.Proto = new(proto)
		parsed, err := parseTunnelConfig(config)
		if err != nil || parsed.Protocol != "" {
			t.Fatal("unsupported protocol was relabeled", proto)
		}
	}
}

func TestConfigRejectsMalformedAuthority(t *testing.T) {
	validSS := fixtureSSConfig("ss.example.invalid", 12345, "password")
	for _, mutate := range []func(*tunnelConfig){
		func(config *tunnelConfig) { config.Proto = nil },
		func(config *tunnelConfig) { config.SS = nil },
		func(config *tunnelConfig) { config.SS.Port = 65536 },
		func(config *tunnelConfig) { config.SS.Port = 0 },
		func(config *tunnelConfig) { config.SS.Method = "aes-256-cfb" },
		func(config *tunnelConfig) { config.SS.Password = "" },
		func(config *tunnelConfig) { config.SS.Server = "bad/host" },
	} {
		config := validSS
		ss := *validSS.SS
		config.SS = &ss
		mutate(&config)
		if _, err := parseTunnelConfig(config); !errors.Is(err, ErrSchema) {
			t.Fatal("malformed SS config accepted", err)
		}
	}
	for _, inJSON := range []string{
		`{`,
		`{"remote_addr":"trojan.invalid","remote_port":443,"password":[],"ssl":{"verify":true}}`,
		`{"remote_addr":"trojan.invalid","remote_port":443,"password":["password"],"ssl":{}}`,
		`{"remote_addr":"trojan.invalid","remote_port":70000,"password":["password"],"ssl":{"verify":true}}`,
		`{"remote_addr":"trojan.invalid","remote_port":443,"password":["password"],"ssl":{"verify":true},"websocket":{"enabled":true,"path":"bad-relative-path"}}`,
	} {
		if _, err := parseTunnelConfig(tunnelConfig{Proto: new(5), InJSON: inJSON}); !errors.Is(err, ErrSchema) {
			t.Fatal("malformed Trojan config accepted", err)
		}
	}
}

func TestAccountMembershipNotAdvertisementExpiry(t *testing.T) {
	for _, test := range []struct {
		profile accountPayload
		tier    string
		active  bool
	}{
		{accountPayload{UserID: 42, Expired: new(true), IsProUser: new(true), ExpireAtTime: 2000000000}, "Free", false},
		{accountPayload{UserID: 42, Expired: new(false), ExpireAtTime: 2000000000}, "VIP", true},
		{accountPayload{UserID: 42, Expired: new(false), IsProUser: new(true), ExpireAt: "2033-05-18 11:33:20"}, "Pro", true},
	} {
		account, err := test.profile.account("f•••@example.invalid", fixtureNow)
		if err != nil || account.Tier != test.tier || account.SubscriptionActive != test.active || !account.Valid() {
			t.Fatal("membership mapping differs", account, err)
		}
		if !test.active && !account.SubscriptionEndsAt.IsZero() {
			t.Fatal("inactive subscription retained expiry")
		}
	}
	for _, profile := range []accountPayload{
		{UserID: 42},
		{UserID: 42, Expired: new(false)},
		{UserID: 42, Expired: new(false), ExpireAtTime: fixtureNow.Add(-time.Hour).Unix()},
	} {
		if _, err := profile.account("•••", fixtureNow); !errors.Is(err, ErrSchema) {
			t.Fatal("incomplete active account accepted")
		}
	}
}

func TestConnectResponseConfigDiscriminator(t *testing.T) {
	config := fixtureSSConfig("ss.example.invalid", 12345, "password")
	for _, response := range []connectResponse{{Config: &config}, {Configs: []tunnelConfig{config}}} {
		configs, err := response.configurations()
		if err != nil || len(configs) != 1 {
			t.Fatal("valid config response rejected")
		}
	}
	for _, response := range []connectResponse{{}, {Config: &config, Configs: []tunnelConfig{config}}} {
		if _, err := response.configurations(); !errors.Is(err, ErrSchema) {
			t.Fatal("ambiguous or empty config response accepted")
		}
	}
	if _, err := parseTunnelConfig(tunnelConfig{Proto: new(5), InJSON: strings.Repeat("x", maxControlBytes+1)}); !errors.Is(err, ErrSchema) {
		t.Fatal("oversized inJson accepted")
	}
}
