package transocks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oshinop/chinadapter/internal/provider"
)

func fixtureDriver(t *testing.T, handler http.HandlerFunc) *Driver {
	t.Helper()
	driver, err := NewDriver(DriverConfig{Client: fixtureClient(t, handler), Clock: func() time.Time { return fixtureNow }})
	if err != nil {
		t.Fatal(err)
	}
	return driver
}

func writeFixtureProfile(w http.ResponseWriter) {
	fmt.Fprint(w, `{"code":0,"user_id":42,"expired":false,"expire_at_time":2000000000,"expire_at":"2033-05-18 11:33:20","is_pro_user":true,"is_realname":true,"password_setup":true,"is_device_login":false,"email":"fixture@example.invalid","remaining_days":100,"ads_free":true}`)
}

func writeFixtureLogin(w http.ResponseWriter) {
	fmt.Fprint(w, `{"code":0,"user_id":42,"expired":false,"token":{"access_token":"fixture-token","token_type":"Bearer","exp":2000000000}}`)
}

func writeFixtureCatalog(w http.ResponseWriter) {
	fmt.Fprint(w, `{"code":0,"lines":[{"id":-1,"name":"Auto","isFree":true},{"id":21,"name":"Shanghai","category":"Pro","location":"Shanghai","isFree":false,"domain":"detect.invalid","iPAddr":"192.0.2.10","detectPort":80},{"id":22,"name":"Guangzhou","category":"VIP","location":"Guangzhou","isFree":false},{"id":23,"name":"Unsupported GTS","category":"Free","isFree":true}]}`)
}

func writeFixtureConnect(w http.ResponseWriter, config tunnelConfig) {
	json.NewEncoder(w).Encode(struct {
		Code int `json:"code"`
		connectResponse
	}{connectResponse: connectResponse{BoostSession: "fixture-boost-session", Config: &config}})
}

func TestDriverLoginAndRefreshSnapshot(t *testing.T) {
	var loginCalls, connectCalls atomic.Int32
	driver := fixtureDriver(t, func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/1/login" && request.Header.Get("Authorization") != "Bearer fixture-token" {
			t.Error("refresh lost token")
		}
		switch request.URL.Path {
		case "/api/1/login":
			loginCalls.Add(1)
			writeFixtureLogin(w)
		case "/api/1/user/misc-info":
			writeFixtureProfile(w)
		case "/api/2/line":
			if request.URL.Query().Get("requestAll") != "true" || request.URL.Query().Get("package_name") != "com.fobwifi.transocks" {
				t.Error("missing catalog query")
			}
			writeFixtureCatalog(w)
		case "/api/2/line/connect/21", "/api/2/line/connect/22", "/api/2/line/connect/23":
			connectCalls.Add(1)
			var payload connectRequest
			if json.NewDecoder(request.Body).Decode(&payload) != nil || payload.Proto != "SS" || len(payload.Methods) != 1 || payload.Methods[0] != "chacha20-ietf-poly1305" || len(payload.AvailableProto) != 2 || payload.AvailableProto[1] != "Trojan" || !payload.valid() {
				t.Error("incorrect connect protocol or metadata")
			}
			if strings.HasSuffix(request.URL.Path, "/21") {
				writeFixtureConnect(w, fixtureSSConfig("SS.EXAMPLE.INVALID.", 12345+int(connectCalls.Load()), "fixture-ss-password"))
			} else if strings.HasSuffix(request.URL.Path, "/22") {
				writeFixtureConnect(w, fixtureTrojanConfig(true))
			} else {
				writeFixtureConnect(w, tunnelConfig{Proto: new(1)})
			}
		default:
			t.Error("unexpected path", request.URL.Path)
			http.NotFound(w, request)
		}
	})
	snapshot, err := driver.Login(context.Background(), provider.Credentials{Account: "fixture@example.invalid", Password: "never-retain-login-password", InstallationID: "fixture-installation"})
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.ValidateSnapshot(snapshot, ProviderID, fixtureNow); err != nil {
		t.Fatal(err)
	}
	if driver.ID() != ProviderID || len(snapshot.Nodes) != 2 || len(snapshot.Authorities) != 2 || snapshot.Account.Tier != "Pro" || snapshot.Account.Display != "f•••@example.invalid" || !snapshot.ExpiresAt.Equal(fixtureNow.Add(time.Hour)) || connectCalls.Load() != 3 {
		t.Fatal("snapshot mapping differs")
	}
	for _, secret := range []string{"never-retain-login-password", "fixture-ss-password", "trojan-first-password", "fixture-boost-session", "fixture@example.invalid"} {
		if strings.Contains(string(snapshot.RefreshState), secret) {
			t.Fatal("refresh retained account credentials or tunnel secrets")
		}
	}
	var state map[string]json.RawMessage
	if json.Unmarshal(snapshot.RefreshState, &state) != nil || len(state) != 4 || state["token"] == nil || state["token_type"] == nil || state["metadata"] == nil || state["protocols"] == nil {
		t.Fatal("refresh state must contain token/type/metadata/protocols only")
	}
	for index, node := range snapshot.Nodes {
		session, lineID, err := authorityFor(snapshot.Authorities[node.AuthorityID].Data, node.Host, node.Port)
		if err != nil || !session.valid() || lineID != int64(21+index) || node.Host != fmt.Sprintf("line-%d.transocks.invalid", lineID) || node.Port != 1 {
			t.Fatal("authority did not pin the stable catalog line")
		}
		// Probes dial the catalog detect endpoint, never the synthetic route or
		// a connect slot; line 22 advertises none.
		probe, err := probeAddress(snapshot.Authorities[node.AuthorityID].Data, node.Host, node.Port)
		if lineID == 21 && (err != nil || probe != "192.0.2.10:80") || lineID == 22 && !errors.Is(err, ErrNoProbeAddress) {
			t.Fatalf("line %d probe address = %q, %v", lineID, probe, err)
		}
		for _, secret := range []string{"fixture-ss-password", "trojan-first-password", "fixture-boost-session", "never-retain-login-password"} {
			if strings.Contains(string(snapshot.Authorities[node.AuthorityID].Data), secret) {
				t.Fatal("authority retained tunnel or login secrets")
			}
		}
	}
	nodesJSON, _ := json.Marshal(snapshot.Nodes)
	for _, secret := range []string{"fixture-token", "fixture-ss-password", "trojan-first-password", "fixture-boost-session"} {
		if strings.Contains(string(nodesJSON), secret) {
			t.Fatal("node metadata contains authority")
		}
	}
	// A new connect returns a different endpoint. Catalog route identities must
	// remain unchanged and Refresh must not reconnect any known line.
	if _, _, err := driver.client.sessions.resolve(context.Background(), fixtureSession(t), 21, nil); err != nil {
		t.Fatal(err)
	}
	refreshed, err := driver.Refresh(context.Background(), snapshot)
	if err != nil || !refreshed.Valid() {
		t.Fatal("refresh failed", err)
	}
	if loginCalls.Load() != 1 || connectCalls.Load() != 4 || string(snapshot.RefreshState) != string(refreshed.RefreshState) || snapshot.Nodes[0].ID != refreshed.Nodes[0].ID || snapshot.Nodes[1].ID != refreshed.Nodes[1].ID {
		t.Fatal("refresh logged in, connected known lines, or changed stable identity")
	}
}

func TestDriverRefreshAuthAndTransientFailures(t *testing.T) {
	for _, phase := range []string{"misc", "catalog"} {
		for _, code := range []int{20001, 40015, 40022} {
			t.Run(fmt.Sprintf("%s/%d", phase, code), func(t *testing.T) {
				var reject atomic.Bool
				driver := fixtureDriver(t, func(w http.ResponseWriter, request *http.Request) {
					path := request.URL.Path
					match := phase == "misc" && path == "/api/1/user/misc-info" || phase == "catalog" && path == "/api/2/line" || phase == "connect" && strings.HasPrefix(path, "/api/2/line/connect/")
					if reject.Load() && match {
						fmt.Fprintf(w, `{"code":%d}`, code)
						return
					}
					switch path {
					case "/api/1/login":
						writeFixtureLogin(w)
					case "/api/1/user/misc-info":
						writeFixtureProfile(w)
					case "/api/2/line":
						fmt.Fprint(w, `{"code":0,"lines":[{"id":21,"name":"Shanghai","isFree":false}]}`)
					default:
						writeFixtureConnect(w, fixtureSSConfig("ss.example.invalid", 12345, "password"))
					}
				})
				current, err := driver.Login(context.Background(), provider.Credentials{Account: "fixture@example.invalid", Password: "password", InstallationID: "installation"})
				if err != nil {
					t.Fatal(err)
				}
				reject.Store(true)
				_, err = driver.Refresh(context.Background(), current)
				want := provider.ErrSessionRejected
				if code == 40022 {
					want = ErrBusinessCode
				}
				if !errors.Is(err, want) {
					t.Fatal("wrong refresh failure classification", err)
				}
				if code == 40022 && errors.Is(err, provider.ErrSessionRejected) {
					t.Fatal("line capacity rejected account token")
				}
			})
		}
	}
}

func TestDriverLoginRejectedAndInvalidState(t *testing.T) {
	driver := fixtureDriver(t, func(w http.ResponseWriter, request *http.Request) { fmt.Fprint(w, `{"code":40001}`) })
	if _, err := driver.Login(context.Background(), provider.Credentials{Account: "fixture@example.invalid", Password: "wrong", InstallationID: "installation"}); !errors.Is(err, provider.ErrLoginRejected) {
		t.Fatal("bad credentials not classified", err)
	}
	if _, err := driver.Refresh(context.Background(), provider.Snapshot{}); !errors.Is(err, provider.ErrNoSession) {
		t.Fatal("invalid refresh state accepted", err)
	}
	if _, err := NewDriver(DriverConfig{}); err == nil {
		t.Fatal("nil client accepted")
	}
	for _, data := range [][]byte{nil, []byte(`{`), []byte(`{"token":"token","token_type":"Bearer","metadata":{}}`)} {
		if _, err := decodeStoredSession(data); !errors.Is(err, ErrSchema) {
			t.Fatal("invalid session accepted", err)
		}
	}
}

func TestDriverKeepsDistinctCatalogLinesWithSharedTunnelEndpoints(t *testing.T) {
	driver := fixtureDriver(t, func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/1/login":
			writeFixtureLogin(w)
		case "/api/1/user/misc-info":
			writeFixtureProfile(w)
		case "/api/2/line":
			fmt.Fprint(w, `{"code":0,"lines":[{"id":21,"name":"First","isFree":true},{"id":22,"name":"Second","isFree":true}]}`)
		default:
			writeFixtureConnect(w, fixtureSSConfig("ss.example.invalid", 12345, request.URL.Path))
		}
	})
	snapshot, err := driver.Login(context.Background(), provider.Credentials{Account: "fixture@example.invalid", Password: "password", InstallationID: "installation"})
	if err != nil || !snapshot.Valid() || len(snapshot.Nodes) != 2 || snapshot.Nodes[0].ID == snapshot.Nodes[1].ID {
		t.Fatal("distinct catalog lines were merged by rotating tunnel endpoint", err)
	}
}

func TestDriverNoUsableProtocolsDoesNotInventAuthority(t *testing.T) {
	driver := fixtureDriver(t, func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/1/login":
			writeFixtureLogin(w)
		case "/api/1/user/misc-info":
			writeFixtureProfile(w)
		case "/api/2/line":
			fmt.Fprint(w, `{"code":0,"lines":[{"id":21,"name":"GTS","isFree":true}]}`)
		default:
			writeFixtureConnect(w, tunnelConfig{Proto: new(1)})
		}
	})
	if _, err := driver.Login(context.Background(), provider.Credentials{Account: "fixture@example.invalid", Password: "password", InstallationID: "installation"}); !errors.Is(err, ErrNoUsableNodes) {
		t.Fatal("unsupported protocols became usable", err)
	}
}

func TestDriverRefreshRejectsChangedAccountBeforeConnect(t *testing.T) {
	var changed atomic.Bool
	var connects atomic.Int32
	driver := fixtureDriver(t, func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/1/login":
			writeFixtureLogin(w)
		case "/api/1/user/misc-info":
			if changed.Load() {
				fmt.Fprint(w, `{"code":0,"user_id":43,"expired":true}`)
			} else {
				writeFixtureProfile(w)
			}
		case "/api/2/line":
			fmt.Fprint(w, `{"code":0,"lines":[{"id":21,"name":"Shanghai","isFree":true}]}`)
		default:
			connects.Add(1)
			writeFixtureConnect(w, fixtureSSConfig("ss.example.invalid", 12345, "password"))
		}
	})
	current, err := driver.Login(context.Background(), provider.Credentials{Account: "fixture@example.invalid", Password: "password", InstallationID: "installation"})
	if err != nil {
		t.Fatal(err)
	}
	changed.Store(true)
	if _, err := driver.Refresh(context.Background(), current); !errors.Is(err, provider.ErrNoSession) {
		t.Fatal("changed account accepted", err)
	}
	if connects.Load() != 1 {
		t.Fatal("refresh acquired another account's tunnel authority")
	}
	current.RefreshState = []byte(`{"token":"invalid-state"}`)
	if _, err := driver.Refresh(context.Background(), current); !errors.Is(err, provider.ErrNoSession) {
		t.Fatal("malformed stored session accepted", err)
	}
}
