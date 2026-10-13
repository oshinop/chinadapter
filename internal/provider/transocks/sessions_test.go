package transocks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/oshinop/chinadapter/internal/provider"
)

func testTunnel(t *testing.T, protocol provider.Protocol, host string, port uint16, config tunnelConfig) (provider.Authority, *SessionManager) {
	t.Helper()
	client := fixtureClient(t, func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/2/line/connect/21" || request.Header.Get("Authorization") != "Bearer fixture-token" {
			t.Error("relay did not connect the pinned line")
		}
		writeFixtureConnect(w, config)
	})
	authority, err := encodeAuthority(protocol, fixtureSession(t), map[string]int64{nodeKey(host, port): 21}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return authority, client.sessions
}

func testSSTunnel(t *testing.T, host string, port uint16, entry shadowsocksEntry) (provider.Authority, *SessionManager) {
	t.Helper()
	config := fixtureSSConfig(host, int(port), entry.Password)
	config.SS.Method = entry.Method
	return testTunnel(t, ShadowsocksProtocol, host, port, config)
}

func testTrojanTunnel(t *testing.T, host string, port uint16, entry trojanEntry) (provider.Authority, *SessionManager) {
	t.Helper()
	remote := trojanRemoteConfig{RemoteAddr: host, RemotePort: int(port), Passwords: []string{entry.Password}}
	remote.SSL.SNI, remote.SSL.Verify = entry.SNI, &entry.Verify
	if entry.WebSocket != nil {
		remote.WebSocket.Enabled, remote.WebSocket.Host, remote.WebSocket.Path = true, entry.WebSocket.Host, entry.WebSocket.Path
	}
	data, err := json.Marshal(remote)
	if err != nil {
		t.Fatal(err)
	}
	return testTunnel(t, TrojanProtocol, host, port, tunnelConfig{Proto: new(5), InJSON: string(data)})
}

func TestSessionManagerLRU(t *testing.T) {
	var calls atomic.Int32
	client := fixtureClient(t, func(w http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		writeFixtureConnect(w, fixtureSSConfig("127.0.0.1", 12345, "password"))
	})
	session := fixtureSession(t)
	for _, id := range []int64{1, 2, 1, 3} {
		if _, _, err := client.sessions.resolve(context.Background(), session, id, nil); err != nil {
			t.Fatal(err)
		}
	}
	manager := client.sessions
	manager.mu.Lock()
	_, first := manager.cache[keyFor(session, 1)]
	_, second := manager.cache[keyFor(session, 2)]
	_, third := manager.cache[keyFor(session, 3)]
	size := len(manager.cache)
	manager.mu.Unlock()
	if calls.Load() != 3 || size != 2 || !first || second || !third {
		t.Fatalf("calls=%d size=%d presence=%v/%v/%v", calls.Load(), size, first, second, third)
	}
	if _, cached, err := manager.resolve(context.Background(), session, 2, nil); err != nil || cached || calls.Load() != 4 {
		t.Fatalf("evicted line was not reconnected: cached=%v calls=%d err=%v", cached, calls.Load(), err)
	}
}

func TestSessionManagerCoalescesConnect(t *testing.T) {
	var calls atomic.Int32
	started, release := make(chan struct{}), make(chan struct{})
	client := fixtureClient(t, func(w http.ResponseWriter, request *http.Request) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		writeFixtureConnect(w, fixtureSSConfig("127.0.0.1", 12345, "password"))
	})
	session := fixtureSession(t)
	var group sync.WaitGroup
	errors := make(chan error, 32)
	for range 32 {
		group.Add(1)
		go func() {
			defer group.Done()
			_, _, err := client.sessions.resolve(context.Background(), session, 21, nil)
			errors <- err
		}()
	}
	<-started
	close(release)
	group.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("connect calls=%d", calls.Load())
	}
}

func TestSessionManagerCachedRefusalReconnectsOnce(t *testing.T) {
	for _, failure := range []error{syscall.ECONNREFUSED, syscall.ECONNRESET} {
		for _, retryFails := range []bool{false, true} {
			t.Run(fmt.Sprintf("%v/retry-fails=%v", failure, retryFails), func(t *testing.T) {
				var calls atomic.Int32
				client := fixtureClient(t, func(w http.ResponseWriter, request *http.Request) {
					port := 12340 + calls.Add(1)
					writeFixtureConnect(w, fixtureSSConfig("127.0.0.1", int(port), "password"))
				})
				session := fixtureSession(t)
				if _, _, err := client.sessions.resolve(context.Background(), session, 21, nil); err != nil {
					t.Fatal(err)
				}
				authority, err := encodeAuthority(ShadowsocksProtocol, session, map[string]int64{"line-21.transocks.invalid:1": 21}, nil)
				if err != nil {
					t.Fatal(err)
				}
				var dials int
				var peer net.Conn
				connection, _, err := client.sessions.dialShadowsocks(context.Background(), authority.Data, "line-21.transocks.invalid", 1, func(_ context.Context, network, address string) (net.Conn, error) {
					dials++
					if network != "tcp" || address != "127.0.0.1:"+strconv.Itoa(12340+dials) {
						t.Error("did not dial returned endpoint")
					}
					if dials == 1 || retryFails {
						return nil, &net.OpError{Op: "dial", Net: "tcp", Err: failure}
					}
					var conn net.Conn
					conn, peer = net.Pipe()
					return conn, nil
				}, "tcp", time.Second)
				if connection != nil {
					_ = connection.Close()
					_ = peer.Close()
				}
				if dials != 2 || calls.Load() != 2 || (retryFails && !errors.Is(err, failure)) || (!retryFails && err != nil) {
					t.Fatalf("dials=%d connects=%d err=%v", dials, calls.Load(), err)
				}
			})
		}
	}
}

func TestSessionManagerRejectionAndProtocolMismatch(t *testing.T) {
	for _, code := range []int{20001, 40015, 40022, 0} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			var calls atomic.Int32
			client := fixtureClient(t, func(w http.ResponseWriter, request *http.Request) {
				calls.Add(1)
				if code == 0 {
					writeFixtureConnect(w, fixtureTrojanConfig(false))
				} else {
					fmt.Fprintf(w, `{"code":%d}`, code)
				}
			})
			authority, err := encodeAuthority(ShadowsocksProtocol, fixtureSession(t), map[string]int64{"line-21.transocks.invalid:1": 21}, nil)
			if err != nil {
				t.Fatal(err)
			}
			dials := 0
			_, _, err = client.sessions.dialShadowsocks(context.Background(), authority.Data, "line-21.transocks.invalid", 1, func(context.Context, string, string) (net.Conn, error) {
				dials++
				return nil, errors.New("must not dial")
			}, "tcp", time.Second)
			want := provider.ErrSessionRejected
			if code == 40022 {
				want = ErrBusinessCode
			}
			if code == 0 {
				want = ErrProtocolMismatch
			}
			if !errors.Is(err, want) || calls.Load() != 1 || dials != 0 {
				t.Fatalf("err=%v calls=%d dials=%d", err, calls.Load(), dials)
			}
		})
	}
}

func TestNewLineProtocolIsLearnedLazily(t *testing.T) {
	var expanded atomic.Bool
	var calls atomic.Int32
	driver := fixtureDriver(t, func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/1/login":
			writeFixtureLogin(w)
		case "/api/1/user/misc-info":
			writeFixtureProfile(w)
		case "/api/2/line":
			if expanded.Load() {
				fmt.Fprint(w, `{"code":0,"lines":[{"id":21,"name":"SS","isFree":true},{"id":22,"name":"Trojan","isFree":true}]}`)
			} else {
				fmt.Fprint(w, `{"code":0,"lines":[{"id":21,"name":"SS","isFree":true}]}`)
			}
		default:
			calls.Add(1)
			if strings.HasSuffix(request.URL.Path, "/22") {
				writeFixtureConnect(w, fixtureTrojanConfig(false))
			} else {
				writeFixtureConnect(w, fixtureSSConfig("127.0.0.1", 12345, "password"))
			}
		}
	})
	current, err := driver.Login(context.Background(), provider.Credentials{Account: "fixture@example.invalid", Password: "password", InstallationID: "installation"})
	if err != nil {
		t.Fatal(err)
	}
	expanded.Store(true)
	current, err = driver.Refresh(context.Background(), current)
	if err != nil || calls.Load() != 1 || len(current.Nodes) != 2 || current.Nodes[1].Protocol != ShadowsocksProtocol {
		t.Fatalf("lazy discovery failed: calls=%d err=%v", calls.Load(), err)
	}
	node := current.Nodes[1]
	_, _, err = driver.client.sessions.dialShadowsocks(context.Background(), current.Authorities[node.AuthorityID].Data, node.Host, node.Port, func(context.Context, string, string) (net.Conn, error) {
		t.Error("mismatched protocol dialed")
		return nil, errors.New("must not dial")
	}, "tcp", time.Second)
	if !errors.Is(err, ErrProtocolMismatch) {
		t.Fatal(err)
	}
	current, err = driver.Refresh(context.Background(), current)
	if err != nil || calls.Load() != 2 || current.Nodes[1].Protocol != TrojanProtocol {
		t.Fatalf("observed Trojan was not corrected: calls=%d err=%v", calls.Load(), err)
	}
}

func TestSessionManagerReconnectsRefusedLoopbackEndpoint(t *testing.T) {
	staleListener := listenTestTCP(t)
	staleHost, stalePort := testEndpoint(t, staleListener.Addr())
	liveListener := listenTestTCP(t)
	liveHost, livePort := testEndpoint(t, liveListener.Addr())
	var calls atomic.Int32
	client := fixtureClient(t, func(w http.ResponseWriter, request *http.Request) {
		if calls.Add(1) == 1 {
			writeFixtureConnect(w, fixtureSSConfig(staleHost, int(stalePort), "old-password"))
		} else {
			writeFixtureConnect(w, fixtureSSConfig(liveHost, int(livePort), "new-password"))
		}
	})
	session := fixtureSession(t)
	if _, _, err := client.sessions.resolve(context.Background(), session, 21, nil); err != nil {
		t.Fatal(err)
	}
	if err := staleListener.Close(); err != nil {
		t.Fatal(err)
	}
	authority, err := encodeAuthority(ShadowsocksProtocol, session, map[string]int64{"line-21.transocks.invalid:1": 21}, nil)
	if err != nil {
		t.Fatal(err)
	}
	connection, config, err := client.sessions.dialShadowsocks(context.Background(), authority.Data, "line-21.transocks.invalid", 1, (&net.Dialer{}).DialContext, "tcp", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if calls.Load() != 2 || config.Port != livePort || config.SS.Password != "new-password" {
		t.Fatal("cached refusal did not reacquire and dial the new tunnel")
	}
}
