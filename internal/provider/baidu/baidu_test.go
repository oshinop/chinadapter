package baidu

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/oshinop/chinadapter/internal/provider"
)

var fixtureNow = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

func fixtureDriver(addresses []netip.Addr, err error) *Driver {
	return NewDriver(DriverConfig{
		Clock: func() time.Time { return fixtureNow },
		lookup: func(_ context.Context, network, host string) ([]netip.Addr, error) {
			if network != "ip4" || host != proxyDomain {
				return nil, errors.New("unexpected lookup")
			}
			return addresses, err
		},
	})
}

func TestDriverIsPublicAndBuildsOneNodePerProxyAddress(t *testing.T) {
	t.Parallel()
	addresses := []netip.Addr{
		netip.MustParseAddr("180.101.50.208"), netip.MustParseAddr("14.215.182.75"),
		netip.MustParseAddr("180.101.50.208"), netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("2001:db8::1"),
	}
	driver := fixtureDriver(addresses, nil)
	if len(driver.Auth().Fields) != 0 {
		t.Fatal("public provider declared credential fields")
	}
	if _, err := driver.Login(context.Background(), provider.Credentials{InstallationID: "install", Fields: map[string]string{"account": "x"}}); !errors.Is(err, provider.ErrInvalidInput) {
		t.Fatalf("login with undeclared fields = %v", err)
	}
	snapshot, err := driver.Login(context.Background(), provider.Credentials{InstallationID: "install"})
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.ValidateSnapshot(snapshot, ProviderID, fixtureNow); err != nil {
		t.Fatal(err)
	}
	// Duplicates, private and IPv6 answers are dropped; order is canonical.
	if len(snapshot.Nodes) != 2 || snapshot.Nodes[0].Host != "14.215.182.75" || snapshot.Nodes[1].Host != "180.101.50.208" {
		t.Fatalf("nodes = %+v", snapshot.Nodes)
	}
	for _, node := range snapshot.Nodes {
		if node.Port != proxyPort || node.Protocol != Protocol || !node.Eligible || node.AuthorityID != authorityID {
			t.Fatalf("node = %+v", node)
		}
	}
	if snapshot.Account.SubscriptionActive || !snapshot.ExpiresAt.Equal(fixtureNow.Add(defaultRefreshInterval)) {
		t.Fatalf("account/expiry = %+v %s", snapshot.Account, snapshot.ExpiresAt)
	}

	// Refresh with the same answers keeps every node ID (stable SOCKS usernames).
	refreshed, err := driver.Refresh(context.Background(), snapshot)
	if err != nil || refreshed.Nodes[0].ID != snapshot.Nodes[0].ID || refreshed.Nodes[1].ID != snapshot.Nodes[1].ID {
		t.Fatalf("refresh changed node identity: %v", err)
	}
}

func TestDriverResolutionFailuresAreTransient(t *testing.T) {
	t.Parallel()
	if _, err := fixtureDriver(nil, nil).Login(context.Background(), provider.Credentials{InstallationID: "install"}); !errors.Is(err, ErrNoProxies) {
		t.Fatalf("empty answer = %v", err)
	}
	lookupErr := errors.New("dns down")
	_, err := fixtureDriver(nil, lookupErr).Login(context.Background(), provider.Credentials{InstallationID: "install"})
	if !errors.Is(err, lookupErr) || errors.Is(err, provider.ErrSessionRejected) {
		t.Fatalf("lookup failure = %v", err)
	}
}

// fakeProxy is a loopback HTTP CONNECT proxy that, like Baidu's, admits only
// requests carrying the X-T5-Auth token, then tunnels to an echo target.
type fakeProxy struct {
	listener net.Listener
	requests chan *http.Request
}

func newFakeProxy(t *testing.T, target string, extra []byte) *fakeProxy {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxy := &fakeProxy{listener: listener, requests: make(chan *http.Request, 4)}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				reader := bufio.NewReader(connection)
				request, err := http.ReadRequest(reader)
				if err != nil {
					return
				}
				proxy.requests <- request
				if request.Method != http.MethodConnect || request.Header.Get("X-T5-Auth") != proxyToken {
					_, _ = io.WriteString(connection, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
					return
				}
				upstream, err := net.Dial("tcp", target)
				if err != nil {
					_, _ = io.WriteString(connection, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
					return
				}
				defer upstream.Close()
				// Extra bytes in the same write as the response must reach the client.
				_, _ = connection.Write(append([]byte("HTTP/1.1 200 Connection established\r\n\r\n"), extra...))
				go func() {
					_, _ = io.Copy(upstream, reader)
					_ = upstream.(*net.TCPConn).CloseWrite()
				}()
				_, _ = io.Copy(connection, upstream)
			}()
		}
	}()
	return proxy
}

func echoServer(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				_, _ = io.Copy(connection, connection)
			}()
		}
	}()
	return listener.Addr().String()
}

func relayRequest(t *testing.T, proxy *fakeProxy, client net.Conn, target provider.Target, token string) provider.RelayRequest {
	t.Helper()
	authority, err := encodeAuthority(proxyAuthority{Host: proxyHostHeader, Token: token, UserAgent: proxyUserAgent})
	if err != nil {
		t.Fatal(err)
	}
	address := proxy.listener.Addr().(*net.TCPAddr)
	return provider.RelayRequest{
		Dial: (&net.Dialer{}).DialContext, Client: client, NodeHost: address.IP.String(), NodePort: uint16(address.Port),
		Target: target, Authority: authority.Data, HandshakeTimeout: 2 * time.Second,
		Admit: func() bool { return true }, Ready: func(net.Addr) error { return nil },
	}
}

func TestTransportTunnelsThroughConnectWithProxyHeaders(t *testing.T) {
	t.Parallel()
	echo := echoServer(t)
	host, port, _ := net.SplitHostPort(echo)
	portNumber, _ := strconv.Atoi(port)
	proxy := newFakeProxy(t, echo, []byte("early"))
	client, local := net.Pipe()
	defer client.Close()
	ready := make(chan struct{})
	request := relayRequest(t, proxy, local, provider.Target{Host: host, Port: uint16(portNumber)}, proxyToken)
	request.Ready = func(net.Addr) error { close(ready); return nil }
	done := make(chan error, 1)
	go func() { done <- NewTransport().RelayStream(context.Background(), request) }()

	connect := <-proxy.requests
	if connect.Host != echo || connect.Header.Get("Host") != "" && connect.Header.Get("Host") != proxyHostHeader {
		t.Fatalf("CONNECT authority = %q", connect.Host)
	}
	if connect.Header.Get("User-Agent") != proxyUserAgent {
		t.Fatalf("CONNECT User-Agent = %q", connect.Header.Get("User-Agent"))
	}
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("relay ended before readiness: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not become ready")
	}
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	buffer := make([]byte, len("early"))
	if _, err := io.ReadFull(client, buffer); err != nil || string(buffer) != "early" {
		t.Fatalf("bytes after the CONNECT response = %q, %v", buffer, err)
	}
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	echoed := make([]byte, 4)
	if _, err := io.ReadFull(client, echoed); err != nil || string(echoed) != "ping" {
		t.Fatalf("echo = %q, %v", echoed, err)
	}
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not stop after the client closed")
	}
}

func TestTransportRejectsRefusedConnectBeforeReady(t *testing.T) {
	t.Parallel()
	proxy := newFakeProxy(t, echoServer(t), nil)
	_, local := net.Pipe()
	ready := false
	request := relayRequest(t, proxy, local, provider.Target{Host: "www.baidu.com", Port: 443}, "rotated-token")
	request.Ready = func(net.Addr) error { ready = true; return nil }
	err := NewTransport().RelayStream(context.Background(), request)
	if !errors.Is(err, ErrConnectRefused) || ready {
		t.Fatalf("refused CONNECT = %v, ready=%v", err, ready)
	}
}

func TestTransportReportsIPv6TargetsUnsupported(t *testing.T) {
	t.Parallel()
	dialed := false
	authority, _ := encodeAuthority(proxyAuthority{Host: proxyHostHeader, Token: proxyToken, UserAgent: proxyUserAgent})
	_, local := net.Pipe()
	err := NewTransport().RelayStream(context.Background(), provider.RelayRequest{
		Dial: func(context.Context, string, string) (net.Conn, error) {
			dialed = true
			return nil, errors.New("unused")
		},
		Client: local, NodeHost: "192.0.2.1", NodePort: 443, Target: provider.Target{Host: "2001:db8::1", Port: 443},
		Authority: authority.Data, HandshakeTimeout: time.Second,
		Admit: func() bool { return true }, Ready: func(net.Addr) error { return nil },
	})
	if !errors.Is(err, provider.ErrAddressUnsupported) || dialed {
		t.Fatalf("IPv6 target = %v, dialed=%v", err, dialed)
	}
}
