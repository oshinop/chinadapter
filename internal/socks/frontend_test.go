package socks

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kfadapter/kfadapter/internal/identity"
	"github.com/kfadapter/kfadapter/internal/provider"
	"github.com/kfadapter/kfadapter/internal/state"
)

const frontendTestTimeout = 5 * time.Second

type frontendSnapshots struct {
	mu    sync.Mutex
	pin   state.TunnelPin
	calls atomic.Int32
}

func (source *frontendSnapshots) CompactPin(string, time.Time) (state.TunnelPin, error) {
	source.calls.Add(1)
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.pin, nil
}

func (source *frontendSnapshots) SessionCurrentPin(pin state.TunnelPin, _ time.Time) bool {
	source.mu.Lock()
	defer source.mu.Unlock()
	return samePinAuthority(pin, source.pin) && sameCanonicalNode(pin.Node, source.pin.Node)
}

func (source *frontendSnapshots) replaceAuthority() {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.pin.Authority.Data = []byte("replacement test authority")
}

// Reuse the regression fixture's protocol-only transport, adding only the
// callbacks needed by each frontend test. No callback dials an upstream.
type frontendStreamTransport struct {
	stubTransport
	relay func(context.Context, provider.RelayRequest) error
	calls atomic.Int32
}

func (transport *frontendStreamTransport) RelayStream(ctx context.Context, request provider.RelayRequest) error {
	transport.calls.Add(1)
	if transport.relay == nil {
		return errors.New("unexpected stream relay")
	}
	return transport.relay(ctx, request)
}

type frontendDatagramTransport struct {
	frontendStreamTransport
	relayDatagrams func(context.Context, provider.DatagramRequest) error
}

func (transport *frontendDatagramTransport) RelayDatagrams(ctx context.Context, request provider.DatagramRequest) error {
	if transport.relayDatagrams == nil {
		return errors.New("unexpected datagram relay")
	}
	return transport.relayDatagrams(ctx, request)
}

type frontendListener struct {
	net.Listener
	localAddrCalls atomic.Int32
	peerIP         net.IP
}

func (listener *frontendListener) Accept() (net.Conn, error) {
	connection, err := listener.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &frontendConnection{Conn: connection, listener: listener}, nil
}

type frontendConnection struct {
	net.Conn
	listener *frontendListener
}

func (connection *frontendConnection) LocalAddr() net.Addr {
	connection.listener.localAddrCalls.Add(1)
	return connection.Conn.LocalAddr()
}

func (connection *frontendConnection) RemoteAddr() net.Addr {
	address := connection.Conn.RemoteAddr()
	if connection.listener.peerIP == nil {
		return address
	}
	peer := *address.(*net.TCPAddr)
	peer.IP = connection.listener.peerIP
	return &peer
}

type frontendFixture struct {
	server      *Server
	snapshots   *frontendSnapshots
	listener    *frontendListener
	credentials identity.Credentials
	serveDone   chan error
}

func newFrontendFixture(t *testing.T, transport provider.Transport, maxConnections int, peerIP net.IP) *frontendFixture {
	t.Helper()
	authority, err := identity.New(bytes.Repeat([]byte{0x42}, 32), "00112233445566778899aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	node := state.Node{
		ID: "stub_node", Provider: "stub", Protocol: transport.Protocol(),
		Host: "127.0.0.1", Port: 12345, AuthorityID: "test", Eligible: true,
	}
	credentials, available := authority.Credentials(node.Route())
	if !available {
		t.Fatal("test route has no credentials")
	}
	node.Selector = credentials.Username
	pin := state.TunnelPin{Node: node, Authority: provider.Authority{Protocol: node.Protocol, Data: []byte("test authority")}}
	snapshots := &frontendSnapshots{pin: pin}
	registry, err := provider.NewRegistry(nil, []provider.Transport{transport})
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{
		Snapshots: snapshots, Identity: authority, Providers: registry,
		InitialSnapshot: &state.RuntimeSnapshot{
			Nodes: []state.Node{node}, Providers: map[provider.ID]provider.Snapshot{node.Provider: {}},
		},
		MaxConnections: maxConnections, HandshakeTimeout: frontendTestTimeout,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("frontend tests must not dial provider endpoints")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	base, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := &frontendListener{Listener: base, peerIP: peerIP}
	fixture := &frontendFixture{
		server: server, snapshots: snapshots, listener: listener, credentials: credentials,
		serveDone: make(chan error, 1),
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { fixture.serveDone <- server.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), frontendTestTimeout)
		defer shutdownCancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			t.Errorf("cleanup Shutdown: %v", err)
		}
		select {
		case err := <-fixture.serveDone:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-shutdownCtx.Done():
			t.Error("Serve did not stop")
		}
	})
	return fixture
}

func (fixture *frontendFixture) connect(t *testing.T) net.Conn {
	t.Helper()
	connection, err := net.DialTimeout("tcp4", fixture.listener.Addr().String(), frontendTestTimeout)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	if err := connection.SetDeadline(time.Now().Add(frontendTestTimeout)); err != nil {
		t.Fatal(err)
	}
	return connection
}

func authenticateFrontend(t *testing.T, connection net.Conn, username, password string) byte {
	t.Helper()
	if err := writeAll(connection, []byte{version5, 2, methodNoAuthentication, methodUserPassword}); err != nil {
		t.Fatal(err)
	}
	var method [2]byte
	if _, err := io.ReadFull(connection, method[:]); err != nil {
		t.Fatal(err)
	}
	if method != [2]byte{version5, methodUserPassword} {
		t.Fatalf("method negotiation = %x", method)
	}
	auth := append([]byte{version1929, byte(len(username))}, username...)
	auth = append(auth, byte(len(password)))
	auth = append(auth, password...)
	if err := writeAll(connection, auth); err != nil {
		t.Fatal(err)
	}
	var status [2]byte
	if _, err := io.ReadFull(connection, status[:]); err != nil {
		t.Fatal(err)
	}
	if status[0] != version1929 {
		t.Fatalf("authentication version = %x", status[0])
	}
	return status[1]
}

func (fixture *frontendFixture) authenticated(t *testing.T) net.Conn {
	t.Helper()
	connection := fixture.connect(t)
	if status := authenticateFrontend(t, connection, fixture.credentials.Username, fixture.credentials.Password); status != 0 {
		t.Fatalf("authentication status = %x, want 00", status)
	}
	return connection
}

func sendFrontendRequest(t *testing.T, connection net.Conn, command byte, destination target) {
	t.Helper()
	// A request and reply share their address encoding; the command occupies
	// the reply-code byte in this test-only use of the protocol writer.
	if err := writeReply(connection, command, destination); err != nil {
		t.Fatal(err)
	}
}

func readFrontendReply(t *testing.T, connection net.Conn, expected byte) target {
	t.Helper()
	var header [4]byte
	if _, err := io.ReadFull(connection, header[:]); err != nil {
		t.Fatal(err)
	}
	if header[0] != version5 || header[1] != expected || header[2] != 0 {
		t.Fatalf("SOCKS reply header = %x, want 05 %02x 00 ATYP", header, expected)
	}
	host, port, err := readTargetAddress(connection, header[3])
	if err != nil {
		t.Fatal(err)
	}
	return target{Host: host, Port: port}
}

func expectFrontendClosed(t *testing.T, connection net.Conn) {
	t.Helper()
	var data [1]byte
	if _, err := connection.Read(data[:]); err == nil {
		t.Fatal("connection remained open")
	} else if networkErr, ok := errors.AsType[net.Error](err); ok && networkErr.Timeout() {
		t.Fatalf("connection did not close: %v", err)
	}
}

func TestSOCKSUsernamePasswordAuthentication(t *testing.T) {
	for _, test := range []struct {
		name     string
		username string
		password string
		status   byte
	}{
		{name: "success"},
		{name: "wrong_password", password: "wrong", status: 1},
		{name: "unknown_username", username: "unknown", status: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFrontendFixture(t, &frontendStreamTransport{}, 0, nil)
			username, password := fixture.credentials.Username, fixture.credentials.Password
			if test.username != "" {
				username = test.username
			}
			if test.password != "" {
				password = test.password
			}
			connection := fixture.connect(t)
			if status := authenticateFrontend(t, connection, username, password); status != test.status {
				t.Fatalf("authentication status = %x, want %x", status, test.status)
			}
			if test.status != 0 {
				expectFrontendClosed(t, connection)
				if calls := fixture.snapshots.calls.Load(); calls != 0 {
					t.Fatalf("failed authentication resolved %d pins", calls)
				}
			}
		})
	}
}

func TestSOCKSBindUnsupported(t *testing.T) {
	transport := &frontendStreamTransport{}
	fixture := newFrontendFixture(t, transport, 0, nil)
	connection := fixture.authenticated(t)
	sendFrontendRequest(t, connection, commandBind, target{Host: "127.0.0.1", Port: 80})
	readFrontendReply(t, connection, replyCommandUnsupported)
	expectFrontendClosed(t, connection)
	if transport.calls.Load() != 0 {
		t.Fatal("BIND reached the transport")
	}
}

func TestSOCKSBadAddressType(t *testing.T) {
	fixture := newFrontendFixture(t, &frontendStreamTransport{}, 0, nil)
	connection := fixture.authenticated(t)
	if err := writeAll(connection, []byte{version5, commandConnect, 0, 0xff}); err != nil {
		t.Fatal(err)
	}
	readFrontendReply(t, connection, replyAddressUnsupported)
	expectFrontendClosed(t, connection)
}

func TestSOCKSUDPUnsupportedDoesNotBind(t *testing.T) {
	transport := &frontendStreamTransport{}
	fixture := newFrontendFixture(t, transport, 0, nil)
	connection := fixture.authenticated(t)
	sendFrontendRequest(t, connection, commandUDP, target{Host: "0.0.0.0"})
	readFrontendReply(t, connection, replyCommandUnsupported)
	expectFrontendClosed(t, connection)
	// Binding an association requires consulting the accepted TCP socket's
	// LocalAddr. Prove that even this prerequisite to ListenUDP was not reached.
	if calls := fixture.listener.localAddrCalls.Load(); calls != 0 {
		t.Fatalf("TCP-only UDP request consulted the bind address %d times", calls)
	}
	if transport.calls.Load() != 0 {
		t.Fatal("UDP request reached a stream-only transport")
	}
}

func TestSOCKSTransportAddressUnsupported(t *testing.T) {
	transport := &frontendStreamTransport{relay: func(context.Context, provider.RelayRequest) error {
		return fmt.Errorf("test transport destination: %w", provider.ErrAddressUnsupported)
	}}
	fixture := newFrontendFixture(t, transport, 0, nil)
	connection := fixture.authenticated(t)
	sendFrontendRequest(t, connection, commandConnect, target{Host: "::1", Port: 80})
	readFrontendReply(t, connection, replyAddressUnsupported)
	expectFrontendClosed(t, connection)
	if calls := transport.calls.Load(); calls != 1 {
		t.Fatalf("stream relays = %d, want 1", calls)
	}
}

func TestSOCKSPinRevalidationRejectsChangedAuthority(t *testing.T) {
	for _, phase := range []string{"before_request", "before_ready"} {
		t.Run(phase, func(t *testing.T) {
			started, release := make(chan struct{}, 1), make(chan struct{})
			var readyCalls atomic.Int32
			transport := &frontendStreamTransport{relay: func(ctx context.Context, request provider.RelayRequest) error {
				started <- struct{}{}
				select {
				case <-release:
				case <-ctx.Done():
					return ctx.Err()
				}
				if !request.Admit() {
					return provider.ErrSessionRejected
				}
				readyCalls.Add(1)
				return request.Ready(nil)
			}}
			fixture := newFrontendFixture(t, transport, 0, nil)
			connection := fixture.authenticated(t)
			if phase == "before_request" {
				fixture.snapshots.replaceAuthority()
			}
			sendFrontendRequest(t, connection, commandConnect, target{Host: "127.0.0.1", Port: 80})
			if phase == "before_ready" {
				select {
				case <-started:
				case <-time.After(frontendTestTimeout):
					t.Fatal("transport setup did not start")
				}
				fixture.snapshots.replaceAuthority()
			}
			close(release)
			readFrontendReply(t, connection, replyGeneralFailure)
			expectFrontendClosed(t, connection)
			if readyCalls.Load() != 0 {
				t.Fatal("changed authority reached Ready")
			}
			if phase == "before_request" && transport.calls.Load() != 0 {
				t.Fatal("changed authority reached the transport")
			}
		})
	}
}

func newFrontendDatagramEcho(packets chan<- []byte) *frontendDatagramTransport {
	return &frontendDatagramTransport{relayDatagrams: func(_ context.Context, request provider.DatagramRequest) error {
		if !request.Admit() {
			return provider.ErrSessionRejected
		}
		if err := request.Ready(request.Packets.LocalAddr()); err != nil {
			return err
		}
		go func() {
			_, _ = io.Copy(io.Discard, request.Control)
			_ = request.Packets.Close()
		}()
		var buffer [65535]byte
		for {
			n, err := request.Packets.ReadPacket(buffer[:])
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return nil
				}
				return err
			}
			packets <- append([]byte(nil), buffer[:n]...)
			if err := request.Packets.WritePacket(buffer[:n]); err != nil {
				return err
			}
		}
	}}
}

func listenFrontendUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	if err := connection.SetDeadline(time.Now().Add(frontendTestTimeout)); err != nil {
		t.Fatal(err)
	}
	return connection
}

func associateFrontendUDP(t *testing.T, fixture *frontendFixture, requested target) (net.Conn, netip.AddrPort) {
	t.Helper()
	control := fixture.authenticated(t)
	sendFrontendRequest(t, control, commandUDP, requested)
	bound := readFrontendReply(t, control, replySucceeded)
	address, err := netip.ParseAddr(bound.Host)
	if err != nil || bound.Port == 0 {
		t.Fatalf("invalid association bound address: %v:%d (%v)", bound.Host, bound.Port, err)
	}
	return control, netip.AddrPortFrom(address, bound.Port)
}

func sendFrontendDatagram(t *testing.T, connection *net.UDPConn, address netip.AddrPort, packet []byte) {
	t.Helper()
	if _, err := connection.WriteToUDPAddrPort(packet, address); err != nil {
		t.Fatal(err)
	}
}

func receiveFrontendDatagram(t *testing.T, connection *net.UDPConn, expected []byte) {
	t.Helper()
	var buffer [65535]byte
	n, _, err := connection.ReadFromUDPAddrPort(buffer[:])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buffer[:n], expected) {
		t.Fatalf("UDP response = %x, want %x", buffer[:n], expected)
	}
}

func receiveFrontendPacket(t *testing.T, packets <-chan []byte, expected []byte) {
	t.Helper()
	select {
	case packet := <-packets:
		if !bytes.Equal(packet, expected) {
			t.Fatalf("transport received = %x, want %x", packet, expected)
		}
	case <-time.After(frontendTestTimeout):
		t.Fatal("transport did not receive the accepted datagram")
	}
}

func TestSOCKSUDPDiscardsInvalidHeaders(t *testing.T) {
	packets := make(chan []byte, 32)
	fixture := newFrontendFixture(t, newFrontendDatagramEcho(packets), 0, nil)
	// The requested address deliberately differs from the TCP peer. It must
	// not override the actual peer address used to filter incoming datagrams.
	_, bound := associateFrontendUDP(t, fixture, target{Host: "192.0.2.9"})
	client := listenFrontendUDP(t)
	valid := []byte{0, 0, 0, addressIPv4, 127, 0, 0, 1, 0, 53, 'o', 'k'}
	invalid := []struct {
		name   string
		packet []byte
	}{
		{"fragmented", []byte{0, 0, 1, addressIPv4, 127, 0, 0, 1, 0, 53}},
		{"reserved_high", []byte{1, 0, 0, addressIPv4, 127, 0, 0, 1, 0, 53}},
		{"reserved_low", []byte{0, 1, 0, addressIPv4, 127, 0, 0, 1, 0, 53}},
		{"unknown_atyp", []byte{0, 0, 0, 0xff, 127, 0, 0, 1, 0, 53}},
		{"short_header", []byte{0, 0, 0}},
		{"short_ipv4", []byte{0, 0, 0, addressIPv4, 127, 0, 0, 1, 0}},
		{"short_ipv6", []byte{0, 0, 0, addressIPv6}},
		{"short_domain", []byte{0, 0, 0, addressDomain, 2, 'a', 0, 53}},
		{"empty_domain", []byte{0, 0, 0, addressDomain, 0, 0, 53}},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			// Consecutive packets on the same loopback flow give a positive
			// barrier: only the valid second packet may reach the transport.
			sendFrontendDatagram(t, client, bound, test.packet)
			sendFrontendDatagram(t, client, bound, valid)
			receiveFrontendDatagram(t, client, valid)
			receiveFrontendPacket(t, packets, valid)
		})
	}
	select {
	case packet := <-packets:
		t.Fatalf("unexpected extra transport packet: %x", packet)
	default:
	}
}

func TestSOCKSUDPInvalidDatagramDoesNotPinPort(t *testing.T) {
	packets := make(chan []byte, 4)
	fixture := newFrontendFixture(t, newFrontendDatagramEcho(packets), 0, nil)
	_, bound := associateFrontendUDP(t, fixture, target{Host: "::1"})
	invalidClient, validClient := listenFrontendUDP(t), listenFrontendUDP(t)
	invalid := []byte{0, 0, 1, addressIPv4, 127, 0, 0, 1, 0, 53}
	valid := []byte{0, 0, 0, addressDomain, 4, 't', 'e', 's', 't', 0, 53, 'x'}
	sendFrontendDatagram(t, invalidClient, bound, invalid)
	sendFrontendDatagram(t, validClient, bound, valid)
	receiveFrontendDatagram(t, validClient, valid)
	receiveFrontendPacket(t, packets, valid)
}

func TestSOCKSUDPPeerFiltering(t *testing.T) {
	packets := make(chan []byte, 4)
	// Simulate another loopback TCP peer without requiring an OS-specific
	// 127.0.0.2 alias. All actual TCP and UDP I/O remains on 127.0.0.1.
	fixture := newFrontendFixture(t, newFrontendDatagramEcho(packets), 0, net.IPv4(127, 0, 0, 2))
	_, bound := associateFrontendUDP(t, fixture, target{Host: "0.0.0.0"})
	client := listenFrontendUDP(t)
	packet := []byte{0, 0, 0, addressIPv4, 127, 0, 0, 1, 0, 53, 'x'}
	sendFrontendDatagram(t, client, bound, packet)
	if err := client.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var buffer [64]byte
	if _, _, err := client.ReadFromUDPAddrPort(buffer[:]); err == nil {
		t.Fatal("another IP received a UDP relay response")
	} else if networkErr, ok := errors.AsType[net.Error](err); !ok || !networkErr.Timeout() {
		t.Fatalf("UDP read: %v, want timeout", err)
	}
	select {
	case packet := <-packets:
		t.Fatalf("another IP reached the transport: %x", packet)
	default:
	}
}

func TestSOCKSUDPPinsClientPort(t *testing.T) {
	for _, pinAtRequest := range []bool{false, true} {
		t.Run(fmt.Sprintf("requested_port_%t", pinAtRequest), func(t *testing.T) {
			packets := make(chan []byte, 4)
			fixture := newFrontendFixture(t, newFrontendDatagramEcho(packets), 0, nil)
			client, other := listenFrontendUDP(t), listenFrontendUDP(t)
			requested := target{Host: "0.0.0.0"}
			if pinAtRequest {
				requested.Port = client.LocalAddr().(*net.UDPAddr).AddrPort().Port()
			}
			_, bound := associateFrontendUDP(t, fixture, requested)
			packet := []byte{0, 0, 0, addressIPv4, 127, 0, 0, 1, 0, 53, 'x'}
			sendFrontendDatagram(t, client, bound, packet)
			receiveFrontendDatagram(t, client, packet)
			receiveFrontendPacket(t, packets, packet)
			sendFrontendDatagram(t, other, bound, packet)
			if err := other.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			var buffer [64]byte
			if _, _, err := other.ReadFromUDPAddrPort(buffer[:]); err == nil {
				t.Fatal("unpinned port received a UDP relay response")
			} else if networkErr, ok := errors.AsType[net.Error](err); !ok || !networkErr.Timeout() {
				t.Fatalf("UDP read: %v, want timeout", err)
			}
			select {
			case packet := <-packets:
				t.Fatalf("unpinned port reached the transport: %x", packet)
			default:
			}
		})
	}
}

func TestSOCKSSlotLimitRejectsExcessConnections(t *testing.T) {
	fixture := newFrontendFixture(t, &frontendStreamTransport{}, 2, nil)
	for range 2 {
		fixture.authenticated(t)
	}
	if slots := len(fixture.server.slots); slots != 2 {
		t.Fatalf("occupied slots = %d, want 2", slots)
	}
	extra := fixture.connect(t)
	// A full listener rejects the accepted socket before method negotiation.
	_ = writeAll(extra, []byte{version5, 1, methodUserPassword})
	expectFrontendClosed(t, extra)
	if slots := len(fixture.server.slots); slots != 2 {
		t.Fatalf("excess connection changed occupied slots to %d", slots)
	}
}

func TestSOCKSShutdownDrainsActiveHandlers(t *testing.T) {
	transport := &frontendStreamTransport{relay: func(_ context.Context, request provider.RelayRequest) error {
		if !request.Admit() {
			return provider.ErrSessionRejected
		}
		if err := request.Ready(nil); err != nil {
			return err
		}
		_, err := io.Copy(io.Discard, request.Client)
		return err
	}}
	fixture := newFrontendFixture(t, transport, 2, nil)
	connections := make([]net.Conn, 2)
	for i := range 2 {
		connections[i] = fixture.authenticated(t)
		sendFrontendRequest(t, connections[i], commandConnect, target{Host: "127.0.0.1", Port: 80})
		readFrontendReply(t, connections[i], replySucceeded)
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), frontendTestTimeout)
	defer cancel()
	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- fixture.server.Shutdown(shutdownCtx) }()
	// Serve's return proves Shutdown has closed the listener before we close
	// the established clients. Preserve its result for the fixture cleanup.
	select {
	case err := <-fixture.serveDone:
		fixture.serveDone <- err
		if err != nil {
			t.Fatal(err)
		}
	case <-shutdownCtx.Done():
		t.Fatal("Shutdown did not stop accepting")
	}
	select {
	case err := <-shutdownDone:
		t.Fatalf("Shutdown returned before active handlers drained: %v", err)
	default:
	}
	for _, connection := range connections {
		_ = connection.Close()
	}
	select {
	case err := <-shutdownDone:
		if err != nil {
			t.Fatalf("Shutdown = %v, want nil", err)
		}
	case <-shutdownCtx.Done():
		t.Fatal("Shutdown did not drain within its deadline")
	}
	fixture.server.lifecycleMu.Lock()
	active := len(fixture.server.active)
	fixture.server.lifecycleMu.Unlock()
	if active != 0 {
		t.Fatalf("active handlers after Shutdown = %d", active)
	}
}

func TestSOCKSShutdownDeadlineCancelsActiveHandler(t *testing.T) {
	cancelled := make(chan struct{})
	transport := &frontendStreamTransport{relay: func(ctx context.Context, request provider.RelayRequest) error {
		if !request.Admit() {
			return provider.ErrSessionRejected
		}
		if err := request.Ready(nil); err != nil {
			return err
		}
		<-ctx.Done()
		close(cancelled)
		return ctx.Err()
	}}
	fixture := newFrontendFixture(t, transport, 0, nil)
	connection := fixture.authenticated(t)
	sendFrontendRequest(t, connection, commandConnect, target{Host: "127.0.0.1", Port: 80})
	readFrontendReply(t, connection, replySucceeded)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := fixture.server.Shutdown(shutdownCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown = %v, want deadline exceeded", err)
	}
	select {
	case <-cancelled:
	case <-time.After(frontendTestTimeout):
		t.Fatal("shutdown deadline did not cancel the active relay")
	}
	expectFrontendClosed(t, connection)
	fixture.server.lifecycleMu.Lock()
	drained := fixture.server.drained
	fixture.server.lifecycleMu.Unlock()
	select {
	case <-drained:
	case <-time.After(frontendTestTimeout):
		t.Fatal("cancelled handler did not drain")
	}
}

func TestSOCKSUDPForwardsAllAddressTypesUnchanged(t *testing.T) {
	packets := make(chan []byte, 4)
	fixture := newFrontendFixture(t, newFrontendDatagramEcho(packets), 0, nil)
	_, bound := associateFrontendUDP(t, fixture, target{Host: "0.0.0.0"})
	client := listenFrontendUDP(t)
	ipv6 := make([]byte, 22)
	ipv6[3], ipv6[19], ipv6[21] = addressIPv6, 1, 53
	for _, packet := range [][]byte{
		{0, 0, 0, addressIPv4, 127, 0, 0, 1, 0, 53, 'x'},
		append(ipv6, 'y'),
		{0, 0, 0, addressDomain, 4, 't', 'e', 's', 't', 0, 53, 'z'},
	} {
		sendFrontendDatagram(t, client, bound, packet)
		receiveFrontendDatagram(t, client, packet)
		receiveFrontendPacket(t, packets, packet)
	}
}

func TestSOCKSUDPTransportAddressUnsupported(t *testing.T) {
	transport := &frontendDatagramTransport{relayDatagrams: func(context.Context, provider.DatagramRequest) error {
		return fmt.Errorf("test datagram destination: %w", provider.ErrAddressUnsupported)
	}}
	fixture := newFrontendFixture(t, transport, 0, nil)
	connection := fixture.authenticated(t)
	sendFrontendRequest(t, connection, commandUDP, target{Host: "0.0.0.0"})
	readFrontendReply(t, connection, replyAddressUnsupported)
	expectFrontendClosed(t, connection)
}
