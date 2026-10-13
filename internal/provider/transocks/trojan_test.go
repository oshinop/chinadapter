package transocks

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oshinop/chinadapter/internal/provider"
	"golang.org/x/net/websocket"
)

func TestTrojanHeaderVector(t *testing.T) {
	actual := trojanHeader("password", 1, []byte{1, 127, 0, 0, 1, 0, 80})
	want := append([]byte("d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01\r\n\x01"), []byte{1, 127, 0, 0, 1, 0, 80, '\r', '\n'}...)
	if !bytes.Equal(actual, want) {
		t.Fatalf("header=%x want=%x", actual, want)
	}
}

func testTrojanCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "relay.test"}, DNSNames: []string{"relay.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// A stock x/net WebSocket server supplies an implementation-independent check
// of HTTP upgrades, masks and binary frames for the optional transport path.
func startTrojanReference(t *testing.T, useWS bool, handler func(net.Conn) error) (string, uint16, <-chan error, <-chan string) {
	t.Helper()
	listener := listenTestTCP(t)
	host, port := testEndpoint(t, listener.Addr())
	certificate := testTrojanCertificate(t)
	sni := make(chan string, 1)
	result := make(chan error, 1)
	secure := tls.NewListener(listener, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) { sni <- hello.ServerName; return nil, nil }})
	if useWS {
		server := &http.Server{ReadHeaderTimeout: 3 * time.Second, Handler: websocket.Server{Handshake: func(config *websocket.Config, request *http.Request) error {
			if request.Host != "front.test" || request.URL.RequestURI() != "/tunnel?x=1" {
				return fmt.Errorf("wrong WS host/path")
			}
			return nil
		}, Handler: func(conn *websocket.Conn) {
			conn.PayloadType = websocket.BinaryFrame
			_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
			result <- handler(conn)
		}}}
		go func() { _ = server.Serve(secure) }()
		t.Cleanup(func() { _ = server.Close() })
	} else {
		go func() {
			conn, err := secure.Accept()
			if err != nil {
				result <- err
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
			result <- handler(conn)
		}()
	}
	return host, port, result, sni
}

func referenceTrojanHeader(reader io.Reader, command byte, address []byte) error {
	// Fixed expected digest is intentionally not computed by trojanHeader.
	expected := append([]byte("d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01\r\n"), command)
	expected = append(expected, address...)
	expected = append(expected, '\r', '\n')
	actual := make([]byte, len(expected))
	if _, err := io.ReadFull(reader, actual); err != nil {
		return err
	}
	if !bytes.Equal(actual, expected) {
		return errors.New("wrong Trojan authentication/command/target")
	}
	return nil
}

func TestTrojanStreamReferenceRoundTrip(t *testing.T) {
	for _, useWS := range []bool{false, true} {
		name := "TLS"
		if useWS {
			name = "WebSocket"
		}
		t.Run(name, func(t *testing.T) {
			payload := bytes.Repeat([]byte("Trojan stream data"), 5000)
			reply := []byte("Trojan response after half-close")
			host, port, server, sni := startTrojanReference(t, useWS, func(conn net.Conn) error {
				if err := referenceTrojanHeader(conn, 1, []byte{3, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'o', 'r', 'g', 0, 80}); err != nil {
					return err
				}
				actual, err := io.ReadAll(conn)
				if err != nil {
					return err
				}
				if !bytes.Equal(actual, payload) {
					return errors.New("wrong Trojan payload")
				}
				return transocksWriteAll(conn, reply)
			})
			entry := trojanEntry{Password: "password", SNI: "relay.test", Verify: false}
			if useWS {
				entry.WebSocket = &trojanWebSocket{Host: "front.test", Path: "/tunnel?x=1"}
			}
			authority, sessions := testTrojanTunnel(t, host, port, entry)
			client, local := testTCPPair(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			ready := make(chan struct{}, 1)
			result := make(chan error, 1)
			var count atomic.Int32
			admitted := false
			go func() {
				result <- NewTrojanTransport(sessions).RelayStream(ctx, provider.RelayRequest{Dial: testPinnedDial(t, "tcp", host, port), Client: local, NodeHost: host, NodePort: port, Target: provider.Target{Host: "example.org", Port: 80}, Authority: authority.Data, HandshakeTimeout: 3 * time.Second, Admit: func() bool { admitted = true; return true }, Ready: func(address net.Addr) error {
					if !admitted {
						return errors.New("Ready before Admit")
					}
					if address.Network() != "tcp" {
						return errors.New("Ready did not expose TCP address")
					}
					count.Add(1)
					ready <- struct{}{}
					return nil
				}})
			}()
			select {
			case <-ready:
			case err := <-result:
				t.Fatalf("before Ready: %v", err)
			}
			if got := <-sni; got != "relay.test" {
				t.Fatalf("SNI=%q", got)
			}
			if err := transocksWriteAll(client, payload); err != nil {
				t.Fatal(err)
			}
			if err := client.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			actual, err := io.ReadAll(client)
			if err != nil || !bytes.Equal(actual, reply) {
				t.Fatalf("reply=%q err=%v", actual, err)
			}
			if err := <-result; err != nil {
				t.Fatal(err)
			}
			if err := <-server; err != nil {
				t.Fatal(err)
			}
			if count.Load() != 1 {
				t.Fatal("Ready not exactly once")
			}
		})
	}
}

func TestTrojanUDPReferenceRoundTrip(t *testing.T) {
	for _, useWS := range []bool{false, true} {
		name := "TLS"
		if useWS {
			name = "WebSocket"
		}
		t.Run(name, func(t *testing.T) {
			host, port, server, _ := startTrojanReference(t, useWS, func(conn net.Conn) error {
				if err := referenceTrojanHeader(conn, 3, []byte{1, 0, 0, 0, 0, 0, 0}); err != nil {
					return err
				}
				for range 2 {
					address := make([]byte, 259)
					size, err := readSocksAddress(conn, address)
					if err != nil {
						return err
					}
					var length [4]byte
					if _, err := io.ReadFull(conn, length[:]); err != nil {
						return err
					}
					if length[2] != '\r' || length[3] != '\n' {
						return ErrProtocol
					}
					payload := make([]byte, binary.BigEndian.Uint16(length[:2]))
					if _, err := io.ReadFull(conn, payload); err != nil {
						return err
					}
					frame := append(address[:size], length[:]...)
					frame = append(frame, payload...)
					for offset := 0; offset < len(frame); {
						end := min(offset+17, len(frame))
						if err := transocksWriteAll(conn, frame[offset:end]); err != nil {
							return err
						}
						offset = end
					}
				}
				return nil
			})
			entry := trojanEntry{Password: "password", SNI: "relay.test"}
			if useWS {
				entry.WebSocket = &trojanWebSocket{Host: "front.test", Path: "/tunnel?x=1"}
			}
			authority, sessions := testTrojanTunnel(t, host, port, entry)
			packets := newTestPackets()
			control, remote := net.Pipe()
			defer remote.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			ready := make(chan struct{}, 1)
			result := make(chan error, 1)
			go func() {
				result <- NewTrojanTransport(sessions).RelayDatagrams(ctx, provider.DatagramRequest{Dial: testPinnedDial(t, "tcp", host, port), Control: control, Packets: packets, NodeHost: host, NodePort: port, Authority: authority.Data, HandshakeTimeout: 3 * time.Second, Admit: func() bool { return true }, Ready: func(net.Addr) error { ready <- struct{}{}; return nil }})
			}()
			select {
			case <-ready:
			case err := <-result:
				t.Fatal(err)
			}
			packets.in <- []byte{0, 0, 0, 3}
			for i, target := range []provider.Target{{Host: "::1", Port: 53}, {Host: "example.org", Port: 53}} {
				address, _ := socksAddress(target)
				packet := append([]byte{0, 0, 0}, address...)
				if i == 1 {
					packet = append(packet, bytes.Repeat([]byte{0x7a}, 9000)...)
				}
				packets.in <- packet
				select {
				case actual := <-packets.out:
					if !bytes.Equal(actual, packet) {
						t.Fatalf("UDP round-trip changed datagram: got %d want %d bytes", len(actual), len(packet))
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			if err := <-server; err != nil {
				t.Fatal(err)
			}
			_ = remote.Close()
			if err := <-result; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTrojanCertificateAndAdmission(t *testing.T) {
	for _, verify := range []bool{true, false} {
		name := "verify"
		if !verify {
			name = "denied-admission"
		}
		t.Run(name, func(t *testing.T) {
			host, port, server, _ := startTrojanReference(t, false, func(conn net.Conn) error {
				if verify {
					var buffer [1]byte
					_, err := conn.Read(buffer[:])
					return err
				}
				return referenceTrojanHeader(conn, 1, []byte{1, 127, 0, 0, 1, 0, 80})
			})
			entry := trojanEntry{Password: "password", SNI: "relay.test", Verify: verify}
			authority, sessions := testTrojanTunnel(t, host, port, entry)
			client, local := net.Pipe()
			defer client.Close()
			defer local.Close()
			ready := false
			err := NewTrojanTransport(sessions).RelayStream(context.Background(), provider.RelayRequest{Dial: testPinnedDial(t, "tcp", host, port), Client: local, NodeHost: host, NodePort: port, Target: provider.Target{Host: "127.0.0.1", Port: 80}, Authority: authority.Data, HandshakeTimeout: 3 * time.Second, Admit: func() bool { return false }, Ready: func(net.Addr) error { ready = true; return nil }})
			if ready {
				t.Fatal("Ready called on failed handshake/admission")
			}
			if verify {
				var unknown x509.UnknownAuthorityError
				if !errors.As(err, &unknown) {
					t.Fatalf("expected certificate verification failure, got %v", err)
				}
			} else {
				if !errors.Is(err, provider.ErrNoSession) {
					t.Fatal(err)
				}
			}
			serverErr := <-server
			if !verify && serverErr != nil {
				t.Fatal(serverErr)
			}
		})
	}
}

func TestTrojanUDPFramingErrors(t *testing.T) {
	for _, test := range []struct {
		name string
		wire []byte
		want error
	}{
		{"separator", []byte{1, 127, 0, 0, 1, 0, 53, 0, 1, 'x', '\n', 1}, ErrProtocol},
		{"truncated-payload", []byte{1, 127, 0, 0, 1, 0, 53, 0, 2, '\r', '\n', 1}, io.ErrUnexpectedEOF},
		{"empty-domain", []byte{3, 0}, ErrProtocol},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := readTrojanDatagrams(bytes.NewReader(test.wire), newTestPackets())
			if !errors.Is(err, test.want) {
				t.Fatalf("got %v want %v", err, test.want)
			}
		})
	}
}

func TestTrojanWebSocketFragmentationAndPing(t *testing.T) {
	reader, writer := net.Pipe()
	defer reader.Close()
	defer writer.Close()
	_ = reader.SetDeadline(time.Now().Add(3 * time.Second))
	_ = writer.SetDeadline(time.Now().Add(3 * time.Second))
	connection := &trojanWSConn{Conn: reader, reader: bufio.NewReader(reader)}
	server := make(chan error, 1)
	go func() {
		if err := transocksWriteAll(writer, []byte{0x02, 2, 'h', 'e', 0x89, 2, 'o', 'k'}); err != nil {
			server <- err
			return
		}
		var pong [8]byte
		if _, err := io.ReadFull(writer, pong[:]); err != nil {
			server <- err
			return
		}
		if pong[0] != 0x8a || pong[1] != 0x82 || pong[6]^pong[2] != 'o' || pong[7]^pong[3] != 'k' {
			server <- errors.New("invalid masked pong")
			return
		}
		server <- transocksWriteAll(writer, []byte{0x80, 3, 'l', 'l', 'o', 0x88, 0})
	}()
	actual, err := io.ReadAll(connection)
	if err != nil || string(actual) != "hello" {
		t.Fatalf("data=%q err=%v", actual, err)
	}
	if err := <-server; err != nil {
		t.Fatal(err)
	}
}

func TestTrojanWebSocketRejectsInvalidFrames(t *testing.T) {
	for _, wire := range [][]byte{{0xc2, 0}, {0x82, 0x80}, {0x80, 0}, {0x89, 126, 0, 126}, {0x82, 126, 0, 1}, {0x81, 0}, {0x88, 1, 0}, {0x82, 127, 0, 0, 0, 0, 0, 0x20, 0, 0}} {
		reader, writer := net.Pipe()
		connection := &trojanWSConn{Conn: reader, reader: bufio.NewReader(reader)}
		go func() { _, _ = writer.Write(wire); _ = writer.Close() }()
		_, err := io.ReadAll(connection)
		_ = reader.Close()
		if !errors.Is(err, ErrProtocol) {
			t.Fatalf("frame %x got %v", wire, err)
		}
	}
}

func TestTrojanHandshakeCancellation(t *testing.T) {
	upstream, peer := net.Pipe()
	defer peer.Close()
	authority, sessions := testTrojanTunnel(t, "node.test", 443, trojanEntry{Password: "x"})
	client, local := net.Pipe()
	defer client.Close()
	defer local.Close()
	ctx, cancel := context.WithCancel(context.Background())
	ready := false
	result := make(chan error, 1)
	go func() {
		result <- NewTrojanTransport(sessions).RelayStream(ctx, provider.RelayRequest{Dial: func(context.Context, string, string) (net.Conn, error) { return upstream, nil }, Client: local, NodeHost: "node.test", NodePort: 443, Target: provider.Target{Host: "x", Port: 80}, Authority: authority.Data, HandshakeTimeout: time.Minute, Admit: func() bool { return true }, Ready: func(net.Addr) error { ready = true; return nil }})
	}()
	var buffer [1]byte
	if _, err := peer.Read(buffer[:]); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-result:
		if err == nil || ready {
			t.Fatalf("err=%v Ready=%v", err, ready)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("TLS handshake did not stop on cancellation")
	}
}

func TestTrojanWebSocketUpgradeErrors(t *testing.T) {
	for _, response := range []string{
		"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: wrong\r\n\r\n",
		"HTTP/1.1 101 Switching Protocols\r\nX-Large: " + string(bytes.Repeat([]byte{'a'}, trojanWSHeaderLimit)) + "\r\n\r\n",
	} {
		client, server := net.Pipe()
		_ = client.SetDeadline(time.Now().Add(3 * time.Second))
		_ = server.SetDeadline(time.Now().Add(3 * time.Second))
		finished := make(chan struct{})
		go func() {
			defer close(finished)
			defer server.Close()
			if _, err := http.ReadRequest(bufio.NewReader(server)); err == nil {
				_ = transocksWriteAll(server, []byte(response))
			}
		}()
		_, err := newTrojanWebSocket(client, "node.test", 443, trojanWebSocket{Path: "/"})
		_ = client.Close()
		<-finished
		if !errors.Is(err, ErrProtocol) {
			t.Fatalf("expected invalid upgrade, got %v", err)
		}
	}
	for _, options := range []trojanWebSocket{{Host: "good\r\nInjected: yes", Path: "/"}, {Host: "good", Path: "https://other.test/"}, {Path: "/\r\n"}} {
		client, server := net.Pipe()
		_, err := newTrojanWebSocket(client, "node.test", 443, options)
		_ = client.Close()
		_ = server.Close()
		if !errors.Is(err, ErrInvalidAuthority) {
			t.Fatalf("accepted invalid WebSocket options: %v", err)
		}
	}
}

func TestTransocksStreamCancellationAndClose(t *testing.T) {
	for _, cancelContext := range []bool{false, true} {
		client, local := testTCPPair(t)
		upstream, peer := testTCPPair(t)
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() { result <- relayTransocks(ctx, local, upstream) }()
		// Synchronize with an active pump before closing its endpoint.
		go func() { _, _ = client.Write([]byte{1}) }()
		var first [1]byte
		if _, err := io.ReadFull(peer, first[:]); err != nil {
			t.Fatal(err)
		}
		if cancelContext {
			cancel()
		} else {
			_ = local.Close()
		}
		select {
		case err := <-result:
			if cancelContext && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation returned %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("relay stranded its other pump after cancellation/close")
		}
		cancel()
	}
}
