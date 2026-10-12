package quickfox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/oshinop/chinadapter/internal/provider"
)

func TestTransportRejectsControlAcknowledgementBeforeDataPreface(t *testing.T) {
	t.Parallel()
	for index := range controlACKSize {
		t.Run(fmt.Sprintf("byte-%d", index), func(t *testing.T) {
			t.Parallel()
			client, adapter := loopbackTCPPair(t)
			control, controlAdapter := loopbackTCPPair(t)
			acknowledgement := make([]byte, controlACKSize)
			acknowledgement[index] = 1
			serverErr := make(chan error, 1)
			go func() {
				if err := readNativePreface(control); err != nil {
					serverErr <- err
					return
				}
				if err := writeAll(control, acknowledgement); err != nil {
					serverErr <- err
					return
				}
				var unexpected [1]byte
				count, err := control.Read(unexpected[:])
				if count != 0 || !errors.Is(err, io.EOF) {
					serverErr <- fmt.Errorf("control after rejection: read %d bytes, error %w", count, err)
					return
				}
				serverErr <- nil
			}()
			dials := 0
			request := nativeRelayRequest(t, adapter, func(context.Context, string, string) (net.Conn, error) {
				dials++
				if dials != 1 {
					return nil, errors.New("unexpected data connection")
				}
				return controlAdapter, nil
			})
			admitted, ready := false, false
			request.Admit = func() bool { admitted = true; return true }
			request.Ready = func(net.Addr) error { ready = true; return nil }
			err := NewTransport().RelayStream(context.Background(), request)
			if !errors.Is(err, ErrHandshake) || dials != 1 || admitted || ready {
				t.Fatalf("rejected acknowledgement: error %v, dials %d, admitted %t, ready %t", err, dials, admitted, ready)
			}
			if err := <-serverErr; err != nil {
				t.Fatal(err)
			}
			_ = client.Close()
		})
	}
}

func TestTransportRejectsTruncatedControlAcknowledgement(t *testing.T) {
	t.Parallel()
	_, adapter := loopbackTCPPair(t)
	control, controlAdapter := loopbackTCPPair(t)
	serverErr := make(chan error, 1)
	go func() {
		defer control.Close()
		if err := readNativePreface(control); err != nil {
			serverErr <- err
			return
		}
		serverErr <- writeAll(control, make([]byte, controlACKSize-1))
	}()
	dials := 0
	request := nativeRelayRequest(t, adapter, func(context.Context, string, string) (net.Conn, error) {
		dials++
		return controlAdapter, nil
	})
	err := NewTransport().RelayStream(context.Background(), request)
	if !errors.Is(err, ErrHandshake) || !errors.Is(err, io.ErrUnexpectedEOF) || dials != 1 {
		t.Fatalf("truncated acknowledgement: error %v, dials %d", err, dials)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestTransportCancellationClosesBothRelayConnections(t *testing.T) {
	t.Parallel()
	client, adapter := loopbackTCPPair(t)
	control, controlAdapter := loopbackTCPPair(t)
	upstream, upstreamAdapter := loopbackTCPPair(t)
	serverErr := make(chan error, 1)
	go func() { serverErr <- completeNativeHandshake(control, upstream) }()
	dials := 0
	request := nativeRelayRequest(t, adapter, func(context.Context, string, string) (net.Conn, error) {
		dials++
		if dials == 1 {
			return controlAdapter, nil
		}
		return upstreamAdapter, nil
	})
	ready := make(chan struct{})
	request.Ready = func(net.Addr) error { close(ready); return nil }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	relayErr := make(chan error, 1)
	go func() { relayErr <- NewTransport().RelayStream(ctx, request) }()
	select {
	case <-ready:
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not become ready")
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-relayErr:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled relay error = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled relay did not return")
	}
	for _, connection := range []*net.TCPConn{client, upstream, control} {
		var buffer [1]byte
		count, err := connection.Read(buffer[:])
		if count != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("connection after cancellation: read %d bytes, error %v", count, err)
		}
	}
}

func TestTransportClientHalfCloseDrainsUpstreamResponse(t *testing.T) {
	t.Parallel()
	client, adapter := loopbackTCPPair(t)
	control, controlAdapter := loopbackTCPPair(t)
	upstream, upstreamAdapter := loopbackTCPPair(t)
	response := bytes.Repeat([]byte("response"), relayBufferSize/4+1)
	serverErr := make(chan error, 1)
	go func() {
		if err := completeNativeHandshake(control, upstream); err != nil {
			serverErr <- err
			return
		}
		encoded, err := io.ReadAll(upstream)
		if err != nil {
			serverErr <- err
			return
		}
		for index := range encoded {
			encoded[index] ^= relayXORByte
		}
		if string(encoded) != "ping" {
			serverErr <- fmt.Errorf("relayed request = %q, want ping", encoded)
			return
		}
		encoded = bytes.Clone(response)
		for index := range encoded {
			encoded[index] ^= relayXORByte
		}
		if err := writeAll(upstream, encoded); err != nil {
			serverErr <- err
			return
		}
		serverErr <- upstream.CloseWrite()
	}()
	dials := 0
	request := nativeRelayRequest(t, adapter, func(context.Context, string, string) (net.Conn, error) {
		dials++
		if dials == 1 {
			return controlAdapter, nil
		}
		return upstreamAdapter, nil
	})
	ready := make(chan struct{})
	request.Ready = func(net.Addr) error { close(ready); return nil }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	relayErr := make(chan error, 1)
	go func() { relayErr <- NewTransport().RelayStream(ctx, request) }()
	select {
	case <-ready:
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not become ready")
	}
	if err := writeAll(client, []byte("ping")); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(client)
	if err != nil || !bytes.Equal(got, response) {
		t.Fatalf("drained response: length %d, want %d, error %v", len(got), len(response), err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	if err := <-relayErr; err != nil {
		t.Fatal(err)
	}
}

func TestTransportIPv6TargetReturnsAddressUnsupported(t *testing.T) {
	t.Parallel()
	_, adapter := loopbackTCPPair(t)
	dials, lookups := 0, 0
	transport := NewTransport()
	transport.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		lookups++
		return nil, errors.New("unexpected lookup")
	}
	request := nativeRelayRequest(t, adapter, func(context.Context, string, string) (net.Conn, error) {
		dials++
		return nil, errors.New("unexpected relay dial")
	})
	request.Target.Host = "2001:db8::1"
	if err := transport.RelayStream(context.Background(), request); !errors.Is(err, provider.ErrAddressUnsupported) {
		t.Fatalf("IPv6 relay error = %v", err)
	}
	if dials != 0 || lookups != 0 {
		t.Fatalf("IPv6 target: dials %d, lookups %d", dials, lookups)
	}
}

func TestResolveTargetWithoutIPv4ReturnsAddressUnsupported(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name      string
		addresses []netip.Addr
		err       error
	}{
		{name: "empty answer"},
		{name: "IPv6 only", addresses: []netip.Addr{netip.MustParseAddr("2001:db8::1")}},
		{name: "IPv4 not found", err: &net.DNSError{Err: "no such host", Name: "target.example", IsNotFound: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			transport := NewTransport()
			transport.lookup = func(_ context.Context, network, host string) ([]netip.Addr, error) {
				if network != "ip4" || host != "target.example" {
					t.Errorf("lookup %s %s", network, host)
				}
				return test.addresses, test.err
			}
			address, err := transport.resolveTarget(context.Background(), "target.example", time.Second)
			if address.IsValid() || !errors.Is(err, provider.ErrAddressUnsupported) {
				t.Fatalf("IPv4 resolution = %v, %v", address, err)
			}
			if test.err != nil && !errors.Is(err, test.err) {
				t.Fatalf("resolution did not preserve DNS error: %v", err)
			}
		})
	}
}

func loopbackTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	for _, connection := range []*net.TCPConn{client, server} {
		if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	return client, server
}

func nativeRelayRequest(t *testing.T, client net.Conn, dial provider.DialContextFunc) provider.RelayRequest {
	t.Helper()
	authority, err := json.Marshal(tunnelAuthority{Token: "0123456789abcdef0123456789abcdef", UserID: 15904241})
	if err != nil {
		t.Fatal(err)
	}
	return provider.RelayRequest{
		NodeHost: "127.0.0.1", NodePort: 443, Target: provider.Target{Host: "192.0.2.1", Port: 80},
		Authority: authority, Client: client, Dial: dial, HandshakeTimeout: time.Second,
		Admit: func() bool { return true }, Ready: func(net.Addr) error { return nil },
	}
}

func readNativePreface(connection net.Conn) error {
	var preface [62]byte
	_, err := io.ReadFull(connection, preface[:])
	return err
}

func completeNativeHandshake(control, upstream net.Conn) error {
	if err := readNativePreface(control); err != nil {
		return err
	}
	if err := writeAll(control, make([]byte, controlACKSize)); err != nil {
		return err
	}
	return readNativePreface(upstream)
}
