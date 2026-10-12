package kuaifan

import (
	"bytes"
	"context"
	"crypto/cipher"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/oshinop/chinadapter/internal/provider"
	"github.com/oshinop/chinadapter/internal/provider/kuaifan/wifiin"
)

const testTunnelPassword = "loopback-password"
const testTunnelExtension = "|token|cc.fancast.major|order|7|MAC|1.0.46"

func TestRelayDelayedServerIV(t *testing.T) {
	baseline := runtime.NumGoroutine()
	defer requireGoroutinesReturn(t, baseline)
	h := startStreamRelay(t, func(conn *net.TCPConn, inbound io.Reader) error {
		if err := expectPlaintext(inbound, "request"); err != nil {
			return err
		}
		// Strictly greater than the one-second handshake deadline. The
		// client has not half-closed, so this is a legal provider delay.
		time.Sleep(3 * time.Second)
		return sendServerResponse(conn, "delayed response")
	})
	if _, err := h.client.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := expectPlaintext(h.client, "delayed response"); err != nil {
		t.Fatal(err)
	}
	if err := h.client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if remainder, err := io.ReadAll(h.client); err != nil || len(remainder) != 0 {
		t.Fatalf("response drain = %q, %v", remainder, err)
	}
	h.finish(t, nil)
}

func TestRelayMissingServerIVCancelled(t *testing.T) {
	baseline := runtime.NumGoroutine()
	defer requireGoroutinesReturn(t, baseline)
	received := make(chan struct{})
	h := startStreamRelay(t, func(_ *net.TCPConn, inbound io.Reader) error {
		if err := expectPlaintext(inbound, "request"); err != nil {
			return err
		}
		close(received)
		_, err := io.Copy(io.Discard, inbound)
		return err
	})
	if _, err := h.client.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	awaitSignal(t, received)
	h.cancel()
	requireClientClosed(t, h.client)
	h.finish(t, context.Canceled)
}

func TestRelayHalfCloseDrainsServerResponse(t *testing.T) {
	for _, request := range []string{"request before half-close", ""} {
		t.Run(fmt.Sprintf("payload_%d", len(request)), func(t *testing.T) {
			baseline := runtime.NumGoroutine()
			defer requireGoroutinesReturn(t, baseline)
			h := startStreamRelay(t, func(conn *net.TCPConn, inbound io.Reader) error {
				got, err := io.ReadAll(inbound)
				if err != nil {
					return err
				}
				if string(got) != request {
					return fmt.Errorf("half-closed request = %q, want %q", got, request)
				}
				return sendServerResponse(conn, "response after EOF")
			})
			if _, err := h.client.Write([]byte(request)); err != nil {
				t.Fatal(err)
			}
			if err := h.client.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(h.client)
			if err != nil || string(got) != "response after EOF" {
				t.Fatalf("half-close response = %q, %v", got, err)
			}
			h.finish(t, nil)
		})
	}
}

func TestRelayCancellationClosesBothEnds(t *testing.T) {
	baseline := runtime.NumGoroutine()
	defer requireGoroutinesReturn(t, baseline)
	h := startStreamRelay(t, func(conn *net.TCPConn, inbound io.Reader) error {
		if err := expectPlaintext(inbound, "request"); err != nil {
			return err
		}
		if err := writeServerResponse(conn, "initial response"); err != nil {
			return err
		}
		// This read must end when cancellation closes the upstream as well
		// as the accepted client, rather than leaving either pump alive.
		_, err := io.Copy(io.Discard, inbound)
		return err
	})
	if _, err := h.client.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := expectPlaintext(h.client, "initial response"); err != nil {
		t.Fatal(err)
	}
	h.cancel()
	requireClientClosed(t, h.client)
	h.finish(t, context.Canceled)
}

func TestOpenWIFIINRejectsInvalidTargetBeforeDial(t *testing.T) {
	for _, target := range []provider.Target{{Host: "bad|host", Port: 443}, {Host: "target", Port: 0}} {
		called := false
		dial := func(context.Context, string, string) (net.Conn, error) {
			called = true
			return nil, errors.New("unexpected dial")
		}
		_, _, _, _, err := openWIFIIN(context.Background(), dial, "127.0.0.1", 11000, target,
			tunnelAuthority{Password: testTunnelPassword, Extension: testTunnelExtension}, time.Second, false)
		if !errors.Is(err, wifiin.ErrInvalidTarget) || called {
			t.Fatalf("invalid target error = %v, dial called = %t", err, called)
		}
	}
}

func TestTransportInvalidAuthoritySentinel(t *testing.T) {
	for _, encoded := range [][]byte{nil, []byte("invalid"), []byte(`{"password":"p","method":"unsupported","extension":"x"}`)} {
		_, err := decodeTunnelAuthority(encoded)
		if !errors.Is(err, ErrInvalidAuthority) || errors.Is(err, ErrSchema) {
			t.Fatalf("invalid authority error = %v", err)
		}
	}
}

type streamRelayHarness struct {
	client *net.TCPConn
	cancel context.CancelFunc
	relay  <-chan error
	server <-chan error
}

func startStreamRelay(t *testing.T, serve func(*net.TCPConn, io.Reader) error) *streamRelayHarness {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	client, accepted := loopbackTCPPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			serverDone <- err
			return
		}
		inbound, err := readClientHandshake(conn, wifiin.OuterType)
		if err == nil {
			err = serve(conn, inbound)
		}
		serverDone <- err
	}()
	authority, err := json.Marshal(tunnelAuthority{Password: testTunnelPassword, Method: "aes-256-cfb", Extension: testTunnelExtension})
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().(*net.TCPAddr)
	ready := make(chan struct{})
	relayDone := make(chan error, 1)
	go func() {
		relayDone <- NewTransport().RelayStream(ctx, provider.RelayRequest{
			Dial: (&net.Dialer{}).DialContext, NodeHost: addr.IP.String(), NodePort: uint16(addr.Port),
			Target: provider.Target{Host: "target.example", Port: 443}, Authority: authority, Client: accepted,
			HandshakeTimeout: time.Second, Admit: func() bool { return true },
			Ready: func(net.Addr) error { close(ready); return nil },
		})
	}()
	awaitSignal(t, ready)
	return &streamRelayHarness{client: client, cancel: cancel, relay: relayDone, server: serverDone}
}

func (h *streamRelayHarness) finish(t *testing.T, want error) {
	t.Helper()
	if err := awaitResult(t, h.relay); !errors.Is(err, want) {
		t.Fatalf("relay error = %v, want %v", err, want)
	}
	if err := awaitResult(t, h.server); err != nil {
		t.Fatalf("loopback server: %v", err)
	}
	_ = h.client.Close()
}

func loopbackTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	server, err := listener.AcceptTCP()
	if err != nil {
		_ = client.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	if err := client.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return client, server
}

func readClientHandshake(conn net.Conn, outerType byte) (io.Reader, error) {
	var prefix [3]byte
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		return nil, err
	}
	if prefix[0] != outerType {
		return nil, fmt.Errorf("outer type = %x, want %x", prefix[0], outerType)
	}
	body := make([]byte, int(binary.BigEndian.Uint16(prefix[1:]))+2)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	if len(body) < wifiin.IVSize+2 {
		return nil, errors.New("truncated client header")
	}
	key := wifiin.DeriveKey(testTunnelPassword)
	stream, err := wifiin.NewDecrypter(key[:], body[:wifiin.IVSize])
	if err != nil {
		return nil, err
	}
	plain := body[wifiin.IVSize : len(body)-2]
	stream.XORKeyStream(plain, plain)
	if !bytes.HasSuffix(plain, []byte(testTunnelExtension)) {
		return nil, errors.New("unexpected client extension")
	}
	if err := writeAll(conn, []byte{0, 0, 0}); err != nil {
		return nil, err
	}
	return &cipher.StreamReader{S: stream, R: conn}, nil
}

func writeServerResponse(conn net.Conn, response string) error {
	key := wifiin.DeriveKey(testTunnelPassword)
	iv := make([]byte, wifiin.IVSize)
	stream, err := wifiin.NewEncrypter(key[:], iv)
	if err != nil {
		return err
	}
	ciphertext := []byte(response)
	stream.XORKeyStream(ciphertext, ciphertext)
	return writeAll(conn, append(iv, ciphertext...))
}

func sendServerResponse(conn *net.TCPConn, response string) error {
	if err := writeServerResponse(conn, response); err != nil {
		return err
	}
	return conn.CloseWrite()
}

func expectPlaintext(reader io.Reader, want string) error {
	got := make([]byte, len(want))
	if _, err := io.ReadFull(reader, got); err != nil {
		return err
	}
	if string(got) != want {
		return fmt.Errorf("plaintext = %q, want %q", got, want)
	}
	return nil
}

func awaitSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for relay signal")
	}
}

func awaitResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for relay result")
		return nil
	}
}

func requireClientClosed(t *testing.T, client net.Conn) {
	t.Helper()
	var data [1]byte
	if n, err := client.Read(data[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("cancelled client read = %d, %v", n, err)
	}
}

func requireGoroutinesReturn(t *testing.T, baseline int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= baseline {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("goroutines did not return to baseline: got %d, baseline %d", runtime.NumGoroutine(), baseline)
}
