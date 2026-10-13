package kuaifan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oshinop/chinadapter/internal/provider"
	"github.com/oshinop/chinadapter/internal/provider/kuaifan/speedin"
)

const testSPEEDINPassword = "speedin-loopback-password"

var testSPEEDINAuth = speedin.Auth{UserID: 12345, Token: "loopback-token", OS: "WINDOWS"}

func speedinTestAuthority(t *testing.T, host string, port uint16) []byte {
	t.Helper()
	authority, err := encodeSPEEDINAuthority(speedinAuthority{
		UserID: testSPEEDINAuth.UserID, Token: testSPEEDINAuth.Token, OS: speedinOS, Method: speedinMethodAES128GCM,
		Passwords: map[string]string{speedinNodeKey(host, port): testSPEEDINPassword},
	})
	if err != nil {
		t.Fatal(err)
	}
	return authority.Data
}

func speedinTestCipher() *speedin.Cipher {
	cipher, err := speedin.NewCipher(testSPEEDINPassword)
	if err != nil {
		panic(err)
	}
	return cipher
}

func readSPEEDINTestRequest(conn net.Conn, target provider.Target) (*speedin.Reader, error) {
	reader, err := speedinTestCipher().NewReader(conn)
	if err != nil {
		return nil, err
	}
	want, err := speedin.EncodeRequest(speedin.Address{Host: target.Host, Port: target.Port}, testSPEEDINAuth)
	if err != nil {
		return nil, err
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(reader, got); err != nil {
		return nil, err
	}
	if !bytes.Equal(got, want) {
		return nil, errors.New("wrong SPEEDIN address/auth request")
	}
	return reader, nil
}

func TestSPEEDINStreamEndToEndAndHalfClose(t *testing.T) {
	if NewSPEEDINTransport().Protocol() != SPEEDINProtocol {
		t.Fatal("wrong protocol")
	}
	for _, host := range []string{"destination.example", "192.0.2.11", "2001:db8::11"} {
		t.Run(host, func(t *testing.T) {
			listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			client, accepted := loopbackTCPPair(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			target := provider.Target{Host: host, Port: 443}
			application := bytes.Repeat([]byte("stream-request"), 700)
			serverDone := make(chan error, 1)
			go func() {
				conn, err := listener.AcceptTCP()
				if err != nil {
					serverDone <- err
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				serverDone <- func() error {
					reader, err := readSPEEDINTestRequest(conn, target)
					if err != nil {
						return err
					}
					writer, err := speedinTestCipher().NewWriter(conn)
					if err != nil {
						return err
					}
					if _, err := writer.Write(append([]byte{1, 0xff, 0xff}, []byte("same-chunk greeting")...)); err != nil {
						return err
					}
					got, err := io.ReadAll(reader)
					if err != nil {
						return err
					}
					if !bytes.Equal(got, application) {
						return errors.New("stream application bytes mismatch")
					}
					_, err = writer.Write([]byte("response after EOF"))
					return err
				}()
			}()
			addr := listener.Addr().(*net.TCPAddr)
			ready := make(chan struct{})
			var readyCalls, admitCalls atomic.Int32
			relayDone := make(chan error, 1)
			go func() {
				relayDone <- NewSPEEDINTransport().RelayStream(ctx, provider.RelayRequest{
					Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
						if network != "tcp" || address != listener.Addr().String() {
							return nil, fmt.Errorf("unexpected dial %s %s", network, address)
						}
						return (&net.Dialer{}).DialContext(ctx, network, address)
					},
					NodeHost: addr.IP.String(), NodePort: uint16(addr.Port), Target: target, Client: accepted,
					Authority: speedinTestAuthority(t, addr.IP.String(), uint16(addr.Port)), HandshakeTimeout: time.Second,
					Admit: func() bool { admitCalls.Add(1); return true },
					Ready: func(local net.Addr) error {
						if local == nil || admitCalls.Load() != 1 {
							return errors.New("readiness before admission")
						}
						readyCalls.Add(1)
						close(ready)
						return nil
					},
				})
			}()
			awaitSignal(t, ready)
			if err := expectPlaintext(client, "same-chunk greeting"); err != nil {
				t.Fatal(err)
			}
			if _, err := client.Write(application); err != nil {
				t.Fatal(err)
			}
			if err := client.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(client)
			if err != nil || string(got) != "response after EOF" {
				t.Fatalf("half-close response = %q,%v", got, err)
			}
			if err := awaitResult(t, relayDone); err != nil {
				t.Fatal(err)
			}
			if err := awaitResult(t, serverDone); err != nil {
				t.Fatal(err)
			}
			if admitCalls.Load() != 1 || readyCalls.Load() != 1 {
				t.Fatal("admission/readiness called more than once")
			}
		})
	}
}

func TestSPEEDINHandshakeMustAcceptBeforeAdmission(t *testing.T) {
	for _, tc := range []struct {
		name             string
		answer           []byte
		admit            bool
		readyError, want error
	}{
		{"rejected", []byte{2, 0, 8}, true, nil, speedin.ErrAuthRejected},
		{"truncated", []byte{1, 0}, true, nil, io.ErrUnexpectedEOF},
		{"revoked", []byte{1, 0, 8}, false, nil, provider.ErrNoSession},
		{"ready_failed", []byte{1, 0, 8}, true, io.ErrClosedPipe, io.ErrClosedPipe},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream, server := net.Pipe()
			defer server.Close()
			client, accepted := net.Pipe()
			defer client.Close()
			defer accepted.Close()
			var admits, readies atomic.Int32
			done := make(chan error, 1)
			go func() {
				defer server.Close()
				_, err := readSPEEDINTestRequest(server, provider.Target{Host: "destination.example", Port: 443})
				if err == nil {
					var writer *speedin.Writer
					writer, err = speedinTestCipher().NewWriter(server)
					if err == nil {
						_, err = writer.Write(tc.answer)
					}
				}
				done <- err
			}()
			err := NewSPEEDINTransport().RelayStream(context.Background(), provider.RelayRequest{
				Dial:   func(context.Context, string, string) (net.Conn, error) { return upstream, nil },
				Client: accepted, NodeHost: "127.0.0.1", NodePort: 9999, Target: provider.Target{Host: "destination.example", Port: 443},
				Authority: speedinTestAuthority(t, "127.0.0.1", 9999), HandshakeTimeout: time.Second,
				Admit: func() bool { admits.Add(1); return tc.admit },
				Ready: func(net.Addr) error { readies.Add(1); return tc.readyError },
			})
			if !errors.Is(err, tc.want) {
				t.Fatalf("handshake result = %v,want %v", err, tc.want)
			}
			if err := awaitResult(t, done); err != nil {
				t.Fatal(err)
			}
			if tc.name == "rejected" || tc.name == "truncated" {
				if admits.Load() != 0 || readies.Load() != 0 {
					t.Fatal("rejected handshake was admitted")
				}
			} else if admits.Load() != 1 || readies.Load() != boolCount(tc.admit) {
				t.Fatal("wrong admission/readiness sequence")
			}
		})
	}
}

func boolCount(value bool) int32 {
	if value {
		return 1
	}
	return 0
}

func TestSPEEDINHandshakeCancellationAndTimeout(t *testing.T) {
	for _, mode := range []string{"cancel", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			upstream, server := net.Pipe()
			defer server.Close()
			client, accepted := net.Pipe()
			defer client.Close()
			defer accepted.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				reader, err := readSPEEDINTestRequest(server, provider.Target{Host: "x", Port: 1})
				if err != nil {
					done <- err
					return
				}
				if mode == "cancel" {
					cancel()
				}
				_, err = io.Copy(io.Discard, reader)
				done <- err
			}()
			var admitted atomic.Bool
			err := NewSPEEDINTransport().RelayStream(ctx, provider.RelayRequest{
				Dial:   func(context.Context, string, string) (net.Conn, error) { return upstream, nil },
				Client: accepted, NodeHost: "node", NodePort: 1, Target: provider.Target{Host: "x", Port: 1},
				Authority: speedinTestAuthority(t, "node", 1), HandshakeTimeout: 100 * time.Millisecond,
				Admit: func() bool { admitted.Store(true); return true }, Ready: func(net.Addr) error { admitted.Store(true); return nil },
			})
			want := context.Canceled
			if mode == "timeout" {
				want = context.DeadlineExceeded
			}
			if !errors.Is(err, want) || admitted.Load() {
				t.Fatalf("%s handshake = %v, admitted=%v", mode, err, admitted.Load())
			}
			if err := awaitResult(t, done); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSPEEDINAuthorityLookupFailsBeforeDial(t *testing.T) {
	client, accepted := net.Pipe()
	defer client.Close()
	defer accepted.Close()
	var calls atomic.Int32
	request := provider.RelayRequest{
		Dial: func(context.Context, string, string) (net.Conn, error) {
			calls.Add(1)
			return nil, errors.New("unexpected dial")
		},
		Client: accepted, NodeHost: "different-node", NodePort: 1, Target: provider.Target{Host: "x", Port: 1},
		Authority: speedinTestAuthority(t, "node", 1), HandshakeTimeout: time.Second, Admit: func() bool { return true }, Ready: func(net.Addr) error { return nil },
	}
	if err := NewSPEEDINTransport().RelayStream(context.Background(), request); !errors.Is(err, ErrInvalidAuthority) || calls.Load() != 0 {
		t.Fatalf("missing password: %v, dial=%d", err, calls.Load())
	}
	request.Authority = []byte("invalid")
	if err := NewSPEEDINTransport().RelayStream(context.Background(), request); !errors.Is(err, ErrInvalidAuthority) || calls.Load() != 0 {
		t.Fatalf("invalid authority: %v", err)
	}
}
