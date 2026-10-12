package kuaifan

import (
	"bytes"
	"context"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/kfadapter/kfadapter/internal/provider"
	"github.com/kfadapter/kfadapter/internal/provider/kuaifan/wifiin"
)

func TestRelayDatagramsDelayedIVAndCancellation(t *testing.T) {
	for _, delay := range []time.Duration{0, 3 * time.Second} {
		t.Run(fmt.Sprintf("IV_delay_%s", delay), func(t *testing.T) {
			baseline := runtime.NumGoroutine()
			defer requireGoroutinesReturn(t, baseline)
			listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			controlClient, control := loopbackTCPPair(t)
			packets := newTestPacketIO()
			defer packets.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			datagram := []byte{0, 0, 0, 1, 127, 0, 0, 1, 0, 53, 'd', 'n', 's'}
			received := make(chan struct{})
			serverDone := make(chan error, 1)
			go func() {
				conn, err := listener.AcceptTCP()
				if err != nil {
					serverDone <- err
					return
				}
				defer conn.Close()
				serverDone <- serveTestDatagrams(conn, datagram, delay, received)
			}()
			authority, err := json.Marshal(tunnelAuthority{Password: testTunnelPassword, Method: "aes-256-cfb", Extension: testTunnelExtension})
			if err != nil {
				t.Fatal(err)
			}
			addr := listener.Addr().(*net.TCPAddr)
			ready := make(chan struct{})
			relayDone := make(chan error, 1)
			go func() {
				relayDone <- NewTransport().RelayDatagrams(ctx, provider.DatagramRequest{
					Dial: (&net.Dialer{}).DialContext, NodeHost: addr.IP.String(), NodePort: uint16(addr.Port),
					Authority: authority, Control: control, Packets: packets, HandshakeTimeout: time.Second,
					Admit: func() bool { return true }, Ready: func(net.Addr) error { close(ready); return nil },
				})
			}()
			awaitSignal(t, ready)
			packets.requests <- datagram
			awaitSignal(t, received)
			if delay != 0 {
				select {
				case response := <-packets.responses:
					if !bytes.Equal(response, datagram) {
						t.Fatalf("UOT response = %x, want %x", response, datagram)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("delayed UOT server IV prevented datagram response")
				}
			}
			cancel()
			requireClientClosed(t, controlClient)
			if err := awaitResult(t, relayDone); !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled UOT relay = %v", err)
			}
			if err := awaitResult(t, serverDone); err != nil {
				t.Fatal(err)
			}
			awaitSignal(t, packets.closed)
		})
	}
}

func serveTestDatagrams(conn *net.TCPConn, datagram []byte, delay time.Duration, received chan<- struct{}) error {
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	inbound, err := readClientHandshake(conn, wifiin.UOTOuterType)
	if err != nil {
		return err
	}
	reader, err := wifiin.NewUOTReader(inbound)
	if err != nil {
		return err
	}
	packet := make([]byte, 1024)
	n, flowID, err := reader.ReadSOCKSDatagram(packet)
	if err != nil {
		return err
	}
	if !bytes.Equal(packet[:n], datagram) || flowID != 7 {
		return errors.New("unexpected UOT request or flow ID")
	}
	close(received)
	if delay != 0 {
		time.Sleep(delay)
		key := wifiin.DeriveKey(testTunnelPassword)
		iv := make([]byte, wifiin.IVSize)
		stream, err := wifiin.NewEncrypter(key[:], iv)
		if err != nil {
			return err
		}
		if err := writeAll(conn, iv); err != nil {
			return err
		}
		writer, err := wifiin.NewUOTWriter(&cipher.StreamWriter{S: stream, W: conn})
		if err != nil {
			return err
		}
		if err := writer.WriteSOCKSDatagram(flowID, datagram); err != nil {
			return err
		}
	}
	_, err = io.Copy(io.Discard, inbound)
	return err
}

// Design §6: an unsupported destination is discarded on its own; the pump keeps
// running and forwards the next valid IPv4 datagram.
func TestPacketsToUOTDiscardsUnsupportedAddressAndContinues(t *testing.T) {
	valid := []byte{0, 0, 0, 1, 127, 0, 0, 1, 0, 53, 'h', 'i'}
	for _, unsupported := range [][]byte{
		{0, 0, 0, 3, 1, 'x', 0, 53},
		append([]byte{0, 0, 0, 4}, make([]byte, 18)...),
	} {
		packets := newTestPacketIO()
		pipeReader, pipeWriter := io.Pipe()
		writer, err := wifiin.NewUOTWriter(pipeWriter)
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- packetsToUOT(packets, writer) }()
		go func() {
			for _, datagram := range [][]byte{unsupported, valid} {
				select {
				case packets.requests <- datagram:
				case <-packets.closed:
					return
				}
			}
		}()
		type frameResult struct {
			n      int
			flowID uint16
			err    error
		}
		frames := make(chan frameResult, 1)
		go func() {
			reader, err := wifiin.NewUOTReader(pipeReader)
			if err != nil {
				frames <- frameResult{err: err}
				return
			}
			frame := make([]byte, 1024)
			n, flowID, err := reader.ReadSOCKSDatagram(frame)
			frames <- frameResult{n: n, flowID: flowID, err: err}
		}()
		select {
		case got := <-frames:
			if got.err != nil || got.n == 0 || got.flowID != packets.FlowID() {
				t.Fatalf("valid datagram after unsupported one: n=%d flow=%d err=%v", got.n, got.flowID, got.err)
			}
		case err := <-done:
			t.Fatalf("pump ended on an unsupported datagram: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("valid datagram was not forwarded after an unsupported one")
		}
		_ = packets.Close()
		_ = pipeReader.Close()
		if err := <-done; !errors.Is(err, net.ErrClosed) {
			t.Fatalf("pump ended with %v, want net.ErrClosed after close", err)
		}
	}
}

type testPacketIO struct {
	requests  chan []byte
	responses chan []byte
	closed    chan struct{}
	closeOnce sync.Once
}

func newTestPacketIO() *testPacketIO {
	return &testPacketIO{requests: make(chan []byte, 1), responses: make(chan []byte, 1), closed: make(chan struct{})}
}

func (*testPacketIO) FlowID() uint16 { return 7 }
func (*testPacketIO) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10000}
}

func (p *testPacketIO) ReadPacket(dst []byte) (int, error) {
	select {
	case packet := <-p.requests:
		return copy(dst, packet), nil
	case <-p.closed:
		return 0, net.ErrClosed
	}
}

func (p *testPacketIO) WritePacket(packet []byte) error {
	select {
	case p.responses <- append([]byte(nil), packet...):
		return nil
	case <-p.closed:
		return net.ErrClosed
	}
}

func (p *testPacketIO) Close() error {
	p.closeOnce.Do(func() { close(p.closed) })
	return nil
}
