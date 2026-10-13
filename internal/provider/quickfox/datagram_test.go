package quickfox

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oshinop/chinadapter/internal/provider"
)

const testFlowID = 40001

func TestRelayDatagramsFramesRequestsAndReplies(t *testing.T) {
	t.Parallel()
	controlClient, control := loopbackTCPPair(t)
	relay, relayAdapter := loopbackTCPPair(t)
	packets := newTestPacketIO()
	transport := NewTransport()
	transport.lookup = func(_ context.Context, network, host string) ([]netip.Addr, error) {
		if network != "ip4" || host != "dns.example" {
			return nil, errors.New("unexpected lookup")
		}
		return []netip.Addr{netip.MustParseAddr("192.0.2.9")}, nil
	}
	ready := make(chan net.Addr, 1)
	done := make(chan error, 1)
	go func() {
		request := nativeDatagramRequest(t, control, packets, func(context.Context, string, string) (net.Conn, error) { return relayAdapter, nil })
		request.Ready = func(address net.Addr) error { ready <- address; return nil }
		done <- transport.RelayDatagrams(context.Background(), request)
	}()

	var preface [62]byte
	if _, err := io.ReadFull(relay, preface[:]); err != nil {
		t.Fatal(err)
	}
	if command := preface[5+int(preface[4])+9]; command&0xf0 != datagramControlMode {
		t.Fatalf("control command = %#x, want datagram base %#x", command, datagramControlMode)
	}
	if err := writeAll(relay, observedControlACK[:]); err != nil {
		t.Fatal(err)
	}
	select {
	case address := <-ready:
		if address.String() != packets.LocalAddr().String() {
			t.Fatalf("ready address = %s", address)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("datagram relay did not become ready")
	}

	// IPv6, oversized, and fragmented datagrams are dropped without ending
	// the association; the following IPv4 and domain datagrams are framed.
	packets.requests <- append([]byte{0, 0, 0, 4}, append(netip.MustParseAddr("2001:db8::1").AsSlice(), 0, 53, 'x')...)
	packets.requests <- append(socksIPv4Request("192.0.2.1:53"), bytes.Repeat([]byte{'x'}, maxDatagramPayload+1)...)
	packets.requests <- []byte{0, 0, 1, 1, 192, 0, 2, 1, 0, 53, 'x'}
	packets.requests <- append(socksIPv4Request("192.0.2.1:53"), "first"...)
	packets.requests <- append([]byte{0, 0, 0, 3, byte(len("dns.example"))}, append([]byte("dns.example"), 0x01, 0xbb, 's', 'e', 'c', 'o', 'n', 'd')...)
	for sequence, want := range []struct {
		target  netip.AddrPort
		payload string
	}{{netip.MustParseAddrPort("192.0.2.1:53"), "first"}, {netip.MustParseAddrPort("192.0.2.9:443"), "second"}} {
		header, payload := readRelayFrame(t, relay)
		if got := binary.BigEndian.Uint16(header[1:3]); got != testFlowID {
			t.Fatalf("frame flow = %d", got)
		}
		target := netip.AddrPortFrom(netip.AddrFrom4([4]byte(header[4:8])), binary.BigEndian.Uint16(header[8:10]))
		if target != want.target || string(payload) != want.payload {
			t.Fatalf("frame %d = %s %q, want %s %q", sequence, target, payload, want.target, want.payload)
		}
		if got := binary.LittleEndian.Uint16(header[10:12]); got != uint16(sequence) || header[12] != 0 || header[13] != 0 {
			t.Fatalf("frame %d sequence/trailer = % x", sequence, header[10:14])
		}
	}

	writeRelayFrame(t, relay, testFlowID+1, "198.51.100.7:3478", "other flow")
	writeRelayFrame(t, relay, testFlowID, "198.51.100.7:3478", "reply")
	select {
	case reply := <-packets.responses:
		want := append(socksIPv4Request("198.51.100.7:3478"), "reply"...)
		if !bytes.Equal(reply, want) {
			t.Fatalf("SOCKS reply = % x, want % x", reply, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("relay reply was not delivered")
	}

	_ = controlClient.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("relay after SOCKS close = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not stop after the SOCKS control connection closed")
	}
	var buffer [1]byte
	if count, err := relay.Read(buffer[:]); count != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("relay connection after stop: read %d bytes, error %v", count, err)
	}
}

func TestRelayDatagramsRejectsInvalidFrameLength(t *testing.T) {
	t.Parallel()
	_, control := loopbackTCPPair(t)
	relay, relayAdapter := loopbackTCPPair(t)
	packets := newTestPacketIO()
	done := make(chan error, 1)
	go func() {
		done <- NewTransport().RelayDatagrams(context.Background(), nativeDatagramRequest(t, control, packets,
			func(context.Context, string, string) (net.Conn, error) { return relayAdapter, nil }))
	}()
	if err := readNativePreface(relay); err != nil {
		t.Fatal(err)
	}
	if err := writeAll(relay, observedControlACK[:]); err != nil {
		t.Fatal(err)
	}
	if err := writeAll(relay, []byte{datagramHeaderSize - 1, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "invalid datagram frame length") {
			t.Fatalf("relay error = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("relay accepted an invalid frame length")
	}
	select {
	case <-packets.closed:
	default:
		t.Fatal("UDP association was not closed")
	}
}

func nativeDatagramRequest(t *testing.T, control net.Conn, packets provider.PacketIO, dial provider.DialContextFunc) provider.DatagramRequest {
	t.Helper()
	stream := nativeRelayRequest(t, control, dial)
	return provider.DatagramRequest{
		Dial: dial, Control: control, Packets: packets, NodeHost: stream.NodeHost, NodePort: stream.NodePort,
		Authority: stream.Authority, HandshakeTimeout: stream.HandshakeTimeout, Admit: stream.Admit, Ready: stream.Ready,
	}
}

func socksIPv4Request(address string) []byte {
	target := netip.MustParseAddrPort(address)
	octets := target.Addr().As4()
	return []byte{0, 0, 0, 1, octets[0], octets[1], octets[2], octets[3], byte(target.Port() >> 8), byte(target.Port())}
}

func readRelayFrame(t *testing.T, relay net.Conn) ([]byte, []byte) {
	t.Helper()
	_ = relay.SetReadDeadline(time.Now().Add(3 * time.Second))
	var length [4]byte
	if _, err := io.ReadFull(relay, length[:]); err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, binary.LittleEndian.Uint32(length[:]))
	if _, err := io.ReadFull(relay, frame); err != nil {
		t.Fatal(err)
	}
	if len(frame) < datagramHeaderSize {
		t.Fatalf("frame length %d", len(frame))
	}
	return frame[:datagramHeaderSize], frame[datagramHeaderSize:]
}

func writeRelayFrame(t *testing.T, relay net.Conn, flowID uint16, source, payload string) {
	t.Helper()
	address := netip.MustParseAddrPort(source)
	frame := make([]byte, 4+datagramHeaderSize+len(payload))
	binary.LittleEndian.PutUint32(frame, uint32(datagramHeaderSize+len(payload)))
	binary.BigEndian.PutUint16(frame[5:7], flowID)
	octets := address.Addr().As4()
	copy(frame[8:12], octets[:])
	binary.BigEndian.PutUint16(frame[12:14], address.Port())
	copy(frame[18:], payload)
	if err := writeAll(relay, frame); err != nil {
		t.Fatal(err)
	}
}

type testPacketIO struct {
	requests  chan []byte
	responses chan []byte
	closed    chan struct{}
	closeOnce sync.Once
}

func newTestPacketIO() *testPacketIO {
	return &testPacketIO{requests: make(chan []byte, 8), responses: make(chan []byte, 8), closed: make(chan struct{})}
}

func (*testPacketIO) FlowID() uint16 { return testFlowID }
func (*testPacketIO) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: testFlowID}
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
