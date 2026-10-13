package quickfox

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"time"

	"github.com/oshinop/chinadapter/internal/provider"
)

// QuickFox datagrams use the client's "udp2tcp" mode, recovered from
// QuickFoxCoreWin.dll 3.60.14 (StartUdpCtrlProtocol, SocksUdp::GetClientPacket)
// and verified against live relays in 2026-10. The control connection
// authenticates with command base 0x30 instead of 0x20 and then carries
// datagrams in both directions, each framed as a little-endian uint32 length
// followed by a 14-byte header and the raw (not XORed) payload:
//
//	0      random byte
//	1..2   association flow ID, big-endian; replies echo it
//	3      random byte
//	4..7   IPv4 destination (request) or source (reply)
//	8..9   port, big-endian
//	10..11 sequence number, little-endian
//	12..13 zero
//
// The relay also offers the same header over native UDP to the port in control
// acknowledgement bytes 8..9, but live relays answered it inconsistently, so
// only the TCP-carried mode is used.
const (
	datagramControlMode = 0x30
	datagramHeaderSize  = 14
	// maxDatagramPayload matches the native client's 2048-byte datagram buffer.
	maxDatagramPayload = 2048 - datagramHeaderSize
	// maxReplyFrame bounds one relay frame; larger lengths desynchronize the stream.
	maxReplyFrame = 1 << 16
	// socksPacketOffset leaves room to build the frame prefix in place before an
	// IPv4 SOCKS request header.
	socksPacketOffset   = 4 + datagramHeaderSize - socksIPv4HeaderSize
	socksIPv4HeaderSize = 10
	maxUDPPacketSize    = 1<<16 - 1
	maxResolvedHosts    = 64
	maxSequence         = 60000
)

var _ provider.DatagramTransport = (*Transport)(nil)

func (transport *Transport) RelayDatagrams(ctx context.Context, request provider.DatagramRequest) error {
	if transport == nil || ctx == nil || request.Dial == nil || request.Control == nil || request.Packets == nil || request.NodeHost == "" ||
		request.NodePort == 0 || request.Admit == nil || request.Ready == nil || request.HandshakeTimeout <= 0 || request.Packets.FlowID() == 0 ||
		transport.clock == nil || transport.lookup == nil {
		return errors.New("quickfox: invalid datagram relay request")
	}
	authority, err := decodeTunnelAuthority(request.Authority)
	if err != nil {
		return err
	}
	upstream, err := dialRelay(ctx, request.Dial, request.NodeHost, request.NodePort, request.HandshakeTimeout)
	if err != nil {
		return err
	}
	defer upstream.Close()
	if err := upstream.SetDeadline(time.Now().Add(request.HandshakeTimeout)); err != nil {
		return fmt.Errorf("quickfox: set datagram control deadline: %w", err)
	}
	preface, err := encodeTunnelAuth(authority, nativeNonce(transport.clock()), datagramControlMode, netip.Addr{}, 0)
	if err != nil {
		return err
	}
	if err := writeAll(upstream, preface); err != nil {
		return fmt.Errorf("quickfox: write datagram control preface: %w", err)
	}
	var acknowledgement [controlACKSize]byte
	if _, err := io.ReadFull(upstream, acknowledgement[:]); err != nil {
		return fmt.Errorf("%w: read datagram control acknowledgement: %w", ErrHandshake, err)
	}
	if err := upstream.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf("quickfox: clear datagram control deadline: %w", err)
	}
	if !request.Admit() {
		return provider.ErrNoSession
	}
	if err := request.Ready(request.Packets.LocalAddr()); err != nil {
		return err
	}
	results := make(chan error, 3)
	closeAll := func() {
		_ = request.Packets.Close()
		_ = upstream.Close()
		_ = request.Control.Close()
	}
	stopCancellation := context.AfterFunc(ctx, closeAll)
	defer stopCancellation()
	writer := &datagramWriter{transport: transport, ctx: ctx, upstream: upstream, timeout: request.HandshakeTimeout}
	go func() { results <- watchControl(request.Control) }()
	go func() { results <- writer.pump(request.Packets) }()
	go func() { results <- readDatagrams(upstream, request.Packets) }()
	err = <-results
	closeAll()
	for range 2 {
		<-results
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err == nil || errors.Is(err, io.EOF) || benignRelayClose(err) {
		return nil
	}
	return err
}

// datagramWriter frames SOCKS UDP requests onto the relay connection. It is
// owned by a single pump goroutine.
type datagramWriter struct {
	transport *Transport
	ctx       context.Context
	upstream  net.Conn
	timeout   time.Duration
	sequence  uint16
	resolved  map[string]netip.Addr
}

func (writer *datagramWriter) pump(packets provider.PacketIO) error {
	buffer := make([]byte, socksPacketOffset+maxUDPPacketSize)
	flowID := packets.FlowID()
	for {
		n, err := packets.ReadPacket(buffer[socksPacketOffset:])
		if err != nil {
			return err
		}
		frame, ok := writer.frame(buffer, socksPacketOffset+n, flowID)
		if !ok {
			// Unsupported, unresolvable, or oversized datagrams are dropped
			// individually; they never end the association.
			continue
		}
		if err := writeAll(writer.upstream, frame); err != nil {
			return fmt.Errorf("quickfox: write datagram frame: %w", err)
		}
	}
}

// frame validates the SOCKS UDP request in buffer[socksPacketOffset:end] and
// rewrites its prefix in place into one relay frame that shares the payload.
func (writer *datagramWriter) frame(buffer []byte, end int, flowID uint16) ([]byte, bool) {
	packet := buffer[socksPacketOffset:end]
	if len(packet) < 4 || packet[2] != 0 {
		return nil, false
	}
	var (
		target    netip.Addr
		port      uint16
		headerLen int
	)
	switch packet[3] {
	case 0x01:
		if len(packet) < socksIPv4HeaderSize {
			return nil, false
		}
		target = netip.AddrFrom4([4]byte(packet[4:8]))
		port, headerLen = binary.BigEndian.Uint16(packet[8:10]), socksIPv4HeaderSize
	case 0x03:
		hostLen := int(packet[4])
		if hostLen == 0 || len(packet) < 7+hostLen {
			return nil, false
		}
		address, ok := writer.resolve(string(packet[5 : 5+hostLen]))
		if !ok {
			return nil, false
		}
		target = address
		port, headerLen = binary.BigEndian.Uint16(packet[5+hostLen:7+hostLen]), 7+hostLen
	case 0x04:
		if len(packet) < 22 {
			return nil, false
		}
		// The relay addresses IPv4 only; IPv4-mapped IPv6 is the same target.
		target = netip.AddrFrom16([16]byte(packet[4:20])).Unmap()
		port, headerLen = binary.BigEndian.Uint16(packet[20:22]), 22
	default:
		return nil, false
	}
	payloadStart := socksPacketOffset + headerLen
	payloadLen := end - payloadStart
	if !target.Is4() || port == 0 || payloadLen > maxDatagramPayload {
		return nil, false
	}
	frame := buffer[payloadStart-4-datagramHeaderSize : end]
	binary.LittleEndian.PutUint32(frame[0:4], uint32(datagramHeaderSize+payloadLen))
	header := frame[4 : 4+datagramHeaderSize]
	header[0] = byte(rand.N(254))
	binary.BigEndian.PutUint16(header[1:3], flowID)
	header[3] = byte(rand.N(254))
	octets := target.As4()
	copy(header[4:8], octets[:])
	binary.BigEndian.PutUint16(header[8:10], port)
	binary.LittleEndian.PutUint16(header[10:12], writer.sequence)
	header[12], header[13] = 0, 0
	// The native client wraps its counter after 60000.
	if writer.sequence > maxSequence {
		writer.sequence = 0
	} else {
		writer.sequence++
	}
	return frame, true
}

// resolve maps a SOCKS domain target to IPv4 with the stream path's resolver,
// caching a bounded number of names for the association's lifetime.
func (writer *datagramWriter) resolve(host string) (netip.Addr, bool) {
	if address, ok := writer.resolved[host]; ok {
		return address, true
	}
	address, err := writer.transport.resolveTarget(writer.ctx, host, writer.timeout)
	if err != nil {
		return netip.Addr{}, false
	}
	if writer.resolved == nil || len(writer.resolved) >= maxResolvedHosts {
		writer.resolved = make(map[string]netip.Addr, maxResolvedHosts)
	}
	writer.resolved[host] = address
	return address, true
}

// readDatagrams converts relay frames for this association's flow into SOCKS
// UDP replies, rewriting each frame header in place.
func readDatagrams(upstream io.Reader, packets provider.PacketIO) error {
	buffer := make([]byte, maxReplyFrame)
	flowID := packets.FlowID()
	var length [4]byte
	for {
		if _, err := io.ReadFull(upstream, length[:]); err != nil {
			return err
		}
		size := binary.LittleEndian.Uint32(length[:])
		if size < datagramHeaderSize || size > maxReplyFrame {
			return fmt.Errorf("quickfox: invalid datagram frame length %d", size)
		}
		frame := buffer[:size]
		if _, err := io.ReadFull(upstream, frame); err != nil {
			return fmt.Errorf("quickfox: read datagram frame: %w", err)
		}
		if binary.BigEndian.Uint16(frame[1:3]) != flowID {
			continue
		}
		source := [4]byte(frame[4:8])
		port := [2]byte(frame[8:10])
		reply := frame[4:]
		reply[0], reply[1], reply[2], reply[3] = 0, 0, 0, 0x01
		copy(reply[4:8], source[:])
		copy(reply[8:10], port[:])
		if err := packets.WritePacket(reply); err != nil {
			return err
		}
	}
}

// watchControl returns when the SOCKS client closes the TCP connection that
// owns the UDP association.
func watchControl(control net.Conn) error {
	var discard [256]byte
	for {
		_, err := control.Read(discard[:])
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}
