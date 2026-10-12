package quickfox

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/oshinop/chinadapter/internal/provider"
)

const (
	relayXORByte    = byte(0x32)
	relayBufferSize = 32 * 1024
	controlACKSize  = 14
)

// ErrHandshake reports a rejected or incomplete native relay handshake.
var ErrHandshake = errors.New("quickfox: relay handshake failed")

type lookupNetIPFunc func(context.Context, string, string) ([]netip.Addr, error)

// Transport implements the observed QuickFox native framed TCP relay for IPv4
// destinations. It validates the 14-byte zero control acknowledgement before
// opening the data connection. The provider's UDP framing remains unavailable
// because it has not been verified.
type Transport struct {
	clock  func() time.Time
	lookup lookupNetIPFunc
}

func NewTransport() *Transport {
	return &Transport{clock: time.Now, lookup: net.DefaultResolver.LookupNetIP}
}

func (*Transport) Protocol() provider.Protocol { return NativeProtocol }

func (transport *Transport) RelayStream(ctx context.Context, request provider.RelayRequest) error {
	if transport == nil || ctx == nil || request.Dial == nil || request.Client == nil || request.NodeHost == "" || request.NodePort == 0 ||
		request.Target.Host == "" || request.Target.Port == 0 || request.Admit == nil || request.Ready == nil || request.HandshakeTimeout <= 0 ||
		transport.clock == nil || transport.lookup == nil {
		return errors.New("quickfox: invalid stream relay request")
	}
	authority, err := decodeTunnelAuthority(request.Authority)
	if err != nil {
		return err
	}
	target, err := transport.resolveTarget(ctx, request.Target.Host, request.HandshakeTimeout)
	if err != nil {
		return err
	}
	control, err := dialRelay(ctx, request.Dial, request.NodeHost, request.NodePort, request.HandshakeTimeout)
	if err != nil {
		return err
	}
	defer control.Close()
	if err := control.SetDeadline(time.Now().Add(request.HandshakeTimeout)); err != nil {
		return fmt.Errorf("quickfox: set control deadline: %w", err)
	}
	nonce := nativeNonce(transport.clock())
	controlPacket, err := encodeTunnelAuth(authority, nonce, 0x20, netip.Addr{}, 0)
	if err != nil {
		return err
	}
	if err := writeAll(control, controlPacket); err != nil {
		return fmt.Errorf("quickfox: write control preface: %w", err)
	}
	var acknowledgement [controlACKSize]byte
	if _, err := io.ReadFull(control, acknowledgement[:]); err != nil {
		return fmt.Errorf("%w: read control acknowledgement: %w", ErrHandshake, err)
	}
	// The existing transport fixture acknowledges with exactly 14 zero bytes;
	// no individual field semantics have been established.
	if acknowledgement != [controlACKSize]byte{} {
		return fmt.Errorf("%w: invalid control acknowledgement", ErrHandshake)
	}
	if err := control.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf("quickfox: clear control deadline: %w", err)
	}

	upstream, err := dialRelay(ctx, request.Dial, request.NodeHost, request.NodePort, request.HandshakeTimeout)
	if err != nil {
		return err
	}
	defer upstream.Close()
	if err := upstream.SetDeadline(time.Now().Add(request.HandshakeTimeout)); err != nil {
		return fmt.Errorf("quickfox: set data deadline: %w", err)
	}
	dataPacket, err := encodeTunnelAuth(authority, nonce, 0x10, target, request.Target.Port)
	if err != nil {
		return err
	}
	if err := writeAll(upstream, dataPacket); err != nil {
		return fmt.Errorf("quickfox: write data preface: %w", err)
	}
	if err := upstream.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf("quickfox: clear data deadline: %w", err)
	}
	if !request.Admit() {
		return provider.ErrNoSession
	}
	if err := request.Ready(upstream.LocalAddr()); err != nil {
		return err
	}
	return relayXOR(ctx, request.Client, upstream)
}

func (transport *Transport) resolveTarget(ctx context.Context, host string, timeout time.Duration) (netip.Addr, error) {
	if address, err := netip.ParseAddr(host); err == nil {
		if address.Is4() {
			return address, nil
		}
		return netip.Addr{}, fmt.Errorf("quickfox: IPv6 targets are unsupported: %w", provider.ErrAddressUnsupported)
	}
	resolveContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	addresses, err := transport.lookup(resolveContext, "ip4", host)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return netip.Addr{}, fmt.Errorf("quickfox: target has no IPv4 address: %w: %w", provider.ErrAddressUnsupported, err)
		}
		return netip.Addr{}, fmt.Errorf("quickfox: resolve target: %w", err)
	}
	for _, address := range addresses {
		if address.Is4() {
			return address, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("quickfox: target has no IPv4 address: %w", provider.ErrAddressUnsupported)
}

func dialRelay(ctx context.Context, dial provider.DialContextFunc, host string, port uint16, timeout time.Duration) (net.Conn, error) {
	dialContext, cancel := context.WithTimeout(ctx, timeout)
	connection, err := dial(dialContext, "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	cancel()
	if ctx.Err() != nil {
		if err == nil {
			_ = connection.Close()
		}
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, fmt.Errorf("quickfox: connect selected upstream: %w", err)
	}
	return connection, nil
}

func nativeNonce(now time.Time) byte {
	seed := uint32(now.Unix())
	state := seed*214013 + 2531011
	return byte(((state >> 16) & 0x7fff) % 16)
}

func encodeTunnelAuth(authority tunnelAuthority, nonce, mode byte, target netip.Addr, targetPort uint16) ([]byte, error) {
	if !validToken(authority.Token) || authority.UserID <= 0 || authority.UserID > int64(^uint32(0)) || nonce > 15 || mode != 0x10 && mode != 0x20 || targetPort != 0 && !target.Is4() {
		return nil, ErrSchema
	}
	identity := []byte("C" + authority.Token + "," + strconv.FormatUint(uint64(authority.AppID), 10))
	if len(identity) > 255 {
		return nil, ErrSchema
	}
	packet := make([]byte, 27+len(identity))
	packet[0] = nonce<<4 | 7
	packet[1] = 0x49
	packet[2] = nonce
	packet[3] = 8
	packet[4] = byte(len(identity))
	copy(packet[5:], identity)
	offset := 5 + len(identity)
	binary.LittleEndian.PutUint32(packet[offset:], uint32(authority.UserID))
	offset += 4
	var targetWord uint32
	if target.Is4() {
		octets := target.As4()
		targetWord = binary.LittleEndian.Uint32(octets[:])
	}
	portWord := (targetPort&0xff)<<8 | targetPort>>8
	checksum := uint32(byte(targetWord)^byte(portWord)^nonce) + uint32(nonce)*0x1110
	binary.LittleEndian.PutUint32(packet[offset:], checksum)
	offset += 4
	packet[offset] = 0x0b
	packet[offset+1] = mode + nonce
	binary.LittleEndian.PutUint16(packet[offset+2:], 0x0400)
	binary.LittleEndian.PutUint32(packet[offset+4:], targetWord)
	binary.LittleEndian.PutUint16(packet[offset+8:], portWord)
	binary.LittleEndian.PutUint32(packet[offset+10:], ^uint32(0))
	return packet, nil
}

func relayXOR(ctx context.Context, client, upstream net.Conn) error {
	results := make(chan error, 2)
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = client.Close()
			_ = upstream.Close()
		})
	}
	cancelled := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			closeBoth()
		case <-cancelled:
		}
	}()
	pump := func(destination, source net.Conn) {
		buffer := make([]byte, relayBufferSize)
		var result error
		for {
			count, readErr := source.Read(buffer)
			if count > 0 {
				for index := range count {
					buffer[index] ^= relayXORByte
				}
				if writeErr := writeAll(destination, buffer[:count]); writeErr != nil {
					result = writeErr
					break
				}
			}
			if readErr != nil {
				if errors.Is(readErr, io.EOF) {
					if closer, ok := destination.(interface{ CloseWrite() error }); ok {
						result = closer.CloseWrite()
					} else {
						result = destination.Close()
					}
				} else {
					result = readErr
				}
				break
			}
		}
		if result != nil && !benignRelayClose(result) {
			closeBoth()
		}
		results <- result
	}
	go pump(upstream, client)
	go pump(client, upstream)
	first := <-results
	second := <-results
	close(cancelled)
	if first != nil && !benignRelayClose(first) {
		return first
	}
	if second != nil && !benignRelayClose(second) {
		return second
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func benignRelayClose(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe)
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) != 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(data) {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}
