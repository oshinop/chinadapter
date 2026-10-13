package transocks

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5" // SIP004 retains the legacy EVP_BytesToKey password derivation.
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/oshinop/chinadapter/internal/provider"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	ssMaxChunk       = 0x3fff
	ssTagSize        = 16
	maxSocksDatagram = 65507
)

// ErrProtocol identifies an invalid or unauthenticated upstream frame.
var ErrProtocol = errors.New("transocks: invalid upstream protocol frame")

// ShadowsocksTransport implements SIP004 AEAD streams and native UDP packets.
// The immutable node pin resolves to its own line's current tunnel endpoint.
type ShadowsocksTransport struct{ sessions *SessionManager }

func NewShadowsocksTransport(sessions *SessionManager) *ShadowsocksTransport {
	return &ShadowsocksTransport{sessions: sessions}
}
func (*ShadowsocksTransport) Protocol() provider.Protocol { return ShadowsocksProtocol }

var (
	_ provider.DatagramTransport = (*ShadowsocksTransport)(nil)
	_ provider.ProbeAddresser    = (*ShadowsocksTransport)(nil)
)

func (*ShadowsocksTransport) ProbeAddress(authority []byte, host string, port uint16) (string, error) {
	return probeAddress(authority, host, port)
}

func (transport *ShadowsocksTransport) RelayStream(ctx context.Context, request provider.RelayRequest) error {
	if transport == nil || !validStreamRequest(ctx, request) {
		return errors.New("transocks: invalid stream relay request")
	}
	address, err := socksAddress(request.Target)
	if err != nil {
		return err
	}
	upstream, config, err := transport.sessions.dialShadowsocks(ctx, request.Authority, request.NodeHost, request.NodePort, request.Dial, "tcp", request.HandshakeTimeout)
	if err != nil {
		return err
	}
	defer upstream.Close()
	stop := context.AfterFunc(ctx, func() { _ = upstream.Close() })
	defer stop()
	if err := upstream.SetDeadline(time.Now().Add(request.HandshakeTimeout)); err != nil {
		return err
	}
	stream, err := newSSStream(upstream, config.SS)
	if err != nil {
		return err
	}
	if err := transocksWriteAll(stream, address); err != nil {
		return fmt.Errorf("transocks: write Shadowsocks destination: %w", err)
	}
	if err := upstream.SetDeadline(time.Time{}); err != nil {
		return err
	}
	if !request.Admit() {
		return provider.ErrNoSession
	}
	if err := request.Ready(upstream.LocalAddr()); err != nil {
		return err
	}
	return relayTransocks(ctx, request.Client, stream)
}

func (transport *ShadowsocksTransport) RelayDatagrams(ctx context.Context, request provider.DatagramRequest) error {
	if transport == nil || !validDatagramRequest(ctx, request) {
		return errors.New("transocks: invalid datagram relay request")
	}
	upstream, config, err := transport.sessions.dialShadowsocks(ctx, request.Authority, request.NodeHost, request.NodePort, request.Dial, "udp", request.HandshakeTimeout)
	if err != nil {
		return err
	}
	defer upstream.Close()
	entry := config.SS
	key, err := ssMasterKey(entry)
	if err != nil {
		return err
	}
	if !request.Admit() {
		return provider.ErrNoSession
	}
	if err := request.Ready(request.Packets.LocalAddr()); err != nil {
		return err
	}
	return relayTransocksDatagrams(ctx, request, upstream, func() error {
		buffer := make([]byte, maxSocksDatagram+32+ssTagSize)
		for {
			n, err := request.Packets.ReadPacket(buffer[len(key) : len(key)+maxSocksDatagram])
			if err != nil {
				return err
			}
			packet := buffer[len(key) : len(key)+n]
			if !validSocksPacket(packet) || len(packet)-3+len(key)+ssTagSize > maxSocksDatagram {
				continue
			}
			// Reuse the SOCKS reserved bytes as the beginning of the random salt.
			wire := buffer[3 : len(key)+n]
			salt := wire[:len(key)]
			if _, err := io.ReadFull(rand.Reader, salt); err != nil {
				return err
			}
			aead, err := ssAEAD(entry.Method, key, salt)
			if err != nil {
				return err
			}
			var nonce [12]byte
			wire = aead.Seal(wire[:len(key)], nonce[:], wire[len(key):], nil)
			if n, err := upstream.Write(wire); err != nil {
				return err
			} else if n != len(wire) {
				return io.ErrShortWrite
			}
		}
	}, func() error {
		buffer := make([]byte, maxSocksDatagram+3)
		for {
			n, err := upstream.Read(buffer[3:])
			if err != nil {
				return err
			}
			wire := buffer[3 : 3+n]
			if len(wire) < len(key)+ssTagSize {
				continue
			}
			aead, err := ssAEAD(entry.Method, key, wire[:len(key)])
			if err != nil {
				return err
			}
			var nonce [12]byte
			plain, err := aead.Open(wire[len(key):len(key)], nonce[:], wire[len(key):], nil)
			if err != nil {
				continue
			} // A corrupt UDP packet does not poison the association.
			if _, err := socksAddressSize(plain); err != nil {
				continue
			}
			reply := buffer[len(key) : 3+len(key)+len(plain)]
			reply[0], reply[1], reply[2] = 0, 0, 0
			if err := request.Packets.WritePacket(reply); err != nil {
				return err
			}
		}
	})
}

func ssMasterKey(entry shadowsocksEntry) ([]byte, error) {
	if !entry.valid() {
		return nil, ErrInvalidAuthority
	}
	size := 32
	if entry.Method == "aes-128-gcm" {
		size = 16
	}
	key := make([]byte, 0, size)
	var previous []byte
	for len(key) < size {
		hash := md5.New()
		_, _ = hash.Write(previous)
		_, _ = io.WriteString(hash, entry.Password)
		previous = hash.Sum(nil)
		key = append(key, previous...)
	}
	return key[:size], nil
}

func ssSubkey(key, salt []byte) ([]byte, error) {
	if len(salt) != len(key) || len(key) != 16 && len(key) != 32 {
		return nil, ErrProtocol
	}
	subkey := make([]byte, len(key))
	_, err := io.ReadFull(hkdf.New(sha1.New, key, salt, []byte("ss-subkey")), subkey)
	return subkey, err
}

func ssAEAD(method string, key, salt []byte) (cipher.AEAD, error) {
	subkey, err := ssSubkey(key, salt)
	if err != nil {
		return nil, err
	}
	switch method {
	case "chacha20-ietf-poly1305":
		return chacha20poly1305.New(subkey)
	case "aes-128-gcm", "aes-256-gcm":
		block, err := aes.NewCipher(subkey)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	default:
		return nil, ErrInvalidAuthority
	}
}

type ssStream struct {
	net.Conn
	method                string
	key                   []byte
	readAEAD, writeAEAD   cipher.AEAD
	readNonce, writeNonce [12]byte
	readBuffer            [ssMaxChunk + ssTagSize]byte
	writeBuffer           [32 + 2 + ssTagSize + ssMaxChunk + ssTagSize]byte
	pending               []byte
}

func newSSStream(connection net.Conn, entry shadowsocksEntry) (*ssStream, error) {
	key, err := ssMasterKey(entry)
	if err != nil {
		return nil, err
	}
	return &ssStream{Conn: connection, method: entry.Method, key: key}, nil
}

func (stream *ssStream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if stream.readAEAD == nil {
		var salt [32]byte
		if _, err := io.ReadFull(stream.Conn, salt[:len(stream.key)]); err != nil {
			return 0, err
		}
		aead, err := ssAEAD(stream.method, stream.key, salt[:len(stream.key)])
		if err != nil {
			return 0, err
		}
		stream.readAEAD = aead
	}
	for len(stream.pending) == 0 {
		var length [2 + ssTagSize]byte
		if _, err := io.ReadFull(stream.Conn, length[:]); err != nil {
			return 0, err
		}
		plain, err := stream.readAEAD.Open(length[:0], stream.readNonce[:], length[:], nil)
		if err != nil {
			return 0, fmt.Errorf("%w: Shadowsocks length authentication", ErrProtocol)
		}
		incrementSSNonce(&stream.readNonce)
		size := int(binary.BigEndian.Uint16(plain))
		if size > ssMaxChunk {
			return 0, fmt.Errorf("%w: Shadowsocks chunk too large", ErrProtocol)
		}
		chunk := stream.readBuffer[:size+ssTagSize]
		if _, err := io.ReadFull(stream.Conn, chunk); err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return 0, err
		}
		stream.pending, err = stream.readAEAD.Open(chunk[:0], stream.readNonce[:], chunk, nil)
		if err != nil {
			return 0, fmt.Errorf("%w: Shadowsocks payload authentication", ErrProtocol)
		}
		incrementSSNonce(&stream.readNonce)
	}
	n := copy(p, stream.pending)
	stream.pending = stream.pending[n:]
	return n, nil
}

func (stream *ssStream) Write(p []byte) (int, error) {
	written := 0
	for len(p) != 0 {
		offset := 0
		if stream.writeAEAD == nil {
			salt := stream.writeBuffer[:len(stream.key)]
			if _, err := io.ReadFull(rand.Reader, salt); err != nil {
				return written, err
			}
			aead, err := ssAEAD(stream.method, stream.key, salt)
			if err != nil {
				return written, err
			}
			stream.writeAEAD = aead
			offset = len(salt)
		}
		size := min(len(p), ssMaxChunk)
		var length [2]byte
		binary.BigEndian.PutUint16(length[:], uint16(size))
		frame := stream.writeBuffer[:offset]
		frame = stream.writeAEAD.Seal(frame, stream.writeNonce[:], length[:], nil)
		incrementSSNonce(&stream.writeNonce)
		frame = stream.writeAEAD.Seal(frame, stream.writeNonce[:], p[:size], nil)
		incrementSSNonce(&stream.writeNonce)
		if err := transocksWriteAll(stream.Conn, frame); err != nil {
			return written, err
		}
		written += size
		p = p[size:]
	}
	return written, nil
}

func (stream *ssStream) CloseWrite() error { return transocksCloseWrite(stream.Conn) }

func incrementSSNonce(nonce *[12]byte) {
	for index := range nonce {
		nonce[index]++
		if nonce[index] != 0 {
			break
		}
	}
}

// The two protocols share SOCKS addresses, pin validation and relay lifetimes.
func socksAddress(target provider.Target) ([]byte, error) {
	if target.Host == "" || target.Port == 0 {
		return nil, provider.ErrAddressUnsupported
	}
	var address []byte
	if ip, err := netip.ParseAddr(target.Host); err == nil {
		if ip.Zone() != "" {
			return nil, provider.ErrAddressUnsupported
		}
		ip = ip.Unmap()
		if ip.Is4() {
			address = append([]byte{1}, ip.AsSlice()...)
		} else {
			address = append([]byte{4}, ip.AsSlice()...)
		}
	} else {
		if len(target.Host) > 255 {
			return nil, provider.ErrAddressUnsupported
		}
		address = append([]byte{3, byte(len(target.Host))}, target.Host...)
	}
	return binary.BigEndian.AppendUint16(address, target.Port), nil
}

func socksAddressSize(address []byte) (int, error) {
	if len(address) < 1 {
		return 0, ErrProtocol
	}
	var size int
	switch address[0] {
	case 1:
		size = 7
	case 4:
		size = 19
	case 3:
		if len(address) < 2 || address[1] == 0 {
			return 0, ErrProtocol
		}
		size = 4 + int(address[1])
	default:
		return 0, ErrProtocol
	}
	if len(address) < size || binary.BigEndian.Uint16(address[size-2:size]) == 0 {
		return 0, ErrProtocol
	}
	return size, nil
}

func readSocksAddress(reader io.Reader, buffer []byte) (int, error) {
	if _, err := io.ReadFull(reader, buffer[:1]); err != nil {
		return 0, err
	}
	var size int
	switch buffer[0] {
	case 1:
		size = 7
	case 4:
		size = 19
	case 3:
		if _, err := io.ReadFull(reader, buffer[1:2]); err != nil {
			return 0, err
		}
		if buffer[1] == 0 {
			return 0, ErrProtocol
		}
		size = 4 + int(buffer[1])
		if _, err := io.ReadFull(reader, buffer[2:size]); err != nil {
			return 0, err
		}
		_, err := socksAddressSize(buffer[:size])
		return size, err
	default:
		return 0, ErrProtocol
	}
	if _, err := io.ReadFull(reader, buffer[1:size]); err != nil {
		return 0, err
	}
	_, err := socksAddressSize(buffer[:size])
	return size, err
}

func validSocksPacket(packet []byte) bool {
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return false
	}
	_, err := socksAddressSize(packet[3:])
	return err == nil
}

func validStreamRequest(ctx context.Context, request provider.RelayRequest) bool {
	return ctx != nil && request.Dial != nil && request.Client != nil && request.NodeHost != "" && request.NodePort != 0 && request.Target.Host != "" && request.Target.Port != 0 && request.HandshakeTimeout > 0 && request.Admit != nil && request.Ready != nil
}

func validDatagramRequest(ctx context.Context, request provider.DatagramRequest) bool {
	return ctx != nil && request.Dial != nil && request.Control != nil && request.Packets != nil && request.NodeHost != "" && request.NodePort != 0 && request.HandshakeTimeout > 0 && request.Admit != nil && request.Ready != nil && request.Packets.FlowID() != 0
}

func dialTransocks(ctx context.Context, dial provider.DialContextFunc, network, host string, port uint16, timeout time.Duration) (net.Conn, error) {
	dialContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	connection, err := dial(dialContext, network, nodeKey(host, port))
	if err != nil {
		return nil, fmt.Errorf("transocks: connect selected upstream: %w", err)
	}
	if ctx.Err() != nil {
		_ = connection.Close()
		return nil, ctx.Err()
	}
	return connection, nil
}

func transocksWriteAll(writer io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := writer.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

func transocksCloseWrite(connection net.Conn) error {
	if closer, ok := connection.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return connection.Close()
}

func relayTransocks(ctx context.Context, client, upstream net.Conn) error {
	var once sync.Once
	closeBoth := func() { once.Do(func() { _ = client.Close(); _ = upstream.Close() }) }
	stop := context.AfterFunc(ctx, closeBoth)
	defer stop()
	results := make(chan error, 2)
	pump := func(destination, source net.Conn) {
		_, err := io.Copy(destination, source)
		if err == nil {
			err = transocksCloseWrite(destination)
		}
		if err != nil {
			closeBoth()
		}
		results <- err
	}
	go pump(upstream, client)
	go pump(client, upstream)
	first, second := <-results, <-results
	if ctx.Err() != nil {
		return ctx.Err()
	}
	for _, err := range []error{first, second} {
		if err != nil && !benignTransocksClose(err) {
			return err
		}
	}
	return nil
}

func benignTransocksClose(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF)
}

func relayTransocksDatagrams(ctx context.Context, request provider.DatagramRequest, upstream net.Conn, send, receive func() error) error {
	var once sync.Once
	closeAll := func() {
		once.Do(func() { _ = request.Packets.Close(); _ = upstream.Close(); _ = request.Control.Close() })
	}
	stop := context.AfterFunc(ctx, closeAll)
	defer stop()
	results := make(chan error, 3)
	go func() { _, err := io.Copy(io.Discard, request.Control); results <- err }()
	go func() { results <- send() }()
	go func() { results <- receive() }()
	err := <-results
	closeAll()
	<-results
	<-results
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if benignTransocksClose(err) {
		return nil
	}
	return err
}
