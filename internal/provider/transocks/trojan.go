package transocks

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/oshinop/chinadapter/internal/provider"
)

// TrojanTransport implements conventional Trojan over TLS, optionally carrying
// the byte stream in RFC 6455 binary WebSocket messages. UDP uses the same TLS
// stream with Trojan's address/length/CRLF framing, not a separate UDP socket.
type TrojanTransport struct{ sessions *SessionManager }

func NewTrojanTransport(sessions *SessionManager) *TrojanTransport {
	return &TrojanTransport{sessions: sessions}
}
func (*TrojanTransport) Protocol() provider.Protocol { return TrojanProtocol }

var (
	_ provider.DatagramTransport = (*TrojanTransport)(nil)
	_ provider.ProbeAddresser    = (*TrojanTransport)(nil)
)

func (*TrojanTransport) ProbeAddress(authority []byte, host string, port uint16) (string, error) {
	return probeAddress(authority, host, port)
}

func (transport *TrojanTransport) RelayStream(ctx context.Context, request provider.RelayRequest) error {
	if transport == nil || !validStreamRequest(ctx, request) {
		return errors.New("transocks: invalid stream relay request")
	}
	address, err := socksAddress(request.Target)
	if err != nil {
		return err
	}
	upstream, _, err := transport.sessions.open(ctx, request.Authority, request.NodeHost, request.NodePort, TrojanProtocol, func(config liveConfig) (net.Conn, error) {
		return openTrojan(ctx, request.Dial, config.Host, config.Port, request.HandshakeTimeout, config.Trojan, 1, address)
	})
	if err != nil {
		return err
	}
	defer upstream.Close()
	if !request.Admit() {
		return provider.ErrNoSession
	}
	if err := request.Ready(upstream.LocalAddr()); err != nil {
		return err
	}
	return relayTransocks(ctx, request.Client, upstream)
}

func (transport *TrojanTransport) RelayDatagrams(ctx context.Context, request provider.DatagramRequest) error {
	if transport == nil || !validDatagramRequest(ctx, request) {
		return errors.New("transocks: invalid datagram relay request")
	}
	// Trojan ignores the initial address for UDP ASSOCIATE. Each record has its
	// own destination; the conventional placeholder is 0.0.0.0:0.
	upstream, _, err := transport.sessions.open(ctx, request.Authority, request.NodeHost, request.NodePort, TrojanProtocol, func(config liveConfig) (net.Conn, error) {
		return openTrojan(ctx, request.Dial, config.Host, config.Port, request.HandshakeTimeout, config.Trojan, 3, []byte{1, 0, 0, 0, 0, 0, 0})
	})
	if err != nil {
		return err
	}
	defer upstream.Close()
	if !request.Admit() {
		return provider.ErrNoSession
	}
	if err := request.Ready(request.Packets.LocalAddr()); err != nil {
		return err
	}
	return relayTransocksDatagrams(ctx, request, upstream, func() error {
		// Four spare bytes let us insert length/CRLF by moving only the small
		// address header, never copying the payload.
		buffer := make([]byte, maxSocksDatagram+4)
		for {
			n, err := request.Packets.ReadPacket(buffer[4:])
			if err != nil {
				return err
			}
			packet := buffer[4 : 4+n]
			if !validSocksPacket(packet) {
				continue
			}
			header, _ := socksAddressSize(packet[3:])
			payload := n - 3 - header
			frame := buffer[3 : 4+n]
			copy(frame[:header], packet[3:3+header])
			binary.BigEndian.PutUint16(frame[header:header+2], uint16(payload))
			frame[header+2], frame[header+3] = '\r', '\n'
			if err := transocksWriteAll(upstream, frame); err != nil {
				return err
			}
		}
	}, func() error { return readTrojanDatagrams(upstream, request.Packets) })
}

func trojanHeader(password string, command byte, address []byte) []byte {
	hash := sha256.Sum224([]byte(password))
	header := make([]byte, 0, 56+5+len(address))
	header = hex.AppendEncode(header, hash[:])
	header = append(header, '\r', '\n', command)
	header = append(header, address...)
	return append(header, '\r', '\n')
}

func openTrojan(ctx context.Context, dial provider.DialContextFunc, host string, port uint16, timeout time.Duration, entry trojanEntry, command byte, address []byte) (net.Conn, error) {
	connection, err := dialTransocks(ctx, dial, "tcp", host, port, timeout)
	if err != nil {
		return nil, err
	}
	complete := false
	defer func() {
		if !complete {
			_ = connection.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	if err := connection.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	sni := entry.SNI
	if sni == "" {
		sni = host
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: sni, InsecureSkipVerify: !entry.Verify}
	if entry.WebSocket != nil {
		config.NextProtos = []string{"http/1.1"}
	}
	secure := tls.Client(connection, config)
	handshakeContext, cancel := context.WithTimeout(ctx, timeout)
	err = secure.HandshakeContext(handshakeContext)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("transocks: Trojan TLS handshake: %w", err)
	}
	var upstream net.Conn = secure
	if entry.WebSocket != nil {
		upstream, err = newTrojanWebSocket(secure, host, port, *entry.WebSocket)
		if err != nil {
			return nil, err
		}
	}
	if err := transocksWriteAll(upstream, trojanHeader(entry.Password, command, address)); err != nil {
		return nil, fmt.Errorf("transocks: write Trojan header: %w", err)
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	complete = true
	return upstream, nil
}

func readTrojanDatagrams(reader io.Reader, packets provider.PacketIO) error {
	buffer := make([]byte, 3+259+4+65535)
	for {
		header, err := readSocksAddress(reader, buffer[3:3+259])
		if err != nil {
			return err
		}
		var length [4]byte
		if _, err := io.ReadFull(reader, length[:]); err != nil {
			return err
		}
		if length[2] != '\r' || length[3] != '\n' {
			return fmt.Errorf("%w: Trojan UDP separator", ErrProtocol)
		}
		size := int(binary.BigEndian.Uint16(length[:2]))
		if _, err := io.ReadFull(reader, buffer[3+header:3+header+size]); err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return err
		}
		if 3+header+size > maxSocksDatagram {
			continue
		}
		buffer[0], buffer[1], buffer[2] = 0, 0, 0
		if err := packets.WritePacket(buffer[:3+header+size]); err != nil {
			return err
		}
	}
}

const (
	trojanWSHeaderLimit = 16 * 1024
	trojanWSFrameLimit  = 1 << 20
	trojanWSWriteSize   = 32 * 1024
)

// This narrow WebSocket client does not negotiate compression, subprotocols or
// early data. It validates the upgrade and streams fragmented binary messages,
// handles interleaved ping/pong, and masks all client frames. Network addresses
// and deadlines remain those of the pinned TLS connection.
type trojanWSConn struct {
	net.Conn
	reader      *bufio.Reader
	remaining   uint64
	fragmented  bool
	writeMu     sync.Mutex
	writeBuffer [14 + trojanWSWriteSize]byte
}

func newTrojanWebSocket(connection net.Conn, host string, port uint16, options trojanWebSocket) (*trojanWSConn, error) {
	path := options.Path
	if path == "" {
		path = "/"
	}
	uri, err := url.ParseRequestURI(path)
	if err != nil || uri.IsAbs() || uri.Host != "" || !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\r\n") {
		return nil, ErrInvalidAuthority
	}
	webHost := options.Host
	if webHost == "" {
		webHost = nodeKey(host, port)
	}
	if strings.ContainsAny(webHost, "\r\n\t /\\") || webHost == "" {
		return nil, ErrInvalidAuthority
	}
	var random [16]byte
	if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(random[:])
	header := "GET " + uri.RequestURI() + " HTTP/1.1\r\nHost: " + webHost + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\n\r\n"
	if err := transocksWriteAll(connection, []byte(header)); err != nil {
		return nil, fmt.Errorf("transocks: WebSocket upgrade write: %w", err)
	}
	limited := &io.LimitedReader{R: connection, N: trojanWSHeaderLimit}
	reader := bufio.NewReader(limited)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		return nil, fmt.Errorf("%w: WebSocket upgrade response: %w", ErrProtocol, err)
	}
	// A 101 response has no HTTP body (http.NoBody). Closing an error
	// response's body drains at most the remaining header-limit bytes, and the
	// caller closes the underlying connection on any failed upgrade.
	_ = response.Body.Close()
	accept := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	if response.StatusCode != http.StatusSwitchingProtocols || !httpHeaderToken(response.Header.Get("Upgrade"), "websocket") || !httpHeaderToken(response.Header.Get("Connection"), "upgrade") || response.Header.Get("Sec-WebSocket-Accept") != base64.StdEncoding.EncodeToString(accept[:]) || response.Header.Get("Sec-WebSocket-Extensions") != "" || response.Header.Get("Sec-WebSocket-Protocol") != "" {
		return nil, fmt.Errorf("%w: WebSocket upgrade rejected", ErrProtocol)
	}
	limited.N = 1<<63 - 1
	return &trojanWSConn{Conn: connection, reader: reader}, nil
}

func httpHeaderToken(value, token string) bool {
	for part := range strings.SplitSeq(value, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}

func (connection *trojanWSConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for connection.remaining == 0 {
		var header [10]byte
		if _, err := io.ReadFull(connection.reader, header[:2]); err != nil {
			return 0, err
		}
		final, opcode := header[0]&0x80 != 0, header[0]&0x0f
		if header[0]&0x70 != 0 || header[1]&0x80 != 0 {
			return 0, ErrProtocol
		}
		size := uint64(header[1] & 0x7f)
		switch size {
		case 126:
			if _, err := io.ReadFull(connection.reader, header[2:4]); err != nil {
				return 0, err
			}
			size = uint64(binary.BigEndian.Uint16(header[2:4]))
			if size < 126 {
				return 0, ErrProtocol
			}
		case 127:
			if _, err := io.ReadFull(connection.reader, header[2:10]); err != nil {
				return 0, err
			}
			size = binary.BigEndian.Uint64(header[2:10])
			if size < 65536 {
				return 0, ErrProtocol
			}
		}
		if size > trojanWSFrameLimit {
			return 0, ErrProtocol
		}
		if opcode&8 != 0 {
			if !final || size > 125 {
				return 0, ErrProtocol
			}
			var payload [125]byte
			if _, err := io.ReadFull(connection.reader, payload[:size]); err != nil {
				return 0, err
			}
			switch opcode {
			case 8:
				if size == 1 {
					return 0, ErrProtocol
				}
				return 0, io.EOF
			case 9:
				if err := connection.writeFrame(10, payload[:size]); err != nil {
					return 0, err
				}
			case 10:
			default:
				return 0, ErrProtocol
			}
			continue
		}
		switch opcode {
		case 2:
			if connection.fragmented {
				return 0, ErrProtocol
			}
			connection.fragmented = !final
		case 0:
			if !connection.fragmented {
				return 0, ErrProtocol
			}
			connection.fragmented = !final
		default:
			return 0, ErrProtocol
		}
		connection.remaining = size
	}
	n, err := connection.reader.Read(p[:min(uint64(len(p)), connection.remaining)])
	connection.remaining -= uint64(n)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}

func (connection *trojanWSConn) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		size := min(len(p), trojanWSWriteSize)
		if err := connection.writeFrame(2, p[:size]); err != nil {
			return written, err
		}
		written += size
		p = p[size:]
	}
	return written, nil
}

func (connection *trojanWSConn) writeFrame(opcode byte, p []byte) error {
	connection.writeMu.Lock()
	defer connection.writeMu.Unlock()
	buffer := connection.writeBuffer[:]
	buffer[0] = 0x80 | opcode
	offset := 2
	if len(p) < 126 {
		buffer[1] = 0x80 | byte(len(p))
	} else {
		buffer[1] = 0x80 | 126
		binary.BigEndian.PutUint16(buffer[2:4], uint16(len(p)))
		offset = 4
	}
	mask := buffer[offset : offset+4]
	if _, err := io.ReadFull(rand.Reader, mask); err != nil {
		return err
	}
	offset += 4
	for index, value := range p {
		buffer[offset+index] = value ^ mask[index%4]
	}
	return transocksWriteAll(connection.Conn, buffer[:offset+len(p)])
}

// TLS close_notify half-closes the underlying byte stream while permitting
// downstream reads. RFC 6455 has no independent application-level half-close;
// sending a WebSocket Close here would prematurely discard pending replies.
func (connection *trojanWSConn) CloseWrite() error { return transocksCloseWrite(connection.Conn) }
