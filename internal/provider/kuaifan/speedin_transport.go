package kuaifan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/oshinop/chinadapter/internal/provider"
	"github.com/oshinop/chinadapter/internal/provider/kuaifan/speedin"
	"github.com/oshinop/chinadapter/internal/provider/kuaifan/wifiin"
)

// SPEEDINTransport implements KuaiFan's authenticated AES-128-GCM stream and
// native UDP protocol. It dials only the pinned catalog endpoint; destination
// domains are encoded for the upstream and never resolved or dialed locally.
type SPEEDINTransport struct{}

func NewSPEEDINTransport() *SPEEDINTransport { return &SPEEDINTransport{} }

func (*SPEEDINTransport) Protocol() provider.Protocol { return SPEEDINProtocol }

var _ provider.DatagramTransport = (*SPEEDINTransport)(nil)

func (transport *SPEEDINTransport) RelayStream(ctx context.Context, request provider.RelayRequest) error {
	if transport == nil || ctx == nil || request.Dial == nil || request.Client == nil || request.NodeHost == "" || request.NodePort == 0 ||
		request.Target.Host == "" || request.Target.Port == 0 || request.Admit == nil || request.Ready == nil || request.HandshakeTimeout <= 0 {
		return errors.New("kuaifan: invalid SPEEDIN stream relay request")
	}
	cipher, auth, err := speedinCredentials(request.Authority, request.NodeHost, request.NodePort)
	if err != nil {
		return err
	}
	header, err := speedin.EncodeRequest(speedin.Address{Host: request.Target.Host, Port: request.Target.Port}, auth)
	if err != nil {
		if errors.Is(err, speedin.ErrInvalidAuth) {
			return fmt.Errorf("%w: %w", ErrInvalidAuthority, err)
		}
		return fmt.Errorf("kuaifan: build SPEEDIN request: %w", err)
	}
	upstream, reader, writer, err := openSPEEDIN(ctx, request, cipher, header)
	if err != nil {
		return err
	}
	defer upstream.Close()
	if err := ctx.Err(); err != nil {
		return err
	}
	if !request.Admit() {
		return provider.ErrNoSession
	}
	if err := request.Ready(upstream.LocalAddr()); err != nil {
		return err
	}
	// The shared relay performs half-closes and joins both pumps. Wrapping the
	// net.Conn prevents io.Copy's TCP fast paths from bypassing encryption.
	err = wifiin.Relay(ctx, request.Client, &cipherConn{Conn: upstream, reader: reader, writer: writer})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func speedinCredentials(data []byte, host string, port uint16) (*speedin.Cipher, speedin.Auth, error) {
	authority, err := decodeSPEEDINAuthority(data)
	if err != nil {
		return nil, speedin.Auth{}, err
	}
	password, ok := authority.Passwords[speedinNodeKey(host, port)]
	if !ok {
		return nil, speedin.Auth{}, ErrInvalidAuthority
	}
	cipher, err := speedin.NewCipher(password)
	if err != nil {
		return nil, speedin.Auth{}, fmt.Errorf("%w: %w", ErrInvalidAuthority, err)
	}
	auth := speedin.Auth{UserID: authority.UserID, Token: authority.Token, OS: authority.OS}
	return cipher, auth, nil
}

func openSPEEDIN(ctx context.Context, request provider.RelayRequest, cipher *speedin.Cipher, header []byte) (net.Conn, *speedin.Reader, *speedin.Writer, error) {
	// One deadline covers the entire dial and provider authentication exchange.
	handshakeCtx, cancel := context.WithTimeout(ctx, request.HandshakeTimeout)
	defer cancel()
	upstream, err := request.Dial(handshakeCtx, "tcp", speedinNodeKey(request.NodeHost, request.NodePort))
	if handshakeCtx.Err() != nil {
		if err == nil {
			_ = upstream.Close()
		}
		return nil, nil, nil, handshakeCtx.Err()
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("kuaifan: connect selected SPEEDIN upstream: %w", err)
	}
	failed := true
	defer func() {
		if failed {
			_ = upstream.Close()
		}
	}()
	stopCancellation := context.AfterFunc(handshakeCtx, func() { _ = upstream.Close() })
	defer stopCancellation()
	deadline, _ := handshakeCtx.Deadline()
	if err := upstream.SetDeadline(deadline); err != nil {
		return nil, nil, nil, fmt.Errorf("kuaifan: set SPEEDIN handshake deadline: %w", err)
	}
	var reader *speedin.Reader
	var writer *speedin.Writer
	err = func() error {
		var err error
		writer, err = cipher.NewWriter(upstream)
		if err != nil {
			return err
		}
		if _, err = writer.Write(header); err != nil {
			return err
		}
		reader, err = cipher.NewReader(upstream)
		if err != nil {
			return err
		}
		_, err = speedin.ReadAuthAnswer(reader)
		return err
	}()
	if handshakeCtx.Err() != nil {
		return nil, nil, nil, handshakeCtx.Err()
	}
	if err != nil {
		// The socket deadline may fire just before the context timer publishes
		// its error. Report the same bounded handshake outcome in either order.
		if !time.Now().Before(deadline) {
			return nil, nil, nil, context.DeadlineExceeded
		}
		return nil, nil, nil, fmt.Errorf("kuaifan: SPEEDIN handshake: %w", err)
	}
	if err := upstream.SetDeadline(time.Time{}); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
		return nil, nil, nil, fmt.Errorf("kuaifan: clear SPEEDIN handshake deadline: %w", err)
	}
	failed = false
	return upstream, reader, writer, nil
}

func (transport *SPEEDINTransport) RelayDatagrams(ctx context.Context, request provider.DatagramRequest) error {
	if transport == nil || ctx == nil || request.Dial == nil || request.Control == nil || request.Packets == nil || request.NodeHost == "" || request.NodePort == 0 ||
		request.Admit == nil || request.Ready == nil || request.HandshakeTimeout <= 0 || request.Packets.FlowID() == 0 {
		return errors.New("kuaifan: invalid SPEEDIN datagram relay request")
	}
	cipher, auth, err := speedinCredentials(request.Authority, request.NodeHost, request.NodePort)
	if err != nil {
		return err
	}
	codec, err := cipher.NewDatagramCodec(auth)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidAuthority, err)
	}
	dialCtx, cancel := context.WithTimeout(ctx, request.HandshakeTimeout)
	upstream, err := request.Dial(dialCtx, "udp", speedinNodeKey(request.NodeHost, request.NodePort))
	dialErr := dialCtx.Err()
	cancel()
	if dialErr != nil {
		if err == nil {
			_ = upstream.Close()
		}
		return dialErr
	}
	if err != nil {
		return fmt.Errorf("kuaifan: connect selected SPEEDIN UDP upstream: %w", err)
	}
	defer upstream.Close()
	if err := ctx.Err(); err != nil {
		return err
	}
	// Native UDP has no separate handshake or positive remote admission signal.
	// Each encrypted datagram carries auth; readiness means a pinned UDP socket
	// exists and local account admission still succeeds, not server acceptance.
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
	go func() { results <- watchControl(request.Control) }()
	go func() { results <- speedinPacketsToNode(request.Packets, upstream, codec) }()
	go func() { results <- speedinNodeToPackets(upstream, request.Packets, codec) }()
	err = <-results
	closeAll()
	for range 2 {
		<-results
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
		return nil
	}
	return err
}

func speedinPacketsToNode(packets provider.PacketIO, upstream net.Conn, codec *speedin.DatagramCodec) error {
	packet := make([]byte, maxUDPDatagramSize)
	plaintext := make([]byte, 0, speedin.MaxPacketSize)
	wire := make([]byte, 0, speedin.MaxPacketSize)
	for {
		n, err := packets.ReadPacket(packet)
		if err != nil {
			return err
		}
		encoded, err := codec.EncodeSOCKS(wire, plaintext, packet[:n])
		if err != nil {
			if errors.Is(err, speedin.ErrInvalidPacket) || errors.Is(err, speedin.ErrFragmentedPacket) {
				continue
			}
			return err
		}
		// A UDP write is exactly one packet. Never retry a short write as a
		// second datagram (unlike stream writeAll).
		n, err = upstream.Write(encoded)
		if err != nil {
			return fmt.Errorf("kuaifan: write SPEEDIN datagram: %w", err)
		}
		if n != len(encoded) {
			return io.ErrShortWrite
		}
	}
}

func speedinNodeToPackets(upstream net.Conn, packets provider.PacketIO, codec *speedin.DatagramCodec) error {
	wire := make([]byte, maxUDPDatagramSize)
	reply := make([]byte, 0, maxUDPDatagramSize)
	for {
		n, err := upstream.Read(wire)
		if err != nil {
			return err
		}
		decoded, err := codec.DecodeSOCKS(reply, wire[:n])
		if err != nil {
			if errors.Is(err, speedin.ErrInvalidPacket) {
				continue
			}
			return err
		}
		if err := packets.WritePacket(decoded); err != nil {
			return err
		}
	}
}
