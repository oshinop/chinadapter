package kuaifan

import (
	"context"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/kfadapter/kfadapter/internal/kuaifan/wifiin"
	"github.com/kfadapter/kfadapter/internal/provider"
)

const maxUDPDatagramSize = 1<<16 - 1

// Transport owns the complete WIFIIN data plane for KuaiFan nodes.
type Transport struct{}

func NewTransport() *Transport { return &Transport{} }

func (*Transport) Protocol() provider.Protocol { return WIFIINProtocol }

func (*Transport) RelayStream(ctx context.Context, request provider.RelayRequest) error {
	if ctx == nil || request.Dial == nil || request.Client == nil || request.NodeHost == "" || request.NodePort == 0 ||
		request.Target.Host == "" || request.Target.Port == 0 || request.Admit == nil || request.Ready == nil || request.HandshakeTimeout <= 0 {
		return errors.New("kuaifan: invalid stream relay request")
	}
	authority, err := decodeTunnelAuthority(request.Authority)
	if err != nil {
		return err
	}
	upstream, header, handshake, key, err := openWIFIIN(ctx, request.Dial, request.NodeHost, request.NodePort, request.Target, authority, request.HandshakeTimeout, false)
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
	lazyInbound, err := wifiin.NewLazyInboundReader(handshake, key, upstream, request.HandshakeTimeout)
	if err != nil {
		return fmt.Errorf("kuaifan: configure delayed WIFIIN IV: %w", err)
	}
	tunnel := &cipherConn{
		Conn: upstream, reader: lazyInbound,
		writer: &outboundCFBWriter{writer: &cipher.StreamWriter{S: header.Stream, W: upstream}, inbound: lazyInbound, conn: upstream},
	}
	return wifiin.Relay(ctx, request.Client, tunnel)
}

func (*Transport) RelayDatagrams(ctx context.Context, request provider.DatagramRequest) error {
	if ctx == nil || request.Dial == nil || request.Control == nil || request.Packets == nil || request.NodeHost == "" || request.NodePort == 0 ||
		request.Admit == nil || request.Ready == nil || request.HandshakeTimeout <= 0 || request.Packets.FlowID() == 0 {
		return errors.New("kuaifan: invalid datagram relay request")
	}
	authority, err := decodeTunnelAuthority(request.Authority)
	if err != nil {
		return err
	}
	upstream, header, handshake, key, err := openWIFIIN(ctx, request.Dial, request.NodeHost, request.NodePort, provider.Target{}, authority, request.HandshakeTimeout, true)
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
	lazyInbound, err := wifiin.NewLazyInboundReader(handshake, key, upstream, request.HandshakeTimeout)
	if err != nil {
		return fmt.Errorf("kuaifan: configure delayed WIFIIN UOT IV: %w", err)
	}
	plaintextWriter := &outboundCFBWriter{
		writer: &cipher.StreamWriter{S: header.Stream, W: upstream}, inbound: lazyInbound, conn: upstream,
	}
	uotWriter, err := wifiin.NewUOTWriter(plaintextWriter)
	if err != nil {
		return err
	}
	uotReader, err := wifiin.NewUOTReader(lazyInbound)
	if err != nil {
		return err
	}
	results := make(chan error, 3)
	go func() { results <- watchControl(request.Control) }()
	go func() { results <- packetsToUOT(request.Packets, uotWriter) }()
	go func() { results <- uotToPackets(request.Packets, uotReader) }()
	err = <-results
	_ = request.Packets.Close()
	_ = upstream.Close()
	_ = request.Control.Close()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
		return nil
	}
	return err
}

func openWIFIIN(ctx context.Context, dial provider.DialContextFunc, nodeHost string, nodePort uint16, target provider.Target, authority tunnelAuthority, timeout time.Duration, datagrams bool) (net.Conn, *wifiin.OutboundHeader, *wifiin.HandshakeReader, []byte, error) {
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	upstream, err := dial(dialCtx, "tcp", net.JoinHostPort(nodeHost, strconv.Itoa(int(nodePort))))
	cancel()
	if ctx.Err() != nil {
		if err == nil {
			_ = upstream.Close()
		}
		return nil, nil, nil, nil, ctx.Err()
	}
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("kuaifan: connect selected upstream: %w", err)
	}
	failed := true
	defer func() {
		if failed {
			_ = upstream.Close()
		}
	}()
	if err := upstream.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("kuaifan: set handshake deadline: %w", err)
	}
	keyArray := wifiin.DeriveKey(authority.Password)
	key := append([]byte(nil), keyArray[:]...)
	var header *wifiin.OutboundHeader
	if datagrams {
		header, err = wifiin.NewUOTOutboundHeader(key, nodeHost, nodePort, authority.Extension)
	} else {
		header, err = wifiin.NewOutboundHeader(key, target.Host, target.Port, authority.Extension)
	}
	if err == nil {
		err = writeAll(upstream, header.Packet)
	}
	handshake := wifiin.NewHandshakeReader(upstream)
	if err == nil {
		err = handshake.ReadACK()
	}
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("kuaifan: WIFIIN handshake: %w", err)
	}
	if err := upstream.SetDeadline(time.Time{}); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
		return nil, nil, nil, nil, fmt.Errorf("kuaifan: clear handshake deadline: %w", err)
	}
	failed = false
	return upstream, header, handshake, key, nil
}

func packetsToUOT(packets provider.PacketIO, writer *wifiin.UOTWriter) error {
	packet := make([]byte, maxUDPDatagramSize)
	for {
		n, err := packets.ReadPacket(packet)
		if err != nil {
			return err
		}
		if err := writer.WriteSOCKSDatagram(packets.FlowID(), packet[:n]); err != nil {
			if errors.Is(err, wifiin.ErrInvalidUDPDatagram) || errors.Is(err, wifiin.ErrFragmentedUDP) || errors.Is(err, wifiin.ErrUnsupportedUDPAddress) {
				continue
			}
			return err
		}
	}
}

func uotToPackets(packets provider.PacketIO, reader *wifiin.UOTReader) error {
	packet := make([]byte, maxUDPDatagramSize)
	for {
		n, flowID, err := reader.ReadSOCKSDatagram(packet)
		if err != nil {
			return fmt.Errorf("kuaifan: read WIFIIN UOT datagram: %w", err)
		}
		if flowID != packets.FlowID() {
			continue
		}
		if err := packets.WritePacket(packet[:n]); err != nil {
			return err
		}
	}
}

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

type cipherConn struct {
	net.Conn
	reader io.Reader
	writer io.Writer
}

func (connection *cipherConn) Read(buffer []byte) (int, error) { return connection.reader.Read(buffer) }
func (connection *cipherConn) Write(buffer []byte) (int, error) {
	return connection.writer.Write(buffer)
}

func (connection *cipherConn) CloseWrite() error {
	if closer, ok := connection.writer.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	if closer, ok := connection.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return connection.Close()
}

type outboundCFBWriter struct {
	writer  io.Writer
	inbound *wifiin.LazyInboundReader
	conn    net.Conn
}

func (writer *outboundCFBWriter) Write(buffer []byte) (int, error) {
	if len(buffer) != 0 {
		if err := writer.inbound.ArmForOutbound(); err != nil {
			return 0, err
		}
	}
	return writer.writer.Write(buffer)
}

func (writer *outboundCFBWriter) CloseWrite() error {
	if !writer.inbound.OutboundStarted() {
		return writer.conn.Close()
	}
	if closer, ok := writer.conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return writer.conn.Close()
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
