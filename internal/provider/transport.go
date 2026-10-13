package provider

import (
	"context"
	"net"
	"time"
)

// DialContextFunc dials the selected provider node or a tunnel endpoint issued
// for that same node by its control plane. SOCKS targets never fall back to a
// direct connection or another node.
type DialContextFunc func(context.Context, string, string) (net.Conn, error)

// Target is the destination requested by the local SOCKS client.
type Target struct {
	Host string
	Port uint16
}

// RelayRequest contains one immutable, revalidated node pin. A transport may
// resolve it through its provider control plane to a current tunnel endpoint,
// but must dial only through Dial and must never select another node or dial
// Target directly. Ready must be called exactly once after the provider
// handshake and final Admit check, before application bytes are relayed.
type RelayRequest struct {
	Dial             DialContextFunc
	Client           net.Conn
	NodeHost         string
	NodePort         uint16
	Target           Target
	Authority        []byte
	HandshakeTimeout time.Duration
	Admit            func() bool
	Ready            func(net.Addr) error
}

// PacketIO is the provider-neutral boundary around a SOCKS UDP association.
// Packets retain their SOCKS UDP request framing so the transport can use its
// own datagram wire protocol without exposing it to the SOCKS package.
type PacketIO interface {
	FlowID() uint16
	LocalAddr() net.Addr
	ReadPacket([]byte) (int, error)
	WritePacket([]byte) error
	Close() error
}

// DatagramRequest extends RelayRequest with an authenticated UDP association.
// The same node/control-plane endpoint resolution rules apply: use only Dial,
// never another node or a direct destination connection.
type DatagramRequest struct {
	Dial             DialContextFunc
	Control          net.Conn
	Packets          PacketIO
	NodeHost         string
	NodePort         uint16
	Authority        []byte
	HandshakeTimeout time.Duration
	Admit            func() bool
	Ready            func(net.Addr) error
}

// Transport owns all provider-specific handshake, encryption, and stream relay
// for one protocol.
type Transport interface {
	Protocol() Protocol
	RelayStream(context.Context, RelayRequest) error
}

// DatagramTransport is the optional capability for SOCKS UDP ASSOCIATE.
// Transports without it are TCP-only; SOCKS replies 0x07 before binding a
// UDP socket for them.
type DatagramTransport interface {
	Transport
	RelayDatagrams(context.Context, DatagramRequest) error
}

// ProbeAddresser is the optional capability for transports whose node route is
// a stable identity rather than a dialable endpoint. ProbeAddress returns the
// host:port a TCP reachability probe should dial for the node, without opening
// a tunnel or consuming provider session capacity.
type ProbeAddresser interface {
	ProbeAddress(authority []byte, nodeHost string, nodePort uint16) (string, error)
}
