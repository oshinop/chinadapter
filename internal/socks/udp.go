package socks

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
)

type udpAssociation struct {
	conn     *net.UDPConn
	clientIP netip.Addr
	flowID   uint16
	endpoint atomic.Pointer[netip.AddrPort]
}

func newUDPAssociation(client net.Conn, requested target) (*udpAssociation, error) {
	remote, ok := client.RemoteAddr().(*net.TCPAddr)
	if !ok || remote == nil {
		return nil, errors.New("socks: UDP association requires a TCP client address")
	}
	clientIP := remote.AddrPort().Addr().Unmap()
	if !clientIP.IsValid() {
		return nil, errBadAddress
	}
	// Parse the requested address for address-type validation, not to identify
	// the sender. Only the TCP peer IP and the pinned datagram port admit traffic.
	if _, err := netip.ParseAddr(requested.Host); err != nil {
		return nil, errAddressTypeUnsupported
	}
	local, ok := client.LocalAddr().(*net.TCPAddr)
	if !ok || local == nil {
		return nil, errors.New("socks: UDP association requires a TCP listener address")
	}
	network := "udp6"
	if local.IP.To4() != nil {
		network = "udp4"
	}
	udp, err := net.ListenUDP(network, &net.UDPAddr{IP: append(net.IP(nil), local.IP...), Zone: local.Zone})
	if err != nil {
		return nil, fmt.Errorf("socks: bind UDP association: %w", err)
	}
	bound, ok := udp.LocalAddr().(*net.UDPAddr)
	if !ok || bound.Port < 1 || bound.Port > 65535 {
		_ = udp.Close()
		return nil, errors.New("socks: invalid UDP association address")
	}
	association := &udpAssociation{conn: udp, clientIP: clientIP, flowID: uint16(bound.Port)}
	if requested.Port != 0 {
		endpoint := netip.AddrPortFrom(clientIP.WithZone(remote.Zone), requested.Port)
		association.endpoint.Store(&endpoint)
	}
	return association, nil
}

func (association *udpAssociation) acceptSource(address netip.AddrPort) bool {
	if !address.IsValid() || address.Port() == 0 || address.Addr().Unmap() != association.clientIP {
		return false
	}
	if endpoint := association.endpoint.Load(); endpoint != nil {
		return address.Port() == endpoint.Port()
	}
	endpoint := new(netip.AddrPort)
	*endpoint = address
	return association.endpoint.CompareAndSwap(nil, endpoint)
}

func (association *udpAssociation) FlowID() uint16      { return association.flowID }
func (association *udpAssociation) LocalAddr() net.Addr { return association.conn.LocalAddr() }
func (association *udpAssociation) Close() error        { return association.conn.Close() }

// validUDPRequest checks the RFC1928 framing without interpreting or copying
// the destination. Providers receive the complete, unchanged request datagram.
func validUDPRequest(packet []byte) bool {
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return false
	}
	switch packet[3] {
	case addressIPv4:
		return len(packet) >= 10
	case addressIPv6:
		return len(packet) >= 22
	case addressDomain:
		return len(packet) >= 5 && packet[4] != 0 && len(packet) >= 7+int(packet[4])
	default:
		return false
	}
}

func (association *udpAssociation) ReadPacket(packet []byte) (int, error) {
	for {
		n, _, flags, source, err := association.conn.ReadMsgUDPAddrPort(packet, nil)
		if err != nil {
			return 0, fmt.Errorf("socks: read client UDP datagram: %w", err)
		}
		if flags&syscall.MSG_TRUNC == 0 && validUDPRequest(packet[:n]) && association.acceptSource(source) {
			return n, nil
		}
	}
}

func (association *udpAssociation) WritePacket(packet []byte) error {
	endpoint := association.endpoint.Load()
	if endpoint == nil {
		return nil
	}
	if _, err := association.conn.WriteToUDPAddrPort(packet, *endpoint); err != nil {
		return fmt.Errorf("socks: write client UDP datagram: %w", err)
	}
	return nil
}
