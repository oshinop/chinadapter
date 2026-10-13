package kuaifan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oshinop/chinadapter/internal/provider"
	"github.com/oshinop/chinadapter/internal/provider/kuaifan/speedin"
)

func TestSPEEDINDatagramsEndToEndAndControlLifetime(t *testing.T) {
	for _, mode := range []string{"control_close", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			_ = server.SetDeadline(time.Now().Add(10 * time.Second))
			addr := server.LocalAddr().(*net.UDPAddr)
			controlClient, control := loopbackTCPPair(t)
			packets := newTestPacketIO()
			defer packets.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ready := make(chan struct{})
			var readyCalls, admitCalls atomic.Int32
			relayDone := make(chan error, 1)
			authority := speedinTestAuthority(t, addr.IP.String(), uint16(addr.Port))
			go func() {
				relayDone <- NewSPEEDINTransport().RelayDatagrams(ctx, provider.DatagramRequest{
					Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
						if network != "udp" || address != addr.String() {
							return nil, fmt.Errorf("unexpected dial %s %s", network, address)
						}
						return (&net.Dialer{}).DialContext(ctx, network, address)
					},
					Control: control, Packets: packets, NodeHost: addr.IP.String(), NodePort: uint16(addr.Port), Authority: authority, HandshakeTimeout: time.Second,
					Admit: func() bool { admitCalls.Add(1); return true },
					Ready: func(local net.Addr) error {
						if local.String() != packets.LocalAddr().String() || admitCalls.Load() != 1 {
							return errors.New("wrong UDP readiness/admission")
						}
						readyCalls.Add(1)
						close(ready)
						return nil
					},
				})
			}()
			awaitSignal(t, ready)
			for _, host := range []string{"destination.example", "192.0.2.12", "2001:db8::12"} {
				address, err := speedin.AppendAddress(nil, speedin.Address{Host: host, Port: 53})
				if err != nil {
					t.Fatal(err)
				}
				datagram := append([]byte{0, 0, 0}, address...)
				datagram = append(datagram, []byte("request "+host)...)
				serverDone := make(chan error, 1)
				go func() {
					serverDone <- func() error {
						wire := make([]byte, 65535)
						n, remote, err := server.ReadFromUDP(wire)
						if err != nil {
							return err
						}
						plain, err := speedinTestCipher().DecodePacket(nil, wire[:n])
						if err != nil {
							return err
						}
						gotAddress, addressLen, err := speedin.ParseAddress(plain)
						if err != nil || gotAddress.Host != host || gotAddress.Port != 53 {
							return fmt.Errorf("UDP target = %#v: %w", gotAddress, err)
						}
						auth, authLen, err := speedin.ParseAuth(plain[addressLen:])
						if err != nil || auth != testSPEEDINAuth || !bytes.Equal(plain[addressLen+authLen:], datagram[3+len(address):]) {
							return errors.New("UDP auth/payload mismatch")
						}
						// Malformed and authenticated-but-malformed replies must
						// be dropped individually before the following valid one.
						if _, err := server.WriteToUDP([]byte{1, 2, 3}, remote); err != nil {
							return err
						}
						bad, err := speedinTestCipher().EncodePacket(nil, append(bytes.Clone(address), 2, 0, 0))
						if err != nil {
							return err
						}
						if _, err := server.WriteToUDP(bad, remote); err != nil {
							return err
						}
						plain[0] |= 0xf0
						reply, err := speedinTestCipher().EncodePacket(nil, plain)
						if err != nil {
							return err
						}
						_, err = server.WriteToUDP(reply, remote)
						return err
					}()
				}()
				packets.requests <- []byte{0, 0, 0, 3} // truncated domain header
				fragment := bytes.Clone(datagram)
				fragment[2] = 1
				packets.requests <- fragment
				reserved := bytes.Clone(datagram)
				reserved[0] = 1
				packets.requests <- reserved
				packets.requests <- datagram
				select {
				case got := <-packets.responses:
					if !bytes.Equal(got, datagram) {
						t.Fatalf("UDP reply = %x,want %x", got, datagram)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("no UDP reply after malformed packets")
				}
				if err := awaitResult(t, serverDone); err != nil {
					t.Fatal(err)
				}
			}
			var want error
			if mode == "cancel" {
				cancel()
				want = context.Canceled
			} else {
				_ = controlClient.Close()
			}
			if err := awaitResult(t, relayDone); !errors.Is(err, want) {
				t.Fatalf("UDP lifetime = %v,want %v", err, want)
			}
			awaitSignal(t, packets.closed)
			if admitCalls.Load() != 1 || readyCalls.Load() != 1 {
				t.Fatal("UDP admission/readiness called more than once")
			}
		})
	}
}

func TestSPEEDINStreamRelayCancellationClosesBothDirections(t *testing.T) {
	client, accepted := loopbackTCPPair(t)
	upstream, server := net.Pipe()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	serverDone := make(chan error, 1)
	go func() {
		reader, err := readSPEEDINTestRequest(server, provider.Target{Host: "x", Port: 1})
		if err != nil {
			serverDone <- err
			return
		}
		writer, err := speedinTestCipher().NewWriter(server)
		if err == nil {
			_, err = writer.Write([]byte{1, 0, 0})
		}
		if err == nil {
			_, err = io.Copy(io.Discard, reader)
		}
		serverDone <- err
	}()
	relayDone := make(chan error, 1)
	go func() {
		relayDone <- NewSPEEDINTransport().RelayStream(ctx, provider.RelayRequest{
			Dial: func(context.Context, string, string) (net.Conn, error) { return upstream, nil }, Client: accepted,
			NodeHost: "node", NodePort: 1, Target: provider.Target{Host: "x", Port: 1}, Authority: speedinTestAuthority(t, "node", 1), HandshakeTimeout: time.Second,
			Admit: func() bool { return true }, Ready: func(net.Addr) error { close(ready); return nil },
		})
	}()
	awaitSignal(t, ready)
	cancel()
	requireClientClosed(t, client)
	if err := awaitResult(t, relayDone); !errors.Is(err, context.Canceled) {
		t.Fatalf("stream cancellation: %v", err)
	}
	if err := awaitResult(t, serverDone); err != nil {
		t.Fatal(err)
	}
}
