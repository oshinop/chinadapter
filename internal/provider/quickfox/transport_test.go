package quickfox

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/oshinop/chinadapter/internal/provider"
)

func TestEncodeTunnelAuthGolden(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 21, 21, 53, 20, 0, time.UTC)
	packet, err := encodeTunnelAuth(
		tunnelAuthority{Token: "0123456789abcdef0123456789abcdef", UserID: 15904241},
		nativeNonce(now), 0x10, netip.MustParseAddr("34.160.111.145"), 80,
	)
	if err != nil {
		t.Fatal(err)
	}
	const want = "47490408234330313233343536373839616263646566303132333435363738396162636465662c30f1adf200664400000b14000422a06f910050ffffffff"
	if got := hex.EncodeToString(packet); got != want {
		t.Fatalf("tunnel packet = %s, want %s", got, want)
	}
}

func TestTransportRelayStream(t *testing.T) {
	t.Parallel()
	transport := NewTransport()
	transport.clock = func() time.Time { return time.Date(2026, 7, 21, 21, 53, 20, 0, time.UTC) }
	transport.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("34.160.111.145")}, nil
	}
	authority, err := json.Marshal(tunnelAuthority{Token: "0123456789abcdef0123456789abcdef", UserID: 15904241})
	if err != nil {
		t.Fatal(err)
	}
	client, adapter := net.Pipe()
	defer client.Close()
	connections := make(chan net.Conn, 2)
	dial := func(context.Context, string, string) (net.Conn, error) {
		adapterSide, relaySide := net.Pipe()
		connections <- relaySide
		return adapterSide, nil
	}
	serverErr := make(chan error, 1)
	go func() {
		control := <-connections
		defer control.Close()
		controlPacket := make([]byte, 62)
		if _, err := io.ReadFull(control, controlPacket); err != nil {
			serverErr <- err
			return
		}
		if controlPacket[len(controlPacket)-13] != 0x24 {
			serverErr <- errors.New("unexpected control mode")
			return
		}
		if _, err := control.Write(make([]byte, controlACKSize)); err != nil {
			serverErr <- err
			return
		}
		data := <-connections
		defer data.Close()
		dataPacket := make([]byte, 62)
		if _, err := io.ReadFull(data, dataPacket); err != nil {
			serverErr <- err
			return
		}
		if dataPacket[len(dataPacket)-13] != 0x14 {
			serverErr <- errors.New("unexpected data mode")
			return
		}
		encoded := make([]byte, 4)
		if _, err := io.ReadFull(data, encoded); err != nil {
			serverErr <- err
			return
		}
		for index := range encoded {
			encoded[index] ^= relayXORByte
		}
		if string(encoded) != "ping" {
			serverErr <- errors.New("unexpected relayed request")
			return
		}
		response := []byte("pong")
		for index := range response {
			response[index] ^= relayXORByte
		}
		_, err := data.Write(response)
		serverErr <- err
	}()

	ready := make(chan struct{})
	relayErr := make(chan error, 1)
	go func() {
		relayErr <- transport.RelayStream(context.Background(), provider.RelayRequest{
			NodeHost: "relay.example", NodePort: 443, Target: provider.Target{Host: "target.example", Port: 80},
			Authority: authority, Client: adapter, Dial: dial, HandshakeTimeout: time.Second,
			Admit: func() bool { return true }, Ready: func(net.Addr) error { close(ready); return nil },
		})
	}()
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not become ready")
	}
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "pong" {
		t.Fatalf("relay response = %q", response)
	}
	_ = client.Close()
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	if err := <-relayErr; err != nil {
		t.Fatal(err)
	}
}
