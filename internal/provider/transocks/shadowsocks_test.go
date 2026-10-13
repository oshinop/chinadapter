package transocks

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oshinop/chinadapter/internal/provider"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestShadowsocksKeyVectors(t *testing.T) {
	for _, test := range []struct{ method, master, subkey string }{
		{"aes-128-gcm", "5f4dcc3b5aa765d61d8327deb882cf99", "ed2a618d9490d1701de885d82aa80616"},
		{"aes-256-gcm", "5f4dcc3b5aa765d61d8327deb882cf992b95990a9151374abd8ff8c5a7a0fe08", "ee187aed3f87574907a39db98606f60a526114831288097cac66054b33a9464f"},
		{"chacha20-ietf-poly1305", "5f4dcc3b5aa765d61d8327deb882cf992b95990a9151374abd8ff8c5a7a0fe08", "ee187aed3f87574907a39db98606f60a526114831288097cac66054b33a9464f"},
	} {
		t.Run(test.method, func(t *testing.T) {
			key, err := ssMasterKey(shadowsocksEntry{Method: test.method, Password: "password"})
			if err != nil || hex.EncodeToString(key) != test.master {
				t.Fatalf("master key = %x, %v", key, err)
			}
			salt := make([]byte, len(key))
			for i := range salt {
				salt[i] = byte(i)
			}
			subkey, err := ssSubkey(key, salt)
			if err != nil || hex.EncodeToString(subkey) != test.subkey {
				t.Fatalf("subkey = %x, %v", subkey, err)
			}
		})
	}
	if _, err := ssMasterKey(shadowsocksEntry{Method: "rc4-md5", Password: "password"}); !errors.Is(err, ErrInvalidAuthority) {
		t.Fatal(err)
	}
	if _, err := ssSubkey(make([]byte, 16), make([]byte, 15)); !errors.Is(err, ErrProtocol) {
		t.Fatal(err)
	}
	nonce := [12]byte{255, 255, 1}
	incrementSSNonce(&nonce)
	if nonce != [12]byte{0, 0, 2} {
		t.Fatalf("nonce carry: %x", nonce)
	}
}

func TestSocksAddresses(t *testing.T) {
	for _, test := range []struct {
		host string
		port uint16
		wire string
	}{
		{"127.0.0.1", 443, "017f00000101bb"},
		{"::1", 53, "04000000000000000000000000000000010035"},
		{"example.org", 80, "030b6578616d706c652e6f72670050"},
	} {
		address, err := socksAddress(provider.Target{Host: test.host, Port: test.port})
		if err != nil || hex.EncodeToString(address) != test.wire {
			t.Fatalf("%s address: %x, %v", test.host, address, err)
		}
		for i := range len(address) {
			if _, err := socksAddressSize(address[:i]); err == nil {
				t.Fatalf("accepted truncated address at %d", i)
			}
		}
		if size, err := socksAddressSize(address); err != nil || size != len(address) {
			t.Fatal(size, err)
		}
	}
	for _, target := range []provider.Target{{Host: "::1%en0", Port: 1}, {Host: string(bytes.Repeat([]byte("a"), 256)), Port: 1}, {Host: "x"}} {
		if _, err := socksAddress(target); !errors.Is(err, provider.ErrAddressUnsupported) {
			t.Fatal(err)
		}
	}
	for _, packet := range [][]byte{{}, {0, 0, 0, 3}, {0, 0, 1, 1, 1, 2, 3, 4, 0, 1}, {1, 0, 0, 1, 1, 2, 3, 4, 0, 1}} {
		if validSocksPacket(packet) {
			t.Fatalf("accepted invalid packet %x", packet)
		}
	}
}

// The loopback reference uses its own EVP/HKDF and framing implementation,
// rather than wrapping the production ssStream on the server side.
func referenceSSAEAD(method, password string, salt []byte) cipher.AEAD {
	var key, previous []byte
	for len(key) < len(salt) {
		hash := md5.Sum(append(append([]byte(nil), previous...), password...))
		previous = hash[:]
		key = append(key, previous...)
	}
	extract := hmac.New(sha1.New, salt)
	_, _ = extract.Write(key)
	prk := extract.Sum(nil)
	var subkey, block []byte
	for counter := byte(1); len(subkey) < len(key); counter++ {
		expand := hmac.New(sha1.New, prk)
		_, _ = expand.Write(block)
		_, _ = expand.Write([]byte("ss-subkey"))
		_, _ = expand.Write([]byte{counter})
		block = expand.Sum(nil)
		subkey = append(subkey, block...)
	}
	if method == "chacha20-ietf-poly1305" {
		aead, _ := chacha20poly1305.New(subkey[:len(key)])
		return aead
	}
	blockCipher, _ := aes.NewCipher(subkey[:len(key)])
	aead, _ := cipher.NewGCM(blockCipher)
	return aead
}

func referenceSSRead(reader io.Reader, entry shadowsocksEntry) ([]byte, error) {
	size := 32
	if entry.Method == "aes-128-gcm" {
		size = 16
	}
	salt := make([]byte, size)
	if _, err := io.ReadFull(reader, salt); err != nil {
		return nil, err
	}
	aead := referenceSSAEAD(entry.Method, entry.Password, salt)
	var nonce [12]byte
	var counter uint64
	var result []byte
	for {
		length := make([]byte, 18)
		if _, err := io.ReadFull(reader, length); err != nil {
			if err == io.EOF {
				return result, nil
			}
			return nil, err
		}
		binary.LittleEndian.PutUint64(nonce[:], counter)
		counter++
		plain, err := aead.Open(nil, nonce[:], length, nil)
		if err != nil {
			return nil, err
		}
		n := int(binary.BigEndian.Uint16(plain))
		if n > 0x3fff {
			return nil, fmt.Errorf("oversized reference chunk")
		}
		wire := make([]byte, n+16)
		if _, err := io.ReadFull(reader, wire); err != nil {
			return nil, err
		}
		binary.LittleEndian.PutUint64(nonce[:], counter)
		counter++
		plain, err = aead.Open(nil, nonce[:], wire, nil)
		if err != nil {
			return nil, err
		}
		result = append(result, plain...)
	}
}

func referenceSSWire(entry shadowsocksEntry, payload []byte, chunkSize int) []byte {
	size := 32
	if entry.Method == "aes-128-gcm" {
		size = 16
	}
	salt := bytes.Repeat([]byte{0x42}, size)
	aead := referenceSSAEAD(entry.Method, entry.Password, salt)
	wire := append([]byte(nil), salt...)
	var nonce [12]byte
	var counter uint64
	for len(payload) > 0 {
		n := min(len(payload), chunkSize)
		var length [2]byte
		binary.BigEndian.PutUint16(length[:], uint16(n))
		binary.LittleEndian.PutUint64(nonce[:], counter)
		counter++
		wire = aead.Seal(wire, nonce[:], length[:], nil)
		binary.LittleEndian.PutUint64(nonce[:], counter)
		counter++
		wire = aead.Seal(wire, nonce[:], payload[:n], nil)
		payload = payload[n:]
	}
	return wire
}

func TestShadowsocksStreamLoopback(t *testing.T) {
	for _, method := range []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"} {
		t.Run(method, func(t *testing.T) {
			listener := listenTestTCP(t)
			host, port := testEndpoint(t, listener.Addr())
			entry := shadowsocksEntry{Method: method, Password: "loopback-password"}
			config := fixtureSSConfig(host, int(port), entry.Password)
			config.SS.Method = method
			authority, sessions := testTunnel(t, ShadowsocksProtocol, "line-21.transocks.invalid", 1, config)
			payload := bytes.Repeat([]byte("chunk-boundaries!"), 5000)
			response := []byte("reply only after client half-close")
			server := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					server <- err
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
				plain, err := referenceSSRead(conn, entry)
				if err == nil {
					expected := append([]byte{3, 11}, []byte("example.org")...)
					expected = append(expected, 0, 80)
					expected = append(expected, payload...)
					if !bytes.Equal(plain, expected) {
						err = fmt.Errorf("reference received wrong target/payload")
					}
				}
				if err == nil {
					wire := referenceSSWire(entry, response, 5)
					for _, b := range wire {
						if err = transocksWriteAll(conn, []byte{b}); err != nil {
							break
						}
					}
				}
				server <- err
			}()
			client, local := testTCPPair(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			ready := make(chan struct{}, 1)
			result := make(chan error, 1)
			var readyCount atomic.Int32
			admitted := false
			go func() {
				result <- NewShadowsocksTransport(sessions).RelayStream(ctx, provider.RelayRequest{Dial: testPinnedDial(t, "tcp", host, port), Client: local, NodeHost: "line-21.transocks.invalid", NodePort: 1, Target: provider.Target{Host: "example.org", Port: 80}, Authority: authority.Data, HandshakeTimeout: 3 * time.Second, Admit: func() bool { admitted = true; return true }, Ready: func(net.Addr) error {
					if !admitted {
						return errors.New("Ready before Admit")
					}
					readyCount.Add(1)
					ready <- struct{}{}
					return nil
				}})
			}()
			select {
			case <-ready:
			case err := <-result:
				t.Fatalf("before Ready: %v", err)
			}
			if err := transocksWriteAll(client, payload); err != nil {
				t.Fatal(err)
			}
			if err := client.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			actual, err := io.ReadAll(client)
			if err != nil || !bytes.Equal(actual, response) {
				t.Fatalf("response=%q err=%v", actual, err)
			}
			if err := <-result; err != nil {
				t.Fatal(err)
			}
			if err := <-server; err != nil {
				t.Fatal(err)
			}
			if readyCount.Load() != 1 {
				t.Fatal("Ready not called exactly once")
			}
		})
	}
}

func TestShadowsocksRejectsBadFrames(t *testing.T) {
	entry := shadowsocksEntry{Method: "aes-128-gcm", Password: "password"}
	valid := referenceSSWire(entry, []byte("hello"), 5)
	badLength := append([]byte(nil), valid...)
	badLength[16] ^= 1
	badPayload := append([]byte(nil), valid...)
	badPayload[len(badPayload)-1] ^= 1
	oversize := referenceSSWire(entry, bytes.Repeat([]byte{1}, ssMaxChunk+1), ssMaxChunk+1)
	for _, test := range []struct {
		name string
		wire []byte
		want error
	}{{"length-tag", badLength, ErrProtocol}, {"payload-tag", badPayload, ErrProtocol}, {"too-large", oversize, ErrProtocol}, {"truncated-payload", valid[:len(valid)-1], io.ErrUnexpectedEOF}, {"truncated-salt", valid[:3], io.ErrUnexpectedEOF}} {
		t.Run(test.name, func(t *testing.T) {
			reader, writer := net.Pipe()
			defer reader.Close()
			go func() { _, _ = writer.Write(test.wire); _ = writer.Close() }()
			stream, err := newSSStream(reader, entry)
			if err != nil {
				t.Fatal(err)
			}
			_, err = io.ReadAll(stream)
			if !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
}

func TestShadowsocksUDPReferenceRoundTrip(t *testing.T) {
	for _, method := range []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"} {
		t.Run(method, func(t *testing.T) {
			upstream, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer upstream.Close()
			_ = upstream.SetDeadline(time.Now().Add(8 * time.Second))
			host, port := testEndpoint(t, upstream.LocalAddr())
			entry := shadowsocksEntry{Method: method, Password: "udp-password"}
			authority, sessions := testSSTunnel(t, host, port, entry)
			server := make(chan error, 1)
			go func() {
				var previous []byte
				buffer := make([]byte, 65535)
				saltSize := 32
				if method == "aes-128-gcm" {
					saltSize = 16
				}
				for range 2 {
					n, peer, err := upstream.ReadFromUDP(buffer)
					if err != nil {
						server <- err
						return
					}
					if n < saltSize+16 {
						server <- ErrProtocol
						return
					}
					salt := buffer[:saltSize]
					if bytes.Equal(previous, salt) {
						server <- errors.New("UDP salt reused")
						return
					}
					previous = append(previous[:0], salt...)
					aead := referenceSSAEAD(method, entry.Password, salt)
					var nonce [12]byte
					plain, err := aead.Open(nil, nonce[:], buffer[saltSize:n], nil)
					if err != nil {
						server <- err
						return
					}
					bad := bytes.Repeat([]byte{0xff}, saltSize+20)
					_, _ = upstream.WriteToUDP(bad, peer)
					responseSalt := bytes.Repeat([]byte{0x73}, saltSize)
					responseAEAD := referenceSSAEAD(method, entry.Password, responseSalt)
					response := responseAEAD.Seal(responseSalt, nonce[:], plain, nil)
					if _, err := upstream.WriteToUDP(response, peer); err != nil {
						server <- err
						return
					}
				}
				server <- nil
			}()
			packets := newTestPackets()
			control, remote := net.Pipe()
			defer remote.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			ready := make(chan struct{}, 1)
			result := make(chan error, 1)
			go func() {
				result <- NewShadowsocksTransport(sessions).RelayDatagrams(ctx, provider.DatagramRequest{Dial: testPinnedDial(t, "udp", host, port), Control: control, Packets: packets, NodeHost: host, NodePort: port, Authority: authority.Data, HandshakeTimeout: 3 * time.Second, Admit: func() bool { return true }, Ready: func(net.Addr) error { ready <- struct{}{}; return nil }})
			}()
			select {
			case <-ready:
			case err := <-result:
				t.Fatal(err)
			}
			packets.in <- []byte{0, 0, 0, 3}
			packets.in <- []byte{0, 0, 1, 1, 127, 0, 0, 1, 0, 53}
			for _, target := range []provider.Target{{Host: "::1", Port: 53}, {Host: "example.org", Port: 53}} {
				address, _ := socksAddress(target)
				packet := append([]byte{0, 0, 0}, address...)
				packet = append(packet, []byte("UDP round trip")...)
				packets.in <- packet
				select {
				case actual := <-packets.out:
					if !bytes.Equal(actual, packet) {
						t.Fatalf("UDP got %x want %x", actual, packet)
					}
				case err := <-result:
					t.Fatalf("UDP relay stopped: %v", err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			if err := <-server; err != nil {
				t.Fatal(err)
			}
			_ = remote.Close()
			if err := <-result; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTransocksAuthorityPinAndAdmission(t *testing.T) {
	otherAuthority, shared := testSSTunnel(t, "other.test", 443, shadowsocksEntry{Method: "aes-128-gcm", Password: "x"})
	for _, transport := range []provider.Transport{NewShadowsocksTransport(shared), NewTrojanTransport(shared)} {
		t.Run(string(transport.Protocol()), func(t *testing.T) {
			client, local := net.Pipe()
			defer client.Close()
			defer local.Close()
			dialed := false
			err := transport.RelayStream(context.Background(), provider.RelayRequest{Dial: func(context.Context, string, string) (net.Conn, error) {
				dialed = true
				return nil, errors.New("must not dial")
			}, Client: local, NodeHost: "node.test", NodePort: 443, Target: provider.Target{Host: "example.org", Port: 80}, Authority: otherAuthority.Data, HandshakeTimeout: time.Second, Admit: func() bool { return true }, Ready: func(net.Addr) error { return errors.New("must not be ready") }})
			if !errors.Is(err, ErrInvalidAuthority) || dialed {
				t.Fatalf("err=%v dialed=%v", err, dialed)
			}
		})
	}
	upstream, peer := net.Pipe()
	defer peer.Close()
	go func() { _, _ = io.Copy(io.Discard, peer) }()
	authority, sessions := testSSTunnel(t, "node.test", 443, shadowsocksEntry{Method: "aes-128-gcm", Password: "x"})
	client, local := net.Pipe()
	defer client.Close()
	defer local.Close()
	ready := false
	err := NewShadowsocksTransport(sessions).RelayStream(context.Background(), provider.RelayRequest{Dial: func(context.Context, string, string) (net.Conn, error) { return upstream, nil }, Client: local, NodeHost: "node.test", NodePort: 443, Target: provider.Target{Host: "x", Port: 80}, Authority: authority.Data, HandshakeTimeout: time.Second, Admit: func() bool { return false }, Ready: func(net.Addr) error { ready = true; return nil }})
	if !errors.Is(err, provider.ErrNoSession) || ready {
		t.Fatalf("err=%v ready=%v", err, ready)
	}
}

func listenTestTCP(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}
func testEndpoint(t *testing.T, address net.Addr) (string, uint16) {
	t.Helper()
	host, p, err := net.SplitHostPort(address.String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(p, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	return host, uint16(port)
}
func testTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener := listenTestTCP(t)
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	local, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close(); _ = local.Close() })
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	_ = local.SetDeadline(time.Now().Add(10 * time.Second))
	return client.(*net.TCPConn), local.(*net.TCPConn)
}
func testPinnedDial(t *testing.T, network, host string, port uint16) provider.DialContextFunc {
	t.Helper()
	return func(ctx context.Context, actualNetwork, address string) (net.Conn, error) {
		if actualNetwork != network || address != nodeKey(host, port) {
			return nil, fmt.Errorf("dial escaped pin: %s %s", actualNetwork, address)
		}
		return (&net.Dialer{}).DialContext(ctx, actualNetwork, address)
	}
}

type testPackets struct {
	in, out chan []byte
	done    chan struct{}
	once    sync.Once
}

func newTestPackets() *testPackets {
	return &testPackets{in: make(chan []byte, 8), out: make(chan []byte, 8), done: make(chan struct{})}
}
func (*testPackets) FlowID() uint16 { return 1 }
func (*testPackets) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}
func (p *testPackets) ReadPacket(buffer []byte) (int, error) {
	select {
	case packet := <-p.in:
		return copy(buffer, packet), nil
	case <-p.done:
		return 0, net.ErrClosed
	}
}
func (p *testPackets) WritePacket(packet []byte) error {
	copyPacket := append([]byte(nil), packet...)
	select {
	case p.out <- copyPacket:
		return nil
	case <-p.done:
		return net.ErrClosed
	}
}
func (p *testPackets) Close() error { p.once.Do(func() { close(p.done) }); return nil }
