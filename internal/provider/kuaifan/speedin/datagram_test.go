package speedin_test

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/oshinop/chinadapter/internal/provider/kuaifan/speedin"
)

func TestDatagramsAgainstReferenceServer(t *testing.T) {
	c := newCipher(t)
	codec, err := c.NewDatagramCodec(testAuth)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"192.0.2.1", "target.example", "2001:db8::1"} {
		t.Run(host, func(t *testing.T) {
			address, err := speedin.AppendAddress(nil, speedin.Address{Host: host, Port: 53})
			if err != nil {
				t.Fatal(err)
			}
			socks := append([]byte{0, 0, 0}, address...)
			socks = append(socks, []byte("udp payload")...)
			wire, err := codec.EncodeSOCKS(nil, nil, socks)
			if err != nil {
				t.Fatal(err)
			}
			plain, err := referenceAEAD(password, wire[:16]).Open(nil, referenceNonce(0), wire[16:], nil)
			if err != nil {
				t.Fatal(err)
			}
			parsedAddress, addressLen, err := speedin.ParseAddress(plain)
			if err != nil || parsedAddress.Host != host || parsedAddress.Port != 53 {
				t.Fatalf("address = %#v, %v", parsedAddress, err)
			}
			parsedAuth, authLen, err := speedin.ParseAuth(plain[addressLen:])
			if err != nil || parsedAuth != testAuth || string(plain[addressLen+authLen:]) != "udp payload" {
				t.Fatal("missing UDP authentication or payload")
			}
			// Server replies contain auth too. High-nibble flags are masked only
			// on decode, while the returned SOCKS header must be ordinary ATYP.
			plain[0] |= 0xa0
			salt := []byte("reference-salt!!")
			reply := append([]byte(nil), salt...)
			reply = referenceAEAD(password, salt).Seal(reply, referenceNonce(0), plain, nil)
			got, err := codec.DecodeSOCKS(make([]byte, 0, 65535), reply)
			if err != nil || !bytes.Equal(got, socks) {
				t.Fatalf("UDP response = %x, %v", got, err)
			}
			for n := range len(reply) {
				if _, err := codec.DecodeSOCKS(nil, reply[:n]); !errors.Is(err, speedin.ErrInvalidPacket) {
					t.Fatalf("truncated UDP at %d: %v", n, err)
				}
			}
			wire2, err := codec.EncodeSOCKS(nil, nil, socks)
			if err != nil || bytes.Equal(wire, wire2) {
				t.Fatal("UDP packet salt reused")
			}
		})
	}
}

func TestDatagramBoundsAndMalformedPackets(t *testing.T) {
	c := newCipher(t)
	codec, err := c.NewDatagramCodec(testAuth)
	if err != nil {
		t.Fatal(err)
	}
	address := []byte{1, 127, 0, 0, 1, 0, 53}
	auth, _ := speedin.AppendAuth(nil, testAuth)
	maxPayload := speedin.MaxPacketSize - speedin.SaltSize - speedin.TagSize - len(address) - len(auth)
	packet := append([]byte{0, 0, 0}, address...)
	packet = append(packet, bytes.Repeat([]byte{'p'}, maxPayload)...)
	wire, err := codec.EncodeSOCKS(nil, nil, packet)
	if err != nil || len(wire) != speedin.MaxPacketSize {
		t.Fatalf("maximum UDP = %d,%v", len(wire), err)
	}
	got, err := codec.DecodeSOCKS(nil, wire)
	if err != nil || !bytes.Equal(got, packet) {
		t.Fatalf("maximum UDP round trip = %d,%v", len(got), err)
	}
	if _, err := codec.EncodeSOCKS(nil, nil, append(packet, 'x')); !errors.Is(err, speedin.ErrInvalidPacket) {
		t.Fatalf("oversized UDP: %v", err)
	}
	valid := append([]byte{0, 0, 0}, address...)
	for _, malformed := range [][]byte{nil, {0}, {0, 0, 0, 3}, {0, 0, 0, 3, 0, 0, 53}, {0, 0, 0, 1, 127, 0, 0, 1, 0, 0}, {1, 0, 0, 1, 127, 0, 0, 1, 0, 53}, {0, 1, 0, 1, 127, 0, 0, 1, 0, 53}, {0, 0, 0, 0x11, 127, 0, 0, 1, 0, 53}} {
		if _, err := codec.EncodeSOCKS(nil, nil, malformed); !errors.Is(err, speedin.ErrInvalidPacket) {
			t.Fatalf("malformed SOCKS %x: %v", malformed, err)
		}
	}
	fragment := bytes.Clone(valid)
	fragment[2] = 1
	if _, err := codec.EncodeSOCKS(nil, nil, fragment); !errors.Is(err, speedin.ErrFragmentedPacket) {
		t.Fatalf("fragmented SOCKS: %v", err)
	}
	for _, body := range [][]byte{nil, {1}, append(bytes.Clone(address), 2, 0, 0), append(bytes.Clone(address), 1, 0, 8, '1', '|', 'x')} {
		wire, err := c.EncodePacket(nil, body)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := codec.DecodeSOCKS(nil, wire); !errors.Is(err, speedin.ErrInvalidPacket) {
			t.Fatalf("malformed UDP body: %v", err)
		}
	}
	wire, _ = codec.EncodeSOCKS(nil, nil, valid)
	wire[len(wire)-1] ^= 1
	if _, err := codec.DecodeSOCKS(nil, wire); !errors.Is(err, speedin.ErrInvalidPacket) {
		t.Fatalf("corrupt packet: %v", err)
	}
}

type boundedWriter struct {
	bytes.Buffer
	limit int
	fail  error
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	if w.fail != nil {
		return 0, w.fail
	}
	return w.Buffer.Write(p[:min(w.limit, len(p))])
}

func TestStreamWriteFailuresAreTerminal(t *testing.T) {
	c := newCipher(t)
	short := &boundedWriter{limit: 1}
	writer, err := c.NewWriter(short)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := writer.Write([]byte("short writes")); n != 12 || err != nil {
		t.Fatalf("short write = %d,%v", n, err)
	}
	chunks, err := referenceChunks(short.Bytes(), 2014)
	if err != nil || string(chunks[0]) != "short writes" {
		t.Fatalf("short-write framing: %v", err)
	}
	failure := errors.New("write failed")
	short.fail = failure
	if n, err := writer.Write([]byte("failed")); n != 0 || !errors.Is(err, failure) {
		t.Fatalf("failed write = %d,%v", n, err)
	}
	short.fail = nil
	before := short.Len()
	if n, err := writer.Write([]byte("cannot retry")); n != 0 || !errors.Is(err, failure) || short.Len() != before {
		t.Fatal("failed stream resumed with advanced nonce")
	}
	if _, err := c.NewWriter(&boundedWriter{limit: 0}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("zero write: %v", err)
	}
	for _, password := range []string{"", strings.Repeat("p", 4097)} {
		if _, err := speedin.NewCipher(password); !errors.Is(err, speedin.ErrInvalidPassword) {
			t.Fatalf("invalid cipher password: %v", err)
		}
	}
}
