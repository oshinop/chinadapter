package speedin_test

import (
	"bytes"
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
	"strings"
	"testing"

	"github.com/oshinop/chinadapter/internal/provider/kuaifan/speedin"
)

const password = "speedin-test-password"

var testAuth = speedin.Auth{UserID: 18446744073709551615, Token: "opaque-token", OS: "WINDOWS"}

// referenceAEAD derives HKDF directly with HMAC rather than the implementation's
// HKDF helper. Reference framing uses a numeric nonce counter, independent of
// the implementation's bytewise little-endian increment routine.
func referenceAEAD(password string, salt []byte) cipher.AEAD {
	master := md5.Sum([]byte(password))
	extract := hmac.New(sha1.New, salt)
	_, _ = extract.Write(master[:])
	expand := hmac.New(sha1.New, extract.Sum(nil))
	_, _ = expand.Write([]byte("ss-subkey\x01"))
	block, err := aes.NewCipher(expand.Sum(nil)[:16])
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return aead
}

func referenceNonce(counter uint64) []byte {
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[:], counter)
	return nonce[:]
}

func referenceChunks(wire []byte, limit int) ([][]byte, error) {
	if len(wire) < 16 {
		return nil, io.ErrUnexpectedEOF
	}
	aead := referenceAEAD(password, wire[:16])
	wire = wire[16:]
	var chunks [][]byte
	var counter uint64
	for len(wire) != 0 {
		if len(wire) < 18 {
			return nil, io.ErrUnexpectedEOF
		}
		length, err := aead.Open(nil, referenceNonce(counter), wire[:18], nil)
		if err != nil {
			return nil, err
		}
		counter++
		size := int(binary.BigEndian.Uint16(length))
		if size > limit {
			return nil, fmt.Errorf("chunk size %d > %d", size, limit)
		}
		wire = wire[18:]
		if len(wire) < size+16 {
			return nil, io.ErrUnexpectedEOF
		}
		chunk, err := aead.Open(nil, referenceNonce(counter), wire[:size+16], nil)
		if err != nil {
			return nil, err
		}
		counter++
		chunks = append(chunks, chunk)
		wire = wire[size+16:]
	}
	return chunks, nil
}

func referenceStream(chunks ...[]byte) []byte {
	salt := []byte("reference-salt!!")
	aead := referenceAEAD(password, salt)
	wire := append([]byte(nil), salt...)
	for i, chunk := range chunks {
		var length [2]byte
		binary.BigEndian.PutUint16(length[:], uint16(len(chunk)))
		wire = aead.Seal(wire, referenceNonce(uint64(2*i)), length[:], nil)
		wire = aead.Seal(wire, referenceNonce(uint64(2*i+1)), chunk, nil)
	}
	return wire
}

func newCipher(t *testing.T) *speedin.Cipher {
	t.Helper()
	c, err := speedin.NewCipher(password)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestIndependentKeyDerivationVector(t *testing.T) {
	// Independently generated with Node's MD5/HMAC-SHA1/AES-128-GCM primitives.
	// Salt = 00..0f; master = 38543fc12100236ea02ff18eed03603b;
	// HKDF subkey = 65923cd424b83d3c9e6bbf5674b93d2f.
	key := speedin.DeriveKey(password)
	if hex.EncodeToString(key[:]) != "38543fc12100236ea02ff18eed03603b" {
		t.Fatal("master key mismatch")
	}
	packet, err := hex.DecodeString("000102030405060708090a0b0c0d0e0ff7994ff0fdcc821e2c7e7aec09aa6e71e54e51aaecc6a3176973a72dc1716593")
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := newCipher(t).DecodePacket(nil, packet)
	if err != nil || string(plaintext) != "vector plaintext" {
		t.Fatalf("vector = %q, %v", plaintext, err)
	}
}

func TestStreamAgainstReferenceServer(t *testing.T) {
	for _, tc := range []struct{ host, addressHex string }{
		{"192.0.2.1", "01c000020101bb"},
		{"target.example", "030e7461726765742e6578616d706c6501bb"},
		{"2001:db8::1", "0420010db800000000000000000000000101bb"},
	} {
		t.Run(tc.host, func(t *testing.T) {
			c := newCipher(t)
			header, err := speedin.EncodeRequest(speedin.Address{Host: tc.host, Port: 443}, testAuth)
			if err != nil {
				t.Fatal(err)
			}
			var wire bytes.Buffer
			writer, err := c.NewWriter(&wire)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write(header); err != nil {
				t.Fatal(err)
			}
			// More than 256 AEAD operations checks nonce carry, not just order.
			application := bytes.Repeat([]byte("payload!"), 80000)
			if n, err := writer.Write(application); err != nil || n != len(application) {
				t.Fatalf("write = %d, %v", n, err)
			}
			chunks, err := referenceChunks(wire.Bytes(), 2014)
			if err != nil {
				t.Fatal(err)
			}
			address, _ := hex.DecodeString(tc.addressHex)
			expectedAuth := []byte("18446744073709551615|opaque-token|WINDOWS")
			want := append(address, 1, byte(len(expectedAuth)>>8), byte(len(expectedAuth)))
			want = append(want, expectedAuth...)
			if !bytes.Equal(chunks[0], want) {
				t.Fatalf("first request = %x, want %x", chunks[0], want)
			}
			if !bytes.Equal(bytes.Join(chunks[1:], nil), application) {
				t.Fatal("application payload/nonce order changed")
			}
			response := referenceStream(append([]byte{1, 0xfe, 0xdc}, []byte("same-chunk response")...), []byte("; next chunk"))
			reader, err := c.NewReader(&oneByteReader{bytes.NewReader(response)})
			if err != nil {
				t.Fatal(err)
			}
			detail, err := speedin.ReadAuthAnswer(reader)
			if err != nil || detail != 0xfedc {
				t.Fatalf("answer detail=%x: %v", detail, err)
			}
			got, err := io.ReadAll(reader)
			if err != nil || string(got) != "same-chunk response; next chunk" {
				t.Fatalf("response = %q, %v", got, err)
			}
		})
	}
}

type oneByteReader struct{ io.Reader }

func (r *oneByteReader) Read(dst []byte) (int, error) { return r.Reader.Read(dst[:min(1, len(dst))]) }

func TestResponseErrorsAndLargeChunks(t *testing.T) {
	c := newCipher(t)
	for _, status := range []byte{0, 2, 255} {
		reader, _ := c.NewReader(bytes.NewReader(referenceStream([]byte{status, 0x12, 0x34})))
		detail, err := speedin.ReadAuthAnswer(reader)
		if !errors.Is(err, speedin.ErrAuthRejected) || detail != 0x1234 {
			t.Fatalf("status %d = detail %x, %v", status, detail, err)
		}
	}
	for _, answer := range [][]byte{nil, {1}, {1, 0}} {
		reader, _ := c.NewReader(bytes.NewReader(referenceStream(answer)))
		if _, err := speedin.ReadAuthAnswer(reader); !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("truncated answer %x: %v", answer, err)
		}
	}
	wire := referenceStream([]byte{1, 0, 0})
	for n := range len(wire) {
		reader, _ := c.NewReader(bytes.NewReader(wire[:n]))
		if _, err := speedin.ReadAuthAnswer(reader); err == nil {
			t.Fatalf("accepted truncated ciphertext at %d", n)
		}
	}
	for _, offset := range []int{16, 34, len(wire) - 1} {
		corrupt := bytes.Clone(wire)
		corrupt[offset] ^= 1
		reader, _ := c.NewReader(bytes.NewReader(corrupt))
		if _, err := speedin.ReadAuthAnswer(reader); !errors.Is(err, speedin.ErrInvalidFrame) {
			t.Fatalf("corrupted offset %d: %v", offset, err)
		}
	}
	large := bytes.Repeat([]byte{'x'}, 65535)
	reader, _ := c.NewReader(bytes.NewReader(referenceStream(nil, large)))
	got, err := io.ReadAll(reader)
	if err != nil || !bytes.Equal(got, large) {
		t.Fatalf("large response = %d, %v", len(got), err)
	}
}

func TestInvalidAddressAndAuthentication(t *testing.T) {
	for _, address := range []speedin.Address{{}, {Host: "x", Port: 0}, {Host: strings.Repeat("x", 256), Port: 1}, {Host: "fe80::1%en0", Port: 1}, {Host: "a\x00b", Port: 1}} {
		if _, err := speedin.AppendAddress(nil, address); !errors.Is(err, speedin.ErrInvalidAddress) {
			t.Fatalf("invalid address: %v", err)
		}
	}
	for _, auth := range []speedin.Auth{{}, {UserID: 1, Token: "bad|token", OS: "WINDOWS"}, {UserID: 1, Token: "t", OS: "bad|os"}, {UserID: 1, Token: strings.Repeat("x", 65535), OS: "WINDOWS"}} {
		if _, err := speedin.AppendAuth(nil, auth); !errors.Is(err, speedin.ErrInvalidAuth) {
			t.Fatalf("invalid auth: %v", err)
		}
	}
	encoded, err := speedin.AppendAuth(nil, testAuth)
	if err != nil {
		t.Fatal(err)
	}
	got, n, err := speedin.ParseAuth(append(encoded, 'x'))
	if err != nil || got != testAuth || n != len(encoded) {
		t.Fatalf("auth round trip = %#v, %d, %v", got, n, err)
	}
	for n := range len(encoded) {
		if _, _, err := speedin.ParseAuth(encoded[:n]); !errors.Is(err, speedin.ErrInvalidAuth) {
			t.Fatalf("auth truncation %d: %v", n, err)
		}
	}
	for _, raw := range []string{"1|t|o|extra", "+1|t|o", "0|t|o", "18446744073709551616|t|o", "1||o", "1|t|"} {
		body := append([]byte{1, byte(len(raw) >> 8), byte(len(raw))}, raw...)
		if _, _, err := speedin.ParseAuth(body); !errors.Is(err, speedin.ErrInvalidAuth) {
			t.Fatalf("malformed auth: %v", err)
		}
	}
}

func TestInitialRequestFitsOneChunk(t *testing.T) {
	address := speedin.Address{Host: "192.0.2.1", Port: 443}
	// IPv4 address (7), version/length (3), and "1|token|WINDOWS".
	maxToken := speedin.MaxChunkSize - 7 - 3 - len("1||WINDOWS")
	auth := speedin.Auth{UserID: 1, Token: strings.Repeat("t", maxToken), OS: "WINDOWS"}
	request, err := speedin.EncodeRequest(address, auth)
	if err != nil || len(request) != speedin.MaxChunkSize {
		t.Fatalf("maximum initial request = %d,%v", len(request), err)
	}
	auth.Token += "t"
	if _, err := speedin.EncodeRequest(address, auth); !errors.Is(err, speedin.ErrInvalidAuth) {
		t.Fatalf("oversized first chunk: %v", err)
	}
}
