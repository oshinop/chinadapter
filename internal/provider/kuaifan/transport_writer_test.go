package kuaifan

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/oshinop/chinadapter/internal/provider/kuaifan/wifiin"
)

func TestOutboundCFBWriterContinuousCipherAndShortWrites(t *testing.T) {
	key := wifiin.DeriveKey("writer-test")
	var iv [wifiin.IVSize]byte
	stream, err := wifiin.NewEncrypter(key[:], iv[:])
	if err != nil {
		t.Fatal(err)
	}
	conn := &testWriteConn{limit: 11}
	writer := newOutboundCFBWriter(stream, conn, nil)
	var want bytes.Buffer
	for _, size := range []int{0, 7, len(writer.scratch) + 17, 2 * len(writer.scratch)} {
		plain := bytes.Repeat([]byte{'x'}, size)
		original := append([]byte(nil), plain...)
		if n, err := writer.Write(plain); err != nil || n != len(plain) {
			t.Fatalf("Write(%d bytes) = %d, %v", size, n, err)
		}
		if !bytes.Equal(plain, original) {
			t.Fatal("encrypted writer modified caller's plaintext")
		}
		want.Write(plain)
	}
	decrypt, err := wifiin.NewDecrypter(key[:], iv[:])
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := conn.output.Bytes()
	got := make([]byte, len(ciphertext))
	decrypt.XORKeyStream(got, ciphertext)
	if !bytes.Equal(got, want.Bytes()) {
		t.Fatal("cipher state was not continuous across scratch buffers and writes")
	}
}

func TestOutboundCFBWriterRejectsNoProgress(t *testing.T) {
	key := wifiin.DeriveKey("writer-test")
	stream, err := wifiin.NewEncrypter(key[:], make([]byte, wifiin.IVSize))
	if err != nil {
		t.Fatal(err)
	}
	writer := newOutboundCFBWriter(stream, &testWriteConn{}, nil)
	if n, err := writer.Write([]byte("plaintext")); n != 0 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("non-progressing Write = %d, %v", n, err)
	}
}

type testWriteConn struct {
	net.Conn
	output bytes.Buffer
	limit  int
}

func (c *testWriteConn) Write(p []byte) (int, error) {
	return c.output.Write(p[:min(len(p), c.limit)])
}
