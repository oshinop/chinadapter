package kuaifan

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/kfadapter/kfadapter/internal/kuaifan/wifiin"
)

// BenchmarkRelay exercises a complete bidirectional encrypted relay with a
// deterministic in-memory connection, excluding network scheduling overhead.
func BenchmarkRelay(b *testing.B) {
	payload := bytes.Repeat([]byte("r"), 256*1024)
	key := wifiin.DeriveKey("benchmark-password")
	var iv [wifiin.IVSize]byte
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for b.Loop() {
		left := &benchmarkConn{Reader: bytes.NewReader(payload)}
		right := &benchmarkConn{Reader: bytes.NewReader(make([]byte, 3+wifiin.IVSize))}
		inbound, err := wifiin.NewLazyInboundReader(wifiin.NewHandshakeReader(right), key[:], right, time.Second)
		if err != nil {
			b.Fatal(err)
		}
		stream, err := wifiin.NewEncrypter(key[:], iv[:])
		if err != nil {
			b.Fatal(err)
		}
		tunnel := &cipherConn{Conn: right, reader: inbound, writer: newOutboundCFBWriter(stream, right, inbound)}
		if err := wifiin.Relay(context.Background(), left, tunnel); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRelayCipherWrites measures the allocation cost of small application
// writes over one long-lived encrypted relay connection.
func BenchmarkRelayCipherWrites(b *testing.B) {
	key := wifiin.DeriveKey("benchmark-password")
	var iv [wifiin.IVSize]byte
	conn := &benchmarkConn{Reader: bytes.NewReader(nil)}
	inbound, err := wifiin.NewLazyInboundReader(wifiin.NewHandshakeReader(conn), key[:], conn, time.Second)
	if err != nil {
		b.Fatal(err)
	}
	stream, err := wifiin.NewEncrypter(key[:], iv[:])
	if err != nil {
		b.Fatal(err)
	}
	writer := newOutboundCFBWriter(stream, conn, inbound)
	payload := make([]byte, 4096)
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for b.Loop() {
		if _, err := writer.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
}

type benchmarkConn struct{ *bytes.Reader }

func (*benchmarkConn) Write(p []byte) (int, error)           { return len(p), nil }
func (*benchmarkConn) Close() error                          { return nil }
func (*benchmarkConn) CloseWrite() error                     { return nil }
func (*benchmarkConn) LocalAddr() net.Addr                   { return &net.TCPAddr{} }
func (*benchmarkConn) RemoteAddr() net.Addr                  { return &net.TCPAddr{} }
func (*benchmarkConn) SetDeadline(time.Time) error           { return nil }
func (*benchmarkConn) SetReadDeadline(time.Time) error       { return nil }
func (*benchmarkConn) SetWriteDeadline(time.Time) error      { return nil }
func (c *benchmarkConn) ReadFrom(r io.Reader) (int64, error) { return io.Copy(io.Discard, r) }
