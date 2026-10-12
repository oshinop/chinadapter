package wifiin

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// ReadDeadlineConn is the narrow connection capability needed while waiting
// for the delayed WIFIIN server IV.
type ReadDeadlineConn interface {
	SetReadDeadline(time.Time) error
}

// LazyInboundReader decrypts the server-to-client WIFIIN stream. The provider
// may defer its IV while the client is still sending application ciphertext.
// Only a client write-side half-close bounds that wait; cancellation closes the
// connection to interrupt an otherwise unbounded read.
type LazyInboundReader struct {
	source  *HandshakeReader
	key     [KeySize]byte
	conn    ReadDeadlineConn
	timeout time.Duration

	initMu  sync.Mutex
	mu      sync.Mutex
	reader  io.Reader
	init    bool
	initErr error

	ivReady       bool
	deadlineArmed bool
}

// NewLazyInboundReader creates the inbound stream reader. timeout applies only
// after ArmAfterCloseWrite, once the client can send no further application data.
func NewLazyInboundReader(source *HandshakeReader, key []byte, conn ReadDeadlineConn, timeout time.Duration) (*LazyInboundReader, error) {
	if source == nil {
		return nil, errors.New("wifiin: handshake reader is required")
	}
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}
	if conn == nil {
		return nil, errors.New("wifiin: read deadline connection is required")
	}
	if timeout <= 0 {
		return nil, errors.New("wifiin: server IV timeout must be positive")
	}
	lazy := &LazyInboundReader{source: source, conn: conn, timeout: timeout}
	copy(lazy.key[:], key)
	return lazy, nil
}

// ArmAfterCloseWrite bounds the delayed IV wait after the client half-closes.
// Once the IV is available the normal stream is not subject to this deadline.
func (r *LazyInboundReader) ArmAfterCloseWrite() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ivReady || r.deadlineArmed {
		return nil
	}
	if err := r.conn.SetReadDeadline(time.Now().Add(r.timeout)); err != nil {
		return fmt.Errorf("wifiin: set delayed server IV deadline: %w", err)
	}
	r.deadlineArmed = true
	return nil
}

// Read initializes the receive cipher on its first non-empty read, then
// transparently decrypts the continuous CFB stream.
func (r *LazyInboundReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := r.initialize(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func (r *LazyInboundReader) initialize() error {
	r.initMu.Lock()
	defer r.initMu.Unlock()
	if r.init {
		return r.initErr
	}
	r.init = true

	iv, err := r.source.ReadServerIV()
	if err != nil {
		r.initErr = fmt.Errorf("wifiin: delayed server IV: %w", err)
		return r.initErr
	}
	stream, err := NewDecrypter(r.key[:], iv[:])
	if err != nil {
		r.initErr = err
		return err
	}

	r.mu.Lock()
	r.ivReady = true
	clearDeadline := r.deadlineArmed
	r.mu.Unlock()
	if clearDeadline {
		if err := r.conn.SetReadDeadline(time.Time{}); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
			r.initErr = fmt.Errorf("wifiin: clear delayed server IV deadline: %w", err)
			return r.initErr
		}
	}
	r.reader = &cipher.StreamReader{S: stream, R: r.source}
	return nil
}
