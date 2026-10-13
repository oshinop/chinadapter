package speedin

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

// Writer encrypts chunks of at most MaxChunkSize plaintext bytes. Its salt is
// emitted once at construction, and its nonce advances twice for each chunk.
// Any write error is terminal because the nonce/framing cannot be retried.
type Writer struct {
	out   io.Writer
	aead  cipher.AEAD
	nonce [NonceSize]byte
	frame [MaxChunkSize + 2 + 2*TagSize]byte
	err   error
}

func (c *Cipher) NewWriter(out io.Writer) (*Writer, error) {
	if out == nil {
		return nil, ErrInvalidFrame
	}
	var salt [SaltSize]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, err
	}
	aead, err := c.authenticator(salt[:])
	if err != nil {
		return nil, err
	}
	if err := writeAll(out, salt[:]); err != nil {
		return nil, err
	}
	return &Writer{out: out, aead: aead}, nil
}

func (w *Writer) Write(data []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	written := 0
	for len(data) != 0 {
		n := min(len(data), MaxChunkSize)
		var length [2]byte
		binary.BigEndian.PutUint16(length[:], uint16(n))
		frame := w.aead.Seal(w.frame[:0], w.nonce[:], length[:], nil)
		incrementNonce(&w.nonce)
		frame = w.aead.Seal(frame, w.nonce[:], data[:n], nil)
		incrementNonce(&w.nonce)
		if err := writeAll(w.out, frame); err != nil {
			w.err = err
			return written, err
		}
		written += n
		data = data[n:]
	}
	return written, nil
}

// Reader hides chunk boundaries and retains unconsumed decrypted bytes. It
// accepts the full uint16 wire length, bounded to 65535 bytes: the recovered
// 2014-byte writer limit is not evidence of a server-side response limit.
type Reader struct {
	in      io.Reader
	cipher  *Cipher
	aead    cipher.AEAD
	nonce   [NonceSize]byte
	length  [2 + TagSize]byte
	buffer  [MaxChunkSize + TagSize]byte
	body    []byte
	pending []byte
	err     error
}

// NewReader is lazy: Read obtains the independently salted response direction.
func (c *Cipher) NewReader(in io.Reader) (*Reader, error) {
	if c == nil {
		return nil, ErrInvalidPassword
	}
	if in == nil {
		return nil, ErrInvalidFrame
	}
	r := &Reader{in: in, cipher: c}
	r.body = r.buffer[:]
	return r, nil
}

func (r *Reader) Read(dst []byte) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}
	if r.err != nil {
		return 0, r.err
	}
	if r.aead == nil {
		var salt [SaltSize]byte
		if _, err := io.ReadFull(r.in, salt[:]); err != nil {
			r.err = err
			return 0, err
		}
		aead, err := r.cipher.authenticator(salt[:])
		if err != nil {
			r.err = err
			return 0, err
		}
		r.aead = aead
	}
	for len(r.pending) == 0 {
		if err := r.readChunk(); err != nil {
			r.err = err
			return 0, err
		}
	}
	n := copy(dst, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

func (r *Reader) readChunk() error {
	if _, err := io.ReadFull(r.in, r.length[:]); err != nil {
		return err
	}
	length, err := r.aead.Open(r.length[:0], r.nonce[:], r.length[:], nil)
	if err != nil {
		return fmt.Errorf("%w: length: %w", ErrInvalidFrame, err)
	}
	incrementNonce(&r.nonce)
	size := int(binary.BigEndian.Uint16(length))
	if size+TagSize > cap(r.body) {
		// Grow only for larger upstream chunks. No old plaintext needs to be
		// copied: the prior chunk has already been fully consumed.
		r.body = make([]byte, min(65535+TagSize, max(size+TagSize, 2*cap(r.body))))
	}
	body := r.body[:size+TagSize]
	if _, err := io.ReadFull(r.in, body); err != nil {
		// EOF after the encrypted length is a truncated frame, not a clean end.
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return err
	}
	r.pending, err = r.aead.Open(body[:0], r.nonce[:], body, nil)
	if err != nil {
		return fmt.Errorf("%w: body: %w", ErrInvalidFrame, err)
	}
	incrementNonce(&r.nonce)
	return nil
}

// ReadAuthAnswer consumes exactly the encrypted provider status and detail,
// preserving application bytes in the same chunk. Detail has no known
// acceptance restriction: every status other than 1 rejects the connection.
func ReadAuthAnswer(in io.Reader) (uint16, error) {
	var answer [3]byte
	if _, err := io.ReadFull(in, answer[:]); err != nil {
		return 0, fmt.Errorf("speedin: read authentication answer: %w", err)
	}
	detail := binary.BigEndian.Uint16(answer[1:])
	if answer[0] != 1 {
		return detail, fmt.Errorf("%w: status=%d detail=%d", ErrAuthRejected, answer[0], detail)
	}
	return detail, nil
}
