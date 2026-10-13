// Package speedin implements KuaiFan's authenticated AES-128-GCM Shadowsocks
// fork, as recovered in docs/kuaifan-speedin-hysteria2-analysis.md section 2.
// A Cipher is immutable and can be shared; stream readers/writers and datagram
// buffers belong to their respective single I/O goroutines.
package speedin

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	SaltSize  = 16
	NonceSize = 12
	TagSize   = 16
	// MaxChunkSize is the recovered client's outbound limit, not a server limit.
	MaxChunkSize = 2014
	// MaxPacketSize bounds encrypted UDP packets to the IPv4 UDP payload limit.
	// Oversized datagrams are rejected, never silently truncated.
	MaxPacketSize   = 65507
	maxPasswordSize = 4096
)

var (
	ErrInvalidPassword  = errors.New("speedin: invalid cipher password")
	ErrInvalidAddress   = errors.New("speedin: invalid destination address")
	ErrInvalidAuth      = errors.New("speedin: invalid authentication block")
	ErrInvalidFrame     = errors.New("speedin: invalid encrypted stream frame")
	ErrAuthRejected     = errors.New("speedin: authentication rejected")
	ErrInvalidPacket    = errors.New("speedin: invalid datagram")
	ErrFragmentedPacket = errors.New("speedin: fragmented SOCKS datagram")
)

// DeriveKey is classic EVP_BytesToKey for the 16-byte AES-128 master key.
// MD5 is required by the upstream protocol; it is not a password-storage KDF.
func DeriveKey(password string) [SaltSize]byte { return md5.Sum([]byte(password)) }

// Cipher holds only the master key. Each stream direction and each datagram
// derives its own AEAD subkey using its independently generated 16-byte salt.
type Cipher struct{ key [SaltSize]byte }

func NewCipher(password string) (*Cipher, error) {
	if password == "" || len(password) > maxPasswordSize {
		return nil, ErrInvalidPassword
	}
	return &Cipher{key: DeriveKey(password)}, nil
}

func (c *Cipher) authenticator(salt []byte) (cipher.AEAD, error) {
	if c == nil || len(salt) != SaltSize {
		return nil, ErrInvalidPassword
	}
	var key [SaltSize]byte
	if _, err := io.ReadFull(hkdf.New(sha1.New, c.key[:], salt, []byte("ss-subkey")), key[:]); err != nil {
		return nil, fmt.Errorf("speedin: derive subkey: %w", err)
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func incrementNonce(nonce *[NonceSize]byte) {
	for i := range nonce {
		nonce[i]++
		if nonce[i] != 0 {
			return
		}
	}
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) != 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(data) {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

// EncodePacket appends salt || AEAD(nonce=0, plaintext) to dst. It uses a
// fresh cryptographic salt on every call; there is no TCP-style length frame.
func (c *Cipher) EncodePacket(dst, plaintext []byte) ([]byte, error) {
	if len(plaintext) > MaxPacketSize-SaltSize-TagSize {
		return nil, ErrInvalidPacket
	}
	start := len(dst)
	dst = append(dst, make([]byte, SaltSize)...)
	if _, err := rand.Read(dst[start:]); err != nil {
		return nil, err
	}
	aead, err := c.authenticator(dst[start:])
	if err != nil {
		return nil, err
	}
	var nonce [NonceSize]byte
	return aead.Seal(dst, nonce[:], plaintext, nil), nil
}

// DecodePacket appends authenticated plaintext to dst. The result shares dst
// when its capacity permits; neither input packet nor existing dst is modified.
func (c *Cipher) DecodePacket(dst, packet []byte) ([]byte, error) {
	if len(packet) < SaltSize+TagSize || len(packet) > MaxPacketSize {
		return nil, ErrInvalidPacket
	}
	aead, err := c.authenticator(packet[:SaltSize])
	if err != nil {
		return nil, err
	}
	var nonce [NonceSize]byte
	plaintext, err := aead.Open(dst, nonce[:], packet[SaltSize:], nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPacket, err)
	}
	return plaintext, nil
}
