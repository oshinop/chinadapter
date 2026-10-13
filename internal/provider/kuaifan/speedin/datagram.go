package speedin

import "fmt"

// DatagramCodec inserts provider authentication in every request, and consumes
// address+authentication from every reply. There is no UDP authentication ACK.
// Replies may carry a different auth identity; the native reader parses rather
// than compares it. The packet AEAD still authenticates all of these bytes.
type DatagramCodec struct {
	cipher *Cipher
	auth   []byte
}

func (c *Cipher) NewDatagramCodec(auth Auth) (*DatagramCodec, error) {
	if c == nil {
		return nil, ErrInvalidPassword
	}
	encoded, err := AppendAuth(nil, auth)
	if err != nil {
		return nil, err
	}
	return &DatagramCodec{cipher: c, auth: encoded}, nil
}

// EncodeSOCKS writes one SPEEDIN datagram into dst's reusable capacity. scratch
// holds reusable plaintext. Neither buffer may overlap the SOCKS input or each
// other. RSV must be zero and fragmented requests are rejected individually.
func (c *DatagramCodec) EncodeSOCKS(dst, scratch, packet []byte) ([]byte, error) {
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 {
		return nil, ErrInvalidPacket
	}
	if packet[2] != 0 {
		return nil, ErrFragmentedPacket
	}
	addressLen, err := addressSize(packet[3:])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPacket, err)
	}
	if len(packet)-3+len(c.auth) > MaxPacketSize-SaltSize-TagSize {
		return nil, ErrInvalidPacket
	}
	scratch = append(scratch[:0], packet[3:3+addressLen]...)
	scratch = append(scratch, c.auth...)
	scratch = append(scratch, packet[3+addressLen:]...)
	return c.cipher.EncodePacket(dst[:0], scratch)
}

// DecodeSOCKS decrypts into dst's reusable capacity and rewrites the plaintext
// into a SOCKS UDP reply. It consumes auth (not the TCP answer) and masks the
// first address byte with 0x0f, matching the recovered native receive path.
func (c *DatagramCodec) DecodeSOCKS(dst, packet []byte) ([]byte, error) {
	// Three leading bytes reserve the SOCKS RSV/FRAG header in the output.
	dst = append(dst[:0], 0, 0, 0)
	plaintext, err := c.cipher.DecodePacket(dst, packet)
	if err != nil {
		return nil, err
	}
	if len(plaintext) <= 3 {
		return nil, ErrInvalidPacket
	}
	plaintext[3] &= 0x0f
	addressLen, err := addressSize(plaintext[3:])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPacket, err)
	}
	authStart := 3 + addressLen
	_, _, _, authLen, err := authParts(plaintext[authStart:])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPacket, err)
	}
	payload := plaintext[authStart+authLen:]
	copy(plaintext[authStart:], payload)
	return plaintext[:authStart+len(payload)], nil
}
