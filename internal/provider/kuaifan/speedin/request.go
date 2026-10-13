package speedin

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"strconv"
	"strings"
)

// Address uses the SOCKS address-family encoding, with a big-endian port last.
type Address struct {
	Host string
	Port uint16
}

// Auth is independent of the cipher password. Token and OS cannot contain a
// pipe because the upstream reader requires exactly three auth components.
type Auth struct {
	UserID uint64
	Token  string
	OS     string
}

func AppendAddress(dst []byte, address Address) ([]byte, error) {
	if address.Host == "" || address.Port == 0 {
		return nil, ErrInvalidAddress
	}
	if ip, err := netip.ParseAddr(address.Host); err == nil {
		if ip.Zone() != "" {
			return nil, ErrInvalidAddress
		}
		if ip.Is4() {
			octets := ip.As4()
			dst = append(dst, 1)
			dst = append(dst, octets[:]...)
		} else {
			octets := ip.As16()
			dst = append(dst, 4)
			dst = append(dst, octets[:]...)
		}
	} else {
		if len(address.Host) > 255 || strings.IndexByte(address.Host, 0) >= 0 {
			return nil, ErrInvalidAddress
		}
		dst = append(dst, 3, byte(len(address.Host)))
		dst = append(dst, address.Host...)
	}
	return binary.BigEndian.AppendUint16(dst, address.Port), nil
}

// addressSize validates an address without allocating a host string.
func addressSize(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, ErrInvalidAddress
	}
	var size int
	switch data[0] {
	case 1:
		size = 7
	case 4:
		size = 19
	case 3:
		if len(data) < 2 || data[1] == 0 {
			return 0, ErrInvalidAddress
		}
		size = 4 + int(data[1])
	default:
		return 0, ErrInvalidAddress
	}
	if len(data) < size || binary.BigEndian.Uint16(data[size-2:size]) == 0 {
		return 0, ErrInvalidAddress
	}
	if data[0] == 3 && bytes.IndexByte(data[2:size-2], 0) >= 0 {
		return 0, ErrInvalidAddress
	}
	return size, nil
}

// ParseAddress consumes one strict address header, leaving subsequent auth or
// application bytes untouched. Only UDP decoding masks the address high nibble.
func ParseAddress(data []byte) (Address, int, error) {
	size, err := addressSize(data)
	if err != nil {
		return Address{}, 0, err
	}
	address := Address{Port: binary.BigEndian.Uint16(data[size-2 : size])}
	switch data[0] {
	case 1:
		address.Host = netip.AddrFrom4([4]byte(data[1:5])).String()
	case 4:
		address.Host = netip.AddrFrom16([16]byte(data[1:17])).String()
	case 3:
		address.Host = string(data[2 : size-2])
	}
	return address, size, nil
}

func AppendAuth(dst []byte, auth Auth) ([]byte, error) {
	if auth.UserID == 0 || auth.Token == "" || auth.OS == "" || strings.ContainsAny(auth.Token, "|\x00") || strings.ContainsAny(auth.OS, "|\x00") {
		return nil, ErrInvalidAuth
	}
	var digits [20]byte
	userID := strconv.AppendUint(digits[:0], auth.UserID, 10)
	size := len(userID) + len(auth.Token) + len(auth.OS) + 2
	if size > 65535 {
		return nil, ErrInvalidAuth
	}
	dst = append(dst, 1)
	dst = binary.BigEndian.AppendUint16(dst, uint16(size))
	dst = append(dst, userID...)
	dst = append(dst, '|')
	dst = append(dst, auth.Token...)
	dst = append(dst, '|')
	return append(dst, auth.OS...), nil
}

// authParts validates the native version, bounded length, decimal identifier,
// and exactly three pipe-separated fields without allocating token strings.
func authParts(data []byte) (uint64, []byte, []byte, int, error) {
	if len(data) < 3 || data[0] != 1 {
		return 0, nil, nil, 0, ErrInvalidAuth
	}
	size := 3 + int(binary.BigEndian.Uint16(data[1:3]))
	if len(data) < size {
		return 0, nil, nil, 0, ErrInvalidAuth
	}
	body := data[3:size]
	first := bytes.IndexByte(body, '|')
	if first <= 0 {
		return 0, nil, nil, 0, ErrInvalidAuth
	}
	rest := body[first+1:]
	second := bytes.IndexByte(rest, '|')
	if second <= 0 || second == len(rest)-1 || bytes.ContainsAny(rest[second+1:], "|\x00") || bytes.IndexByte(rest[:second], 0) >= 0 {
		return 0, nil, nil, 0, ErrInvalidAuth
	}
	for _, digit := range body[:first] {
		if digit < '0' || digit > '9' {
			return 0, nil, nil, 0, ErrInvalidAuth
		}
	}
	userID, err := strconv.ParseUint(string(body[:first]), 10, 64)
	if err != nil || userID == 0 {
		return 0, nil, nil, 0, ErrInvalidAuth
	}
	return userID, rest[:second], rest[second+1:], size, nil
}

func ParseAuth(data []byte) (Auth, int, error) {
	userID, token, os, size, err := authParts(data)
	if err != nil {
		return Auth{}, 0, err
	}
	return Auth{UserID: userID, Token: string(token), OS: string(os)}, size, nil
}

// EncodeRequest builds the first TCP plaintext: address || provider auth.
func EncodeRequest(address Address, auth Auth) ([]byte, error) {
	request, err := AppendAddress(nil, address)
	if err != nil {
		return nil, err
	}
	request, err = AppendAuth(request, auth)
	if err != nil {
		return nil, err
	}
	// Destination and authentication must fit together in the first chunk.
	if len(request) > MaxChunkSize {
		return nil, ErrInvalidAuth
	}
	return request, nil
}
