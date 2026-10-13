package kuaifan

import (
	"encoding/json"
	"net"
	"strconv"

	"github.com/oshinop/chinadapter/internal/provider"
)

// SPEEDINProtocol is the Shadowsocks-AEAD-derived transport that KuaiFan's
// Windows 4.7.6 (INTERNATIONAL) catalog selects. See
// docs/kuaifan-speedin-hysteria2-analysis.md §2.
const SPEEDINProtocol provider.Protocol = "kuaifan-speedin"

const (
	speedinMethodAES128GCM = "aes-128-gcm"
	speedinOS              = "WINDOWS"
	maxSPEEDINPasswords    = maxLines
)

// speedinAuthority is the opaque provider.Authority data for every SPEEDIN
// node of one profile. The cipher password is per catalog line, so it is
// keyed by the node's net.JoinHostPort(Host, Port) exactly as emitted in the
// snapshot. The account ID comes from the decrypted authority and the token is
// the current login session token (not the authority response token).
type speedinAuthority struct {
	UserID    uint64            `json:"userId"`
	Token     string            `json:"token"`
	OS        string            `json:"os"`
	Method    string            `json:"method"`
	Passwords map[string]string `json:"passwords"`
}

func speedinNodeKey(host string, port uint16) string {
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}

func (authority speedinAuthority) valid() bool {
	if authority.UserID == 0 || authority.Token == "" || len(authority.Token) > maxControlFieldBytes ||
		authority.OS != speedinOS || authority.Method != speedinMethodAES128GCM ||
		len(authority.Passwords) == 0 || len(authority.Passwords) > maxSPEEDINPasswords {
		return false
	}
	for key, password := range authority.Passwords {
		if key == "" || password == "" || len(password) > maxControlFieldBytes {
			return false
		}
	}
	return true
}

func encodeSPEEDINAuthority(authority speedinAuthority) (provider.Authority, error) {
	if !authority.valid() {
		return provider.Authority{}, ErrInvalidAuthority
	}
	data, err := json.Marshal(authority)
	if err != nil {
		return provider.Authority{}, ErrInvalidAuthority
	}
	return provider.Authority{Protocol: SPEEDINProtocol, Data: data}, nil
}

func decodeSPEEDINAuthority(data []byte) (speedinAuthority, error) {
	var authority speedinAuthority
	if len(data) == 0 || len(data) > 1<<20 || json.Unmarshal(data, &authority) != nil || !authority.valid() {
		return speedinAuthority{}, ErrInvalidAuthority
	}
	return authority, nil
}
