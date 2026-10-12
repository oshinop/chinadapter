// Package credentials derives installation-scoped subscription and SOCKS credentials.
package credentials

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/oshinop/chinadapter/internal/provider"
)

var ErrInvalidKey = errors.New("invalid installation identity key")

// Identity is immutable and safe to share between goroutines. An uninitialized
// installation has an Identity but no usable subscription or SOCKS authority.
type Identity struct {
	key            [sha256.Size]byte
	initialized    bool
	subscriptionID string
	password       string
}

func New(derivedHash []byte, installationID string) (*Identity, error) {
	raw, err := hex.DecodeString(installationID)
	if err != nil || len(raw) != 16 || hex.EncodeToString(raw) != installationID {
		return nil, ErrInvalidKey
	}
	result := &Identity{}
	if len(derivedHash) == 0 {
		return result, nil
	}
	if len(derivedHash) != sha256.Size {
		return nil, ErrInvalidKey
	}
	result.key = mac(derivedHash, "chinadapter/instance/v3\x00"+installationID)
	result.initialized = true
	result.subscriptionID = uuid(mac(result.key[:], "chinadapter/subscription/v3"))
	result.password = uuid(mac(result.key[:], "chinadapter/socks-password/v3"))
	return result, nil
}

func (identity *Identity) SubscriptionID() string {
	if identity == nil {
		return ""
	}
	return identity.subscriptionID
}
func (identity *Identity) Password() string {
	if identity == nil {
		return ""
	}
	return identity.password
}

type Credentials struct{ Username, Password string }

func (identity *Identity) Credentials(route provider.Route) (Credentials, bool) {
	if identity == nil || !identity.initialized {
		return Credentials{}, false
	}
	key, err := provider.NodeKey(route)
	if err != nil {
		return Credentials{}, false
	}
	digest := mac(identity.key[:], "chinadapter/socks-user/v3\x00"+key)
	return Credentials{Username: "n_" + base64.RawURLEncoding.EncodeToString(digest[:12]), Password: identity.password}, true
}

func (identity *Identity) AuthenticatePassword(password string) bool {
	return identity != nil && identity.initialized && subtle.ConstantTimeCompare([]byte(password), []byte(identity.password)) == 1
}

func (identity *Identity) MatchesSubscriptionID(id string) bool {
	return identity != nil && identity.initialized && subtle.ConstantTimeCompare([]byte(id), []byte(identity.subscriptionID)) == 1
}

// ParseSubscriptionPath accepts only /sub/<lowercase canonical UUIDv8>, with
// the RFC 9562 variant bits. It deliberately rejects escaped aliases.
func ParseSubscriptionPath(path string) (string, bool) {
	if len(path) != 41 || !strings.HasPrefix(path, "/sub/") {
		return "", false
	}
	id := path[5:]
	if !ValidUUID(id) {
		return "", false
	}
	return id, true
}
func ValidUUID(id string) bool {
	if len(id) != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' || id[14] != '8' {
		return false
	}
	raw := strings.ReplaceAll(id, "-", "")
	decoded, err := hex.DecodeString(raw)
	return err == nil && len(decoded) == 16 && decoded[8]>>6 == 2 && hex.EncodeToString(decoded) == raw
}
func uuid(digest [sha256.Size]byte) string {
	digest[6] = digest[6]&0x0f | 0x80
	digest[8] = digest[8]&0x3f | 0x80
	encoded := hex.EncodeToString(digest[:16])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}
func mac(key []byte, message string) [sha256.Size]byte {
	hash := hmac.New(sha256.New, key)
	_, _ = hash.Write([]byte(message))
	var digest [sha256.Size]byte
	hash.Sum(digest[:0])
	return digest
}
