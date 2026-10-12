package kuaifan

import (
	"context"
	"encoding/json"
)

// Authority is the independently validated authority response. No caller
// should serialize or log this value; it includes tunnel material by necessity.
type Authority struct {
	UserID            string
	OrderID           string
	EncryptKey        string
	EncryptType       string
	ProviderToken     string
	ProviderExtension string
}

// FetchAuthority obtains and decrypts authority using the login token. The
// returned provider token stays distinct from LoginSession.Token.
func (c *Client) FetchAuthority(ctx context.Context, session LoginSession) (Authority, error) {
	return c.profile.fetchAuthority(ctx, c, session)
}

type authorityKey struct {
	UserID      json.RawMessage `json:"userId"`
	EncryptKey  string          `json:"encryptKey"`
	EncryptType string          `json:"encryptType"`
	OrderID     string          `json:"orderId"`
}

func authorityKeyWithinLimit(key authorityKey) bool {
	_, err := parsePositiveInt32(key.UserID, true)
	return err == nil &&
		withinLimit(key.EncryptKey, maxControlFieldBytes) &&
		withinLimit(key.EncryptType, maxControlFieldBytes) &&
		withinLimit(key.OrderID, maxControlFieldBytes)
}
