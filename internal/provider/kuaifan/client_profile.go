package kuaifan

import (
	"context"
	"encoding/json"
	"net/url"

	wireprofile "github.com/kfadapter/kfadapter/internal/provider/kuaifan/profile"
)

// EmailLogin is transient account input. InstallationID is protected random
// application state and is never sourced from host hardware.
type EmailLogin struct {
	Account        string
	Password       string
	InstallationID string
}

type providerProfile interface {
	id() wireprofile.ID
	userAgent() string
	configFields() any
	requiresPostLoginRefresh() bool
	login(context.Context, *Client, *url.URL, EmailLogin) (LoginSession, error)
	refresh(context.Context, *Client, LoginSession) (LoginSession, error)
	fetchAuthority(context.Context, *Client, LoginSession) (Authority, error)
	fetchLines(context.Context, *Client, LoginSession) (Lines, error)
	validateLine(map[string]json.RawMessage, string) (bool, error)
}

// Profile returns the immutable control profile used by this client.
func (c *Client) Profile() wireprofile.ID {
	if c == nil || c.profile == nil {
		return ""
	}
	return c.profile.id()
}

func (c *Client) requiresPostLoginRefresh() bool {
	return c != nil && c.profile != nil && c.profile.requiresPostLoginRefresh()
}
