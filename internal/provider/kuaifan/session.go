package kuaifan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/oshinop/chinadapter/internal/provider"
)

// AccountProfile is the account metadata validated by user/refresh.do.
type AccountProfile struct {
	IsVIP     bool
	VIPEndsAt time.Time
}

func sessionFromFields(fields map[string]json.RawMessage, base *url.URL) (LoginSession, error) {
	token, err := requiredString(fields, "token")
	if err != nil {
		return LoginSession{}, err
	}
	userID, err := requiredPositiveInt32(fields, "userId")
	if err != nil {
		return LoginSession{}, err
	}
	isVIP, err := requiredBool(fields, "isVip")
	if err != nil {
		return LoginSession{}, err
	}
	vipEndsAt, err := requiredUnixMilli(fields, "vipEndTime")
	if err != nil || isVIP && vipEndsAt.IsZero() {
		return LoginSession{}, ErrSchema
	}
	return LoginSession{
		UserID: userID, Token: token, APIBase: cloneURL(base),
		Profile: AccountProfile{IsVIP: isVIP, VIPEndsAt: vipEndsAt},
	}, nil
}

// LoginSession is profile-bound credential material. The iOS profile requires
// a post-login refresh; the Windows beta consumes its complete login profile.
type LoginSession struct {
	UserID  int32
	Token   string
	APIBase *url.URL
	Profile AccountProfile
}

// Login performs configuration selection and then the email/password login.
// A rejected login is returned as ErrLoginRejected and is never retried here.
func (c *Client) Login(ctx context.Context, input EmailLogin) (LoginSession, error) {
	configuration, err := c.FetchClientConfig(ctx)
	if err != nil {
		return LoginSession{}, err
	}
	return c.loginAt(ctx, configuration.APIBase, input)
}

func (c *Client) loginAt(ctx context.Context, base *url.URL, input EmailLogin) (LoginSession, error) {
	return c.profile.login(ctx, c, base, input)
}

// RefreshSession validates the login token against user/refresh.do, accepts a
// rotated token, and captures the authoritative VIP profile. The response must
// remain bound to the same user before any authority or line request is sent.
func (c *Client) RefreshSession(ctx context.Context, session LoginSession) (LoginSession, error) {
	return c.profile.refresh(ctx, c, session)
}

func (c *Client) validateSession(session LoginSession) error {
	if session.UserID <= 0 || session.Token == "" || session.APIBase == nil || !withinLimit(session.Token, maxControlFieldBytes) {
		return ErrSchema
	}
	_, err := parseApprovedBase(session.APIBase.String(), c.allowedHosts)
	return err
}

func businessStatus(status int) error { return fmt.Errorf("%w: %d", ErrBusinessStatus, status) }

// sessionRejectedStatus is the business status KuaiFan returns on
// authenticated endpoints for a token it no longer accepts. Observed live in
// 2026-10 on refresh.do and getAuthority.do for both profiles.
const sessionRejectedStatus = -5

// authenticatedStatus classifies a non-success status from an endpoint that
// carries the login token. Only the observed rejection status ends the
// session; every other status stays transient.
func authenticatedStatus(status int) error {
	if status == sessionRejectedStatus {
		return fmt.Errorf("%w: %w: %d", provider.ErrSessionRejected, ErrBusinessStatus, status)
	}
	return businessStatus(status)
}
