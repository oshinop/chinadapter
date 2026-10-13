package kuaifan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	wireprofile "github.com/oshinop/chinadapter/internal/provider/kuaifan/profile"
)

type windowsClientProfile struct{ wire wireprofile.Windows }

func (p windowsClientProfile) id() wireprofile.ID { return wireprofile.WindowsID }
func (p windowsClientProfile) userAgent() string  { return p.wire.UserAgent() }
func (p windowsClientProfile) configFields() any  { return p.wire.ConfigFields() }
func (p windowsClientProfile) requiresPostLoginRefresh() bool {
	return p.wire.RequiresPostLoginRefresh()
}

func (p windowsClientProfile) login(ctx context.Context, c *Client, base *url.URL, input EmailLogin) (LoginSession, error) {
	fields, err := p.wire.BuildLoginFields(wireprofile.LoginInput{
		Account: input.Account, Password: input.Password, InstallationID: input.InstallationID,
	}, c.timestamp(), c.language, c.random)
	if err != nil {
		return LoginSession{}, err
	}
	response, err := c.post(ctx, base, "/v4/user/login.do", fields)
	fields.ClearPassword()
	if err != nil {
		return LoginSession{}, err
	}
	if *response.Status != 1 && *response.Status != 119 {
		return LoginSession{}, fmt.Errorf("%w: %d", ErrLoginRejected, *response.Status)
	}
	return sessionFromFields(response.Fields, base)
}

func (windowsClientProfile) refresh(ctx context.Context, c *Client, session LoginSession) (LoginSession, error) {
	if err := c.validateSession(session); err != nil {
		return LoginSession{}, err
	}
	response, err := c.post(ctx, session.APIBase, "/v4/user/refresh.do", map[string]any{
		"userId": session.UserID, "token": session.Token,
	})
	if err != nil {
		return LoginSession{}, err
	}
	if *response.Status != 1 && *response.Status != 119 {
		return LoginSession{}, authenticatedStatus(*response.Status)
	}
	updated, err := sessionFromFields(response.Fields, session.APIBase)
	if err != nil || updated.UserID != session.UserID {
		return LoginSession{}, ErrSchema
	}
	return updated, nil
}

func (windowsClientProfile) fetchAuthority(ctx context.Context, c *Client, session LoginSession) (Authority, error) {
	if err := c.validateSession(session); err != nil {
		return Authority{}, err
	}
	response, err := c.post(ctx, session.APIBase, "/v4/invpn/getAuthority.do", map[string]any{
		"userId": session.UserID, "token": session.Token,
	})
	if err != nil {
		return Authority{}, err
	}
	if *response.Status != 1 {
		return Authority{}, authenticatedStatus(*response.Status)
	}
	authKey, err := requiredStringLimit(response.Fields, "authKey", maxAuthorityAuthKeyBytes)
	if err != nil {
		return Authority{}, err
	}
	providerToken, err := requiredString(response.Fields, "token")
	if err != nil {
		return Authority{}, err
	}
	var decrypted struct {
		UserID json.RawMessage `json:"userId"`
	}
	if err := c.authorityCodec.DecodeJSON([]byte(authKey), &decrypted); err != nil {
		return Authority{}, fmt.Errorf("control: decrypt authority: %w", err)
	}
	userID, err := parsePositiveInt32(decrypted.UserID, true)
	if err != nil || userID != session.UserID {
		return Authority{}, ErrSchema
	}
	return Authority{UserID: formatUserID(userID), ProviderToken: providerToken}, nil
}

func (windowsClientProfile) fetchLines(ctx context.Context, c *Client, session LoginSession) (Lines, error) {
	if err := c.validateSession(session); err != nil {
		return Lines{}, err
	}
	response, err := c.post(ctx, session.APIBase, "/v4/invpn/getLines.do", map[string]any{
		"userId": session.UserID, "token": session.Token, "os": wireprofile.WindowsOS,
		"time": c.timestamp(), "clientVersion": wireprofile.WindowsClientVersion,
		"edition": wireprofile.WindowsEdition,
	})
	if err != nil {
		return Lines{}, err
	}
	if *response.Status != 1 {
		return Lines{}, authenticatedStatus(*response.Status)
	}
	return validateLinesForProfile(response.Fields, c.language, windowsClientProfile{})
}

func (p windowsClientProfile) validateLine(object map[string]json.RawMessage, provider string) (bool, error) {
	// Other providers and supported rows with a different cipher stay metadata
	// only. A SPEEDIN row must name its cipher; an eligible row also needs its
	// own bounded, nonempty password. Never substitute WIFIIN authority keys.
	if provider != "SPEEDIN" {
		return false, nil
	}
	method, err := requiredString(object, "method")
	if err != nil {
		return false, ErrInvalidLine
	}
	if method != wireprofile.WindowsTunnelMethod {
		return false, nil
	}
	password, err := requiredString(object, "password")
	if err != nil {
		return false, ErrInvalidLine
	}
	eligible, err := p.wire.ValidateLine(provider, password)
	if err != nil {
		return false, ErrInvalidLine
	}
	return eligible, nil
}
