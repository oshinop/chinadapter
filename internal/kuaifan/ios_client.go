package kuaifan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	wireprofile "github.com/kfadapter/kfadapter/internal/kuaifan/profile"
	"github.com/kfadapter/kfadapter/internal/kuaifan/wifiin"
)

type iosClientProfile struct{ wire wireprofile.IOS }

func (p iosClientProfile) id() wireprofile.ID             { return wireprofile.IOSID }
func (p iosClientProfile) userAgent() string              { return p.wire.UserAgent() }
func (p iosClientProfile) configFields() any              { return p.wire.ConfigFields() }
func (p iosClientProfile) requiresPostLoginRefresh() bool { return p.wire.RequiresPostLoginRefresh() }

func (p iosClientProfile) login(ctx context.Context, c *Client, base *url.URL, input EmailLogin) (LoginSession, error) {
	fields, err := p.wire.BuildLoginFields(wireprofile.LoginInput{
		Account: input.Account, Password: input.Password, InstallationID: input.InstallationID,
	}, c.timestamp(), c.random)
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
	token, err := requiredString(response.Fields, "token")
	if err != nil {
		return LoginSession{}, err
	}
	userID, err := requiredPositiveInt32(response.Fields, "userId")
	if err != nil {
		return LoginSession{}, err
	}
	return LoginSession{UserID: userID, Token: token, APIBase: cloneURL(base)}, nil
}

func (iosClientProfile) refresh(ctx context.Context, c *Client, session LoginSession) (LoginSession, error) {
	if err := c.validateSession(session); err != nil {
		return LoginSession{}, err
	}
	response, err := c.post(ctx, session.APIBase, "/v4/user/refresh.do", map[string]any{
		"userId": session.UserID,
		"token":  session.Token,
	})
	if err != nil {
		return LoginSession{}, err
	}
	if *response.Status != 1 {
		return LoginSession{}, authenticatedStatus(*response.Status)
	}
	updated, err := sessionFromFields(response.Fields, session.APIBase)
	if err != nil || updated.UserID != session.UserID {
		return LoginSession{}, ErrSchema
	}
	return updated, nil
}

func (iosClientProfile) fetchAuthority(ctx context.Context, c *Client, session LoginSession) (Authority, error) {
	if err := c.validateSession(session); err != nil {
		return Authority{}, err
	}
	response, err := c.post(ctx, session.APIBase, "/v4/invpn/getAuthority.do", map[string]any{
		"userId": session.UserID,
		"token":  session.Token,
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
	var decrypted authorityKey
	if err := c.authorityCodec.DecodeJSON([]byte(authKey), &decrypted); err != nil {
		return Authority{}, fmt.Errorf("control: decrypt authority: %w", err)
	}
	authorityUserID, err := parsePositiveInt32(decrypted.UserID, true)
	if err != nil || authorityUserID != session.UserID || decrypted.OrderID == "" || decrypted.EncryptKey == "" || !authorityKeyWithinLimit(decrypted) {
		return Authority{}, ErrSchema
	}
	method := strings.ToLower(decrypted.EncryptType)
	if method != "aes-256-cfb" {
		return Authority{}, ErrUnsupportedCipher
	}
	userIDText := formatUserID(authorityUserID)
	providerExtension, err := wifiin.ProviderExtensionForProfile(string(wireprofile.IOSID), providerToken, decrypted.OrderID, userIDText)
	if err != nil {
		return Authority{}, ErrSchema
	}
	return Authority{
		UserID: userIDText, OrderID: decrypted.OrderID, EncryptKey: decrypted.EncryptKey,
		EncryptType: method, ProviderToken: providerToken, ProviderExtension: providerExtension,
	}, nil
}

func (iosClientProfile) fetchLines(ctx context.Context, c *Client, session LoginSession) (Lines, error) {
	if err := c.validateSession(session); err != nil {
		return Lines{}, err
	}
	response, err := c.post(ctx, session.APIBase, "/v4/invpn/getLines.do", map[string]any{
		"userId": session.UserID, "token": session.Token, "time": c.timestamp(),
		"os": wireprofile.IOSOS, "clientVersion": wireprofile.IOSClientVersion, "edition": wireprofile.IOSEdition,
	})
	if err != nil {
		return Lines{}, err
	}
	if *response.Status != 1 {
		return Lines{}, authenticatedStatus(*response.Status)
	}
	return validateLinesForProfile(response.Fields, c.language, iosClientProfile{})
}

func (p iosClientProfile) validateLine(_ map[string]json.RawMessage, provider string) (bool, error) {
	eligible, err := p.wire.ValidateLine(provider, "")
	if err != nil {
		return false, ErrInvalidLine
	}
	return eligible, nil
}
