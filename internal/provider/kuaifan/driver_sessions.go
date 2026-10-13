package kuaifan

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/oshinop/chinadapter/internal/provider"
	wireprofile "github.com/oshinop/chinadapter/internal/provider/kuaifan/profile"
)

func (driver *Driver) loginBoth(ctx context.Context, input EmailLogin) ([2]LoginSession, error) {
	return parallelSessions(ctx, driver.clients, false, func(child context.Context, client *Client) (LoginSession, error) {
		copyInput := input
		session, err := client.Login(child, copyInput)
		copyInput.Password = ""
		if err != nil {
			return LoginSession{}, err
		}
		if client.requiresPostLoginRefresh() {
			return client.RefreshSession(child, session)
		}
		return session, nil
	})
}

// The persisted state deliberately stores protocol-neutral login tokens. Legacy
// Windows WIFIIN sessions migrate in place on a successful beta refresh; until
// then the caller's complete prior generation remains unchanged.
type driverState struct {
	IOS     storedLoginSession `json:"ios"`
	Windows storedLoginSession `json:"windows"`
}

type storedLoginSession struct {
	UserID int32  `json:"userId"`
	Token  string `json:"token"`
}

// A rejected profile retains its prior token so a later refresh can retry it.
func updatedDriverState(current driverState, sessions [2]LoginSession) (driverState, bool) {
	refreshed := false
	for index, session := range sessions {
		if session.UserID <= 0 || session.Token == "" {
			continue
		}
		stored := storedLoginSession{UserID: session.UserID, Token: session.Token}
		if index == 0 {
			current.IOS = stored
		} else {
			current.Windows = stored
		}
		refreshed = true
	}
	return current, refreshed
}

func (driver *Driver) refreshBoth(ctx context.Context, current driverState) ([2]LoginSession, error) {
	return parallelSessions(ctx, driver.clients, true, func(child context.Context, client *Client) (LoginSession, error) {
		stored := current.IOS
		if client.Profile() == wireprofile.WindowsID {
			stored = current.Windows
		}
		if stored.UserID <= 0 || stored.Token == "" {
			return LoginSession{}, provider.ErrNoSession
		}
		configuration, err := retry(child, driver, func() (ClientConfig, error) { return client.FetchClientConfig(child) })
		if err != nil {
			return LoginSession{}, err
		}
		session := LoginSession{UserID: stored.UserID, Token: stored.Token, APIBase: configuration.APIBase}
		return retry(child, driver, func() (LoginSession, error) { return client.RefreshSession(child, session) })
	})
}

func parallelSessions(ctx context.Context, clients [2]*Client, tolerateRejection bool, call func(context.Context, *Client) (LoginSession, error)) ([2]LoginSession, error) {
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		index   int
		session LoginSession
		err     error
	}
	results := make(chan result, len(clients))
	for index, client := range clients {
		go func() {
			session, err := call(child, client)
			results <- result{index: index, session: session, err: err}
		}()
	}
	var sessions [2]LoginSession
	var firstErr, rejection error
	for range clients {
		result := <-results
		if result.err != nil {
			if tolerateRejection && errors.Is(result.err, provider.ErrSessionRejected) {
				rejection = result.err
			} else if firstErr == nil {
				firstErr = result.err
				cancel()
			}
			continue
		}
		sessions[result.index] = result.session
	}
	if firstErr != nil {
		if rejection != nil && sessions[0].UserID <= 0 && sessions[1].UserID <= 0 {
			return sessions, rejection
		}
		return sessions, firstErr
	}
	if rejection != nil {
		if sessions[0].UserID > 0 || sessions[1].UserID > 0 {
			return sessions, nil
		}
		return sessions, rejection
	}
	if sessions[0].UserID <= 0 || sessions[0].UserID != sessions[1].UserID {
		return [2]LoginSession{}, ErrSchema
	}
	return sessions, nil
}

func decodeDriverState(encoded []byte) (driverState, error) {
	var state driverState
	if len(encoded) == 0 || len(encoded) > 1<<20 || json.Unmarshal(encoded, &state) != nil ||
		state.IOS.UserID <= 0 || state.Windows.UserID != state.IOS.UserID || state.IOS.Token == "" || state.Windows.Token == "" {
		return driverState{}, ErrSchema
	}
	return state, nil
}
