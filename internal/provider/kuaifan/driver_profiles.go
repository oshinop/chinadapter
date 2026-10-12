package kuaifan

import (
	"context"
	"errors"

	"github.com/oshinop/chinadapter/internal/provider"
)

type completeProfile struct {
	client    *Client
	session   LoginSession
	authority Authority
	lines     Lines
}

func (driver *Driver) fetchBothProfiles(ctx context.Context, sessions [2]LoginSession, retryRequests bool) ([2]completeProfile, error) {
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		index   int
		profile completeProfile
		err     error
	}
	results := make(chan result, len(driver.clients))
	for index, client := range driver.clients {
		go func() {
			if sessions[index].UserID <= 0 {
				results <- result{index: index}
				return
			}
			authority, lines, err := driver.fetchAuthorityAndLines(child, client, sessions[index], retryRequests)
			results <- result{index: index, profile: completeProfile{client: client, session: sessions[index], authority: authority, lines: lines}, err: err}
		}()
	}
	var profiles [2]completeProfile
	var firstErr, rejection error
	for range driver.clients {
		result := <-results
		if result.err != nil {
			if retryRequests && errors.Is(result.err, provider.ErrSessionRejected) {
				rejection = result.err
			} else if firstErr == nil {
				firstErr = result.err
				cancel()
			}
			continue
		}
		profiles[result.index] = result.profile
	}
	if firstErr != nil {
		if rejection != nil && profiles[0].client == nil && profiles[1].client == nil {
			return profiles, rejection
		}
		return profiles, firstErr
	}
	if profiles[0].client == nil && profiles[1].client == nil {
		return profiles, rejection
	}
	return profiles, nil
}

func (driver *Driver) fetchAuthorityAndLines(ctx context.Context, client *Client, session LoginSession, retryRequests bool) (Authority, Lines, error) {
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		authority *Authority
		lines     *Lines
		err       error
	}
	results := make(chan result, 2)
	go func() {
		var authority Authority
		var err error
		if retryRequests {
			authority, err = retry(child, driver, func() (Authority, error) { return client.FetchAuthority(child, session) })
		} else {
			authority, err = client.FetchAuthority(child, session)
		}
		if err != nil {
			results <- result{err: err}
			return
		}
		results <- result{authority: &authority}
	}()
	go func() {
		var lines Lines
		var err error
		if retryRequests {
			lines, err = retry(child, driver, func() (Lines, error) { return client.FetchLines(child, session) })
		} else {
			lines, err = client.FetchLines(child, session)
		}
		if err != nil {
			results <- result{err: err}
			return
		}
		results <- result{lines: &lines}
	}()
	var authority Authority
	var lines Lines
	var firstErr error
	for range 2 {
		result := <-results
		if result.err != nil && firstErr == nil {
			firstErr = result.err
			cancel()
		}
		if result.authority != nil {
			authority = *result.authority
		}
		if result.lines != nil {
			lines = *result.lines
		}
	}
	if firstErr != nil {
		return Authority{}, Lines{}, firstErr
	}
	if authority.ProviderToken == "" || session.Token == "" || len(lines.Lines) == 0 {
		return Authority{}, Lines{}, ErrSchema
	}
	return authority, lines, nil
}
