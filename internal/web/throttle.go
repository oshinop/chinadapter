package web

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"
)

type accessAttempt struct {
	failures  int
	windowEnd time.Time
	blockedTo time.Time
	inFlight  bool
	createdAt time.Time
}

type accessAdmission uint8

const (
	accessAdmitted accessAdmission = iota
	accessBusy
	accessRateLimited
)

// loginAttempt is keyed exclusively by the opaque browser session token. It
// never stores an account identifier, password, or backend error detail.
type loginAttempt struct {
	failures  int
	windowEnd time.Time
	inFlight  bool
}

type loginAdmission uint8

const (
	loginAdmitted loginAdmission = iota
	loginBusy
	loginRateLimited
	loginSessionInactive
)

// beginAccess reserves the one verifier operation in flight for a source.
// Concurrent attempts are rejected before they reach the backend.
func (s *sessionStore) beginAccess(client string) (accessAdmission, time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.trimAccessAttemptsLocked()
	now := s.now()
	attempt, tracked := s.accessAttempts[client]
	if !tracked && len(s.accessAttempts) >= 1024 && !s.evictAccessAttemptLocked(now) {
		return accessRateLimited, time.Second
	}
	if attempt.inFlight {
		return accessBusy, 0
	}
	if now.Before(attempt.blockedTo) {
		return accessRateLimited, attempt.blockedTo.Sub(now)
	}
	if !attempt.windowEnd.IsZero() && !now.Before(attempt.windowEnd) {
		attempt = accessAttempt{}
	}
	if !tracked || attempt.createdAt.IsZero() {
		attempt.createdAt = now
	}
	attempt.inFlight = true
	s.accessAttempts[client] = attempt
	return accessAdmitted, 0
}

// finishAccess releases a reservation and records only failed verification.
func (s *sessionStore) finishAccess(client string, successful, countedFailure bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	attempt, reserved := s.accessAttempts[client]
	if !reserved || !attempt.inFlight {
		return
	}
	attempt.inFlight = false
	if successful {
		delete(s.accessAttempts, client)
		return
	}
	if !countedFailure {
		s.accessAttempts[client] = attempt
		return
	}
	now := s.now()
	if attempt.windowEnd.IsZero() || !now.Before(attempt.windowEnd) {
		attempt.failures = 0
		attempt.windowEnd = now.Add(time.Minute)
	}
	attempt.failures++
	if attempt.failures >= 5 {
		attempt.failures = 0
		attempt.windowEnd = now.Add(time.Minute)
		attempt.blockedTo = now.Add(time.Minute)
	}
	s.accessAttempts[client] = attempt
	s.trimAccessAttemptsLocked()
}

// beginLogin atomically checks the per-session failure window and reserves the
// only backend login slot for that browser session. Concurrent attempts never
// reach the backend and do not count as credential failures.
func (s *sessionStore) beginLogin(ctx context.Context, token string) (loginAdmission, time.Duration) {
	token = sessionKey(token)
	s.mu.Lock()
	expired := s.pruneLocked()
	if _, active := s.sessions[token]; !active {
		s.mu.Unlock()
		s.deleteBrowserSessions(ctx, expired)
		return loginSessionInactive, 0
	}
	now := s.now()
	attempt := s.loginAttempts[token]
	if attempt.inFlight {
		s.mu.Unlock()
		s.deleteBrowserSessions(ctx, expired)
		return loginBusy, 0
	}
	if !attempt.windowEnd.IsZero() && !now.Before(attempt.windowEnd) {
		attempt = loginAttempt{}
	}
	if attempt.failures >= 5 {
		s.mu.Unlock()
		s.deleteBrowserSessions(ctx, expired)
		return loginRateLimited, attempt.windowEnd.Sub(now)
	}
	attempt.inFlight = true
	s.loginAttempts[token] = attempt
	s.mu.Unlock()
	s.deleteBrowserSessions(ctx, expired)
	return loginAdmitted, 0
}

// finishLogin releases a prior login reservation exactly once. It never
// recreates login state for a session that logout or expiry removed in flight.
func (s *sessionStore) finishLogin(ctx context.Context, token string, successful, countedFailure bool) {
	token = sessionKey(token)
	s.mu.Lock()
	session, active := s.sessions[token]
	if !active {
		delete(s.loginAttempts, token)
		s.mu.Unlock()
		return
	}
	if !s.now().Before(session.expiresAt) {
		s.removeSessionLocked(token)
		s.mu.Unlock()
		s.deleteBrowserSessions(ctx, []string{token})
		return
	}
	attempt, reserved := s.loginAttempts[token]
	if !reserved || !attempt.inFlight {
		s.mu.Unlock()
		return
	}
	if successful {
		delete(s.loginAttempts, token)
		s.mu.Unlock()
		return
	}
	now := s.now()
	if !attempt.windowEnd.IsZero() && !now.Before(attempt.windowEnd) {
		attempt.failures = 0
		attempt.windowEnd = time.Time{}
	}
	attempt.inFlight = false
	if countedFailure {
		if attempt.windowEnd.IsZero() {
			attempt.windowEnd = now.Add(time.Minute)
		}
		if attempt.failures < 5 {
			attempt.failures++
		}
	}
	if attempt.failures == 0 {
		delete(s.loginAttempts, token)
		s.mu.Unlock()
		return
	}
	s.loginAttempts[token] = attempt
	s.mu.Unlock()
}

func (s *sessionStore) trimAccessAttemptsLocked() {
	now := s.now()
	for client, attempt := range s.accessAttempts {
		if !attempt.inFlight && !now.Before(attempt.windowEnd) && !now.Before(attempt.blockedTo) {
			delete(s.accessAttempts, client)
		}
	}
}

// Evict the oldest idle, unblocked source; never erase an active verifier or a
// penalty window to admit a new client.
func (s *sessionStore) evictAccessAttemptLocked(now time.Time) bool {
	var oldest string
	var createdAt time.Time
	for client, attempt := range s.accessAttempts {
		if attempt.inFlight || now.Before(attempt.blockedTo) {
			continue
		}
		if oldest == "" || attempt.createdAt.Before(createdAt) {
			oldest, createdAt = client, attempt.createdAt
		}
	}
	if oldest == "" {
		return false
	}
	delete(s.accessAttempts, oldest)
	return true
}

func (s *sessionStore) trimLoginAttemptsLocked() {
	now := s.now()
	for token, attempt := range s.loginAttempts {
		if !attempt.inFlight && !now.Before(attempt.windowEnd) {
			delete(s.loginAttempts, token)
		}
	}
	for len(s.loginAttempts) > s.max {
		removed := false
		for token, attempt := range s.loginAttempts {
			if attempt.inFlight {
				continue
			}
			delete(s.loginAttempts, token)
			removed = true
			break
		}
		if !removed {
			return
		}
	}
}

func accessFailureCounts(err error) bool {
	var public publicProblemError
	return errors.As(err, &public) && public.HTTPStatus() == http.StatusUnauthorized
}

func loginFailureCounts(err error) bool {
	var public publicProblemError
	return !errors.As(err, &public) || public.Code() == "login_rejected"
}

func clientIdentity(remoteAddress string) string {
	host, _, err := net.SplitHostPort(remoteAddress)
	if err != nil {
		host = remoteAddress
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if ip.IsLoopback() {
			return "loopback"
		}
		if ip.Is6() {
			return netip.PrefixFrom(ip.WithZone(""), 64).Masked().String()
		}
		return ip.String()
	}
	if host == "" {
		return "unknown"
	}
	return host
}

func retryAfterHeader(header http.Header, delay time.Duration) {
	seconds := int(delay.Round(time.Second).Seconds())
	if seconds < 1 {
		seconds = 1
	}
	header.Set("Retry-After", strconv.Itoa(seconds))
}
