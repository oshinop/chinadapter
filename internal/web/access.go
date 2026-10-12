package web

import (
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

func (a *API) accessStatus(w http.ResponseWriter, r *http.Request) {
	if a.backend == nil {
		a.backendUnavailable(w)
		return
	}
	status, err := a.backend.AccessStatus(r.Context())
	if err != nil {
		a.writeAccessError(w, err)
		return
	}
	response := struct {
		Initialized   bool       `json:"initialized"`
		Authenticated bool       `json:"authenticated"`
		ExpiresAt     *time.Time `json:"expiresAt,omitempty"`
	}{Initialized: status.Initialized}
	if _, session, authenticated := a.authenticate(r); authenticated {
		response.Authenticated = true
		expiresAt := session.expiresAt
		response.ExpiresAt = &expiresAt
	}
	a.writeJSON(w, http.StatusOK, response)
}

func (a *API) access(w http.ResponseWriter, r *http.Request, setup bool) {
	if a.backend == nil {
		a.backendUnavailable(w)
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := readJSONBody(w, r, accessTokenLimit, &body); err != nil {
		a.writeBodyError(w, err)
		return
	}
	body.Token = strings.TrimSpace(body.Token)
	client := clientIdentity(r.RemoteAddr)
	admission, retry := a.sessions.beginAccess(client)
	switch admission {
	case accessBusy:
		w.Header().Set("Retry-After", "1")
		a.writeProblem(w, http.StatusTooManyRequests, "access_in_progress", "Access request in progress")
		return
	case accessRateLimited:
		retryAfterHeader(w.Header(), retry)
		a.writeProblem(w, http.StatusTooManyRequests, "access_rate_limited", "Too Many Requests")
		return
	case accessAdmitted:
		// Admitted requests continue below.
	}
	successful, countedFailure := false, false
	defer func() { a.sessions.finishAccess(client, successful, countedFailure) }()
	if !validAccessToken(body.Token) {
		countedFailure = true
		a.writeProblem(w, http.StatusUnauthorized, "invalid_access_token", "Authentication required")
		return
	}
	a.accessMu.RLock()
	defer a.accessMu.RUnlock()
	var err error
	if setup {
		err = a.backend.AccessSetup(r.Context(), body.Token)
	} else {
		err = a.backend.AccessLogin(r.Context(), body.Token)
	}
	if err != nil {
		countedFailure = accessFailureCounts(err)
		a.writeAccessError(w, err)
		return
	}
	successful = true
	token, session, err := a.sessions.create(r.Context())
	if err != nil {
		a.writeProblem(w, http.StatusServiceUnavailable, "session_unavailable", "Session unavailable")
		return
	}
	status := http.StatusOK
	if setup {
		status = http.StatusCreated
	}
	setSessionCookie(w, token, session.expiresAt)
	a.writeJSON(w, status, struct {
		Initialized   bool      `json:"initialized"`
		Authenticated bool      `json:"authenticated"`
		ExpiresAt     time.Time `json:"expiresAt"`
	}{Initialized: true, Authenticated: true, ExpiresAt: session.expiresAt})
}

func (a *API) changeAccessToken(w http.ResponseWriter, r *http.Request, token string, session browserSession) {
	if a.backend == nil {
		a.backendUnavailable(w)
		return
	}
	var body struct {
		Current string `json:"current"`
		Next    string `json:"next"`
	}
	if err := readJSONBody(w, r, accessTokenLimit, &body); err != nil {
		a.writeBodyError(w, err)
		return
	}
	body.Current, body.Next = strings.TrimSpace(body.Current), strings.TrimSpace(body.Next)
	client := clientIdentity(r.RemoteAddr)
	admission, retry := a.sessions.beginAccess(client)
	switch admission {
	case accessBusy:
		w.Header().Set("Retry-After", "1")
		a.writeProblem(w, http.StatusTooManyRequests, "access_in_progress", "Access request in progress")
		return
	case accessRateLimited:
		retryAfterHeader(w.Header(), retry)
		a.writeProblem(w, http.StatusTooManyRequests, "access_rate_limited", "Too Many Requests")
		return
	case accessAdmitted:
	}
	successful, countedFailure := false, false
	defer func() { a.sessions.finishAccess(client, successful, countedFailure) }()
	if !validAccessToken(body.Current) {
		countedFailure = true
		a.writeProblem(w, http.StatusUnauthorized, "invalid_access_token", "Authentication required")
		return
	}
	// The write lock includes verifier rotation, revocation and the replacement
	// caller session; concurrent access logins cannot mint an old-token session.
	a.accessMu.Lock()
	defer a.accessMu.Unlock()
	if !a.sessions.matches(r.Context(), token, session) {
		a.writeProblem(w, http.StatusUnauthorized, "not_authenticated", "Authentication required")
		return
	}
	if err := a.backend.AccessChangeToken(r.Context(), body.Current, body.Next); err != nil {
		countedFailure = accessFailureCounts(err)
		a.writeAccessError(w, err)
		return
	}
	successful = true
	if err := a.sessions.revokeAll(r.Context()); err != nil {
		a.writeProblem(w, http.StatusServiceUnavailable, "session_unavailable", "Session unavailable")
		return
	}
	newToken, newSession, err := a.sessions.create(r.Context())
	if err != nil {
		a.writeProblem(w, http.StatusServiceUnavailable, "session_unavailable", "Session unavailable")
		return
	}
	setSessionCookie(w, newToken, newSession.expiresAt)
	a.writeJSON(w, http.StatusOK, struct {
		Initialized   bool      `json:"initialized"`
		Authenticated bool      `json:"authenticated"`
		ExpiresAt     time.Time `json:"expiresAt"`
	}{Initialized: true, Authenticated: true, ExpiresAt: newSession.expiresAt})
}

func (a *API) lock(w http.ResponseWriter, r *http.Request, token string) {
	if err := a.requireEmptyJSON(w, r); err != nil {
		a.writeBodyError(w, err)
		return
	}
	if err := a.revokeBrowserSession(r.Context(), token); err != nil {
		a.writeProblem(w, http.StatusServiceUnavailable, "session_unavailable", "Session unavailable")
		return
	}
	clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func validAccessToken(token string) bool {
	return utf8.ValidString(token) && len(token) >= 16 && len(token) <= 128
}
