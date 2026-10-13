package web

import (
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

func (a *API) login(w http.ResponseWriter, r *http.Request, token string) {
	if a.backend == nil {
		a.backendUnavailable(w)
		return
	}
	var body struct {
		Provider string            `json:"provider"`
		Fields   map[string]string `json:"fields"`
	}
	if err := readJSONBody(w, r, a.config.JSONBodyLimit, &body); err != nil {
		a.writeBodyError(w, err)
		return
	}
	// Only the shape is checked here; which fields are required belongs to the
	// provider's AuthSpec and is enforced by the runtime.
	if !validProviderID(body.Provider) || !validCredentialFields(body.Fields) {
		a.writeProblem(w, http.StatusBadRequest, "invalid_login", "Invalid login")
		return
	}
	admission, retry := a.sessions.beginLogin(r.Context(), token)
	switch admission {
	case loginBusy:
		w.Header().Set("Retry-After", "1")
		a.writeProblem(w, http.StatusTooManyRequests, "login_in_progress", "Login already in progress")
		return
	case loginRateLimited:
		retryAfterHeader(w.Header(), retry)
		a.writeProblem(w, http.StatusTooManyRequests, "login_rate_limited", "Too Many Requests")
		return
	case loginSessionInactive:
		a.writeProblem(w, http.StatusUnauthorized, "not_authenticated", "Authentication required")
		return
	case loginAdmitted:
		// Admitted requests continue below.
	}
	ctx := r.Context()
	successful, countedFailure := false, false
	defer func() { a.sessions.finishLogin(ctx, token, successful, countedFailure) }()
	if !a.extendProviderWriteDeadline(w) {
		return
	}
	account, err := a.backend.Login(ctx, LoginInput{Provider: body.Provider, Fields: body.Fields})
	clear(body.Fields)
	if err != nil {
		countedFailure = loginFailureCounts(err)
		a.writeBackendError(w, err, "login_failed", http.StatusUnauthorized)
		return
	}
	successful = true
	a.writeJSON(w, http.StatusOK, redactAccount(&account))
}

func (a *API) accountLogout(w http.ResponseWriter, r *http.Request) {
	if a.backend == nil {
		a.backendUnavailable(w)
		return
	}
	var body struct {
		Provider string `json:"provider"`
	}
	if err := readJSONBody(w, r, a.config.JSONBodyLimit, &body); err != nil {
		a.writeBodyError(w, err)
		return
	}
	if !validProviderID(body.Provider) {
		a.writeProblem(w, http.StatusBadRequest, "invalid_provider", "Invalid provider")
		return
	}
	if err := a.backend.Logout(r.Context(), body.Provider); err != nil {
		a.writeBackendError(w, err, "logout_failed", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) refresh(w http.ResponseWriter, r *http.Request) {
	if a.backend == nil {
		a.backendUnavailable(w)
		return
	}
	var body struct {
		Provider string `json:"provider"`
	}
	if err := readJSONBody(w, r, a.config.JSONBodyLimit, &body); err != nil {
		a.writeBodyError(w, err)
		return
	}
	if body.Provider != "" && !validProviderID(body.Provider) {
		a.writeProblem(w, http.StatusBadRequest, "invalid_provider", "Invalid provider")
		return
	}
	if !a.extendProviderWriteDeadline(w) {
		return
	}
	if err := a.backend.Refresh(r.Context(), body.Provider); err != nil {
		a.writeBackendError(w, err, "refresh_failed", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// Kuaifan refresh has three sequential request stages, each with three attempts;
// profiles and linked providers run concurrently. Login fits within this bound.
func (a *API) extendProviderWriteDeadline(w http.ResponseWriter) bool {
	timeout := a.config.ProviderRequestTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	budget := 9*timeout + 10*time.Second
	if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(budget)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		a.backendUnavailable(w)
		return false
	}
	return true
}

func validProviderID(value string) bool {
	if len(value) == 0 || len(value) > 32 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}

const maxCredentialFields = 16

// validCredentialFields bounds the submitted field map: identifier keys and
// bounded UTF-8 values without NUL. Empty maps are valid for public providers.
func validCredentialFields(fields map[string]string) bool {
	if len(fields) > maxCredentialFields {
		return false
	}
	for key, value := range fields {
		if !validProviderID(key) || len(value) > 4096 || !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0 {
			return false
		}
	}
	return true
}
