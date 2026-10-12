package web

import (
	"encoding/json"
	"errors"
	"net/http"
)

type publicProblemError interface {
	error
	Code() string
	HTTPStatus() int
}

func (a *API) writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (a *API) writeProblem(w http.ResponseWriter, status int, code, title string) {
	w.Header().Set("Content-Type", "application/problem+json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Type   string `json:"type"`
		Code   string `json:"code"`
		Status int    `json:"status"`
		Title  string `json:"title"`
	}{Type: "urn:kfadapter:problem:" + code, Code: code, Status: status, Title: title})
}

func (a *API) writeBodyError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errContentType):
		a.writeProblem(w, http.StatusUnsupportedMediaType, "invalid_content_type", "Unsupported Content Type")
	case errors.Is(err, errBodyTooLarge):
		a.writeProblem(w, http.StatusRequestEntityTooLarge, "body_too_large", "Request body too large")
	default:
		a.writeProblem(w, http.StatusBadRequest, "invalid_json", "Invalid JSON")
	}
}

func (a *API) writeBackendError(w http.ResponseWriter, err error, fallback string, status int) {
	var public publicProblemError
	if errors.As(err, &public) {
		code := public.Code()
		if code == "" {
			code = fallback
		}
		publicStatus := public.HTTPStatus()
		if publicStatus >= 400 && publicStatus <= 599 {
			status = publicStatus
		}
		a.writeProblem(w, status, code, problemTitle(status))
		return
	}
	a.writeProblem(w, status, fallback, problemTitle(status))
}

func (a *API) writeAccessError(w http.ResponseWriter, err error) {
	var public publicProblemError
	if errors.As(err, &public) {
		switch public.HTTPStatus() {
		case http.StatusConflict:
			a.writeProblem(w, http.StatusConflict, "access_initialized", "Conflict")
			return
		case http.StatusBadRequest:
			a.writeProblem(w, http.StatusBadRequest, "invalid_next_access_token", "Invalid next access token")
			return
		case http.StatusUnauthorized:
			a.writeProblem(w, http.StatusUnauthorized, "invalid_access_token", "Authentication required")
			return
		}
	}
	a.writeProblem(w, http.StatusServiceUnavailable, "access_unavailable", "Service unavailable")
}

func (a *API) backendUnavailable(w http.ResponseWriter) {
	a.writeProblem(w, http.StatusServiceUnavailable, "service_unavailable", "Service unavailable")
}

func problemTitle(status int) string {
	return http.StatusText(status)
}

func writeEmptyNotFound(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", "0")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusNotFound)
}
