package app

import (
	"context"
	"errors"
	"net/http"

	"github.com/kfadapter/kfadapter/internal/provider"
	"github.com/kfadapter/kfadapter/internal/state"
)

var errRuntimeStopped = errors.New("app: runtime stopped")

// ErrProbeBusy means all bounded direct-probe slots are in use.
var ErrProbeBusy = errors.New("app: probe capacity reached")

// ErrStaleProbe means the pinned probe target changed before publication.
var ErrStaleProbe = errors.New("app: stale probe")

// problemError exposes only a stable browser-safe classification. The cause
// remains available to Go callers, but its text must never cross the boundary.
type problemError struct {
	cause  error
	code   string
	status int
}

func (e *problemError) Error() string {
	switch e.code {
	case "access_initialized":
		return "access token already initialized"
	case "access_invalid":
		return "access token rejected"
	case "access_next_invalid":
		return "next access token rejected"
	case "access_unavailable":
		return "access unavailable"
	case "login_rejected":
		return "login rejected"
	case "account_exists":
		return "provider account already exists"
	case "operation_in_progress":
		return "login operation in progress"
	case "login_unavailable":
		return "login unavailable"
	case "stale_probe":
		return "probe result is stale"
	case "probe_busy":
		return "probe capacity reached"
	case "node_not_found":
		return "node not found"
	case "node_ineligible":
		return "node is not eligible"
	case "node_snapshot_unavailable":
		return "node snapshot unavailable"
	case "tcp_probe_timeout":
		return "TCP reachability check timed out"
	default:
		return "TCP reachability check failed"
	}
}

func (e *problemError) Unwrap() error   { return e.cause }
func (e *problemError) Code() string    { return e.code }
func (e *problemError) HTTPStatus() int { return e.status }

func classifyAccessSetupError(cause error) error {
	switch {
	case errors.Is(cause, state.ErrAccessTokenAlreadyInitialized):
		return &problemError{cause: cause, code: "access_initialized", status: http.StatusConflict}
	case errors.Is(cause, state.ErrInvalidNextAccessToken):
		return &problemError{cause: cause, code: "access_next_invalid", status: http.StatusBadRequest}
	case errors.Is(cause, state.ErrInvalidAccessToken):
		return invalidAccessError()
	default:
		return &problemError{cause: cause, code: "access_unavailable", status: http.StatusServiceUnavailable}
	}
}

func invalidAccessError() error {
	return &problemError{cause: state.ErrInvalidAccessToken, code: "access_invalid", status: http.StatusUnauthorized}
}

func classifyLoginError(cause error) error {
	switch {
	case errors.Is(cause, provider.ErrLoginRejected):
		return &problemError{cause: cause, code: "login_rejected", status: http.StatusUnauthorized}
	case errors.Is(cause, provider.ErrAccountExists):
		return &problemError{cause: cause, code: "account_exists", status: http.StatusConflict}
	case errors.Is(cause, state.ErrOperationInProgress):
		return &problemError{cause: cause, code: "operation_in_progress", status: http.StatusConflict}
	default:
		return &problemError{cause: cause, code: "login_unavailable", status: http.StatusServiceUnavailable}
	}
}

func tcpProbeProblem(cause, contextError error) error {
	if errors.Is(cause, context.DeadlineExceeded) || errors.Is(contextError, context.DeadlineExceeded) {
		return &problemError{cause: cause, code: "tcp_probe_timeout", status: http.StatusGatewayTimeout}
	}
	return &problemError{cause: cause, code: "tcp_probe_failed", status: http.StatusBadGateway}
}
