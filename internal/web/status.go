package web

import (
	"io"
	"net/http"
)

func (a *API) health(w http.ResponseWriter, r *http.Request) {
	setNoStore(w.Header())
	if a.liveness != nil && !a.liveness.Healthy() {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		if r.Method != http.MethodHead {
			_, _ = io.WriteString(w, "unhealthy\n")
		}
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = io.WriteString(w, "ok\n")
	}
}

func (a *API) status(w http.ResponseWriter, r *http.Request) {
	if a.backend == nil {
		a.backendUnavailable(w)
		return
	}
	status, err := a.backend.Status(r.Context())
	if err != nil {
		a.writeBackendError(w, err, "status_unavailable", http.StatusServiceUnavailable)
		return
	}
	for id, account := range status.Accounts {
		status.Accounts[id] = *redactAccount(&account)
	}
	status.Version = firstNonEmpty(status.Version, a.config.Version)
	if status.Deployment.StartedAt.IsZero() {
		status.Deployment.StartedAt = a.config.StartedAt
	}
	if a.subscriptions != nil {
		metadata, err := a.subscriptions.Metadata(r.Context())
		if err != nil {
			a.writeBackendError(w, err, "subscription_unavailable", http.StatusServiceUnavailable)
			return
		}
		status.Subscription = metadata
	}
	status.DataPlane.SocksAddress = a.socksAddress(r)
	a.writeJSON(w, http.StatusOK, status)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
