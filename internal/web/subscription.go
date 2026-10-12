package web

import (
	"net"
	"net/http"
	"strings"
)

func (a *API) subscriptionMetadata(w http.ResponseWriter, r *http.Request) {
	if a.subscriptions == nil {
		a.writeProblem(w, http.StatusServiceUnavailable, "subscription_unavailable", "Subscription unavailable")
		return
	}
	metadata, err := a.subscriptions.Metadata(r.Context())
	if err != nil {
		a.writeBackendError(w, err, "subscription_unavailable", http.StatusServiceUnavailable)
		return
	}
	a.writeJSON(w, http.StatusOK, metadata)
}

func (a *API) subscriptionURL(w http.ResponseWriter, r *http.Request) {
	if a.subscriptions == nil {
		a.writeProblem(w, http.StatusServiceUnavailable, "subscription_unavailable", "Subscription unavailable")
		return
	}
	subscriptionURL, err := a.subscriptions.SubscriptionURL(r.Context(), a.baseURL(r.Host), a.socksAddress(r))
	if err != nil {
		a.writeBackendError(w, err, "subscription_unavailable", http.StatusServiceUnavailable)
		return
	}
	a.writeJSON(w, http.StatusOK, subscriptionURL)
}

func (a *API) baseURL(requestHost string) string {
	if hostname, ok := a.advertisedHostname(requestHost); ok {
		if a.listenPort == "80" {
			return "http://" + hostname
		}
		return "http://" + net.JoinHostPort(hostname, a.listenPort)
	}
	return "http://" + requestHost
}

// Subscription paths retain the deliberately empty failure contract, including
// malformed UUIDs and unsupported methods. They are not browser API routes.
func (a *API) serveSubscription(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/sub" && !strings.HasPrefix(r.URL.Path, "/sub/") {
		return false
	}
	if a.subscriptions == nil {
		writeEmptyNotFound(w)
	} else {
		binding, _ := a.subscriptions.ParseSubscriptionPath(r.URL.EscapedPath())
		a.subscriptions.ServeSubscription(w, r, binding, a.socksAddress(r))
	}
	return true
}
