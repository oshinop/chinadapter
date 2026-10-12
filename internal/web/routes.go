package web

import (
	"net/http"
)

// apiRoute keeps method negotiation separate from the browser security boundary:
// wrong methods are rejected before authentication or mutation checks.
type apiRoute struct {
	method  string
	path    string
	public  bool
	handler func(http.ResponseWriter, *http.Request, string, browserSession)
}

func (a *API) routes() []apiRoute {
	plain := func(handler http.HandlerFunc) func(http.ResponseWriter, *http.Request, string, browserSession) {
		return func(w http.ResponseWriter, r *http.Request, _ string, _ browserSession) { handler(w, r) }
	}
	return []apiRoute{
		{http.MethodGet, "/healthz", true, plain(a.health)},
		{http.MethodGet, "/api/v1/access/status", true, plain(a.accessStatus)},
		{http.MethodPost, "/api/v1/access/setup", true, plain(func(w http.ResponseWriter, r *http.Request) { a.access(w, r, true) })},
		{http.MethodPost, "/api/v1/access/login", true, plain(func(w http.ResponseWriter, r *http.Request) { a.access(w, r, false) })},
		{http.MethodGet, "/api/v1/status", false, plain(a.status)},
		{http.MethodGet, "/api/v1/nodes", false, plain(a.nodes)},
		{http.MethodGet, "/api/v1/nodes/{id}/details", false, plain(func(w http.ResponseWriter, r *http.Request) { a.nodeDetails(w, r, r.PathValue("id")) })},
		{http.MethodPost, "/api/v1/nodes/{id}/probe", false, plain(func(w http.ResponseWriter, r *http.Request) { a.probe(w, r, r.PathValue("id")) })},
		{http.MethodPost, "/api/v1/auth/login", false, func(w http.ResponseWriter, r *http.Request, token string, _ browserSession) { a.login(w, r, token) }},
		{http.MethodPost, "/api/v1/auth/logout", false, plain(a.accountLogout)},
		{http.MethodPost, "/api/v1/access/logout", false, func(w http.ResponseWriter, r *http.Request, token string, _ browserSession) { a.lock(w, r, token) }},
		{http.MethodPost, "/api/v1/access/token", false, a.changeAccessToken},
		{http.MethodPost, "/api/v1/control/refresh", false, plain(a.refresh)},
		{http.MethodGet, "/api/v1/subscription", false, plain(a.subscriptionMetadata)},
		{http.MethodGet, "/api/v1/subscription/url", false, plain(a.subscriptionURL)},
		{http.MethodGet, "/api/v1/events", false, a.events},
		{http.MethodPost, "/api/v1/diagnostics/export", false, plain(a.diagnostics)},
	}
}

func (a *API) newHandler() http.Handler {
	mux := http.NewServeMux()
	for _, route := range a.routes() {
		mux.Handle(route.method+" "+route.path, a.browserBoundary(route))
		allow := route.method
		if route.method == http.MethodGet {
			allow = "GET, HEAD"
		}
		mux.HandleFunc(route.path, func(w http.ResponseWriter, _ *http.Request) {
			setNoStore(w.Header())
			w.Header().Set("Allow", allow)
			a.writeProblem(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method Not Allowed")
		})
	}
	mux.HandleFunc("/api/v1/auth/session", func(w http.ResponseWriter, _ *http.Request) { writeEmptyNotFound(w) })
	mux.HandleFunc("/api/", func(w http.ResponseWriter, _ *http.Request) {
		setNoStore(w.Header())
		a.writeProblem(w, http.StatusNotFound, "not_found", "Not Found")
	})
	return mux
}

// HEAD follows GET routing and status negotiation without emitting a body.
type headResponseWriter struct{ http.ResponseWriter }

func (w headResponseWriter) Write(p []byte) (int, error) { return len(p), nil }
func (w headResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w headResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}
