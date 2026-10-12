package web

import (
	"errors"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

const (
	sessionCookieName = "chinadapter_session"
	defaultJSONLimit  = 64 << 10
	accessTokenLimit  = 4 << 10
)

// ServeHTTP is intentionally free of request logging. In particular, invalid
// subscription paths are never formatted into a log message.
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodHead {
		w = headResponseWriter{w}
	}
	if !requestHostAllowed(a.listenIP, a.listenPort, a.hostname, r.Host) {
		setSecurityHeaders(w.Header())
		setNoStore(w.Header())
		a.writeProblem(w, http.StatusBadRequest, "invalid_host", "Invalid Host")
		return
	}
	setSecurityHeaders(w.Header())
	if a.serveSubscription(w, r) {
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/") && strings.Contains(r.URL.Path, "//") {
		setNoStore(w.Header())
		a.writeProblem(w, http.StatusNotFound, "not_found", "Not Found")
		return
	}
	if r.URL.Path != "/healthz" && !strings.HasPrefix(r.URL.Path, "/api/") && r.URL.Path != "/api" {
		a.serveAsset(w, r)
		return
	}
	a.handler.ServeHTTP(w, r)
}

func (a *API) browserBoundary(route apiRoute) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w.Header())
		var token string
		var session browserSession
		if !route.public {
			var authenticated bool
			token, session, authenticated = a.authenticate(r)
			if !authenticated {
				a.writeProblem(w, http.StatusUnauthorized, "not_authenticated", "Authentication required")
				return
			}
		}
		mutation := route.method == http.MethodPost
		if route.path == "/api/v1/events" {
			if !originAllowed(r.Header.Get("Origin"), "http://"+r.Host) {
				a.writeProblem(w, http.StatusForbidden, "invalid_origin", "Invalid Origin")
				return
			}
		}
		if mutation && !isJSONContentType(r.Header.Get("Content-Type")) {
			a.writeProblem(w, http.StatusUnsupportedMediaType, "invalid_content_type", "Unsupported Content Type")
			return
		}
		route.handler(w, r, token, session)
	})
}

func (a *API) advertisedHostname(requestHost string) (string, bool) {
	return acceptedHostname(a.listenIP, a.listenPort, a.hostname, requestHost)
}

func (a *API) socksAddress(r *http.Request) string {
	if hostname, ok := a.advertisedHostname(r.Host); ok {
		return net.JoinHostPort(hostname, a.socksPort)
	}
	if !a.socksIP.IsUnspecified() {
		return a.config.SocksListen
	}
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil && a.listenPort == "80" {
		host = r.Host
	}
	if requestIP, err := netip.ParseAddr(host); err == nil && requestIP.Is4() == a.socksIP.Is4() {
		return net.JoinHostPort(host, a.socksPort)
	}
	return a.config.SocksListen
}

func requestHostAllowed(listenIP netip.Addr, listenPort, hostname, requestHost string) bool {
	requestIP, requestPort, err := canonicalNumericAddress(requestHost)
	if err == nil && requestPort == listenPort && (requestIP == listenIP || listenIP.IsUnspecified() && requestIP.Is4() == listenIP.Is4()) {
		return true
	}
	_, ok := acceptedHostname(listenIP, listenPort, hostname, requestHost)
	return ok
}

func acceptedHostname(listenIP netip.Addr, listenPort, configuredHostname, requestHost string) (string, bool) {
	if configuredHostname != "" && hostnameMatches(configuredHostname, listenPort, requestHost) {
		return configuredHostname, true
	}
	if (listenIP.IsUnspecified() || listenIP.IsLoopback()) && hostnameMatches("localhost", listenPort, requestHost) {
		return "localhost", true
	}
	return "", false
}

func hostnameMatches(hostname, listenPort, requestHost string) bool {
	return strings.EqualFold(requestHost, net.JoinHostPort(hostname, listenPort)) ||
		listenPort == "80" && strings.EqualFold(requestHost, hostname)
}

func canonicalNumericAddress(hostport string) (netip.Addr, string, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil || host == "" || port == "" {
		return netip.Addr{}, "", errors.New("host and port are required")
	}
	parsedPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil || parsedPort == 0 || strconv.FormatUint(parsedPort, 10) != port {
		return netip.Addr{}, "", errors.New("port must be canonical")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.String() != host {
		return netip.Addr{}, "", errors.New("address must be canonical")
	}
	return ip, port, nil
}

func isJSONContentType(header string) bool {
	mediaType, _, err := mime.ParseMediaType(header)
	return err == nil && mediaType == "application/json"
}

func originAllowed(header, expected string) bool {
	if header == "" || header != expected {
		return false
	}
	parsed, err := url.Parse(header)
	return err == nil && parsed.Scheme == "http" && parsed.Host != "" && parsed.User == nil && parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == ""
}

func setSecurityHeaders(header http.Header) {
	header.Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self'; object-src 'none'; script-src 'self'; style-src 'self'")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
}

func setNoStore(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set("Pragma", "no-cache")
}
