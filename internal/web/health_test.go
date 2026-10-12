package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The container healthcheck and external monitors read /healthz; it must be
// the plain liveness response, never the SPA fallback page.
func TestHealthzReturnsPlainLiveness(t *testing.T) {
	api := newTestAPI(t, &fakeBackend{}, newFakeSubscriptions())
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		request := httptest.NewRequest(method, "http://"+testHost+"/healthz", nil)
		response := httptest.NewRecorder()
		api.ServeHTTP(response, request)
		wantBody := "ok\n"
		if method == http.MethodHead {
			wantBody = ""
		}
		if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "text/plain; charset=utf-8" || response.Body.String() != wantBody {
			t.Fatalf("%s /healthz = %d %q %q", method, response.Code, response.Header().Get("Content-Type"), response.Body.String())
		}
	}
}
