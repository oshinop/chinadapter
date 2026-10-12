package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestRouteTableWrongMethodsAndHEAD(t *testing.T) {
	closedEvents := make(chan Event)
	close(closedEvents)
	api := newTestAPI(t, &fakeBackend{events: closedEvents}, newFakeSubscriptions())
	cookie, _ := establish(t, api)
	for _, route := range api.routes() {
		path := strings.ReplaceAll(route.path, "{id}", "node-alpha")
		t.Run(route.method+" "+path, func(t *testing.T) {
			wrong := request(api, http.MethodDelete, path, "", cookie, testOrigin)
			allow := route.method
			if route.method == http.MethodGet {
				allow = "GET, HEAD"
			}
			if wrong.Code != http.StatusMethodNotAllowed || wrong.Header().Get("Allow") != allow {
				t.Fatalf("wrong method = %d Allow=%q", wrong.Code, wrong.Header().Get("Allow"))
			}
			if !strings.HasPrefix(wrong.Header().Get("Content-Type"), "application/problem+json") {
				t.Fatalf("problem content type=%q", wrong.Header().Get("Content-Type"))
			}
			if route.method == http.MethodGet {
				get := request(api, http.MethodGet, path, "", cookie, testOrigin)
				head := request(api, http.MethodHead, path, "", cookie, testOrigin)
				if head.Code != get.Code || head.Body.Len() != 0 {
					t.Fatalf("GET=%d HEAD=%d body=%q", get.Code, head.Code, head.Body.String())
				}
			}
		})
	}
}

func TestUnknownPathsReturnTypedProblem(t *testing.T) {
	api := newTestAPI(t, &fakeBackend{}, newFakeSubscriptions())
	for _, path := range []string{"/api/v1/unknown", "/assets/missing.js", "/missing.json"} {
		response := request(api, http.MethodGet, path, "", nil, "")
		if response.Code != http.StatusNotFound || !strings.HasPrefix(response.Header().Get("Content-Type"), "application/problem+json") {
			t.Fatalf("path=%q status=%d headers=%v", path, response.Code, response.Header())
		}
		var problem struct {
			Type string `json:"type"`
			Code string `json:"code"`
		}
		if err := json.NewDecoder(response.Body).Decode(&problem); err != nil {
			t.Fatal(err)
		}
		if problem.Type != "urn:kfadapter:problem:not_found" || problem.Code != "not_found" {
			t.Fatalf("problem=%+v", problem)
		}
	}
}
