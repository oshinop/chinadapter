package web

import (
	"net/http"
	"path"
	"strings"
)

func (a *API) nodes(w http.ResponseWriter, r *http.Request) {
	if a.backend == nil {
		a.backendUnavailable(w)
		return
	}
	nodes, err := a.backend.Nodes(r.Context())
	if err != nil {
		a.writeBackendError(w, err, "nodes_unavailable", http.StatusServiceUnavailable)
		return
	}
	a.writeJSON(w, http.StatusOK, struct {
		Nodes []Node `json:"nodes"`
	}{Nodes: nodes})
}

func (a *API) nodeDetails(w http.ResponseWriter, r *http.Request, id string) {
	if a.backend == nil {
		a.backendUnavailable(w)
		return
	}
	if !validResourceID(id) {
		a.writeProblem(w, http.StatusNotFound, "not_found", "Not Found")
		return
	}
	details, err := a.backend.NodeDetails(r.Context(), id)
	if err != nil {
		a.writeBackendError(w, err, "node_details_unavailable", http.StatusServiceUnavailable)
		return
	}
	details.SocksAddress = a.socksAddress(r)
	a.writeJSON(w, http.StatusOK, details)
}

func (a *API) probe(w http.ResponseWriter, r *http.Request, id string) {
	if a.backend == nil {
		a.backendUnavailable(w)
		return
	}
	if !validResourceID(id) {
		a.writeProblem(w, http.StatusNotFound, "not_found", "Not Found")
		return
	}
	if err := a.requireEmptyJSON(w, r); err != nil {
		a.writeBodyError(w, err)
		return
	}
	result, err := a.backend.Probe(r.Context(), id)
	if err != nil {
		a.writeBackendError(w, err, "probe_failed", http.StatusServiceUnavailable)
		return
	}
	a.writeJSON(w, http.StatusOK, result)
}

func validResourceID(value string) bool {
	return value != "" && value == path.Base(value) && !strings.ContainsAny(value, "\r\n") && len(value) <= 256
}
