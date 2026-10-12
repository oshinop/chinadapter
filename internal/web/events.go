package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func (a *API) writeSSE(w http.ResponseWriter, flusher http.Flusher, payload string) bool {
	controller := http.NewResponseController(w)
	if err := controller.SetWriteDeadline(time.Now().Add(a.config.WriteTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return false
	}
	defer func() { _ = controller.SetWriteDeadline(time.Time{}) }()
	if _, err := io.WriteString(w, payload); err != nil {
		return false
	}
	flusher.Flush()
	return true
}

func (a *API) events(w http.ResponseWriter, r *http.Request, token string, session browserSession) {
	if !a.sessions.matches(r.Context(), token, session) {
		a.writeProblem(w, http.StatusUnauthorized, "not_authenticated", "Authentication required")
		return
	}
	source, ok := a.backend.(EventSource)
	if !ok {
		a.writeProblem(w, http.StatusServiceUnavailable, "events_unavailable", "Events unavailable")
		return
	}
	streamContext, stopStream := context.WithCancel(r.Context())
	defer stopStream()
	events, cancel, err := source.Subscribe(streamContext)
	if err != nil {
		a.writeBackendError(w, err, "events_unavailable", http.StatusServiceUnavailable)
		return
	}
	defer cancel()
	flusher, ok := w.(http.Flusher)
	if !ok {
		a.writeProblem(w, http.StatusInternalServerError, "streaming_unavailable", "Streaming unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	if !a.writeSSE(w, flusher, "retry: 1000\n\n") {
		return
	}
	heartbeat := time.NewTicker(a.config.SSEHeartbeat)
	defer heartbeat.Stop()
	checkEvery := a.config.SSEHeartbeat
	if checkEvery > 15*time.Second {
		checkEvery = 15 * time.Second
	}
	sessionCheck := time.NewTicker(checkEvery)
	defer sessionCheck.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-session.done:
			return
		case <-sessionCheck.C:
			if !a.sessions.matches(r.Context(), token, session) {
				return
			}
		case <-heartbeat.C:
			if !a.writeSSE(w, flusher, ": keepalive\n\n") {
				return
			}
		case event, open := <-events:
			if !open {
				return
			}
			if !a.sessions.matches(r.Context(), token, session) {
				return
			}
			if event.Type == "" || strings.ContainsAny(event.Type, "\r\n") {
				continue
			}
			payload, err := json.Marshal(redactDiagnostic(event.Data))
			if err != nil || len(payload) > a.config.SSEMaxEventBytes {
				continue
			}
			if !a.writeSSE(w, flusher, fmt.Sprintf("event: %s\ndata: %s\n\n", event.Type, payload)) {
				return
			}
		}
	}
}
