package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

var (
	errContentType   = errors.New("content type must be application/json")
	errBodyTooLarge  = errors.New("request body is too large")
	errMalformedJSON = errors.New("request body must be one JSON object")
)

func (a *API) requireEmptyJSON(w http.ResponseWriter, r *http.Request) error {
	var body struct{}
	return readJSONBody(w, r, a.config.JSONBodyLimit, &body)
}

func readJSONBody(w http.ResponseWriter, r *http.Request, limit int, target any) error {
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		return errContentType
	}
	if limit <= 0 {
		limit = defaultJSONLimit
	}
	body := http.MaxBytesReader(w, r.Body, int64(limit)+1)
	defer body.Close()
	raw, err := io.ReadAll(body)
	if raw != nil {
		defer clear(raw)
	}
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return errBodyTooLarge
		}
		return errMalformedJSON
	}
	if len(raw) > limit {
		return errBodyTooLarge
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return errMalformedJSON
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errMalformedJSON
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errMalformedJSON
	}
	return nil
}
