package kuaifan

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	wireprofile "github.com/kfadapter/kfadapter/internal/kuaifan/profile"
)

func hardenedHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Client{Transport: &http.Transport{
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}}
}

type responseEnvelope struct {
	Status *int                       `json:"status"`
	Msg    *string                    `json:"msg"`
	Fields map[string]json.RawMessage `json:"fields"`
}

type httpStatusError struct{ status int }

func (err *httpStatusError) Error() string {
	return fmt.Sprintf("control: unexpected HTTP status %d", err.status)
}

func (err *httpStatusError) Unwrap() error { return ErrHTTPStatus }

func (c *Client) post(ctx context.Context, base *url.URL, route string, fields any) (responseEnvelope, error) {
	if base == nil {
		return responseEnvelope{}, ErrUnapprovedAPIBase
	}
	if _, err := parseApprovedBase(base.String(), c.allowedHosts); err != nil {
		return responseEnvelope{}, err
	}
	payload, err := requestEnvelope(fields, c.language, c.timestamp(), c.random)
	if err != nil {
		return responseEnvelope{}, err
	}
	body, err := c.normalCodec.EncodeJSON(payload)
	if err != nil {
		return responseEnvelope{}, err
	}
	endpoint := base.ResolveReference(&url.URL{Path: route})
	requestCtx, cancel := context.WithTimeout(ctx, c.requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return responseEnvelope{}, fmt.Errorf("control: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json; UTF-8")
	req.Header.Set("User-Agent", c.profile.userAgent())
	response, err := c.httpClient.Do(req)
	if err != nil {
		return responseEnvelope{}, fmt.Errorf("control: request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return responseEnvelope{}, &httpStatusError{status: response.StatusCode}
	}
	if response.ContentLength > int64(base64MaximumEncodedSize()) {
		return responseEnvelope{}, ErrResponseTooLarge
	}
	encoded, err := readBounded(response.Body, base64MaximumEncodedSize())
	if err != nil {
		return responseEnvelope{}, err
	}
	var envelope responseEnvelope
	if err := c.normalCodec.DecodeJSON(encoded, &envelope); err != nil {
		return responseEnvelope{}, fmt.Errorf("%w: decode response: %w", ErrInvalidEnvelope, err)
	}
	if envelope.Status == nil || len(envelope.Fields) > maxResponseFields || (envelope.Msg != nil && !withinLimit(*envelope.Msg, maxControlFieldBytes)) {
		return responseEnvelope{}, ErrInvalidEnvelope
	}
	return envelope, nil
}

func requestEnvelope(fields any, language, timestamp string, randomness io.Reader) (map[string]any, error) {
	encoded, err := json.Marshal(fields)
	if err != nil {
		return nil, fmt.Errorf("control: marshal request fields: %w", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(encoded, &payload); err != nil || payload == nil {
		return nil, fmt.Errorf("control: request fields must be an object: %w", err)
	}
	if _, hasLanguage := payload["lang"]; !hasLanguage {
		payload["lang"] = language
	}
	if _, hasNonce := payload["nonce"]; !hasNonce {
		nonce, err := wireprofile.RandomInt(randomness, 100000000)
		if err != nil {
			return nil, fmt.Errorf("control: nonce: %w", err)
		}
		payload["nonce"] = fmt.Sprintf("%08d", nonce)
	}
	if _, hasTime := payload["time"]; !hasTime {
		payload["time"] = timestamp
	}
	return payload, nil
}

func (c *Client) timestamp() string {
	now := c.clock().In(c.location)
	return now.Format("20060102150405") + fmt.Sprintf("%03d", now.Nanosecond()/int(time.Millisecond))
}

func normalizedAllowlist(input []string) (map[string]struct{}, error) {
	allowed := make(map[string]struct{}, len(input))
	if len(input) == 0 {
		allowed[defaultAPIHost] = struct{}{}
	}
	for _, candidate := range input {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if strings.Contains(candidate, "://") {
			parsed, err := url.Parse(candidate)
			if err != nil || parsed.Hostname() == "" || parsed.Scheme != "https" || parsed.User != nil {
				return nil, ErrUnapprovedAPIBase
			}
			candidate = parsed.Hostname()
		}
		candidate = strings.ToLower(strings.TrimSuffix(candidate, "."))
		if candidate == "" || strings.ContainsAny(candidate, "/?#@") {
			return nil, ErrUnapprovedAPIBase
		}
		allowed[candidate] = struct{}{}
	}
	return allowed, nil
}

func parseApprovedBase(raw string, allowed map[string]struct{}) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, ErrUnapprovedAPIBase
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return nil, ErrUnapprovedAPIBase
	}
	port := parsed.Port()
	if (port != "" || strings.HasSuffix(parsed.Host, ":")) && !isCanonicalURLPort(port) {
		return nil, ErrUnapprovedAPIBase
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if _, ok := allowed[host]; !ok {
		return nil, ErrUnapprovedAPIBase
	}
	parsed.Path = ""
	parsed.RawPath = ""
	return parsed, nil
}

func isCanonicalURLPort(port string) bool {
	if len(port) == 0 || (len(port) > 1 && port[0] == '0') {
		return false
	}
	parsedPort, err := strconv.ParseUint(port, 10, 16)
	return err == nil && parsedPort > 0
}

func cloneURL(in *url.URL) *url.URL {
	out := *in
	return &out
}

func base64MaximumEncodedSize() int { return 4 * ((MaxPlaintextBytes + blockSize + 2) / 3) }

func readBounded(reader io.Reader, limit int) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("control: read response: %w", err)
	}
	if len(data) > limit {
		return nil, ErrResponseTooLarge
	}
	return data, nil
}
