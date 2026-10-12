package quickfox

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kfadapter/kfadapter/internal/provider"
)

func TestClientLoginLocalValidationReturnsInvalidInput(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name           string
		account        string
		password       string
		installationID string
	}{
		{name: "bad installation ID", account: "alice@example.com", password: "password", installationID: "invalid"},
		{name: "empty password", account: "alice@example.com", installationID: "00112233445566778899aabbccddeeff"},
		{name: "oversized password", account: "alice@example.com", password: strings.Repeat("p", maxControlFieldSize+1), installationID: "00112233445566778899aabbccddeeff"},
		{name: "empty account", password: "password", installationID: "00112233445566778899aabbccddeeff"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var calls atomic.Int64
			client := loopbackControlClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
			_, err := client.Login(context.Background(), test.account, test.password, test.installationID)
			if !errors.Is(err, provider.ErrInvalidInput) || errors.Is(err, ErrLoginRejected) || calls.Load() != 0 {
				t.Fatalf("local validation: error %v, HTTP calls %d", err, calls.Load())
			}
		})
	}
}

func TestClientLoginAcceptsMaximumPasswordSize(t *testing.T) {
	t.Parallel()
	var calls atomic.Int64
	client := loopbackControlClient(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		writeEncryptedResponse(t, writer, accountPayload{
			Token: "0123456789abcdef0123456789abcdef", UserID: 1, Email: "alice@example.com",
		})
	}))
	session, err := client.Login(context.Background(), "alice@example.com", strings.Repeat("p", maxControlFieldSize), "00112233445566778899aabbccddeeff")
	if err != nil || session.Profile.UserID != 1 || calls.Load() != 1 {
		t.Fatalf("maximum password: user ID %d, error %v, HTTP calls %d", session.Profile.UserID, err, calls.Load())
	}
}

func TestClientLoginRejectionIncludesBusinessCode(t *testing.T) {
	t.Parallel()
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusOK} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			t.Parallel()
			client := loopbackControlClient(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				if err := json.NewEncoder(writer).Encode(map[string]any{"code": code, "success": false, "data": nil}); err != nil {
					t.Error(err)
				}
			}))
			_, err := client.Login(context.Background(), "alice@example.com", "password", "00112233445566778899aabbccddeeff")
			want := fmt.Sprintf("%s: %d", ErrLoginRejected, code)
			if !errors.Is(err, ErrLoginRejected) || errors.Is(err, provider.ErrInvalidInput) || err.Error() != want {
				t.Fatalf("business rejection = %v, want %q wrapping ErrLoginRejected", err, want)
			}
		})
	}
}

func TestClientResponseBound(t *testing.T) {
	t.Parallel()
	const limit = 1 << 20
	if maxResponseBytes != limit {
		t.Fatalf("response bound = %d, want %d", maxResponseBytes, limit)
	}
	for _, test := range []struct {
		name         string
		size         int
		chunked      bool
		wantRead     int64
		wantRejected bool
	}{
		{name: "declared oversized", size: 2 * limit, wantRead: 0, wantRejected: true},
		{name: "chunked oversized", size: 2 * limit, chunked: true, wantRead: limit + 1, wantRejected: true},
		{name: "exactly one MiB", size: limit, wantRead: limit},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			const prefix = `{"code":200,"success":true,"data":{"padding":"`
			const suffix = `"}}`
			body := prefix + strings.Repeat("x", test.size-len(prefix)-len(suffix)) + suffix
			client := loopbackControlClient(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				if !test.chunked {
					writer.Header().Set("Content-Length", strconv.Itoa(len(body)))
				}
				writer.WriteHeader(http.StatusOK)
				writer.(http.Flusher).Flush()
				// Oversized replies can be closed before the server finishes writing.
				_, _ = io.WriteString(writer, body)
			}))
			baseTransport := client.httpClient.Transport
			if baseTransport == nil {
				baseTransport = http.DefaultTransport
			}
			var readBytes atomic.Int64
			var closed atomic.Bool
			client.httpClient.Transport = controlRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				response, err := baseTransport.RoundTrip(request)
				if err != nil {
					return nil, err
				}
				response.Body = &countedResponseBody{ReadCloser: response.Body, readBytes: &readBytes, closed: &closed}
				return response, nil
			})
			var response struct {
				Padding string `json:"padding"`
			}
			err := client.do(context.Background(), http.MethodGet, "/response", nil, "", "00112233-4455-4677-8899-aabbccddeeff", &response)
			if test.wantRejected {
				if !errors.Is(err, ErrSchema) {
					t.Fatalf("oversized response error = %v", err)
				}
			} else if err != nil || len(response.Padding) != test.size-len(prefix)-len(suffix) {
				t.Fatalf("bounded response: padding length %d, error %v", len(response.Padding), err)
			}
			if readBytes.Load() != test.wantRead || !closed.Load() {
				t.Fatalf("response body: read %d bytes, want %d, closed %t", readBytes.Load(), test.wantRead, closed.Load())
			}
		})
	}
}

func TestDecodeDataSupportsBothKeys(t *testing.T) {
	t.Parallel()
	plaintext := []byte(`{"payload":"` + strings.Repeat("value", 1024) + `"}`)
	for _, key := range []string{responseKey, requestKey} {
		ciphertext, err := encryptCBC(plaintext, []byte(key))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(base64.StdEncoding.EncodeToString(ciphertext))
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeData(raw)
		if err != nil || !bytes.Equal(decoded, plaintext) {
			t.Fatalf("decrypted response: length %d, error %v", len(decoded), err)
		}
	}
}

func TestDecryptCBCReusesScratchWithoutChangingCiphertext(t *testing.T) {
	t.Parallel()
	plaintext := []byte(`{"payload":"value"}`)
	ciphertext, err := encryptCBC(plaintext, []byte(requestKey))
	if err != nil {
		t.Fatal(err)
	}
	before := bytes.Clone(ciphertext)
	scratch := make([]byte, len(ciphertext))
	_, _ = decryptCBC(ciphertext, []byte(responseKey), scratch)
	decoded, err := decryptCBC(ciphertext, []byte(requestKey), scratch)
	if err != nil || !bytes.Equal(decoded, plaintext) || !bytes.Equal(ciphertext, before) {
		t.Fatalf("scratch decryption: length %d, ciphertext unchanged %t, error %v", len(decoded), bytes.Equal(ciphertext, before), err)
	}
	if &decoded[0] != &scratch[0] {
		t.Fatal("decryption did not return the reused scratch buffer")
	}
}

type countedResponseBody struct {
	io.ReadCloser
	readBytes *atomic.Int64
	closed    *atomic.Bool
}

func (body *countedResponseBody) Read(buffer []byte) (int, error) {
	count, err := body.ReadCloser.Read(buffer)
	body.readBytes.Add(int64(count))
	return count, err
}

func (body *countedResponseBody) Close() error {
	body.closed.Store(true)
	return body.ReadCloser.Close()
}

func loopbackControlClient(t *testing.T, handler http.Handler) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := NewClient(Config{
		Clock:  func() time.Time { return time.Date(2026, 7, 22, 6, 0, 0, 0, time.UTC) },
		Random: bytes.NewReader(bytes.Repeat([]byte{0x5a}, 512)), RequestTimeout: 2 * time.Second,
		httpClient: server.Client(), apiBase: server.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}
