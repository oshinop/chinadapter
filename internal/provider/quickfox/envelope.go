package quickfox

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/oshinop/chinadapter/internal/provider"
)

const (
	defaultAPIBase      = "https://api.quick-fox.com"
	clientVersion       = "3.59.6"
	platformType        = "2"
	requestKey          = "6PNkQ8aleI5MNgj6"
	responseKey         = "5bj6PNkQ8aleI5MN"
	apiIV               = "PNkQ8aleI5MNgj6r"
	maxRequestBytes     = 64 << 10
	maxResponseBytes    = 1 << 20
	maxControlFieldSize = 4096

	// sessionRejectedCode is the envelope code QuickFox returns for a token it
	// no longer accepts, with message "token失效，请重新登录" and no success
	// field. Observed live in 2026-10 on /user/info.
	sessionRejectedCode = http.StatusUnauthorized
)

type envelope struct {
	Code    *int            `json:"code"`
	Data    json.RawMessage `json:"data"`
	Success *bool           `json:"success"`
}

func (c *Client) do(ctx context.Context, method, path string, payload any, token, deviceCode string, target any) error {
	if c == nil || ctx == nil || !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#") || !validDeviceCode(deviceCode) {
		return ErrSchema
	}
	var body io.Reader
	if method != http.MethodGet {
		plaintext, err := json.Marshal(payload)
		if err != nil || len(plaintext) > maxRequestBytes {
			return ErrSchema
		}
		ciphertext, err := encryptCBC(plaintext, []byte(requestKey))
		if err != nil {
			return err
		}
		encoded, err := json.Marshal(struct {
			Data string `json:"data"`
		}{Data: base64.StdEncoding.EncodeToString(ciphertext)})
		if err != nil {
			return ErrSchema
		}
		body = bytes.NewReader(encoded)
	}
	requestContext, cancel := context.WithTimeout(ctx, c.requestTimeout)
	defer cancel()
	endpoint := *c.apiBase
	endpoint.Path = path
	request, err := http.NewRequestWithContext(requestContext, method, endpoint.String(), body)
	if err != nil {
		return ErrSchema
	}
	nonce := make([]byte, 16)
	if _, err := io.ReadFull(c.random, nonce); err != nil {
		return fmt.Errorf("quickfox: request nonce: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("version", clientVersion)
	request.Header.Set("platformType", platformType)
	request.Header.Set("nonce", hex.EncodeToString(nonce))
	request.Header.Set("proxyChannel", "")
	request.Header.Set("channel", "official")
	request.Header.Set("lang", "zh_CN")
	request.Header.Set("deviceCode", deviceCode)
	if token != "" {
		request.Header.Set("token", token)
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("quickfox: control request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return &httpStatusError{status: response.StatusCode}
	}
	if response.ContentLength > maxResponseBytes {
		return ErrSchema
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("quickfox: read response: %w", err)
	}
	if len(encoded) == 0 || len(encoded) > maxResponseBytes {
		return ErrSchema
	}
	var wrapped envelope
	if json.Unmarshal(encoded, &wrapped) != nil || wrapped.Code == nil {
		return ErrSchema
	}
	if token != "" && *wrapped.Code == sessionRejectedCode {
		return fmt.Errorf("%w: %w", provider.ErrSessionRejected, &businessCodeError{code: *wrapped.Code})
	}
	if wrapped.Success == nil || len(wrapped.Data) == 0 {
		return ErrSchema
	}
	if *wrapped.Code != http.StatusOK || !*wrapped.Success {
		return &businessCodeError{code: *wrapped.Code}
	}
	decoded, err := decodeData(wrapped.Data)
	if err != nil {
		return err
	}
	if len(decoded) == 0 || len(decoded) > maxResponseBytes || json.Unmarshal(decoded, target) != nil {
		return ErrSchema
	}
	return nil
}

func decodeData(raw json.RawMessage) ([]byte, error) {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil, ErrSchema
	}
	if raw[0] != '"' {
		return append([]byte(nil), raw...), nil
	}
	var encoded string
	if json.Unmarshal(raw, &encoded) != nil || encoded == "" {
		return nil, ErrSchema
	}
	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 || len(ciphertext) > maxResponseBytes {
		return nil, ErrCrypto
	}
	// Keep the ciphertext intact while both keys decrypt into the same scratch.
	scratch := make([]byte, len(ciphertext))
	for _, key := range []string{responseKey, requestKey} {
		plaintext, decryptErr := decryptCBC(ciphertext, []byte(key), scratch)
		if decryptErr == nil && json.Valid(plaintext) {
			return plaintext, nil
		}
	}
	return nil, ErrCrypto
}

func encryptCBC(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrCrypto
	}
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	padded := make([]byte, len(plaintext)+padding)
	copy(padded, plaintext)
	for index := len(plaintext); index < len(padded); index++ {
		padded[index] = byte(padding)
	}
	cipher.NewCBCEncrypter(block, []byte(apiIV)).CryptBlocks(padded, padded)
	return padded, nil
}

func decryptCBC(ciphertext, key, scratch []byte) ([]byte, error) {
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 || len(scratch) != len(ciphertext) {
		return nil, ErrCrypto
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrCrypto
	}
	plaintext := scratch
	cipher.NewCBCDecrypter(block, []byte(apiIV)).CryptBlocks(plaintext, ciphertext)
	padding := int(plaintext[len(plaintext)-1])
	if padding == 0 || padding > aes.BlockSize || padding > len(plaintext) {
		return nil, ErrCrypto
	}
	for _, value := range plaintext[len(plaintext)-padding:] {
		if int(value) != padding {
			return nil, ErrCrypto
		}
	}
	return plaintext[:len(plaintext)-padding], nil
}
