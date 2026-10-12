package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

func (a *API) diagnostics(w http.ResponseWriter, r *http.Request) {
	if a.backend == nil {
		a.backendUnavailable(w)
		return
	}
	if err := a.requireEmptyJSON(w, r); err != nil {
		a.writeBodyError(w, err)
		return
	}
	diagnostic, err := a.backend.Diagnostics(r.Context())
	if err != nil {
		a.writeBackendError(w, err, "diagnostics_unavailable", http.StatusServiceUnavailable)
		return
	}
	redacted := redactDiagnostic(diagnostic)
	encoded, err := json.Marshal(redacted)
	if err != nil {
		a.writeProblem(w, http.StatusInternalServerError, "diagnostics_unavailable", "Diagnostics unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\"kfadapter-diagnostics.json\"")
	w.Header().Set("Content-Length", fmt.Sprint(len(encoded)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(encoded)
}

func redactAccount(account *Account) *Account {
	if account == nil {
		return nil
	}
	clone := *account
	clone.Display = maskAccount(clone.Display)
	return &clone
}

func maskAccount(account string) string {
	if account == "" {
		return ""
	}
	if strings.Contains(account, "•••") {
		return account
	}
	at := strings.IndexByte(account, '@')
	if at > 0 {
		return string([]rune(account[:at])[0]) + "•••" + account[at:]
	}
	runes := []rune(account)
	if len(runes) == 0 {
		return ""
	}
	return string(runes[0]) + "•••"
}

func redactDiagnostic(value any) any {
	encoded, err := json.Marshal(value)
	if err != nil {
		return map[string]any{"diagnostic": "redacted"}
	}
	var decoded any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return map[string]any{"diagnostic": "redacted"}
	}
	return redactDiagnosticValue(decoded, "")
}

func redactDiagnosticValue(value any, key string) any {
	if diagnosticSecretKey(key) {
		return "redacted"
	}
	switch typed := value.(type) {
	case map[string]any:
		redacted := make(map[string]any, len(typed))
		for childKey, child := range typed {
			redacted[childKey] = redactDiagnosticValue(child, childKey)
		}
		return redacted
	case []any:
		redacted := make([]any, len(typed))
		for index, child := range typed {
			redacted[index] = redactDiagnosticValue(child, key)
		}
		return redacted
	case string:
		if strings.Contains(typed, "socks5://") || strings.Contains(typed, "/sub/") || looksLikeSelectorCredential(typed) {
			return "redacted"
		}
	}
	return value
}

func diagnosticSecretKey(key string) bool {
	normalized := strings.NewReplacer("_", "", "-", "", ".", "").Replace(strings.ToLower(key))
	for _, secret := range []string{"account", "password", "token", "authkey", "encryptkey", "providerextension", "capability", "accesskey", "selectorkey", "proxyauthkey", "credential", "session", "secret", "endpoint", "address", "host", "url"} {
		if strings.Contains(normalized, secret) {
			return true
		}
	}
	return false
}

func looksLikeSelectorCredential(value string) bool {
	return (strings.HasPrefix(value, "n_") && len(value) == 18) || (strings.HasPrefix(value, "p_") && len(value) == 26)
}
