package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/kfadapter/kfadapter/internal/provider"
)

// Refresh failures are logged by class only; provider text must never reach the log.
func TestRefreshErrorClassOmitsProviderText(t *testing.T) {
	const secret = "password=hunter2 token=abc123"
	err := fmt.Errorf("%w: upstream said %s", provider.ErrLoginRejected, secret)
	class := refreshErrorClass(err)
	if class != "login_rejected" {
		t.Fatalf("refreshErrorClass = %q, want login_rejected", class)
	}
	for _, leaked := range []string{"hunter2", "abc123", "password"} {
		if strings.Contains(class, leaked) {
			t.Fatalf("log class %q leaked %q", class, leaked)
		}
	}
}
