package accounts

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/oshinop/chinadapter/internal/provider"
)

// Refresh failures surface by class only; provider text must never reach logs
// or the browser.
func TestErrorClassOmitsProviderText(t *testing.T) {
	const secret = "password=hunter2 token=abc123"
	for _, tc := range []struct {
		err  error
		want string
	}{
		{fmt.Errorf("%w: upstream said %s", provider.ErrLoginRejected, secret), "login_rejected"},
		{fmt.Errorf("%w: upstream said %s", provider.ErrSessionRejected, secret), "session_rejected"},
		{fmt.Errorf("dial %s: %w", secret, context.DeadlineExceeded), "network"},
		{fmt.Errorf("upstream said %s", secret), "unclassified"},
	} {
		class := ErrorClass(tc.err)
		if class != tc.want {
			t.Fatalf("ErrorClass(%v) = %q, want %q", tc.err, class, tc.want)
		}
		for _, leaked := range []string{"hunter2", "abc123", "password"} {
			if strings.Contains(class, leaked) {
				t.Fatalf("class %q leaked %q", class, leaked)
			}
		}
	}
}
