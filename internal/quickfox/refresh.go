package quickfox

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/kfadapter/kfadapter/internal/provider"
)

// Catalog refresh never rotates the stored token. Retry only transient transport
// failures here; the account supervisor retains state and retries all other
// non-rejection failures on its longer schedule.
func (driver *Driver) retryCatalog(ctx context.Context, token, deviceCode string) (catalog, error) {
	const attempts = 3
	for attempt := range attempts {
		if err := ctx.Err(); err != nil {
			return catalog{}, err
		}
		value, err := driver.client.Catalog(ctx, token, deviceCode)
		if err == nil || !retryable(err) || attempt+1 == attempts {
			return value, err
		}
		timer := time.NewTimer((250 * time.Millisecond) << attempt)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return catalog{}, ctx.Err()
		case <-timer.C:
		}
	}
	return catalog{}, nil
}

func retryable(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, provider.ErrSessionRejected) ||
		errors.Is(err, ErrLoginRejected) || errors.Is(err, ErrBusinessCode) || errors.Is(err, ErrSchema) ||
		errors.Is(err, ErrCrypto) || errors.Is(err, ErrInvalidLine) {
		return false
	}
	var status *httpStatusError
	if errors.As(err, &status) {
		return status.status == http.StatusRequestTimeout || status.status == http.StatusTooManyRequests || status.status >= http.StatusInternalServerError && status.status <= 599
	}
	var networkErr net.Error
	return errors.As(err, &networkErr) && (networkErr.Timeout() || networkErr.Temporary()) //nolint:staticcheck // Temporary is the errno-level signal net.OpError exposes; dropping it would stop retrying resets and descriptor exhaustion.
}
