package quickfox

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/cenkalti/backoff/v5"

	"github.com/oshinop/chinadapter/internal/provider"
)

// Catalog refresh never rotates the stored token. Retry only transient transport
// failures here; the account supervisor retains state and retries all other
// non-rejection failures on its longer schedule.
func (driver *Driver) retryCatalog(ctx context.Context, token, deviceCode string) (catalog, error) {
	const attempts = 3
	value, err := backoff.Retry(ctx, func() (catalog, error) {
		if err := ctx.Err(); err != nil {
			return catalog{}, backoff.Permanent(err)
		}
		value, err := driver.client.Catalog(ctx, token, deviceCode)
		if err != nil && !retryable(err) {
			return value, backoff.Permanent(err)
		}
		return value, err
	}, backoff.WithBackOff(newCatalogBackOff()), backoff.WithMaxTries(attempts), backoff.WithMaxElapsedTime(0))
	// Retry checks its attempt limit before unwrapping permanent errors.
	var permanent *backoff.PermanentError
	if errors.As(err, &permanent) {
		err = permanent.Unwrap()
	}
	if err != nil && ctx.Err() != nil && errors.Is(err, context.Cause(ctx)) {
		return catalog{}, ctx.Err()
	}
	return value, err
}

// Clamp randomized delays too: the previous three-attempt schedule never
// waited longer than 500ms between requests.
type catalogBackOff struct{ backoff.ExponentialBackOff }

func newCatalogBackOff() *catalogBackOff {
	return &catalogBackOff{backoff.ExponentialBackOff{
		InitialInterval: 250 * time.Millisecond, RandomizationFactor: backoff.DefaultRandomizationFactor,
		Multiplier: 2, MaxInterval: 500 * time.Millisecond,
	}}
}

func (policy *catalogBackOff) NextBackOff() time.Duration {
	return min(policy.ExponentialBackOff.NextBackOff(), policy.MaxInterval)
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
