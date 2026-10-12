package kuaifan

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/cenkalti/backoff/v5"
)

func retry[T any](ctx context.Context, driver *Driver, call func() (T, error)) (T, error) {
	var zero T
	value, err := backoff.Retry(ctx, func() (T, error) {
		if err := ctx.Err(); err != nil {
			return zero, backoff.Permanent(err)
		}
		value, err := call()
		if err != nil && !retryable(err) {
			return value, backoff.Permanent(err)
		}
		return value, err
	}, backoff.WithBackOff(newRetryBackOff(driver)), backoff.WithMaxTries(uint(driver.attempts)), backoff.WithMaxElapsedTime(0))
	// Retry checks its attempt limit before unwrapping permanent errors.
	var permanent *backoff.PermanentError
	if errors.As(err, &permanent) {
		err = permanent.Unwrap()
	}
	if err != nil && ctx.Err() != nil && errors.Is(err, context.Cause(ctx)) {
		return zero, ctx.Err()
	}
	return value, err
}

func retryable(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) ||
		errors.Is(err, ErrLoginRejected) || errors.Is(err, ErrBusinessStatus) || errors.Is(err, ErrSchema) ||
		errors.Is(err, ErrInvalidEnvelope) || errors.Is(err, ErrInvalidPadding) || errors.Is(err, ErrMalformedCiphertext) ||
		errors.Is(err, ErrResponseTooLarge) || errors.Is(err, ErrUnsupportedCipher) || errors.Is(err, ErrInvalidLine) {
		return false
	}
	var status *httpStatusError
	if errors.As(err, &status) {
		return status.status == http.StatusRequestTimeout || status.status == http.StatusTooManyRequests || status.status >= http.StatusInternalServerError && status.status <= 599
	}
	var networkErr net.Error
	return errors.As(err, &networkErr) && (networkErr.Timeout() || networkErr.Temporary()) //nolint:staticcheck // Temporary is the errno-level signal net.OpError exposes; dropping it would stop retrying resets and descriptor exhaustion.
}

// MaxInterval caps the library's base interval, not its randomized delay.
// Clamp the latter as well to preserve the configured request delay ceiling.
type retryBackOff struct{ backoff.ExponentialBackOff }

func newRetryBackOff(driver *Driver) *retryBackOff {
	return &retryBackOff{backoff.ExponentialBackOff{
		InitialInterval: driver.backoff, RandomizationFactor: backoff.DefaultRandomizationFactor,
		Multiplier: 2, MaxInterval: driver.maxBackoff,
	}}
}

func (policy *retryBackOff) NextBackOff() time.Duration {
	return min(policy.ExponentialBackOff.NextBackOff(), policy.MaxInterval)
}
