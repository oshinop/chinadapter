package kuaifan

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	wireprofile "github.com/kfadapter/kfadapter/internal/provider/kuaifan/profile"
)

func retry[T any](ctx context.Context, driver *Driver, call func() (T, error)) (T, error) {
	var zero T
	for attempt := range driver.attempts {
		select {
		case <-ctx.Done():
			return zero, ctx.Err()
		default:
		}
		value, err := call()
		if err == nil || !retryable(err) || attempt+1 == driver.attempts {
			return value, err
		}
		delay := retryDelay(driver, attempt)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return zero, ctx.Err()
		case <-timer.C:
		}
	}
	return zero, nil
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

func retryDelay(driver *Driver, attempt int) time.Duration {
	base := driver.backoff
	for range attempt {
		if base >= driver.maxBackoff/2 {
			base = driver.maxBackoff
			break
		}
		base *= 2
	}
	jitter, err := wireprofile.RandomInt(driver.clients[0].random, int(base/time.Millisecond)+1)
	if err != nil {
		return base
	}
	return time.Duration(jitter) * time.Millisecond
}
