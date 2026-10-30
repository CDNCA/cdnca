package pluginwebhook

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

type RetryPolicy struct {
	BaseDelay     time.Duration
	MaxDelay      time.Duration
	RetryAfterMax time.Duration
}

func (policy RetryPolicy) delay(attempt uint64, retryAfter time.Duration, random func(int64) int64) time.Duration {
	if attempt == 0 || policy.BaseDelay <= 0 || policy.MaxDelay < policy.BaseDelay ||
		policy.RetryAfterMax <= 0 || policy.RetryAfterMax > policy.MaxDelay || random == nil {
		return 0
	}
	delay := policy.BaseDelay
	for current := uint64(1); current < attempt && delay < policy.MaxDelay; current++ {
		if delay > policy.MaxDelay/2 {
			delay = policy.MaxDelay
			break
		}
		delay *= 2
	}
	if delay > policy.MaxDelay {
		delay = policy.MaxDelay
	}
	spread := delay / 2
	if spread > 0 {
		jitter := random(int64(spread) + 1)
		if jitter < 0 || jitter > int64(spread) {
			jitter = 0
		}
		delay = delay - spread + time.Duration(jitter)
	}
	if retryAfter > policy.RetryAfterMax {
		retryAfter = policy.RetryAfterMax
	}
	if retryAfter > delay {
		delay = retryAfter
	}
	if delay > policy.MaxDelay {
		return policy.MaxDelay
	}
	return delay
}

func parseRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.ParseInt(value, 10, 32); err == nil {
		if seconds <= 0 {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}
	when, err := http.ParseTime(value)
	if err != nil || !when.After(now) {
		return 0
	}
	return when.Sub(now)
}
