package pluginwebhook

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestRetryDelayIsJitteredBoundedAndHonorsCappedRetryAfter(t *testing.T) {
	t.Parallel()
	policy := RetryPolicy{BaseDelay: time.Second, MaxDelay: time.Minute, RetryAfterMax: 30 * time.Second}
	if delay := policy.delay(1, 0, func(max int64) int64 { return max - 1 }); delay != time.Second {
		t.Fatalf("attempt 1 delay = %s", delay)
	}
	if delay := policy.delay(10, 0, func(max int64) int64 { return max - 1 }); delay != time.Minute {
		t.Fatalf("capped delay = %s", delay)
	}
	if delay := policy.delay(2, 2*time.Minute, func(int64) int64 { return 0 }); delay != 30*time.Second {
		t.Fatalf("Retry-After cap = %s", delay)
	}
}

func TestParseRetryAfterSupportsSecondsAndHTTPDate(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 22, 0, 0, 0, 0, time.UTC)
	if got := parseRetryAfter("12", now); got != 12*time.Second {
		t.Fatalf("seconds = %s", got)
	}
	if got := parseRetryAfter(now.Add(20*time.Second).Format(http.TimeFormat), now); got != 20*time.Second {
		t.Fatalf("date = %s", got)
	}
	if got := parseRetryAfter("secret", now); got != 0 {
		t.Fatalf("invalid = %s", got)
	}
}

func TestSanitizersRedactSensitiveFieldsHeadersAndBoundOutput(t *testing.T) {
	t.Parallel()
	preview := sanitizePreview([]byte(`{"accessToken":"top-secret","nested":{"clientSecret":"hidden","apiKey":"key-value","ok":"visible"}}`), "application/json", 256)
	if strings.Contains(preview, "top-secret") || strings.Contains(preview, "hidden") ||
		strings.Contains(preview, "key-value") || !strings.Contains(preview, "visible") {
		t.Fatalf("preview = %q", preview)
	}
	if got := sanitizePreview([]byte(strings.Repeat("x", 100)), "text/plain", 16); len(got) > 16 || strings.Contains(got, strings.Repeat("x", 17)) {
		t.Fatalf("bounded preview = %q", got)
	}
	headers := sanitizeHeaders(http.Header{
		"Authorization": []string{"Bearer secret"}, "Set-Cookie": []string{"session=secret"},
		"Content-Type": []string{"application/json"}, "Retry-After": []string{"10"},
	})
	if headers["Authorization"] != redactedValue || headers["Set-Cookie"] != redactedValue ||
		headers["Content-Type"] != "application/json" || headers["Retry-After"] != "10" {
		t.Fatalf("headers = %#v", headers)
	}
}
