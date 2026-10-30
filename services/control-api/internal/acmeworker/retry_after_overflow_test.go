package acmeworker

import (
	"net/http"
	"testing"
	"time"
)

func TestRetryAfterNumericOverflowSaturatesBeforeConfiguredCap(t *testing.T) {
	now := time.Date(2026, 8, 7, 1, 0, 0, 0, time.UTC)
	config := DefaultConfig("https://acme.example.test/directory")
	config.Clock = func() time.Time { return now }
	config.RetryBase = 250 * time.Millisecond
	config.MaxRetryAfter = 5 * time.Second
	worker := &Worker{config: config}

	tests := []struct {
		name  string
		value string
		want  time.Duration
	}{
		{name: "largest signed integer", value: "9223372036854775807", want: config.MaxRetryAfter},
		{name: "beyond unsigned integer", value: "18446744073709551616", want: config.MaxRetryAfter},
		{name: "negative integer", value: "-1", want: config.RetryBase},
		{name: "blank", value: "   ", want: config.RetryBase},
		{name: "valid seconds", value: "3", want: 3 * time.Second},
		{name: "date at cap", value: now.Add(config.MaxRetryAfter).Format(http.TimeFormat), want: config.MaxRetryAfter},
		{name: "past date", value: now.Add(-time.Second).Format(http.TimeFormat), want: config.RetryBase},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := &http.Response{Header: make(http.Header)}
			response.Header.Set("Retry-After", test.value)
			if got := worker.retryBackoff(1, nil, response); got != test.want {
				t.Fatalf("retryBackoff(Retry-After=%q) = %s, want %s", test.value, got, test.want)
			}
		})
	}
}
