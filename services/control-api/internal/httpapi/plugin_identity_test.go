package httpapi

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPluginWriteLimiterPerInstallation(t *testing.T) {
	now := time.Date(2026, 10, 30, 3, 0, 0, 0, time.UTC)
	limiter := newPluginWriteLimiter(func() time.Time { return now })
	limiter.limit = 2
	first, second := uuid.New(), uuid.New()
	for i := 0; i < 2; i++ {
		if _, _, ok := limiter.allow(first); !ok {
			t.Fatalf("write %d refused", i+1)
		}
	}
	now = now.Add(15 * time.Second)
	retry, firstRefusal, ok := limiter.allow(first)
	if ok || !firstRefusal || retry != 45 {
		t.Fatalf("over limit = retry %d first %v ok %v, want 45 true false", retry, firstRefusal, ok)
	}
	if _, firstRefusal, ok := limiter.allow(first); ok || firstRefusal {
		t.Fatalf("second refusal first=%v ok=%v, want false false", firstRefusal, ok)
	}
	if _, _, ok := limiter.allow(second); !ok {
		t.Fatal("another installation shares the window")
	}
	now = now.Add(45 * time.Second)
	if _, _, ok := limiter.allow(first); !ok {
		t.Fatal("new window still refused")
	}
}

func TestIsWriteMethod(t *testing.T) {
	for method, want := range map[string]bool{"GET": false, "HEAD": false, "OPTIONS": false, "POST": true, "PUT": true, "PATCH": true, "DELETE": true} {
		if got := isWriteMethod(method); got != want {
			t.Errorf("isWriteMethod(%s) = %v, want %v", method, got, want)
		}
	}
}
