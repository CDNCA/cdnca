package edgeoutbox

import (
	"errors"
	"testing"
	"time"
)

func TestConfigValidationAndBackoffCap(t *testing.T) {
	config := DefaultConfig()
	if err := config.validate(); err != nil {
		t.Fatalf("default config rejected: %v", err)
	}
	invalid := config
	invalid.LeaseTimeout = 2 * invalid.OperationTimeout
	if err := invalid.validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("short lease error = %v, want ErrInvalidConfig", err)
	}
	invalid = config
	invalid.Stream = "bad.stream"
	if err := invalid.validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("invalid stream error = %v, want ErrInvalidConfig", err)
	}
	if got := retryDelay(time.Second, 5*time.Second, 1); got != time.Second {
		t.Fatalf("first retry delay = %s", got)
	}
	if got := retryDelay(time.Second, 5*time.Second, 4); got != 5*time.Second {
		t.Fatalf("capped retry delay = %s", got)
	}
	if got := retryDelay(time.Second, 5*time.Second, 1_000_000); got != 5*time.Second {
		t.Fatalf("large-attempt retry delay = %s", got)
	}
}
