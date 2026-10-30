package edgeoutbox

import (
	"errors"
	"fmt"
	"time"
)

const CommandSubjectPrefix = "cdnca.agent.commands"

var (
	ErrInvalidConfig = errors.New("invalid edge outbox publisher configuration")
	ErrClaimLost     = errors.New("edge outbox claim was lost")
)

type Config struct {
	Stream           string
	BatchSize        int
	LeaseTimeout     time.Duration
	OperationTimeout time.Duration
	PollInterval     time.Duration
	BaseBackoff      time.Duration
	MaxBackoff       time.Duration
	MaxPayloadBytes  int
	MaxErrorBytes    int
}

func DefaultConfig() Config {
	return Config{
		Stream:           "AGENT_COMMANDS",
		BatchSize:        64,
		LeaseTimeout:     30 * time.Second,
		OperationTimeout: 5 * time.Second,
		PollInterval:     500 * time.Millisecond,
		BaseBackoff:      time.Second,
		MaxBackoff:       5 * time.Minute,
		MaxPayloadBytes:  1 << 20,
		MaxErrorBytes:    1024,
	}
}

func (c Config) validate() error {
	if !validNATSName(c.Stream) {
		return fmt.Errorf("%w: stream name is invalid", ErrInvalidConfig)
	}
	if c.BatchSize <= 0 || c.BatchSize > 256 || c.OperationTimeout <= 0 ||
		c.LeaseTimeout < 3*c.OperationTimeout || c.PollInterval <= 0 ||
		c.BaseBackoff <= 0 || c.MaxBackoff < c.BaseBackoff ||
		c.MaxPayloadBytes <= 0 || c.MaxPayloadBytes > 1<<20 ||
		c.MaxErrorBytes <= 0 || c.MaxErrorBytes > 2048 {
		return fmt.Errorf("%w: limits or durations are invalid", ErrInvalidConfig)
	}
	return nil
}

func validNATSName(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}

func retryDelay(base, maximum time.Duration, attempts int) time.Duration {
	delay := base
	for current := 1; current < attempts && delay < maximum; current++ {
		if delay > maximum/2 {
			return maximum
		}
		delay *= 2
	}
	if delay > maximum {
		return maximum
	}
	return delay
}
