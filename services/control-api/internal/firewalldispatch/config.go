package firewalldispatch

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	CommandStream        = "AGENT_FIREWALL_COMMANDS"
	StatusStream         = "AGENT_FIREWALL_STATUS"
	CommandSubjectPrefix = "cdnca.agent.firewall.commands"
	StatusSubjectPrefix  = "cdnca.agent.firewall.status"
)

var ErrInvalidConfig = errors.New("invalid firewall dispatcher configuration")

type Config struct {
	CommandStream        string
	StatusStream         string
	CommandSubjectPrefix string
	StatusSubjectPrefix  string
	StatusConsumer       string
	BatchSize            int
	LeaseTimeout         time.Duration
	OperationTimeout     time.Duration
	PollInterval         time.Duration
	BaseBackoff          time.Duration
	MaxBackoff           time.Duration
	MaxAttempts          int
	MaxCommandBytes      int
	MaxStatusBytes       int
}

func DefaultConfig() Config {
	return Config{
		CommandStream: CommandStream, StatusStream: StatusStream,
		CommandSubjectPrefix: CommandSubjectPrefix, StatusSubjectPrefix: StatusSubjectPrefix,
		StatusConsumer: "control_firewall_dispatch", BatchSize: 4,
		LeaseTimeout: 30 * time.Second, OperationTimeout: 5 * time.Second,
		PollInterval: 500 * time.Millisecond, BaseBackoff: time.Second, MaxBackoff: 5 * time.Minute,
		MaxAttempts: 16, MaxCommandBytes: 1 << 20, MaxStatusBytes: 1 << 20,
	}
}

func (c Config) validate() error {
	if !validNATSName(c.CommandStream) || !validNATSName(c.StatusStream) || !validNATSName(c.StatusConsumer) ||
		!validSubjectPrefix(c.CommandSubjectPrefix) || !validSubjectPrefix(c.StatusSubjectPrefix) ||
		c.CommandSubjectPrefix == c.StatusSubjectPrefix {
		return fmt.Errorf("%w: NATS names are invalid", ErrInvalidConfig)
	}
	if c.BatchSize <= 0 || c.BatchSize > 64 || c.OperationTimeout <= 0 ||
		c.LeaseTimeout < time.Duration(c.BatchSize+1)*c.OperationTimeout ||
		c.PollInterval <= 0 || c.BaseBackoff <= 0 || c.MaxBackoff < c.BaseBackoff || c.MaxAttempts != 16 ||
		c.MaxCommandBytes <= 0 || c.MaxCommandBytes > 1<<20 || c.MaxStatusBytes <= 0 || c.MaxStatusBytes > 1<<20 {
		return fmt.Errorf("%w: limits or durations are invalid", ErrInvalidConfig)
	}
	return nil
}

func validNATSName(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-' || char == '_' {
			continue
		}
		return false
	}
	return true
}

func validSubjectPrefix(value string) bool {
	if strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, token := range strings.Split(value, ".") {
		if !validNATSName(token) {
			return false
		}
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
