package edgeartifact

import (
	"fmt"
	"time"
)

const (
	DefaultMaxChunkBytes   = 256 << 10
	HardMaxChunkBytes      = 1 << 20
	DefaultMaxRequestBytes = 4 << 10
	HardMaxRequestBytes    = 16 << 10
	maxStoredArtifactBytes = 4 << 20
)

type Config struct {
	MaxChunkBytes   int
	MaxRequestBytes int
	MaxFutureSkew   time.Duration
	MaxRequestAge   time.Duration
}

func DefaultConfig() Config {
	return Config{
		MaxChunkBytes:   DefaultMaxChunkBytes,
		MaxRequestBytes: DefaultMaxRequestBytes,
		MaxFutureSkew:   5 * time.Minute,
		MaxRequestAge:   15 * time.Minute,
	}
}

func (c Config) validate() error {
	if c.MaxChunkBytes <= 0 || c.MaxChunkBytes > HardMaxChunkBytes ||
		c.MaxRequestBytes <= 0 || c.MaxRequestBytes > HardMaxRequestBytes ||
		c.MaxFutureSkew <= 0 || c.MaxRequestAge <= 0 {
		return fmt.Errorf("%w: limits and time windows are invalid", ErrInvalidConfig)
	}
	return nil
}
