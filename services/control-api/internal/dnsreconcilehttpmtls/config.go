package dnsreconcilehttpmtls

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"
)

var ErrInvalidConfig = errors.New("invalid DNS reconcile workload mTLS listener configuration")

type Config struct {
	ListenAddress              string
	ServerCertificateFile      string
	ServerPrivateKeyFile       string
	ClientCAFile               string
	MinimumCertificateValidity time.Duration
	StartupTimeout             time.Duration
	ReadHeaderTimeout          time.Duration
	ReadTimeout                time.Duration
	WriteTimeout               time.Duration
	IdleTimeout                time.Duration
	MaxHeaderBytes             int
	Logger                     *slog.Logger
}

func DefaultConfig() Config {
	return Config{
		ListenAddress: "127.0.0.1:9543", MinimumCertificateValidity: 24 * time.Hour,
		StartupTimeout: 10 * time.Second, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second,
		IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10,
	}
}

func (config *Config) Validate() error {
	if config == nil {
		return invalidConfig("configuration is required")
	}
	host, portText, err := net.SplitHostPort(config.ListenAddress)
	port, portErr := strconv.Atoi(portText)
	if err != nil || portErr != nil || host == "" || port < 1 || port > 65535 ||
		strings.TrimSpace(config.ListenAddress) != config.ListenAddress {
		return invalidConfig("listen address must be an exact host:port value")
	}
	for _, value := range []string{config.ServerCertificateFile, config.ServerPrivateKeyFile, config.ClientCAFile} {
		if value == "" || strings.TrimSpace(value) != value {
			return invalidConfig("TLS material paths are required")
		}
	}
	if config.MinimumCertificateValidity <= 0 || config.MinimumCertificateValidity > 90*24*time.Hour ||
		config.StartupTimeout <= 0 || config.StartupTimeout > 5*time.Minute ||
		config.ReadHeaderTimeout <= 0 || config.ReadHeaderTimeout > 5*time.Minute ||
		config.ReadTimeout < config.ReadHeaderTimeout || config.ReadTimeout > 5*time.Minute ||
		config.WriteTimeout <= 0 || config.WriteTimeout > 5*time.Minute ||
		config.IdleTimeout <= 0 || config.IdleTimeout > 5*time.Minute ||
		config.MaxHeaderBytes < 4<<10 || config.MaxHeaderBytes > 1<<20 {
		return invalidConfig("listener limits are outside the allowed range")
	}
	if config.Logger != nil && config.Logger.Handler() == nil {
		return invalidConfig("logger handler is required")
	}
	return nil
}

func invalidConfig(message string) error { return fmt.Errorf("%w: %s", ErrInvalidConfig, message) }
