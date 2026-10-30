package controlgrpc

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	maxMessageBytes      = 64 << 20
	maxConcurrentStreams = 1 << 16
	maxStartupTimeout    = 5 * time.Minute
	maxShutdownTimeout   = 5 * time.Minute
	maxConnectionTimeout = 2 * time.Minute
	maxKeepaliveDuration = time.Hour
	maxCertificateWindow = 90 * 24 * time.Hour
)

var ErrInvalidConfig = errors.New("invalid ControlInternal gRPC configuration")

type Config struct {
	ListenAddress              string
	ServerCertificateFile      string
	ServerPrivateKeyFile       string
	GatewayClientCAFile        string
	MinimumCertificateValidity time.Duration

	StartupTimeout         time.Duration
	ShutdownTimeout        time.Duration
	MaxReceiveMessageBytes int
	MaxSendMessageBytes    int
	MaxConcurrentStreams   uint32
	ConnectionTimeout      time.Duration
	KeepaliveTime          time.Duration
	KeepaliveTimeout       time.Duration
	MinimumClientPingTime  time.Duration
}

func DefaultConfig() Config {
	return Config{
		ListenAddress:              "127.0.0.1:9091",
		MinimumCertificateValidity: 24 * time.Hour,
		StartupTimeout:             10 * time.Second,
		ShutdownTimeout:            15 * time.Second,
		MaxReceiveMessageBytes:     4 << 20,
		MaxSendMessageBytes:        4 << 20,
		MaxConcurrentStreams:       1024,
		ConnectionTimeout:          10 * time.Second,
		KeepaliveTime:              30 * time.Second,
		KeepaliveTimeout:           10 * time.Second,
		MinimumClientPingTime:      10 * time.Second,
	}
}

func (c Config) Validate() error {
	if err := validateListenAddress(c.ListenAddress); err != nil {
		return err
	}
	if strings.TrimSpace(c.ServerCertificateFile) == "" {
		return invalidConfig("server certificate file is required")
	}
	if strings.TrimSpace(c.ServerPrivateKeyFile) == "" {
		return invalidConfig("server private key file is required")
	}
	if strings.TrimSpace(c.GatewayClientCAFile) == "" {
		return invalidConfig("Gateway client CA file is required")
	}
	if c.MinimumCertificateValidity <= 0 || c.MinimumCertificateValidity > maxCertificateWindow {
		return invalidConfig("minimum certificate validity must be positive and at most 90 days")
	}
	if c.StartupTimeout <= 0 || c.StartupTimeout > maxStartupTimeout {
		return invalidConfig("startup timeout must be positive and at most 5 minutes")
	}
	if c.ShutdownTimeout <= 0 || c.ShutdownTimeout > maxShutdownTimeout {
		return invalidConfig("shutdown timeout must be positive and at most 5 minutes")
	}
	if c.MaxReceiveMessageBytes <= 0 || c.MaxReceiveMessageBytes > maxMessageBytes {
		return invalidConfig("maximum receive message size must be positive and at most 64 MiB")
	}
	if c.MaxSendMessageBytes <= 0 || c.MaxSendMessageBytes > maxMessageBytes {
		return invalidConfig("maximum send message size must be positive and at most 64 MiB")
	}
	if c.MaxConcurrentStreams == 0 || c.MaxConcurrentStreams > maxConcurrentStreams {
		return invalidConfig("maximum concurrent streams must be between 1 and 65536")
	}
	if c.ConnectionTimeout <= 0 || c.ConnectionTimeout > maxConnectionTimeout {
		return invalidConfig("connection timeout must be positive and at most 2 minutes")
	}
	if c.KeepaliveTime <= 0 || c.KeepaliveTime > maxKeepaliveDuration {
		return invalidConfig("keepalive time must be positive and at most 1 hour")
	}
	if c.KeepaliveTimeout <= 0 || c.KeepaliveTimeout > maxKeepaliveDuration {
		return invalidConfig("keepalive timeout must be positive and at most 1 hour")
	}
	if c.MinimumClientPingTime <= 0 || c.MinimumClientPingTime > maxKeepaliveDuration {
		return invalidConfig("minimum client ping time must be positive and at most 1 hour")
	}
	return nil
}

func validateListenAddress(address string) error {
	if address == "" || strings.TrimSpace(address) != address {
		return invalidConfig("listen address must be an exact host:port value")
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil || host == "" || portText == "" {
		return invalidConfig("listen address must be an exact host:port value")
	}
	for _, character := range portText {
		if character < '0' || character > '9' {
			return invalidConfig("listen port must be numeric")
		}
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return invalidConfig("listen port must be between 1 and 65535")
	}
	if net.ParseIP(strings.TrimSuffix(host, ".")) == nil && !validHostname(host) {
		return invalidConfig("listen host must be an IP address or DNS hostname")
	}
	return nil
}

func validHostname(host string) bool {
	if len(host) == 0 || len(host) > 253 || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
				(character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func invalidConfig(message string) error {
	return fmt.Errorf("%w: %s", ErrInvalidConfig, message)
}
