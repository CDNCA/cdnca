package main

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const (
	defaultHealthAddress      = "127.0.0.1:8082"
	defaultHealthCheckTimeout = 2 * time.Second
	defaultStartupTimeout     = 15 * time.Second
	defaultShutdownTimeout    = 15 * time.Second
)

type config struct {
	enrollmentAddress   string
	agentAddress        string
	agentPublicEndpoint string
	healthAddress       string
	instanceID          string
	version             string
	// trustedProxiesFile lists trusted CDN back-to-origin ranges
	// ("cidr=Header" lines, ADR 0013 §4.4); empty = the shipped Cloudflare list.
	trustedProxiesFile string

	serverCertificateFile string
	serverKeyFile         string
	// tunnelCertificateFile/tunnelKeyFile: optional public certificate for
	// the outer TLS of WebSocket tunnels (CDN origin verification); both or
	// neither.
	tunnelCertificateFile string
	tunnelKeyFile         string
	agentClientCAFile     string

	controlAddress              string
	controlServerName           string
	controlCertificateFile      string
	controlKeyFile              string
	controlServerCAFile         string
	controlClientWorkloadURISAN string

	redisURL              string
	natsURL               string
	telemetryNATSURL      string
	telemetryNATSUser     string
	telemetryNATSPassword string

	healthCheckTimeout time.Duration
	startupTimeout     time.Duration
	shutdownTimeout    time.Duration
}

func loadConfig() (config, error) {
	return readConfig(os.LookupEnv)
}

func readConfig(lookup func(string) (string, bool)) (config, error) {
	required := func(name string) (string, error) {
		rawValue, ok := lookup(name)
		value := strings.TrimSpace(rawValue)
		if !ok || value == "" {
			return "", fmt.Errorf("%s is required", name)
		}
		if (name == "CDNCA_CONTROL_CLIENT_WORKLOAD_URI_SAN" || name == "CDNCA_TELEMETRY_NATS_URL") && rawValue != value {
			return "", fmt.Errorf("%s is invalid", name)
		}
		return value, nil
	}
	optionalDuration := func(name string, fallback time.Duration) (time.Duration, error) {
		value, ok := lookup(name)
		if !ok {
			return fallback, nil
		}
		if value == "" || value != strings.TrimSpace(value) {
			return 0, fmt.Errorf("%s must be a positive duration", name)
		}
		duration, err := time.ParseDuration(value)
		if err != nil || duration <= 0 {
			return 0, fmt.Errorf("%s must be a positive duration", name)
		}
		return duration, nil
	}
	optionalAddress := func(name, fallback string) (string, error) {
		value, ok := lookup(name)
		if !ok {
			return fallback, nil
		}
		if value == "" || value != strings.TrimSpace(value) {
			return "", fmt.Errorf("%s must be a host:port listener", name)
		}
		return value, nil
	}

	values := make(map[string]string, 16)
	for _, name := range []string{
		"CDNCA_GATEWAY_ENROLLMENT_ADDR",
		"CDNCA_GATEWAY_AGENT_ADDR",
		"CDNCA_GATEWAY_INSTANCE_ID",
		"CDNCA_GATEWAY_VERSION",
		"CDNCA_GATEWAY_TLS_CERT_FILE",
		"CDNCA_GATEWAY_TLS_KEY_FILE",
		"CDNCA_GATEWAY_AGENT_CLIENT_CA_FILE",
		"CDNCA_CONTROL_ADDRESS",
		"CDNCA_CONTROL_SERVER_NAME",
		"CDNCA_CONTROL_CLIENT_CERT_FILE",
		"CDNCA_CONTROL_CLIENT_KEY_FILE",
		"CDNCA_CONTROL_SERVER_CA_FILE",
		"CDNCA_CONTROL_CLIENT_WORKLOAD_URI_SAN",
		"CDNCA_REDIS_URL",
		"CDNCA_NATS_URL",
		"CDNCA_TELEMETRY_NATS_URL",
	} {
		value, err := required(name)
		if err != nil {
			return config{}, err
		}
		values[name] = value
	}
	telemetryNATSUser, _ := lookup("CDNCA_TELEMETRY_NATS_USER")
	telemetryNATSPassword, _ := lookup("CDNCA_TELEMETRY_NATS_PASSWORD")
	if (telemetryNATSUser == "") != (telemetryNATSPassword == "") {
		return config{}, fmt.Errorf("CDNCA_TELEMETRY_NATS_USER and CDNCA_TELEMETRY_NATS_PASSWORD must be set together")
	}
	healthAddress, err := optionalAddress("CDNCA_GATEWAY_HEALTH_ADDR", defaultHealthAddress)
	if err != nil {
		return config{}, err
	}
	agentPublicEndpoint, err := optionalAddress("CDNCA_GATEWAY_AGENT_PUBLIC_ENDPOINT", values["CDNCA_GATEWAY_AGENT_ADDR"])
	if err != nil {
		return config{}, err
	}
	healthCheckTimeout, err := optionalDuration("CDNCA_GATEWAY_HEALTH_CHECK_TIMEOUT", defaultHealthCheckTimeout)
	if err != nil {
		return config{}, err
	}
	startupTimeout, err := optionalDuration("CDNCA_GATEWAY_STARTUP_TIMEOUT", defaultStartupTimeout)
	if err != nil {
		return config{}, err
	}
	shutdownTimeout, err := optionalDuration("CDNCA_GATEWAY_SHUTDOWN_TIMEOUT", defaultShutdownTimeout)
	if err != nil {
		return config{}, err
	}
	trustedProxiesFile, _ := lookup("CDNCA_GATEWAY_TRUSTED_PROXIES_FILE")
	tunnelCertificateFile, _ := lookup("CDNCA_GATEWAY_TUNNEL_TLS_CERT_FILE")
	tunnelKeyFile, _ := lookup("CDNCA_GATEWAY_TUNNEL_TLS_KEY_FILE")
	if (tunnelCertificateFile == "") != (tunnelKeyFile == "") ||
		(tunnelCertificateFile != "" && (!filepath.IsAbs(tunnelCertificateFile) || !filepath.IsAbs(tunnelKeyFile))) {
		return config{}, fmt.Errorf("CDNCA_GATEWAY_TUNNEL_TLS_CERT_FILE and CDNCA_GATEWAY_TUNNEL_TLS_KEY_FILE must be absolute paths set together")
	}
	cfg := config{
		enrollmentAddress:           values["CDNCA_GATEWAY_ENROLLMENT_ADDR"],
		agentAddress:                values["CDNCA_GATEWAY_AGENT_ADDR"],
		agentPublicEndpoint:         agentPublicEndpoint,
		healthAddress:               healthAddress,
		instanceID:                  values["CDNCA_GATEWAY_INSTANCE_ID"],
		version:                     values["CDNCA_GATEWAY_VERSION"],
		trustedProxiesFile:          trustedProxiesFile,
		serverCertificateFile:       values["CDNCA_GATEWAY_TLS_CERT_FILE"],
		serverKeyFile:               values["CDNCA_GATEWAY_TLS_KEY_FILE"],
		tunnelCertificateFile:       tunnelCertificateFile,
		tunnelKeyFile:               tunnelKeyFile,
		agentClientCAFile:           values["CDNCA_GATEWAY_AGENT_CLIENT_CA_FILE"],
		controlAddress:              values["CDNCA_CONTROL_ADDRESS"],
		controlServerName:           values["CDNCA_CONTROL_SERVER_NAME"],
		controlCertificateFile:      values["CDNCA_CONTROL_CLIENT_CERT_FILE"],
		controlKeyFile:              values["CDNCA_CONTROL_CLIENT_KEY_FILE"],
		controlServerCAFile:         values["CDNCA_CONTROL_SERVER_CA_FILE"],
		controlClientWorkloadURISAN: values["CDNCA_CONTROL_CLIENT_WORKLOAD_URI_SAN"],
		redisURL:                    values["CDNCA_REDIS_URL"],
		natsURL:                     values["CDNCA_NATS_URL"],
		telemetryNATSURL:            values["CDNCA_TELEMETRY_NATS_URL"],
		telemetryNATSUser:           telemetryNATSUser,
		telemetryNATSPassword:       telemetryNATSPassword,
		healthCheckTimeout:          healthCheckTimeout,
		startupTimeout:              startupTimeout,
		shutdownTimeout:             shutdownTimeout,
	}
	if err := cfg.validate(); err != nil {
		return config{}, err
	}
	return cfg, nil
}

func (c config) validate() error {
	if err := validateListenAddress("CDNCA_GATEWAY_ENROLLMENT_ADDR", c.enrollmentAddress); err != nil {
		return err
	}
	if err := validateListenAddress("CDNCA_GATEWAY_AGENT_ADDR", c.agentAddress); err != nil {
		return err
	}
	if err := validateGatewayPublicEndpoint(c.agentPublicEndpoint); err != nil {
		return err
	}
	if err := validateListenAddress("CDNCA_GATEWAY_HEALTH_ADDR", c.healthAddress); err != nil {
		return err
	}
	ports := make(map[string]string, 3)
	for _, listener := range []struct{ name, address string }{
		{name: "CDNCA_GATEWAY_ENROLLMENT_ADDR", address: c.enrollmentAddress},
		{name: "CDNCA_GATEWAY_AGENT_ADDR", address: c.agentAddress},
		{name: "CDNCA_GATEWAY_HEALTH_ADDR", address: c.healthAddress},
	} {
		_, port, _ := net.SplitHostPort(listener.address)
		if previous, exists := ports[port]; exists {
			return fmt.Errorf("%s and %s must use different ports", previous, listener.name)
		}
		ports[port] = listener.name
	}
	parsedID, err := uuid.Parse(c.instanceID)
	if err != nil || parsedID.String() != c.instanceID {
		return fmt.Errorf("CDNCA_GATEWAY_INSTANCE_ID must be a canonical UUID")
	}
	if !validVersion(c.version) {
		return fmt.Errorf("CDNCA_GATEWAY_VERSION is invalid")
	}
	if err := validateControlAddress(c.controlAddress); err != nil {
		return err
	}
	if !validServerName(c.controlServerName) {
		return fmt.Errorf("CDNCA_CONTROL_SERVER_NAME is invalid")
	}
	if !validWorkloadURISAN(c.controlClientWorkloadURISAN) {
		return fmt.Errorf("CDNCA_CONTROL_CLIENT_WORKLOAD_URI_SAN is invalid")
	}
	if _, err := redis.ParseURL(c.redisURL); err != nil {
		return fmt.Errorf("CDNCA_REDIS_URL is invalid")
	}
	natsURL, err := url.Parse(c.natsURL)
	if err != nil || natsURL.Host == "" || (natsURL.Scheme != "nats" && natsURL.Scheme != "tls" && natsURL.Scheme != "wss") {
		return fmt.Errorf("CDNCA_NATS_URL must use nats://, tls:// or wss://")
	}
	if err := validateTelemetryNATSURL(c.telemetryNATSURL); err != nil {
		return err
	}
	if (c.telemetryNATSUser == "") != (c.telemetryNATSPassword == "") {
		return fmt.Errorf("CDNCA_TELEMETRY_NATS_USER and CDNCA_TELEMETRY_NATS_PASSWORD must be set together")
	}
	if c.healthCheckTimeout <= 0 || c.startupTimeout <= 0 || c.shutdownTimeout <= 0 {
		return fmt.Errorf("gateway lifecycle timeouts must be positive")
	}
	if c.healthCheckTimeout > c.startupTimeout || c.healthCheckTimeout >= c.shutdownTimeout {
		return fmt.Errorf("Gateway health check timeout must fit within startup and shutdown timeouts")
	}
	return nil
}

func validateTelemetryNATSURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("CDNCA_TELEMETRY_NATS_URL is invalid")
	}
	port := parsed.Port()
	if port == "" {
		return fmt.Errorf("CDNCA_TELEMETRY_NATS_URL is invalid")
	}
	if err := validatePort(port); err != nil {
		return fmt.Errorf("CDNCA_TELEMETRY_NATS_URL is invalid")
	}
	loopback := strings.EqualFold(parsed.Hostname(), "localhost")
	if address := net.ParseIP(parsed.Hostname()); address != nil {
		loopback = address.IsLoopback()
	}
	if parsed.Scheme == "nats" && loopback || (parsed.Scheme == "tls" || parsed.Scheme == "wss") && !loopback {
		return nil
	}
	return fmt.Errorf("CDNCA_TELEMETRY_NATS_URL must use nats:// on loopback or tls:// / wss:// remotely")
}

func validateGatewayPublicEndpoint(value string) error {
	if value == "" || value != strings.TrimSpace(value) {
		return fmt.Errorf("CDNCA_GATEWAY_AGENT_PUBLIC_ENDPOINT must be a host:port endpoint")
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil || host == "" || port == "" {
		return fmt.Errorf("CDNCA_GATEWAY_AGENT_PUBLIC_ENDPOINT must be a host:port endpoint")
	}
	parsed, err := strconv.ParseUint(port, 10, 16)
	if err != nil || parsed == 0 {
		return fmt.Errorf("CDNCA_GATEWAY_AGENT_PUBLIC_ENDPOINT must be a host:port endpoint")
	}
	return nil
}

func validWorkloadURISAN(value string) bool {
	if value == "" || len(value) > 256 || strings.TrimSpace(value) != value || strings.Contains(value, "*") {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.IsAbs() && parsed.Scheme != "" && parsed.Host != "" && parsed.Path != "" &&
		!strings.Contains(parsed.Path, "*") && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" &&
		parsed.String() == value
}

func validServerName(name string) bool {
	if net.ParseIP(name) != nil {
		return true
	}
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func validVersion(version string) bool {
	if len(version) == 0 || len(version) > 128 {
		return false
	}
	for index, character := range version {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') {
			continue
		}
		if index > 0 && (character == '.' || character == '-' || character == '_' || character == '+') {
			continue
		}
		return false
	}
	return true
}

func validateListenAddress(name, address string) error {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%s must be a host:port listener", name)
	}
	if err := validatePort(port); err != nil {
		return fmt.Errorf("%s has an invalid port", name)
	}
	return nil
}

func validateControlAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || strings.TrimSpace(host) == "" || strings.Contains(address, "://") {
		return fmt.Errorf("CDNCA_CONTROL_ADDRESS must be a host:port target")
	}
	if err := validatePort(port); err != nil {
		return fmt.Errorf("CDNCA_CONTROL_ADDRESS has an invalid port")
	}
	return nil
}

func validatePort(port string) error {
	value, err := strconv.Atoi(port)
	if err != nil || value < 1 || value > 65535 {
		return fmt.Errorf("invalid port")
	}
	return nil
}
