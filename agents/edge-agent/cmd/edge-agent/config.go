package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/diskguard"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/enrollment"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/logdiskguard"
	"github.com/google/uuid"
)

const maxConfigFileBytes = 64 << 10

type fileConfig struct {
	Version                 int                     `json:"version"`
	NodeID                  string                  `json:"node_id,omitempty"`
	IngressSourceIPv4       string                  `json:"ingress_source_ipv4,omitempty"`
	IngressSourceIPv6       string                  `json:"ingress_source_ipv6,omitempty"`
	ArtifactEncryptionKeyID string                  `json:"artifact_encryption_key_id,omitempty"`
	IdentityDir             string                  `json:"identity_dir,omitempty"`
	ArtifactTrustFile       string                  `json:"artifact_trust_file"`
	DeploymentRoot          string                  `json:"deployment_root"`
	JournalDir              string                  `json:"journal_dir"`
	Gateway                 gatewaySettings         `json:"gateway"`
	OpenResty               openRestySettings       `json:"openresty"`
	CertificateRuntime      certificateSettings     `json:"certificate_runtime"`
	Limits                  limitSettings           `json:"limits"`
	Timeouts                timeoutSettings         `json:"timeouts"`
	DiskGuard               diskGuardSettings       `json:"disk_guard"`
	Telemetry               telemetrySettings       `json:"telemetry"`
	SecurityRuntime         securityRuntimeSettings `json:"security_runtime"`
	Upgrade                 upgradeSettings         `json:"upgrade"`
	DrainRuntime            drainRuntimeSettings    `json:"drain_runtime"`
	NodeMonitoring          nodeMonitoringSettings  `json:"node_monitoring"`
	MarketProbe             marketProbeSettings     `json:"market_probe"`
	CacheTask               cacheTaskSettings       `json:"cache_task"`
	DynamicRouting          dynamicRoutingSettings  `json:"dynamic_routing"`
	Identity                *enrollment.Identity    `json:"-"`
	ConfigPath              string                  `json:"-"`
	WAFEngine               wafEngineSettings       `json:"waf_engine"`
	XDP                     xdpSettings             `json:"xdp"`
}

type gatewaySettings struct {
	Address              string `json:"address"`
	ServerName           string `json:"server_name"`
	RootCAFile           string `json:"root_ca_file"`
	ClientCertificate    string `json:"client_certificate_file,omitempty"`
	ClientPrivateKeyFile string `json:"client_private_key_file,omitempty"`
	// EnrollmentAddress is the Gateway's server-TLS enrollment listener
	// (host:port), used to recover an expired certificate (ADR 0013 GW-02).
	// Empty: the gateway.address host on DefaultEnrollmentPort.
	EnrollmentAddress string `json:"enrollment_address,omitempty"`
	// Transport "grpc" (default) dials address directly; "ws" opens the
	// WebSocket tunnel at address (a CDN entrance or the gateway port,
	// ADR 0013 §4.2). TunnelHost is the outer SNI/Host when it differs from
	// the address host; TunnelAudience defaults to upgrade.installation_id.
	Transport      string `json:"transport,omitempty"`
	TunnelHost     string `json:"tunnel_host,omitempty"`
	TunnelAudience string `json:"tunnel_audience,omitempty"`
	// Endpoints are tried in order after address (ADR 0013 §4.5): other
	// gateways or another entrance (CDN 443 ws / direct grpc) of the same one.
	Endpoints []gatewayEndpointSettings `json:"endpoints,omitempty"`
}

type gatewayEndpointSettings struct {
	Address    string `json:"address"`
	ServerName string `json:"server_name"`
	Transport  string `json:"transport,omitempty"`
	TunnelHost string `json:"tunnel_host,omitempty"`
}

// tunnelAudience is the installation ID signed into tunnel upgrade tokens.
func (c fileConfig) tunnelAudience() string {
	if c.Gateway.TunnelAudience != "" {
		return c.Gateway.TunnelAudience
	}
	return c.Upgrade.InstallationID
}

// DefaultEnrollmentPort is the Gateway enrollment listener port (install-control.sh).
const DefaultEnrollmentPort = "19443"

// enrollmentAddress is where certificate recovery dials.
func (g gatewaySettings) enrollmentAddress() string {
	if g.EnrollmentAddress != "" {
		return g.EnrollmentAddress
	}
	host, _, err := net.SplitHostPort(g.Address)
	if err != nil {
		return ""
	}
	return net.JoinHostPort(host, DefaultEnrollmentPort)
}

type openRestySettings struct {
	Binary     string `json:"binary"`
	ConfigFile string `json:"config_file"`
	HealthURL  string `json:"health_url"`
	Version    string `json:"version,omitempty"`
	// SystemdService marks the installed native profile (workers run as
	// cdnca-runtime, dynamicRoutingGlobals). No unit runs OpenResty: the
	// dynamic routing runtime starts and owns the master (dynroute.Recover).
	// The name stays because installed configurations carry it.
	SystemdService string `json:"systemd_service,omitempty"`
	// HTTP3Probe is the absolute path of the packaged h3probe (HTTP/3 health
	// probe). Without it the node does not declare HTTP_3.
	HTTP3Probe string `json:"http3_probe,omitempty"`
}

type certificateSettings struct {
	StateRoot     string `json:"state_root"`
	ListenAddress string `json:"listen_address"`
	ListenPort    uint16 `json:"listen_port"`
}

type limitSettings struct {
	MaxCommandBytes       int    `json:"max_command_bytes"`
	MaxStatusBytes        int    `json:"max_status_bytes"`
	MaxArtifactBytes      uint64 `json:"max_artifact_bytes"`
	MaxDecompressedBytes  int64  `json:"max_decompressed_bytes"`
	MaxArtifactChunkBytes uint32 `json:"max_artifact_chunk_bytes"`
	MaxActiveDeployments  int    `json:"max_active_deployments"`
	CommandQueueSize      int    `json:"command_queue_size"`
	MaxFiles              int    `json:"max_files"`
	MaxFileBytes          int64  `json:"max_file_bytes"`
	MaxTotalBytes         int64  `json:"max_total_bytes"`
	RetainReleases        int    `json:"retain_releases"`
}

type timeoutSettings struct {
	Handshake      string `json:"handshake"`
	ArtifactFetch  string `json:"artifact_fetch"`
	InitialBackoff string `json:"initial_backoff"`
	MaximumBackoff string `json:"maximum_backoff"`
	Precheck       string `json:"precheck"`
	Reload         string `json:"reload"`
	Health         string `json:"health"`
	HealthInterval string `json:"health_interval"`
	HealthRequest  string `json:"health_request"`
}

type parsedTimeouts struct {
	Handshake               time.Duration
	ArtifactFetch           time.Duration
	InitialBackoff          time.Duration
	MaximumBackoff          time.Duration
	Precheck                time.Duration
	Reload                  time.Duration
	Health                  time.Duration
	HealthInterval          time.Duration
	HealthRequest           time.Duration
	TelemetrySoftAgeLimit   time.Duration
	TelemetryHardAgeLimit   time.Duration
	TelemetryEmptyInterval  time.Duration
	TelemetryHandshake      time.Duration
	TelemetryAck            time.Duration
	TelemetryInitialBackoff time.Duration
	TelemetryMaximumBackoff time.Duration
	DrainCommandLimit       time.Duration
	DrainResumeInterval     time.Duration
}

type diskGuardSettings struct {
	Enabled           bool   `json:"enabled"`
	ConfigID          string `json:"config_id"`
	Revision          uint64 `json:"revision"`
	LogRoot           string `json:"log_root"`
	LockPath          string `json:"lock_path"`
	LowWatermark      uint16 `json:"low_watermark"`
	HighWatermark     uint16 `json:"high_watermark"`
	EvaluationPeriod  string `json:"evaluation_period"`
	MinimumAge        string `json:"minimum_age"`
	MinimumRemain     int    `json:"minimum_remain"`
	MaxDeletedFiles   int    `json:"max_deleted_files"`
	MaxAllocatedBytes uint64 `json:"max_allocated_bytes"`
	MinimumFreeBytes  uint64 `json:"minimum_free_bytes"`
	MaxRoundDuration  string `json:"max_round_duration"`
	DryRun            bool   `json:"dry_run"`
}

type telemetrySettings struct {
	Enabled                   bool   `json:"enabled"`
	IndependentMetricsEnabled bool   `json:"independent_metrics_enabled"`
	SpoolRoot                 string `json:"spool_root"`
	MaxEventBytes             int    `json:"max_event_bytes"`
	MaxSegmentBytes           int64  `json:"max_segment_bytes"`
	SoftLimitBytes            int64  `json:"soft_limit_bytes"`
	HardLimitBytes            int64  `json:"hard_limit_bytes"`
	MaxTenantBytes            int64  `json:"max_tenant_bytes"`
	MaxSpoolBatchEvents       int    `json:"max_spool_batch_events"`
	FlushBatchEvents          int    `json:"flush_batch_events"`
	PressureMode              string `json:"pressure_mode"`
	AccessSampleEvery         uint32 `json:"access_sample_every"`
	SecuritySampleEvery       uint32 `json:"security_sample_every"`
	SoftAgeLimit              string `json:"soft_age_limit"`
	HardAgeLimit              string `json:"hard_age_limit"`
	EmptyInterval             string `json:"empty_interval"`
	HandshakeTimeout          string `json:"handshake_timeout"`
	AckTimeout                string `json:"ack_timeout"`
	InitialBackoff            string `json:"initial_backoff"`
	MaximumBackoff            string `json:"maximum_backoff"`
	MaxRecordsPerBatch        int    `json:"max_records_per_batch"`
	MaxRecordBytes            int    `json:"max_record_bytes"`
	MaxBatchBytes             int    `json:"max_batch_bytes"`
}

type upgradeSettings struct {
	Enabled                   bool     `json:"enabled"`
	InstallationID            string   `json:"installation_id"`
	Root                      string   `json:"root"`
	ControlExecutionTrustFile string   `json:"control_execution_trust_file"`
	EdgeExecutionTrustFile    string   `json:"edge_execution_trust_file"`
	InstallerReceiptTrustFile string   `json:"installer_receipt_trust_file"`
	DownloadHost              string   `json:"download_host"`
	DownloadAddresses         []string `json:"download_addresses"`
	DownloadPort              uint16   `json:"download_port"`
	DownloadRootCAFile        string   `json:"download_root_ca_file"`
	Timeout                   string   `json:"timeout"`
	MaxArtifactBytes          int64    `json:"max_artifact_bytes"`
	DiskReserveBytes          int64    `json:"disk_reserve_bytes"`
}

type drainRuntimeSettings struct {
	Enabled        bool   `json:"enabled"`
	Prefix         string `json:"prefix"`
	StateRoot      string `json:"state_root"`
	CommandLimit   string `json:"command_limit"`
	ResumeInterval string `json:"resume_interval"`
}

func defaultFileConfig() fileConfig {
	return fileConfig{
		Version: 1,
		// Dynamic routing is the only node runtime (1.0.35 baseline).
		DynamicRouting: dynamicRoutingSettings{Enabled: true},
		OpenResty: openRestySettings{
			Binary:     "/usr/local/openresty/bin/openresty",
			ConfigFile: "nginx.conf",
			HealthURL:  "http://127.0.0.1:18080/healthz",
		},
		Limits: limitSettings{
			MaxCommandBytes:       1 << 20,
			MaxStatusBytes:        256 << 10,
			MaxArtifactBytes:      128 << 20,
			MaxDecompressedBytes:  128 << 20,
			MaxArtifactChunkBytes: 1 << 20,
			MaxActiveDeployments:  128,
			CommandQueueSize:      32,
			MaxFiles:              4096,
			MaxFileBytes:          16 << 20,
			MaxTotalBytes:         128 << 20,
			RetainReleases:        5,
		},
		Timeouts: timeoutSettings{
			Handshake:      "10s",
			ArtifactFetch:  "2m",
			InitialBackoff: "250ms",
			MaximumBackoff: "30s",
			Precheck:       "15s",
			Reload:         "15s",
			Health:         "30s",
			HealthInterval: "500ms",
			HealthRequest:  "2s",
		},
		DiskGuard: diskGuardSettings{
			Enabled: false, ConfigID: "edge-agent-logs", Revision: 1,
			LogRoot: "/var/log/cdnca-edge-agent", LockPath: "/var/lib/cdnca-edge-agent/diskguard.lock",
			LowWatermark: 8000, HighWatermark: 9000, EvaluationPeriod: "30s",
			MinimumAge: "24h", MinimumRemain: 7, MaxDeletedFiles: 100,
			MaxAllocatedBytes: 1 << 30, MinimumFreeBytes: 512 << 20,
			MaxRoundDuration: "2s", DryRun: true,
		},
		Telemetry: telemetrySettings{
			Enabled: false, SpoolRoot: "/var/lib/cdnca-edge-agent/event-spool",
			MaxEventBytes: 64 << 10, MaxSegmentBytes: 16 << 20,
			SoftLimitBytes: 1 << 30, HardLimitBytes: 2 << 30, MaxTenantBytes: 1 << 30,
			MaxSpoolBatchEvents: 10000, FlushBatchEvents: 1000, PressureMode: "backpressure",
			SoftAgeLimit: "24h", HardAgeLimit: "168h", EmptyInterval: "1s",
			HandshakeTimeout: "10s", AckTimeout: "10s", InitialBackoff: "250ms", MaximumBackoff: "30s",
			MaxRecordsPerBatch: 64, MaxRecordBytes: 1 << 20, MaxBatchBytes: 4 << 20,
		},
		Upgrade:        upgradeSettings{Enabled: false},
		DrainRuntime:   drainRuntimeSettings{Enabled: false},
		NodeMonitoring: nodeMonitoringSettings{Enabled: false},
	}
}

func loadConfig(path string) (fileConfig, parsedTimeouts, error) {
	physicalPath, err := canonicalConfigPath(path)
	if err != nil {
		return fileConfig{}, parsedTimeouts{}, err
	}
	content, err := readConfigFile(physicalPath)
	if err != nil {
		return fileConfig{}, parsedTimeouts{}, err
	}
	config, timeouts, err := decodeConfigAtPath(content, physicalPath)
	if err != nil {
		return fileConfig{}, parsedTimeouts{}, err
	}
	if config.Version == 2 {
		// An expired certificate does not stop the agent (ADR 0013 GW-02): it
		// recovers the certificate before connecting; OpenResty keeps serving.
		identity, err := enrollment.LoadIdentityAllowingExpired(config.IdentityDir, time.Now())
		if err != nil {
			return fileConfig{}, parsedTimeouts{}, errors.New("load enrollment identity")
		}
		config.Identity = &identity
	}
	guardConfig, err := config.diskGuardConfig()
	if err != nil {
		return fileConfig{}, parsedTimeouts{}, err
	}
	if config.DiskGuard.Enabled {
		if _, err := diskguard.New(guardConfig, diskguard.Options{}); err != nil {
			return fileConfig{}, parsedTimeouts{}, errors.New("disk_guard runtime paths are unsafe")
		}
	}
	return config, timeouts, nil
}

func readConfigFile(path string) ([]byte, error) {
	physicalPath, err := canonicalConfigPath(path)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(physicalPath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open configuration: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() < 0 || info.Size() > maxConfigFileBytes {
		return nil, errors.New("configuration must be an owner-only regular file within the size limit")
	}
	content, err := io.ReadAll(io.LimitReader(file, maxConfigFileBytes+1))
	if err != nil || len(content) > maxConfigFileBytes {
		return nil, errors.New("read configuration")
	}
	return content, nil
}

func canonicalConfigPath(path string) (string, error) {
	if !absoluteCleanPath(path) {
		return "", errors.New("configuration path must be absolute and clean")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("inspect configuration path: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("configuration path cannot be a symbolic link")
	}
	physical, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolve configuration path: %w", err)
	}
	return physical, nil
}

func decodeConfig(content []byte) (fileConfig, parsedTimeouts, error) {
	return decodeConfigAtPath(content, "")
}

func decodeConfigAtPath(content []byte, configPath string) (fileConfig, parsedTimeouts, error) {
	if err := rejectDuplicateJSONKeys(content); err != nil {
		return fileConfig{}, parsedTimeouts{}, fmt.Errorf("invalid configuration JSON: %w", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(content, &fields); err != nil {
		return fileConfig{}, parsedTimeouts{}, fmt.Errorf("invalid configuration JSON: %w", err)
	}
	if _, exists := fields["version"]; !exists {
		return fileConfig{}, parsedTimeouts{}, errors.New("configuration version is required")
	}
	if raw, exists := fields["disk_guard"]; exists {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil || object == nil {
			return fileConfig{}, parsedTimeouts{}, errors.New("disk_guard configuration must be an object")
		}
	}
	if raw, exists := fields["telemetry"]; exists {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil || object == nil {
			return fileConfig{}, parsedTimeouts{}, errors.New("telemetry configuration must be an object")
		}
	}
	if raw, exists := fields["certificate_runtime"]; exists {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil || object == nil {
			return fileConfig{}, parsedTimeouts{}, errors.New("certificate_runtime configuration must be an object")
		}
	} else {
		return fileConfig{}, parsedTimeouts{}, errors.New("certificate_runtime configuration is required")
	}
	if raw, exists := fields["drain_runtime"]; exists {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil || object == nil {
			return fileConfig{}, parsedTimeouts{}, errors.New("drain_runtime configuration must be an object")
		}
	}
	if raw, exists := fields["node_monitoring"]; exists {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil || object == nil {
			return fileConfig{}, parsedTimeouts{}, errors.New("node_monitoring configuration must be an object")
		}
	}
	var version int
	if err := json.Unmarshal(fields["version"], &version); err != nil {
		return fileConfig{}, parsedTimeouts{}, errors.New("configuration version is invalid")
	}
	switch version {
	case 1:
		if _, exists := fields["identity_dir"]; exists {
			return fileConfig{}, parsedTimeouts{}, errors.New("version 1 configuration cannot use identity_dir")
		}
	case 2:
		for _, name := range []string{"node_id", "artifact_encryption_key_id"} {
			if _, exists := fields[name]; exists {
				return fileConfig{}, parsedTimeouts{}, fmt.Errorf("version 2 configuration cannot override %s", name)
			}
		}
		var gatewayFields map[string]json.RawMessage
		if raw, exists := fields["gateway"]; exists {
			if err := json.Unmarshal(raw, &gatewayFields); err != nil {
				return fileConfig{}, parsedTimeouts{}, errors.New("gateway configuration is invalid")
			}
		}
		for _, name := range []string{"client_certificate_file", "client_private_key_file"} {
			if _, exists := gatewayFields[name]; exists {
				return fileConfig{}, parsedTimeouts{}, fmt.Errorf("version 2 configuration cannot override gateway.%s", name)
			}
		}
	default:
		return fileConfig{}, parsedTimeouts{}, errors.New("unsupported configuration version")
	}
	config := defaultFileConfig()
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return fileConfig{}, parsedTimeouts{}, fmt.Errorf("invalid configuration JSON: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fileConfig{}, parsedTimeouts{}, errors.New("invalid configuration JSON: trailing data")
	}
	config.ConfigPath = configPath
	timeouts, err := config.validate()
	if err != nil {
		return fileConfig{}, parsedTimeouts{}, err
	}
	return config, timeouts, nil
}

func (c fileConfig) validate() (parsedTimeouts, error) {
	if c.OpenResty.SystemdService != "" {
		if c.OpenResty.SystemdService != "cdnca-openresty-native.service" {
			return parsedTimeouts{}, errors.New("openresty.systemd_service is invalid")
		}
		if c.DeploymentRoot != "/var/lib/cdnca-edge" || c.OpenResty.Binary != "/usr/local/openresty/bin/openresty" || c.OpenResty.ConfigFile != "nginx.conf" {
			return parsedTimeouts{}, errors.New("native OpenResty service requires the installed native profile")
		}
	}
	switch c.Version {
	case 1:
		if parsed, err := uuid.Parse(c.NodeID); err != nil || parsed.String() != c.NodeID {
			return parsedTimeouts{}, errors.New("node_id must be a canonical UUID")
		}
		if !boundedIdentifier(c.ArtifactEncryptionKeyID) {
			return parsedTimeouts{}, errors.New("artifact_encryption_key_id is required")
		}
		if c.IdentityDir != "" {
			return parsedTimeouts{}, errors.New("version 1 configuration cannot use identity_dir")
		}
	case 2:
		if !absoluteCleanPath(c.IdentityDir) || c.IdentityDir == string(filepath.Separator) {
			return parsedTimeouts{}, errors.New("identity_dir must be an absolute clean non-root path")
		}
		if c.NodeID != "" || c.ArtifactEncryptionKeyID != "" || c.Gateway.ClientCertificate != "" || c.Gateway.ClientPrivateKeyFile != "" {
			return parsedTimeouts{}, errors.New("version 2 identity fields cannot be overridden")
		}
		if err := rejectSymlinkAncestors(c.IdentityDir); err != nil {
			return parsedTimeouts{}, fmt.Errorf("identity_dir is unsafe: %w", err)
		}
	default:
		return parsedTimeouts{}, errors.New("unsupported configuration version")
	}
	if err := validateIngressSourceAddress("ingress_source_ipv4", c.IngressSourceIPv4, true); err != nil {
		return parsedTimeouts{}, err
	}
	if err := validateIngressSourceAddress("ingress_source_ipv6", c.IngressSourceIPv6, false); err != nil {
		return parsedTimeouts{}, err
	}
	for name, path := range map[string]string{
		"artifact_trust_file":  c.ArtifactTrustFile,
		"deployment_root":      c.DeploymentRoot,
		"journal_dir":          c.JournalDir,
		"gateway.root_ca_file": c.Gateway.RootCAFile,
		"openresty.binary":     c.OpenResty.Binary,
	} {
		if !absoluteCleanPath(path) {
			return parsedTimeouts{}, fmt.Errorf("%s must be an absolute clean path", name)
		}
	}
	if c.Version == 1 {
		for name, path := range map[string]string{
			"gateway.client_certificate": c.Gateway.ClientCertificate,
			"gateway.client_private_key": c.Gateway.ClientPrivateKeyFile,
		} {
			if !absoluteCleanPath(path) {
				return parsedTimeouts{}, fmt.Errorf("%s must be an absolute clean path", name)
			}
		}
	}
	if c.DeploymentRoot == string(filepath.Separator) || c.JournalDir == string(filepath.Separator) || pathsOverlap(c.DeploymentRoot, c.JournalDir) {
		return parsedTimeouts{}, errors.New("deployment_root and journal_dir must be separate non-root paths")
	}
	for name, path := range map[string]string{"deployment_root": c.DeploymentRoot, "journal_dir": c.JournalDir} {
		if err := rejectSymlinkAncestors(path); err != nil {
			return parsedTimeouts{}, fmt.Errorf("%s is unsafe: %w", name, err)
		}
	}
	if err := validateGatewayAddress(c.Gateway.Address); err != nil {
		return parsedTimeouts{}, err
	}
	if c.Gateway.EnrollmentAddress != "" {
		if err := validateGatewayAddress(c.Gateway.EnrollmentAddress); err != nil {
			return parsedTimeouts{}, errors.New("gateway.enrollment_address must be a host:port pair")
		}
	}
	if strings.TrimSpace(c.Gateway.ServerName) != c.Gateway.ServerName || c.Gateway.ServerName == "" || len(c.Gateway.ServerName) > 253 {
		return parsedTimeouts{}, errors.New("gateway.server_name is required")
	}
	if err := validateGatewayTransport(c); err != nil {
		return parsedTimeouts{}, err
	}
	if err := validateRelativeConfigPath(c.OpenResty.ConfigFile); err != nil {
		return parsedTimeouts{}, err
	}
	if err := validateLoopbackHealthURL(c.OpenResty.HealthURL); err != nil {
		return parsedTimeouts{}, err
	}
	if len(c.OpenResty.Version) > 128 || strings.ContainsAny(c.OpenResty.Version, "\r\n") {
		return parsedTimeouts{}, errors.New("openresty.version is invalid")
	}
	if c.OpenResty.HTTP3Probe != "" && (!absoluteCleanPath(c.OpenResty.HTTP3Probe) || len(c.OpenResty.HTTP3Probe) > 4096 ||
		strings.ContainsAny(c.OpenResty.HTTP3Probe, "\x00\r\n")) {
		return parsedTimeouts{}, errors.New("openresty.http3_probe must be an absolute clean path")
	}
	if !absoluteCleanPath(c.CertificateRuntime.StateRoot) || c.CertificateRuntime.StateRoot == string(filepath.Separator) ||
		pathsOverlap(c.CertificateRuntime.StateRoot, c.DeploymentRoot) || pathsOverlap(c.CertificateRuntime.StateRoot, c.JournalDir) {
		return parsedTimeouts{}, errors.New("certificate_runtime.state_root must be a separate absolute clean non-root path")
	}
	if c.ConfigPath != "" && pathsOverlap(c.CertificateRuntime.StateRoot, filepath.Dir(c.ConfigPath)) {
		return parsedTimeouts{}, errors.New("certificate_runtime.state_root must be separate from the configuration directory")
	}
	if c.Version == 2 && pathsOverlap(c.CertificateRuntime.StateRoot, c.IdentityDir) {
		return parsedTimeouts{}, errors.New("certificate_runtime.state_root must be separate from identity_dir")
	}
	for name, path := range map[string]string{
		"artifact_trust_file":  c.ArtifactTrustFile,
		"gateway.root_ca_file": c.Gateway.RootCAFile,
		"openresty.binary":     c.OpenResty.Binary,
	} {
		if pathsOverlap(c.CertificateRuntime.StateRoot, filepath.Dir(path)) {
			return parsedTimeouts{}, fmt.Errorf("certificate_runtime.state_root must be separate from %s", name)
		}
	}
	if c.Version == 1 {
		for name, path := range map[string]string{
			"gateway.client_certificate": c.Gateway.ClientCertificate,
			"gateway.client_private_key": c.Gateway.ClientPrivateKeyFile,
		} {
			if pathsOverlap(c.CertificateRuntime.StateRoot, filepath.Dir(path)) {
				return parsedTimeouts{}, fmt.Errorf("certificate_runtime.state_root must be separate from %s", name)
			}
		}
	}
	if c.Telemetry.Enabled && pathsOverlap(c.CertificateRuntime.StateRoot, c.Telemetry.SpoolRoot) {
		return parsedTimeouts{}, errors.New("certificate_runtime.state_root must be separate from telemetry.spool_root")
	}
	if c.NodeMonitoring.Enabled {
		if c.NodeMonitoring.DefaultPort == 0 || !absoluteCleanPath(c.NodeMonitoring.StateDir) ||
			c.NodeMonitoring.StateDir == string(filepath.Separator) || pathsOverlap(c.NodeMonitoring.StateDir, c.DeploymentRoot) ||
			pathsOverlap(c.NodeMonitoring.StateDir, c.JournalDir) || pathsOverlap(c.NodeMonitoring.StateDir, c.CertificateRuntime.StateRoot) {
			return parsedTimeouts{}, errors.New("node_monitoring state_dir/default_port are invalid or overlap another runtime")
		}
		if err := rejectSymlinkAncestors(c.NodeMonitoring.StateDir); err != nil {
			return parsedTimeouts{}, fmt.Errorf("node_monitoring.state_dir is unsafe: %w", err)
		}
	}
	if err := c.MarketProbe.validate(); err != nil {
		return parsedTimeouts{}, err
	}
	if err := c.XDP.validate(); err != nil {
		return parsedTimeouts{}, err
	}
	if _, err := c.CacheTask.config(); err != nil {
		return parsedTimeouts{}, err
	}
	if err := c.validateDynamicRouting(); err != nil {
		return parsedTimeouts{}, err
	}
	if err := c.WAFEngine.validate(c); err != nil {
		return parsedTimeouts{}, err
	}
	if err := c.Upgrade.validate(c); err != nil {
		return parsedTimeouts{}, err
	}
	if c.DiskGuard.Enabled && (pathsOverlap(c.CertificateRuntime.StateRoot, c.DiskGuard.LogRoot) ||
		pathsOverlap(c.CertificateRuntime.StateRoot, c.DiskGuard.LockPath)) {
		return parsedTimeouts{}, errors.New("certificate_runtime.state_root must be separate from disk_guard paths")
	}
	if err := rejectSymlinkAncestors(c.CertificateRuntime.StateRoot); err != nil {
		return parsedTimeouts{}, fmt.Errorf("certificate_runtime.state_root is unsafe: %w", err)
	}
	certificateAddress, err := netip.ParseAddr(c.CertificateRuntime.ListenAddress)
	if err != nil || certificateAddress.Zone() != "" || certificateAddress.Is4In6() || !certificateAddress.IsLoopback() ||
		certificateAddress.String() != c.CertificateRuntime.ListenAddress {
		return parsedTimeouts{}, errors.New("certificate_runtime.listen_address must be a canonical loopback IP")
	}
	if c.CertificateRuntime.ListenPort == 0 {
		return parsedTimeouts{}, errors.New("certificate_runtime.listen_port must be nonzero")
	}
	if err := c.Limits.validate(); err != nil {
		return parsedTimeouts{}, err
	}
	if _, err := c.diskGuardConfig(); err != nil {
		return parsedTimeouts{}, err
	}
	timeouts, err := c.Timeouts.parse()
	if err != nil {
		return parsedTimeouts{}, err
	}
	telemetry, err := c.Telemetry.parse(c.DeploymentRoot, c.JournalDir)
	if err != nil {
		return parsedTimeouts{}, err
	}
	timeouts.TelemetrySoftAgeLimit = telemetry.softAge
	timeouts.TelemetryHardAgeLimit = telemetry.hardAge
	timeouts.TelemetryEmptyInterval = telemetry.emptyInterval
	timeouts.TelemetryHandshake = telemetry.handshake
	timeouts.TelemetryAck = telemetry.ack
	timeouts.TelemetryInitialBackoff = telemetry.initialBackoff
	timeouts.TelemetryMaximumBackoff = telemetry.maximumBackoff
	if _, err := c.logDiskGuardConfig(); err != nil {
		return parsedTimeouts{}, err
	}
	if _, err := validateSecurityRuntime(c.SecurityRuntime); err != nil {
		return parsedTimeouts{}, err
	}
	drainCommandLimit, drainResumeInterval, err := c.DrainRuntime.parse(c)
	if err != nil {
		return parsedTimeouts{}, err
	}
	timeouts.DrainCommandLimit = drainCommandLimit
	timeouts.DrainResumeInterval = drainResumeInterval
	return timeouts, nil
}

func validateIngressSourceAddress(name, value string, wantIPv4 bool) error {
	if value == "" {
		return nil
	}
	address, err := netip.ParseAddr(value)
	if err != nil || address.String() != value || address.Is4In6() || address.Zone() != "" ||
		address.Is4() != wantIPv4 || address.IsUnspecified() || address.IsMulticast() ||
		address.IsLinkLocalUnicast() || address == netip.MustParseAddr("255.255.255.255") {
		return fmt.Errorf("%s must be a canonical unicast address of the declared family", name)
	}
	return nil
}

type parsedTelemetryTimeouts struct {
	softAge        time.Duration
	hardAge        time.Duration
	emptyInterval  time.Duration
	handshake      time.Duration
	ack            time.Duration
	initialBackoff time.Duration
	maximumBackoff time.Duration
}

func (t telemetrySettings) parse(deploymentRoot, journalDir string) (parsedTelemetryTimeouts, error) {
	if !t.Enabled {
		return parsedTelemetryTimeouts{}, nil
	}
	if !absoluteCleanPath(t.SpoolRoot) || t.SpoolRoot == string(filepath.Separator) || pathsOverlap(t.SpoolRoot, deploymentRoot) || pathsOverlap(t.SpoolRoot, journalDir) {
		return parsedTelemetryTimeouts{}, errors.New("telemetry.spool_root must be a separate absolute clean non-root path")
	}
	if err := rejectSymlinkAncestors(t.SpoolRoot); err != nil {
		return parsedTelemetryTimeouts{}, fmt.Errorf("telemetry.spool_root is unsafe: %w", err)
	}
	if t.MaxEventBytes < 256 || t.MaxEventBytes > 1<<20 || t.MaxSegmentBytes < int64(t.MaxEventBytes+64) || t.MaxSegmentBytes > 1<<30 ||
		t.SoftLimitBytes < t.MaxSegmentBytes || t.SoftLimitBytes >= t.HardLimitBytes || t.HardLimitBytes > 1<<40 ||
		t.MaxTenantBytes < t.MaxSegmentBytes || t.MaxTenantBytes > t.HardLimitBytes ||
		t.MaxSpoolBatchEvents < 1 || t.MaxSpoolBatchEvents > 10000 || t.FlushBatchEvents < 1 || t.FlushBatchEvents > t.MaxSpoolBatchEvents {
		return parsedTelemetryTimeouts{}, errors.New("telemetry spool and flush limits are invalid")
	}
	switch t.PressureMode {
	case "backpressure":
		if t.AccessSampleEvery != 0 || t.SecuritySampleEvery != 0 {
			return parsedTelemetryTimeouts{}, errors.New("telemetry sampling must be disabled in backpressure mode")
		}
	case "sample":
		if t.AccessSampleEvery == 0 || t.SecuritySampleEvery == 0 || t.AccessSampleEvery > 1_000_000 || t.SecuritySampleEvery > 1_000_000 {
			return parsedTelemetryTimeouts{}, errors.New("telemetry sampling bounds are invalid")
		}
	default:
		return parsedTelemetryTimeouts{}, errors.New("telemetry pressure mode is invalid")
	}
	softAge, err := parseBoundedDuration("telemetry.soft_age_limit", t.SoftAgeLimit, 29*24*time.Hour)
	if err != nil {
		return parsedTelemetryTimeouts{}, err
	}
	hardAge, err := parseBoundedDuration("telemetry.hard_age_limit", t.HardAgeLimit, 29*24*time.Hour)
	if err != nil || softAge >= hardAge {
		return parsedTelemetryTimeouts{}, errors.New("telemetry age limits are invalid")
	}
	empty, err := parseBoundedDuration("telemetry.empty_interval", t.EmptyInterval, time.Hour)
	if err != nil {
		return parsedTelemetryTimeouts{}, err
	}
	handshake, err := parseBoundedDuration("telemetry.handshake_timeout", t.HandshakeTimeout, time.Hour)
	if err != nil {
		return parsedTelemetryTimeouts{}, err
	}
	ack, err := parseBoundedDuration("telemetry.ack_timeout", t.AckTimeout, time.Hour)
	if err != nil {
		return parsedTelemetryTimeouts{}, err
	}
	initial, err := parseBoundedDuration("telemetry.initial_backoff", t.InitialBackoff, time.Hour)
	if err != nil {
		return parsedTelemetryTimeouts{}, err
	}
	maximum, err := parseBoundedDuration("telemetry.maximum_backoff", t.MaximumBackoff, time.Hour)
	if err != nil || maximum < initial {
		return parsedTelemetryTimeouts{}, errors.New("telemetry reconnect backoff is invalid")
	}
	if t.MaxRecordsPerBatch < 1 || t.MaxRecordsPerBatch > 1000 || t.MaxRecordBytes < 256 || t.MaxRecordBytes > 1<<20 ||
		t.MaxBatchBytes < t.MaxRecordBytes || t.MaxBatchBytes > 16<<20 {
		return parsedTelemetryTimeouts{}, errors.New("telemetry transport batch limits are invalid")
	}
	return parsedTelemetryTimeouts{
		softAge: softAge, hardAge: hardAge, emptyInterval: empty,
		handshake: handshake, ack: ack, initialBackoff: initial, maximumBackoff: maximum,
	}, nil
}

func parseBoundedDuration(name, value string, maximum time.Duration) (time.Duration, error) {
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 || duration > maximum {
		return 0, fmt.Errorf("%s must be between 0 and %s", name, maximum)
	}
	return duration, nil
}

func (settings drainRuntimeSettings) parse(config fileConfig) (time.Duration, time.Duration, error) {
	if !settings.Enabled {
		if settings.Prefix != "" || settings.StateRoot != "" || settings.CommandLimit != "" || settings.ResumeInterval != "" {
			return 0, 0, errors.New("disabled drain_runtime cannot configure runtime fields")
		}
		return 0, 0, nil
	}
	for name, path := range map[string]string{
		"prefix": settings.Prefix, "state_root": settings.StateRoot,
	} {
		if !absoluteCleanPath(path) || path == string(filepath.Separator) {
			return 0, 0, fmt.Errorf("drain_runtime.%s must be an absolute clean non-root path", name)
		}
		if err := rejectSymlinkAncestors(path); err != nil {
			return 0, 0, fmt.Errorf("drain_runtime.%s is unsafe: %w", name, err)
		}
	}
	if pathsOverlap(settings.Prefix, settings.StateRoot) {
		return 0, 0, errors.New("drain_runtime prefix and state_root must be separate")
	}
	restricted := []string{
		config.DeploymentRoot,
		config.JournalDir,
		config.CertificateRuntime.StateRoot,
		config.IdentityDir,
		config.Telemetry.SpoolRoot,
		config.DiskGuard.LogRoot,
		config.DiskGuard.LockPath,
		config.Upgrade.Root,
	}
	for _, path := range []string{
		config.ArtifactTrustFile,
		config.Gateway.RootCAFile,
		config.Gateway.ClientCertificate,
		config.Gateway.ClientPrivateKeyFile,
		config.OpenResty.Binary,
	} {
		if path != "" {
			restricted = append(restricted, filepath.Dir(path))
		}
	}
	if config.ConfigPath != "" {
		restricted = append(restricted, filepath.Dir(config.ConfigPath))
	}
	for _, runtimePath := range []string{settings.Prefix, settings.StateRoot} {
		for _, protectedPath := range restricted {
			if protectedPath != "" && pathsOverlap(runtimePath, protectedPath) {
				return 0, 0, errors.New("drain_runtime paths must be separate from other runtime state and trust paths")
			}
		}
	}
	commandLimit, err := parseBoundedDuration("drain_runtime.command_limit", settings.CommandLimit, time.Minute)
	if err != nil {
		return 0, 0, err
	}
	resumeInterval, err := parseBoundedDuration("drain_runtime.resume_interval", settings.ResumeInterval, time.Minute)
	if err != nil {
		return 0, 0, err
	}
	return commandLimit, resumeInterval, nil
}

func (c fileConfig) diskGuardConfig() (diskguard.Config, error) {
	settings := c.DiskGuard
	period, err := time.ParseDuration(settings.EvaluationPeriod)
	if err != nil || period < 5*time.Second || period > time.Hour {
		return diskguard.Config{}, errors.New("disk_guard.evaluation_period must be between 5s and 1h")
	}
	minimumAge, err := time.ParseDuration(settings.MinimumAge)
	if err != nil || minimumAge < time.Hour || minimumAge > 90*24*time.Hour {
		return diskguard.Config{}, errors.New("disk_guard.minimum_age must be between 1h and 2160h")
	}
	if settings.LowWatermark < 5000 || settings.LowWatermark > 9500 ||
		settings.HighWatermark < 6000 || settings.HighWatermark > 9900 ||
		settings.LowWatermark >= settings.HighWatermark ||
		settings.HighWatermark-settings.LowWatermark < 100 {
		return diskguard.Config{}, errors.New("disk_guard watermarks are invalid")
	}
	if settings.MinimumRemain < 1 || settings.MinimumRemain > 1000 ||
		settings.MaxDeletedFiles < 1 || settings.MaxDeletedFiles > 10000 ||
		settings.MaxAllocatedBytes < 1<<20 || settings.MaxAllocatedBytes > 16<<30 {
		return diskguard.Config{}, errors.New("disk_guard retention or deletion limits are invalid")
	}
	config := diskguard.Config{
		SchemaVersion: diskguard.ConfigSchemaVersion,
		ConfigID:      settings.ConfigID, Revision: settings.Revision, LockPath: settings.LockPath,
		LowWatermark: settings.LowWatermark, HighWatermark: settings.HighWatermark,
		EvaluationPeriod: period, MaxDeletedFiles: settings.MaxDeletedFiles,
		MaxAllocatedBytes: settings.MaxAllocatedBytes, DryRun: settings.DryRun,
		Directories: []diskguard.ManagedDirectory{{
			ID: "agent-logs", Path: settings.LogRoot, Kind: diskguard.DirectoryRotatedLogs,
			Patterns: []string{"*.log.*", "*.log-*"}, ActiveNames: []string{"agent.log"},
			MinimumAge: minimumAge, MinimumRemain: settings.MinimumRemain,
		}},
		ProtectedPaths: c.diskGuardProtectedPaths(),
	}
	if err := diskguard.ValidateConfig(config); err != nil {
		return diskguard.Config{}, errors.New("disk_guard configuration is unsafe")
	}
	return config, nil
}

func (c fileConfig) logDiskGuardConfig() (logdiskguard.Config, error) {
	settings := c.DiskGuard
	config := logdiskguard.Config{Enabled: settings.Enabled && c.Telemetry.Enabled}
	if !config.Enabled {
		return config, nil
	}
	base, err := c.diskGuardConfig()
	if err != nil {
		return logdiskguard.Config{}, err
	}
	maximumDuration, err := time.ParseDuration(settings.MaxRoundDuration)
	if err != nil || maximumDuration < 10*time.Millisecond || maximumDuration > time.Minute {
		return logdiskguard.Config{}, errors.New("disk_guard.max_round_duration must be between 10ms and 1m")
	}
	if settings.MinimumFreeBytes < 1<<20 || settings.MinimumFreeBytes > 1<<50 {
		return logdiskguard.Config{}, errors.New("disk_guard.minimum_free_bytes must be between 1MiB and 1PiB")
	}
	stateRoot := filepath.Join(filepath.Dir(settings.LockPath), "log-disk-guard")
	config = logdiskguard.Config{
		Enabled: true, SchemaVersion: logdiskguard.ConfigSchemaVersion, ConfigID: settings.ConfigID + "-spool",
		Revision: settings.Revision, SpoolRoot: c.Telemetry.SpoolRoot, StateRoot: stateRoot,
		LockPath: filepath.Join(stateRoot, "guard.lock"), LowWatermark: settings.LowWatermark,
		HighWatermark: settings.HighWatermark, MinimumFreeBytes: settings.MinimumFreeBytes,
		MinimumAge: base.Directories[0].MinimumAge, EvaluationPeriod: base.EvaluationPeriod,
		MaxRoundDuration: maximumDuration, MaxDeletedFiles: settings.MaxDeletedFiles,
		MaxDeletedBytes: settings.MaxAllocatedBytes, DryRun: settings.DryRun,
	}
	if err := logdiskguard.ValidateConfig(config); err != nil {
		return logdiskguard.Config{}, errors.New("log disk guard configuration is unsafe")
	}
	return config, nil
}

func (c fileConfig) diskGuardProtectedPaths() []string {
	paths := []string{
		"/etc/cdnca-edge-agent",
		"/usr/lib/cdnca-edge-agent",
		"/var/lib/cdnca-edge-agent",
		"/var/lib/cdnca-edge-agent-backups",
		c.DeploymentRoot,
		c.JournalDir,
		c.CertificateRuntime.StateRoot,
		filepath.Dir(c.ArtifactTrustFile),
		filepath.Dir(c.Gateway.RootCAFile),
		filepath.Dir(c.OpenResty.Binary),
	}
	if c.ConfigPath != "" {
		paths = append(paths, filepath.Dir(c.ConfigPath))
	}
	if c.IdentityDir != "" {
		paths = append(paths, c.IdentityDir)
	}
	if c.Telemetry.SpoolRoot != "" {
		paths = append(paths, c.Telemetry.SpoolRoot)
	}
	if c.Upgrade.Enabled {
		paths = append(paths, c.Upgrade.Root)
		for _, path := range []string{c.Upgrade.ControlExecutionTrustFile, c.Upgrade.EdgeExecutionTrustFile,
			c.Upgrade.InstallerReceiptTrustFile, c.Upgrade.DownloadRootCAFile} {
			paths = append(paths, filepath.Dir(path))
		}
	}
	for _, path := range []string{c.Gateway.ClientCertificate, c.Gateway.ClientPrivateKeyFile} {
		if path != "" {
			paths = append(paths, filepath.Dir(path))
		}
	}
	stateRoot := filepath.Dir(c.JournalDir)
	paths = append(paths,
		filepath.Join(stateRoot, "audit"),
		filepath.Join(stateRoot, "event-spool"),
		filepath.Join(stateRoot, "upgrades"),
		filepath.Join(stateRoot, "versions"),
		filepath.Join(stateRoot, "rollbacks"),
	)
	return paths
}

func (u upgradeSettings) validate(config fileConfig) error {
	if !u.Enabled {
		return nil
	}
	installationID, err := uuid.Parse(u.InstallationID)
	if err != nil || installationID == uuid.Nil || installationID.String() != u.InstallationID {
		return errors.New("upgrade.installation_id must be a canonical UUID")
	}
	for name, path := range map[string]string{
		"root": u.Root, "control_execution_trust_file": u.ControlExecutionTrustFile,
		"edge_execution_trust_file":    u.EdgeExecutionTrustFile,
		"installer_receipt_trust_file": u.InstallerReceiptTrustFile,
		"download_root_ca_file":        u.DownloadRootCAFile,
	} {
		if !absoluteCleanPath(path) || path == string(filepath.Separator) {
			return fmt.Errorf("upgrade.%s must be an absolute clean non-root path", name)
		}
	}
	if pathsOverlap(u.Root, config.DeploymentRoot) || pathsOverlap(u.Root, config.JournalDir) ||
		pathsOverlap(u.Root, config.CertificateRuntime.StateRoot) ||
		(config.IdentityDir != "" && pathsOverlap(u.Root, config.IdentityDir)) ||
		(config.Telemetry.SpoolRoot != "" && pathsOverlap(u.Root, config.Telemetry.SpoolRoot)) {
		return errors.New("upgrade.root must be separate from other runtime state")
	}
	if err := rejectSymlinkAncestors(u.Root); err != nil {
		return fmt.Errorf("upgrade.root is unsafe: %w", err)
	}
	if !validUpgradeDownloadHost(u.DownloadHost) || u.DownloadPort == 0 || len(u.DownloadAddresses) == 0 || len(u.DownloadAddresses) > 16 {
		return errors.New("upgrade download host, addresses, and port are invalid")
	}
	seen := make(map[netip.Addr]struct{}, len(u.DownloadAddresses))
	for _, raw := range u.DownloadAddresses {
		address, err := netip.ParseAddr(raw)
		if err != nil || address.String() != raw || address.IsUnspecified() || address.IsMulticast() {
			return errors.New("upgrade download address is invalid")
		}
		address = address.Unmap()
		if _, exists := seen[address]; exists {
			return errors.New("upgrade download addresses contain a duplicate")
		}
		seen[address] = struct{}{}
	}
	// An IP literal host (control plane without a DNS name) must pin exactly
	// that one address; the certificate then carries it as an IP SAN.
	if literal, err := netip.ParseAddr(u.DownloadHost); err == nil &&
		(len(u.DownloadAddresses) != 1 || u.DownloadAddresses[0] != literal.String()) {
		return errors.New("upgrade download IP host must pin exactly its own address")
	}
	timeout, err := time.ParseDuration(u.Timeout)
	if err != nil || timeout <= 0 || timeout > 24*time.Hour {
		return errors.New("upgrade.timeout must be between 0 and 24h")
	}
	if u.MaxArtifactBytes <= 0 || u.MaxArtifactBytes > 285229182 || u.DiskReserveBytes < 0 || u.DiskReserveBytes > 1<<40 {
		return errors.New("upgrade artifact and disk limits are invalid")
	}
	return nil
}

func validUpgradeDownloadHost(host string) bool {
	if address, err := netip.ParseAddr(host); err == nil {
		return address.String() == host && address.Zone() == "" && !address.Is4In6() &&
			!address.IsUnspecified() && !address.IsMulticast()
	}
	if host == "" || host != strings.ToLower(host) || strings.TrimSuffix(host, ".") != host ||
		strings.Contains(host, "xn--") || net.ParseIP(host) != nil || len(host) > 253 {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func (l limitSettings) validate() error {
	if l.MaxCommandBytes <= 0 || l.MaxStatusBytes <= 0 || l.MaxArtifactBytes == 0 || l.MaxDecompressedBytes <= 0 || l.MaxArtifactChunkBytes == 0 || l.MaxActiveDeployments <= 0 || l.CommandQueueSize <= 0 {
		return errors.New("gateway limits must be positive")
	}
	if l.MaxFiles <= 0 || l.MaxFileBytes <= 0 || l.MaxTotalBytes <= 0 || l.RetainReleases < 2 {
		return errors.New("deployment limits are invalid")
	}
	if l.MaxFileBytes > l.MaxTotalBytes || l.MaxTotalBytes > l.MaxDecompressedBytes || l.MaxArtifactBytes > math.MaxInt64 || uint64(l.MaxArtifactChunkBytes) > l.MaxArtifactBytes {
		return errors.New("artifact and deployment limits are inconsistent")
	}
	if uint64(l.MaxArtifactChunkBytes)+(64<<10) > uint64(math.MaxInt) {
		return errors.New("artifact chunk limit exceeds platform capacity")
	}
	return nil
}

func (t timeoutSettings) parse() (parsedTimeouts, error) {
	values := map[string]string{
		"handshake": t.Handshake, "artifact_fetch": t.ArtifactFetch,
		"initial_backoff": t.InitialBackoff, "maximum_backoff": t.MaximumBackoff,
		"precheck": t.Precheck, "reload": t.Reload, "health": t.Health,
		"health_interval": t.HealthInterval, "health_request": t.HealthRequest,
	}
	parsed := make(map[string]time.Duration, len(values))
	for name, value := range values {
		duration, err := time.ParseDuration(value)
		if err != nil || duration <= 0 || duration > 24*time.Hour {
			return parsedTimeouts{}, fmt.Errorf("timeouts.%s must be between 0 and 24h", name)
		}
		parsed[name] = duration
	}
	if parsed["maximum_backoff"] < parsed["initial_backoff"] || parsed["health_interval"] > parsed["health"] || parsed["health_request"] > parsed["health"] {
		return parsedTimeouts{}, errors.New("timeout values are inconsistent")
	}
	return parsedTimeouts{
		Handshake: parsed["handshake"], ArtifactFetch: parsed["artifact_fetch"],
		InitialBackoff: parsed["initial_backoff"], MaximumBackoff: parsed["maximum_backoff"],
		Precheck: parsed["precheck"], Reload: parsed["reload"], Health: parsed["health"],
		HealthInterval: parsed["health_interval"], HealthRequest: parsed["health_request"],
	}, nil
}

func validateGatewayTransport(c fileConfig) error {
	if len(c.Gateway.Endpoints) > 8 {
		return errors.New("gateway.endpoints allows at most 8 entries")
	}
	for _, endpoint := range c.Gateway.Endpoints {
		if err := validateGatewayAddress(endpoint.Address); err != nil {
			return fmt.Errorf("gateway.endpoints: %w", err)
		}
		if strings.TrimSpace(endpoint.ServerName) != endpoint.ServerName || endpoint.ServerName == "" || len(endpoint.ServerName) > 253 {
			return errors.New("gateway.endpoints server_name is required")
		}
		single := c
		single.Gateway.Transport, single.Gateway.TunnelHost, single.Gateway.Endpoints = endpoint.Transport, endpoint.TunnelHost, nil
		if err := validateGatewayTransport(single); err != nil {
			return fmt.Errorf("gateway.endpoints: %w", err)
		}
	}
	switch c.Gateway.Transport {
	case "", "grpc":
		if c.Gateway.TunnelHost != "" {
			return errors.New("gateway.tunnel_host requires gateway.transport ws")
		}
		return nil
	case "ws":
	default:
		return errors.New("gateway.transport must be grpc or ws")
	}
	if host := c.Gateway.TunnelHost; host != "" && (strings.TrimSpace(host) != host || len(host) > 253 || strings.ContainsAny(host, ":/ ")) {
		return errors.New("gateway.tunnel_host must be a host name")
	}
	audience, err := uuid.Parse(c.tunnelAudience())
	if err != nil || audience == uuid.Nil || audience.String() != c.tunnelAudience() {
		return errors.New("gateway.transport ws requires gateway.tunnel_audience or upgrade.installation_id")
	}
	return nil
}

func validateGatewayAddress(value string) error {
	if strings.TrimSpace(value) != value || strings.Contains(value, "://") {
		return errors.New("gateway.address must be a host:port pair")
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil || host == "" {
		return errors.New("gateway.address must be a host:port pair")
	}
	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil || number == 0 {
		return errors.New("gateway.address contains an invalid port")
	}
	return nil
}

func validateRelativeConfigPath(value string) error {
	if value == "" || filepath.IsAbs(value) || filepath.Clean(value) != value || value == "." || strings.HasPrefix(value, ".."+string(filepath.Separator)) {
		return errors.New("openresty.config_file must be a clean relative path")
	}
	return nil
}

func validateLoopbackHealthURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path == "" {
		return errors.New("openresty.health_url must be a plain HTTP loopback URL without credentials, query, or fragment")
	}
	address, err := netip.ParseAddr(parsed.Hostname())
	if err != nil || !address.IsLoopback() || parsed.Port() == "" {
		return errors.New("openresty.health_url must use a literal loopback address and explicit port")
	}
	port, err := strconv.ParseUint(parsed.Port(), 10, 16)
	if err != nil || port == 0 {
		return errors.New("openresty.health_url contains an invalid port")
	}
	return nil
}

func absoluteCleanPath(value string) bool {
	return value != "" && filepath.IsAbs(value) && filepath.Clean(value) == value
}

func pathsOverlap(left, right string) bool {
	for _, pair := range [][2]string{{left, right}, {right, left}} {
		relative, err := filepath.Rel(pair[0], pair[1])
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func rejectSymlinkAncestors(path string) error {
	volume := filepath.VolumeName(path)
	root := volume + string(filepath.Separator)
	current := root
	for _, component := range strings.Split(strings.TrimPrefix(path, root), string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("inspect path component: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("path contains a symbolic link")
		}
	}
	return nil
}

func boundedIdentifier(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character == 0x7f || character == '/' || character == '\\' {
			return false
		}
	}
	return true
}

func rejectDuplicateJSONKeys(content []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	var readValue func() error
	readValue = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("object key is not a string")
				}
				if _, exists := seen[key]; exists {
					return fmt.Errorf("duplicate field %q", key)
				}
				seen[key] = struct{}{}
				if err := readValue(); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := readValue(); err != nil {
					return err
				}
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		_, err = decoder.Token()
		return err
	}
	if err := readValue(); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}
