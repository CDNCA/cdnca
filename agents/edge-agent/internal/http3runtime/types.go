package http3runtime

import (
	"errors"
	"time"
)

const (
	SchemaVersionV1         = "cdnca.edge.http3/v1"
	RuntimeFamilyOpenResty  = "openresty"
	RuntimeVersionOpenResty = "1.31.1.1"
)

const (
	maxPolicyBytes          = 1 << 20
	maxCertificateBytes     = 4 << 20
	minIdleTimeoutMS        = 1_000
	maxIdleTimeoutMS        = 600_000
	minWorkerConnections    = 16
	maxWorkerConnections    = 65_535
	maxConnectionsPerClient = 10_000
	maxConcurrentStreams    = 1_024
	minHeaderBytes          = 1_024
	maxHeaderBytes          = 65_536
	minActiveConnectionIDs  = 2
	maxActiveConnectionIDs  = 16
	maxAltSvcAgeSeconds     = 604_800
	stateSchemaVersion      = 1
)

var (
	ErrInvalidPolicy = errors.New("invalid HTTP/3 policy")
	ErrInvalidPath   = errors.New("invalid HTTP/3 runtime path")
	ErrConflict      = errors.New("HTTP/3 policy version conflict")
	ErrCorruptState  = errors.New("corrupt HTTP/3 runtime state")
	ErrPrecheck      = errors.New("HTTP/3 policy precheck failed")
	ErrPortConflict  = errors.New("HTTP/3 listener port conflict")
	ErrUnsupported   = errors.New("unsupported HTTP/3 runtime")
	ErrActivation    = errors.New("HTTP/3 policy activation failed")
	ErrHealth        = errors.New("HTTP/3 policy health check failed")
)

type RuntimeRef struct {
	Family  string `json:"family"`
	Version string `json:"version"`
}

type Listener struct {
	Address             string `json:"address"`
	Port                int    `json:"port"`
	ServerName          string `json:"server_name"`
	AltSvcMaxAgeSeconds int    `json:"alt_svc_max_age_seconds"`
}

type TLSConfig struct {
	MinimumVersion    string `json:"minimum_version"`
	CertificateFile   string `json:"certificate_file"`
	CertificateSHA256 string `json:"certificate_sha256"`
	PrivateKeyFile    string `json:"private_key_file"`
	PrivateKeySHA256  string `json:"private_key_sha256"`
}

type Limits struct {
	IdleTimeoutMS        int `json:"idle_timeout_ms"`
	WorkerConnections    int `json:"worker_connections"`
	ConnectionsPerClient int `json:"connections_per_client"`
	ConcurrentStreams    int `json:"concurrent_streams"`
	RequestHeaderBytes   int `json:"request_header_bytes"`
	ActiveConnectionIDs  int `json:"active_connection_ids"`
}

type Policy struct {
	SchemaVersion string     `json:"schema_version"`
	VersionID     string     `json:"version_id"`
	Protocols     []string   `json:"protocols"`
	Runtime       RuntimeRef `json:"runtime"`
	Listener      Listener   `json:"listener"`
	TLS           TLSConfig  `json:"tls"`
	Limits        Limits     `json:"limits"`
}

func (policy Policy) HTTP3Enabled() bool {
	return len(policy.Protocols) == 3 && policy.Protocols[2] == "http3"
}

type CompiledPolicy struct {
	Policy        Policy
	Digest        string
	CanonicalJSON []byte
	NginxConfig   []byte
}

type ApplyState string

const (
	StateApplied ApplyState = "applied"
	StateFailed  ApplyState = "failed"
)

type Result struct {
	VersionID               string     `json:"version_id"`
	Digest                  string     `json:"digest"`
	State                   ApplyState `json:"state"`
	ActiveVersionID         string     `json:"active_version_id,omitempty"`
	ActiveDigest            string     `json:"active_digest,omitempty"`
	RunningVersionUnchanged bool       `json:"running_version_unchanged"`
	ErrorCode               string     `json:"error_code,omitempty"`
	AppliedAt               time.Time  `json:"applied_at,omitempty"`
}

type Status struct {
	Active    bool      `json:"active"`
	VersionID string    `json:"version_id,omitempty"`
	Digest    string    `json:"digest,omitempty"`
	AppliedAt time.Time `json:"applied_at,omitempty"`
}
