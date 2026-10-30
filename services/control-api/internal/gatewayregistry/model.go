// Package gatewayregistry manages standalone Agent Gateways (ADR 0013
// §3.2–§3.4, GW-06/GW-08): the Gateway list, one-time binding tokens, the
// certificates the control plane signs for each Gateway and the check
// ControlInternal runs on every bound Gateway call.
//
// The co-located Gateway of an "all" installation keeps the installer's
// spiffe://cdn-platform/gateway/control certificate and is not in the table.
package gatewayregistry

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

const (
	// PermissionManage gates every admin route (platform scope; platform.admin too).
	PermissionManage = "system.gateway.manage"

	// WorkloadURIPrefix + gateway_id is the client certificate URI SAN of a
	// bound Gateway; ControlInternal accepts the prefix (ADR 0013 §3.2).
	WorkloadURIPrefix = "spiffe://cdn-platform/gateway/"

	KindClient = "client"
	KindServer = "server"

	StatusPending  = "pending"
	StatusBound    = "bound"
	StatusActive   = "active"
	StatusDisabled = "disabled"
	StatusDeleted  = "deleted"

	TokenTTL            = time.Hour
	ClientCertTTL       = 30 * 24 * time.Hour
	ServerCertTTL       = 90 * 24 * time.Hour
	certificateBackdate = 5 * time.Minute
	// DisabledGrace: a disabled Gateway closes the sessions still left after
	// 30 minutes (ADR 0013 §5.2); ControlInternal keeps serving it two
	// settings polls longer so that close happens on the Gateway's clock.
	DisabledGrace = 32 * time.Minute

	actionCreate  = "system.gateway.create"
	actionToken   = "system.gateway.binding_token"
	actionBind    = "system.gateway.bind"
	actionDisable = "system.gateway.disable"
	actionEnable  = "system.gateway.enable"
	actionDelete  = "system.gateway.delete"
	actionRenew   = "system.gateway.renew_certificate"
)

var (
	ErrInvalidInput         = errors.New("gateway registry invalid input")
	ErrPermissionDenied     = errors.New("gateway registry permission denied")
	ErrNotFound             = errors.New("gateway not found")
	ErrConflict             = errors.New("gateway state does not allow this operation")
	ErrNameTaken            = errors.New("gateway name already in use")
	ErrInvalidToken         = errors.New("gateway binding token is invalid, expired or used")
	ErrRemoteAccessDisabled = errors.New("standalone gateway access is not enabled on this control plane")
	ErrGatewayUnauthorized  = errors.New("gateway certificate is unknown, revoked or deleted")
	ErrUnavailable          = errors.New("gateway registry unavailable")
	// ErrSettingsChanged: If-Match no longer matches the gateway settings (G1).
	ErrSettingsChanged = errors.New("gateway settings were changed by someone else")
)

// Actor is the authenticated platform administrator of a write.
type Actor struct {
	UserID  uuid.UUID
	ScopeID uuid.UUID
	IP      string
}

// Gateway is one row of the Gateway management page.
type Gateway struct {
	ID             uuid.UUID  `json:"id"`
	Name           string     `json:"name"`
	Host           string     `json:"host"`
	EnrollmentPort *int       `json:"enrollment_port"`
	AgentPort      *int       `json:"agent_port"`
	Status         string     `json:"status"`
	Version        string     `json:"version"`
	CreatedAt      time.Time  `json:"created_at"`
	BoundAt        *time.Time `json:"bound_at"`
	ReadyAt        *time.Time `json:"ready_at"`
	// ClientCertificateExpiresAt / ServerCertificateExpiresAt: newest
	// unrevoked certificate of each kind.
	ClientCertificateExpiresAt *time.Time `json:"client_certificate_expires_at"`
	ServerCertificateExpiresAt *time.Time `json:"server_certificate_expires_at"`
	// SourceIP is the binding request address; AllowedIPs the addresses
	// ControlInternal/Redis/NATS accept from this Gateway (default SourceIP).
	SourceIP   *string  `json:"source_ip"`
	AllowedIPs []string `json:"allowed_ips"`
}

// CreateInput is the "add Gateway" form.
type CreateInput struct {
	Name string `json:"name"`
	Host string `json:"host"`
}

// Created carries the one-time token, shown once.
type Created struct {
	Gateway        Gateway   `json:"gateway"`
	BindingToken   string    `json:"binding_token"`
	TokenExpiresAt time.Time `json:"token_expires_at"`
}

// RemoteEndpoints are what a bound Gateway connects to (ADR 0013 §3.3). Empty
// ControlInternalAddress: the control plane has not opened standalone
// Gateway access and binding is refused before the token is consumed.
type RemoteEndpoints struct {
	ControlInternalAddress    string `json:"control_internal_address"`
	ControlInternalServerName string `json:"control_internal_server_name"`
	RedisURL                  string `json:"redis_url"`
	NATSURL                   string `json:"nats_url"`
	TelemetryNATSURL          string `json:"telemetry_nats_url"`
}

// BindRequest is POST /v1/gateway-bindings/complete.
type BindRequest struct {
	Token string `json:"token"`
	// ClientCSR: Ed25519, for the Gateway → ControlInternal client certificate.
	ClientCSR []byte `json:"client_csr_der"`
	// ServerCSR: ECDSA P-256, for the node channel server certificate.
	ServerCSR      []byte `json:"server_csr_der"`
	EnrollmentPort int    `json:"enrollment_port"`
	AgentPort      int    `json:"agent_port"`
	Version        string `json:"version"`
}

// BindResult is everything the gateway installer writes (no private keys:
// they never leave the Gateway).
type BindResult struct {
	GatewayID            uuid.UUID       `json:"gateway_id"`
	InstallationID       string          `json:"installation_id"`
	WorkloadURISAN       string          `json:"workload_uri_san"`
	ClientCertificatePEM string          `json:"client_certificate_pem"`
	ServerCertificatePEM string          `json:"server_certificate_pem"`
	RootCAPEM            string          `json:"root_ca_pem"`
	NodeCAPEM            string          `json:"node_ca_pem"`
	Endpoints            RemoteEndpoints `json:"endpoints"`
}

// RenewResult is a renewed Gateway certificate.
type RenewResult struct {
	CertificatePEM []byte
	NotAfter       time.Time
	RenewAt        time.Time
}
