package dnsacme

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// 节点管理 > DNS配置 is one installation-wide DNS configuration, edited by the
// platform administrator. DNS providers, zones, CNAME claims and background
// jobs are tenant scoped, so SyncPlatformTenants copies the platform source
// into every active tenant scope; the CNAME allocator and the DNS write
// runtime consume those tenant copies unchanged.

var (
	ErrPlatformOnly          = errors.New("the DNS configuration is managed by the platform administrator")
	ErrPlatformNotConfigured = errors.New("the DNS configuration has no provider yet")
	ErrPlatformZoneInUse     = errors.New("the CNAME domain still has sites allocated")
	// ErrZoneNotHosted: the DNS account hosts neither the CNAME domain nor a
	// parent of it (dns_zone_not_hosted, 该域名不在所选 DNS 账号下).
	ErrZoneNotHosted = errors.New("the domain is not hosted by the DNS account")
)

// PlatformMinTTL / PlatformMaxTTL bound the record TTL every supported
// provider accepts at least on paid plans (Cloudflare 60..86400 or 1=auto,
// Alibaba Cloud / DNSPod / Huawei 1..86400 subject to plan minimums).
const (
	PlatformDefaultTTL = 600
	PlatformMinTTL     = 1
	PlatformMaxTTL     = 86400
)

// PlatformMinTTLFor is the provider's lowest record TTL: Cloudflare's lowest
// non-automatic TTL is 60 seconds (1 means automatic there).
func PlatformMinTTLFor(providerType string) int {
	switch providerType {
	case "cloudflare":
		return 60
	case "namecom":
		// name.com: "a minimum TTL of 300, or 5 minutes".
		return 300
	}
	return PlatformMinTTL
}

// weightProviders lists the provider types whose reconcile adapter writes a
// per-record weight (dnsproviderremote.ProviderCapabilityMatrix Weight).
var weightProviders = map[string]bool{"dnspod_cn": true}

// PlatformWeightSupported reports whether IP weights reach the provider.
func PlatformWeightSupported(providerType string) bool { return weightProviders[providerType] }

type PlatformConfig struct {
	ProviderType string `json:"provider_type,omitempty"`
	// Identifiers are the non-secret credential fields (ID, Huawei region and
	// project); secrets are never returned.
	Identifiers     map[string]string `json:"identifiers"`
	SecretSaved     bool              `json:"secret_saved"`
	TTL             int               `json:"ttl"`
	IPWeight        bool              `json:"ip_weight"`
	WeightSupported bool              `json:"weight_supported"`
	Revision        int64             `json:"version"`
	UpdatedAt       *time.Time        `json:"updated_at,omitempty"`
	Sync            PlatformSync      `json:"sync"`
	LastError       *PlatformDNSError `json:"last_error"`
}

type PlatformSync struct {
	Tenants int        `json:"tenants"`
	Error   string     `json:"error,omitempty"`
	At      *time.Time `json:"at,omitempty"`
}

// PlatformDNSError is the newest DNS write outcome across tenants when it is a
// failure: a CNAME allocation, a retarget, a 记录修复/清除CDN无关解析 step, or
// the platform synchronisation itself.
type PlatformDNSError struct {
	Source  string    `json:"source"`
	Code    string    `json:"code"`
	Message string    `json:"message,omitempty"`
	At      time.Time `json:"at"`
}

// PlatformConnection is the result of 连接测试: the credentials were accepted
// and each CNAME domain's standing in the account.
type PlatformConnection struct {
	ProviderType string                   `json:"provider_type"`
	Zones        []PlatformConnectionZone `json:"zones"`
}

// PlatformConnectionZone statuses: hosted (the account hosts the domain or a
// parent, Apex), not_hosted, unchecked (custom HTTP / plugin providers have
// no domain list).
const (
	PlatformZoneHosted    = "hosted"
	PlatformZoneNotHosted = "not_hosted"
	PlatformZoneUnchecked = "unchecked"
)

type PlatformConnectionZone struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Apex   string `json:"apex,omitempty"`
}

type SavePlatformConfigRequest struct {
	ProviderType string
	// Credentials replace the stored ones when present (all fields of the
	// provider); nil keeps the stored credentials of the same provider type.
	Credentials      map[string]string
	TTL              int
	IPWeight         bool
	ExpectedRevision int64
	IdempotencyKey   string
	RequestID        string
}

type PlatformZone struct {
	ID        uuid.UUID `json:"id"`
	DisplayID int64     `json:"display_id"`
	Name      string    `json:"name"`
	Remark    string    `json:"remark"`
	InUse     bool      `json:"in_use"`
	// RandomAllocation: the domain takes part in random CNAME allocation.
	RandomAllocation bool      `json:"random_allocation"`
	Revision         int64     `json:"version"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type PlatformZonePage struct {
	Items []PlatformZone `json:"items"`
	Total int            `json:"total"`
}

type PlatformZoneQuery struct {
	Search string
	Page   int
	Limit  int
}

type PlatformZoneRequest struct {
	ID     uuid.UUID
	Name   string
	Remark string
	// RandomAllocation: nil keeps the current mark (false on create).
	RandomAllocation *bool
	ExpectedRevision int64
	IdempotencyKey   string
	RequestID        string
	// ProviderZoneApex is set by the service from the provider's domain list.
	ProviderZoneApex string
}

// PlatformTenant is a tenant scope holding a copy of the platform DNS config.
type PlatformTenant struct {
	TenantID uuid.UUID
	ScopeID  uuid.UUID
}

// identifierFields are the credential fields shown back in the form.
var identifierFields = map[string][]string{
	"aliyun": {"access_key_id"}, "huawei": {"access_key", "region", "project_id"}, "dns_la": {"api_id"},
	"dnspod_cn": {"dp_id"}, "dns_com": {"api_key", "plan"}, "cloudflare": {}, "custom_http": {"endpoint"}, "namecom": {"username"},
	ProviderTypePlugin: {PluginCredentialField},
}
