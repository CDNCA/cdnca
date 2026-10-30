package l4forward

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
)

const (
	ProtocolTCP     = "tcp"
	ProtocolUDP     = "udp"
	RuntimeSchemaV2 = "cdnca.edge.l4/v2"

	// 负载方式取值：rr=轮循、ip_hash=定源。
	BalanceWayRoundRobin = "rr"
	BalanceWayIPHash     = "ip_hash"

	// 「默认设置」只开放这三个设置项，取值形态与前端字符串一致。
	SettingProxyProtocol  = "proxy_protocol"
	SettingListenProtocol = "listen_protocol"
	SettingBalanceWay     = "balance_way"

	DefaultScopeGlobal = "global"
	DefaultScopeGroup  = "group"

	DefaultValueEnabled  = "1"
	DefaultValueDisabled = "0"

	GeoActionAllow = "allow"
	GeoActionBlock = "block"

	PublicationStateUnknown     = "unknown"
	PublicationStatePending     = "pending"
	PublicationStateLeased      = "leased"
	PublicationStateRetrying    = "retrying"
	PublicationStateReconciling = "reconciling"
	PublicationStateSucceeded   = "succeeded"
	PublicationStateFailed      = "failed"
	PublicationStateSuperseded  = "superseded"

	// ACL 默认行为 (acl.default_action) and rule actions.
	ACLActionAllow = "allow"
	ACLActionDeny  = "deny"

	// 设置状态 (「设置网站状态」): only normal streams are served.
	AdminStatusNormal          = "normal"
	AdminStatusLocked          = "locked"
	AdminStatusTrafficExceeded = "traffic_exceeded"
	AdminStatusPackageExpired  = "package_expired"

	// 同步状态 (sync_state), from the latest intent's delivery.
	SyncStateDone    = "done"
	SyncStatePending = "pending"
	SyncStateFailed  = "failed"
)

type EligibilityState string

const (
	EligibilityEligible   EligibilityState = "eligible"
	EligibilityIneligible EligibilityState = "ineligible"
)

// ErrSharedPortProxyProtocol refuses a PROXY stream on a port shared with
// other streams or websites, which the node serves behind a dispatcher.
var ErrSharedPortProxyProtocol = errors.New("layer-four forwarding PROXY protocol on a shared port")

var (
	ErrInvalidInput = errors.New("invalid layer-four forwarding input")
	// ErrGuardRuleLimit: more guard rules than the platform's stream ACL rule
	// limit (acl_max_limit) allows.
	// It is an ErrInvalidInput (the API answers 400).
	ErrGuardRuleLimit      = fmt.Errorf("%w: guard rules exceed the platform ACL rule limit", ErrInvalidInput)
	ErrNotFound            = errors.New("layer-four forwarding rule not found")
	ErrPermissionDenied    = errors.New("layer-four forwarding permission denied")
	ErrPortConflict        = errors.New("layer-four forwarding listen port conflict")
	ErrNameConflict        = errors.New("layer-four forwarding name conflict")
	ErrRevisionConflict    = errors.New("layer-four forwarding revision conflict")
	ErrIdempotencyConflict = errors.New("layer-four forwarding idempotency conflict")

	ErrGroupNotFound      = errors.New("layer-four stream group not found")
	ErrGroupNameConflict  = errors.New("layer-four stream group name conflict")
	ErrGroupInUse         = errors.New("layer-four stream group still referenced")
	ErrDefaultNotFound    = errors.New("layer-four stream default not found")
	ErrDefaultScopeNeedID = errors.New("layer-four stream default requires a group")
)

// FieldError names the request field a stream save refused (L4-006): the API
// answers validation_error with details.field/reason so the form can point at
// it. It is an ErrInvalidInput. Reason is invalid, required or limit.
type FieldError struct {
	Field  string
	Reason string
}

func (e *FieldError) Error() string {
	return "invalid layer-four forwarding field " + e.Field + ": " + e.Reason
}
func (e *FieldError) Unwrap() error { return ErrInvalidInput }

func fieldError(field, reason string) error { return &FieldError{Field: field, Reason: reason} }

type Actor struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	ScopeKind string
}

type OwnerReference struct {
	ID          uuid.UUID `json:"id"`
	DisplayName string    `json:"display_name"`
}

// GroupReference 是转发列表「分组」列的渲染所需，同行展示分组名与备注浮层。
type GroupReference struct {
	ID     uuid.UUID `json:"id"`
	Name   string    `json:"name"`
	Remark string    `json:"remark"`
}

type DNSPolicy struct {
	PositiveMinTTLSeconds uint32 `json:"positive_min_ttl_seconds"`
	PositiveMaxTTLSeconds uint32 `json:"positive_max_ttl_seconds"`
	NegativeTTLSeconds    uint32 `json:"negative_ttl_seconds"`
	StaleIfErrorSeconds   uint32 `json:"stale_if_error_seconds"`
	AllowPrivateAddresses bool   `json:"allow_private_addresses"`
}

type GeoRegionCIDRs struct {
	Region string   `json:"region"`
	CIDRs  []string `json:"cidrs"`
}

type GeoPolicy struct {
	Enabled             bool             `json:"enabled"`
	UnknownRegionAction string           `json:"unknown_region_action"`
	TrustedProxyCIDRs   []string         `json:"trusted_proxy_cidrs"`
	BlockedRegions      []string         `json:"blocked_regions"`
	RegionCIDRs         []GeoRegionCIDRs `json:"region_cidrs"`
}

type RuntimeGeoPolicy struct {
	Enabled             bool             `json:"enabled"`
	TenantID            string           `json:"tenant_id"`
	StreamID            string           `json:"stream_id"`
	Revision            int64            `json:"revision"`
	UnknownRegionAction string           `json:"unknown_region_action"`
	TrustedProxyCIDRs   []string         `json:"trusted_proxy_cidrs"`
	BlockedRegions      []string         `json:"blocked_regions"`
	RegionCIDRs         []GeoRegionCIDRs `json:"region_cidrs"`
}

// PortEnd (migration 334) makes a listener the port range Port..PortEnd;
// 0 is the single Port and is omitted.
type RuntimeListener struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     uint16 `json:"port"`
	PortEnd  uint16 `json:"port_end,omitempty"`
}

type AdditionalListener struct {
	ID       uuid.UUID `json:"id"`
	Protocol string    `json:"protocol"`
	Address  string    `json:"address"`
	Port     uint16    `json:"port"`
	PortEnd  uint16    `json:"port_end,omitempty"`
}

// FollowPort (migration 334): the origin is reached on the client's port.
// Origins / Balance (migration 490, tcp/udp v11): the origin list and 定源.
type RuntimeEndpoint struct {
	Address    string                  `json:"address,omitempty"`
	Host       string                  `json:"host,omitempty"`
	Port       uint16                  `json:"port"`
	FollowPort bool                    `json:"follow_port,omitempty"`
	Origins    []edgeconfig.L4OriginV2 `json:"origins,omitempty"`
	Balance    string                  `json:"balance,omitempty"`
}

// Origin is one entry of a stream's 源站列表 (backend: addr / weight /
// state up|down): an IP address or, alone, a domain name.
type Origin struct {
	Address string `json:"address"`
	Weight  int    `json:"weight"`
	Down    bool   `json:"down"`
}

// ACLRule is one IP 访问规则: a single address or a network (CIDR) allowed
// or denied; the first matching rule decides, otherwise DefaultAction.
type ACLRule struct {
	CIDR   string `json:"cidr"`
	Action string `json:"action"`
}

// ACL is a stream's 访问控制 IP rules (acl {default_action, rule}). The
// node enforces it as the stream's guard rules (client_ip allow / drop,
// edgeconfig.L4GuardRuleV2), ahead of the stream's own guard rules.
type ACL struct {
	DefaultAction string    `json:"default_action"`
	Rules         []ACLRule `json:"rules"`
}

// LineReference is the 线路 column: the region and line group the stream is
// served by: the stream's own, else its package's (migration 506: a stream
// belongs to no website).
type LineReference struct {
	RegionID            *uuid.UUID `json:"region_id"`
	RegionName          string     `json:"region_name"`
	NodeGroupID         *uuid.UUID `json:"node_group_id"`
	NodeGroupName       string     `json:"node_group_name"`
	BackupNodeGroupID   *uuid.UUID `json:"backup_node_group_id"`
	BackupNodeGroupName string     `json:"backup_node_group_name"`
}

// Overrides is what the stream sets itself (cname_domain, cname_mode,
// region_id, node_group_id, backup_node_group); each nil field follows the
// stream's package.
type Overrides struct {
	CNAMEDomain       *string    `json:"cname_domain"`
	CNAMEMode         *string    `json:"cname_mode"`
	RegionID          *uuid.UUID `json:"region_id"`
	NodeGroupID       *uuid.UUID `json:"node_group_id"`
	BackupNodeGroupID *uuid.UUID `json:"backup_node_group_id"`
}

type RuntimeSpec struct {
	SchemaVersion           string               `json:"schema_version"`
	TenantID                string               `json:"tenant_id"`
	StreamID                string               `json:"stream_id"`
	Revision                int64                `json:"revision"`
	Listener                RuntimeListener      `json:"listener"`
	AdditionalListeners     []AdditionalListener `json:"additional_listeners,omitempty"`
	Endpoint                RuntimeEndpoint      `json:"endpoint"`
	DNS                     DNSPolicy            `json:"dns"`
	Geo                     RuntimeGeoPolicy     `json:"geo"`
	ConnectTimeoutMS        int                  `json:"connect_timeout_ms"`
	ResponseTimeoutMS       int                  `json:"response_timeout_ms"`
	MaxConnectionsPerClient int                  `json:"max_connections_per_client"`
	DrainTimeoutMS          int                  `json:"drain_timeout_ms"`
	ProxyProtocolInbound    bool                 `json:"proxy_protocol_inbound"`
	ProxyProtocolOutbound   bool                 `json:"proxy_protocol_outbound"`
	TLSPassthrough          bool                 `json:"tls_passthrough,omitempty"`
	ServerNames             []string             `json:"server_names,omitempty"`
	// NewConnRate is set only for a limited stream (migration 299).
	NewConnRate *edgeconfig.L4NewConnRateV2 `json:"new_conn_rate,omitempty"`
	// TOA is set only for a TOA stream (L4_TOA v1).
	TOA bool `json:"toa,omitempty"`
	// SessionLog is set only for a logging stream (migration 328).
	SessionLog bool `json:"session_log,omitempty"`
	// GuardRules is set only for a guarded stream (migration 335): the ACL's
	// rules first, then the stream's own.
	GuardRules []GuardRule `json:"guard_rules,omitempty"`
	// ListenIPv6 is set only for an IPv6 stream (migration 490).
	ListenIPv6 bool `json:"listen_ipv6,omitempty"`
}

type PublishIntent struct {
	ID                          uuid.UUID   `json:"id"`
	Version                     int64       `json:"version"`
	Operation                   string      `json:"operation"`
	DesiredState                string      `json:"desired_state"`
	ResourceRevision            int64       `json:"resource_revision"`
	ConfigurationSourceRevision int64       `json:"configuration_source_revision"`
	RuntimeSpec                 RuntimeSpec `json:"runtime_spec"`
	State                       string      `json:"state"`
	AutomaticRequestID          *uuid.UUID  `json:"automatic_request_id"`
	PublicationID               *uuid.UUID  `json:"publication_id"`
	RolloutID                   *uuid.UUID  `json:"rollout_id"`
	CreatedAt                   time.Time   `json:"created_at"`
}

type Forward struct {
	ID            uuid.UUID `json:"id"`
	DisplayID     string    `json:"display_id"`
	ScopeID       uuid.UUID `json:"scope_id"`
	CNAME         *string   `json:"cname,omitempty"`
	CNAMEDomain   *string   `json:"cname_domain,omitempty"`
	CNAMEHostname *string   `json:"cname_hostname,omitempty"`
	CNAMEState    *string   `json:"cname_state,omitempty"`
	// CNAMEFailureCode: why the stream's own CNAME failed (migration 505).
	CNAMEFailureCode        *string              `json:"cname_failure_code,omitempty"`
	PackageSubscriptionID   *uuid.UUID           `json:"package_subscription_id"`
	PackageName             *string              `json:"package_name"`
	PackageExpiresAt        *time.Time           `json:"package_expires_at"`
	EligibilityState        EligibilityState     `json:"eligibility_state"`
	Owner                   *OwnerReference      `json:"owner"`
	Name                    string               `json:"name"`
	Remark                  string               `json:"remark"`
	Protocol                string               `json:"protocol"`
	ListenAddress           string               `json:"listen_address"`
	ListenPort              uint16               `json:"listen_port"`
	AdditionalListeners     []AdditionalListener `json:"additional_listeners,omitempty"`
	UpstreamAddress         string               `json:"upstream_address"`
	UpstreamHost            string               `json:"upstream_host"`
	UpstreamPort            uint16               `json:"upstream_port"`
	DNS                     DNSPolicy            `json:"dns_policy"`
	Geo                     GeoPolicy            `json:"geo_policy"`
	ConnectTimeoutMS        int                  `json:"connect_timeout_ms"`
	ResponseTimeoutMS       int                  `json:"response_timeout_ms"`
	MaxConnectionsPerClient int                  `json:"max_connections_per_client"`
	ProxyProtocolInbound    bool                 `json:"proxy_protocol_inbound"`
	ProxyProtocolV1         bool                 `json:"proxy_protocol_v1"`
	TLSPassthrough          bool                 `json:"tls_passthrough"`
	ServerNames             []string             `json:"server_names"`
	ListenPortEnd           uint16               `json:"listen_port_end"`
	UpstreamFollowPort      bool                 `json:"upstream_follow_port"`
	// 单 IP 新建连接速率 (migration 299): 0 is unlimited.
	MaxNewConnectionsPerClientPerSecond int `json:"max_new_connections_per_client_per_second"`
	NewConnectionBurst                  int `json:"new_connection_burst"`
	NewConnectionBanSeconds             int `json:"new_connection_ban_seconds"`
	// 回源携带客户端 IP via TOA (TCP option 254); excludes ProxyProtocolV1.
	TOA bool `json:"toa"`
	// 会话日志 (migration 328): access log with the client and live sessions.
	SessionLogEnabled bool `json:"session_log_enabled"`
	// 防护规则 (migration 335): in evaluation order; always an array.
	GuardRules []GuardRule `json:"guard_rules"`
	// 源站列表 (migration 490): always an array (one entry for a single origin).
	Origins []Origin `json:"origins"`
	// IPv6开启 / 访问控制 / 设置状态 (migration 490).
	ListenIPv6  bool   `json:"listen_ipv6"`
	ACL         ACL    `json:"acl"`
	AdminStatus string `json:"admin_status"`
	// 转发自有 CNAME域名 / CNAME模式 / 线路分组 (migration 491, 更多操作):
	// nil follows the package. Line and the CNAME columns
	// above are the effective values.
	Overrides Overrides `json:"overrides"`
	// 线路 / 同步状态: read only, derived (never written by a client).
	Line          LineReference    `json:"line"`
	SyncState     string           `json:"sync_state"`
	BalanceWay    string           `json:"balance_way"`
	Groups        []GroupReference `json:"groups"`
	Enabled       bool             `json:"enabled"`
	Revision      int64            `json:"revision"`
	PublishIntent PublishIntent    `json:"publish_intent"`
	CreatedAt     time.Time        `json:"created_at"`
	UpdatedAt     time.Time        `json:"updated_at"`
	ownerUserID   uuid.UUID
}

// MarshalJSON always writes server_names as an array, including for rows and
// stored responses that predate it.
func (forward Forward) MarshalJSON() ([]byte, error) {
	type plain Forward
	if forward.ServerNames == nil {
		forward.ServerNames = []string{}
	}
	if forward.GuardRules == nil {
		forward.GuardRules = []GuardRule{}
	}
	if forward.Origins == nil {
		forward.Origins = []Origin{}
	}
	if forward.ACL.Rules == nil {
		forward.ACL.Rules = []ACLRule{}
	}
	if forward.ACL.DefaultAction == "" {
		forward.ACL.DefaultAction = ACLActionAllow
	}
	if forward.AdminStatus == "" {
		forward.AdminStatus = AdminStatusNormal
	}
	if forward.SyncState == "" {
		forward.SyncState = SyncStatePending // a write's response: not delivered yet
	}
	return json.Marshal(plain(forward))
}

type Fields struct {
	PackageSubscriptionID   *uuid.UUID            `json:"package_subscription_id"`
	Name                    string                `json:"name"`
	Remark                  string                `json:"remark"`
	Protocol                string                `json:"protocol"`
	ListenAddress           string                `json:"listen_address"`
	ListenPort              uint16                `json:"listen_port"`
	AdditionalListeners     *[]AdditionalListener `json:"additional_listeners,omitempty"`
	UpstreamAddress         string                `json:"upstream_address"`
	UpstreamHost            string                `json:"upstream_host"`
	UpstreamPort            uint16                `json:"upstream_port"`
	DNS                     DNSPolicy             `json:"dns_policy"`
	Geo                     GeoPolicy             `json:"geo_policy"`
	ConnectTimeoutMS        int                   `json:"connect_timeout_ms"`
	ResponseTimeoutMS       int                   `json:"response_timeout_ms"`
	MaxConnectionsPerClient int                   `json:"max_connections_per_client"`
	ProxyProtocolInbound    bool                  `json:"proxy_protocol_inbound"`
	ProxyProtocolV1         bool                  `json:"proxy_protocol_v1"`
	// TLSPassthrough streams forward TLS unterminated and are picked by SNI
	// (ServerNames: exact host names or a leading "*." wildcard), so they
	// can share a TCP port with other TLS consumers. Omitted when unset so
	// idempotency digests of plain requests do not change.
	TLSPassthrough bool     `json:"tls_passthrough,omitempty"`
	ServerNames    []string `json:"server_names,omitempty"`
	// 单 IP 新建连接速率 (new_conn_rate, tcp/udp v6): connections (UDP:
	// sessions) per second one client IP may open, 0 = unlimited; a burst
	// above it; and how long a client over it is refused (0 = only the excess).
	// Omitted when 0 so idempotency digests of other requests do not change.
	MaxNewConnectionsPerClientPerSecond int `json:"max_new_connections_per_client_per_second,omitempty"`
	NewConnectionBurst                  int `json:"new_connection_burst,omitempty"`
	NewConnectionBanSeconds             int `json:"new_connection_ban_seconds,omitempty"`
	// 回源携带客户端 IP: TOA writes the IPv4 client address into TCP option
	// 254 towards the origin (L4_TOA nodes only). TCP only; excludes PROXY
	// protocol in both directions. Omitted when unset (digests unchanged).
	TOA bool `json:"toa,omitempty"`
	// 会话日志 (session_log, tcp/udp v7). Omitted when false so idempotency
	// digests of other requests do not change.
	SessionLogEnabled bool `json:"session_log_enabled,omitempty"`
	// 端口范围 / 跟随端口回源 (port_end / follow_port, tcp/udp v9, migration
	// 331): the listener is listen_port..listen_port_end (at most 1000 ports,
	// 0 = single); with follow-port the origin is reached on the client's port
	// and upstream_port is set to listen_port. Omitted when unset.
	ListenPortEnd      uint16 `json:"listen_port_end,omitempty"`
	UpstreamFollowPort bool   `json:"upstream_follow_port,omitempty"`
	// 防护规则 (guard_rules, tcp/udp v10, migration 335): evaluated in order,
	// the first rule whose conditions all hold decides (drop / ban / allow).
	// Each rule carries its id (a UUID the client generates, so retries keep
	// the request digest). Omitted when empty (digests unchanged).
	GuardRules []GuardRule `json:"guard_rules,omitempty"`
	// 源站列表 (migration 490): several origins with weight and up/down; when
	// set, upstream_address/upstream_host are taken from it (the first
	// origin). Several origins must be IP addresses; one may be a domain.
	// Omitted when unset (digests of single-origin requests unchanged).
	Origins []Origin `json:"origins,omitempty"`
	// IPv6开启 (migration 490): also listen on IPv6. Omitted when false.
	ListenIPv6 bool `json:"listen_ipv6,omitempty"`
	// 访问控制 (migration 490): nil keeps default allow without rules.
	ACL        *ACL   `json:"acl,omitempty"`
	BalanceWay string `json:"balance_way"`
	Enabled    bool   `json:"enabled"`
}

// GuardRule is the edge contract of one L4 guard rule (edgeconfig.L4GuardRuleV2).
type GuardRule = edgeconfig.L4GuardRuleV2

type CreateRequest struct {
	TargetScopeID  uuid.UUID
	OwnerUserID    uuid.UUID
	Fields         Fields
	GroupIDs       []uuid.UUID
	IdempotencyKey string
	RequestID      string
}

type UpdateRequest struct {
	ID               uuid.UUID
	ExpectedRevision int64
	Fields           Fields
	// GroupIDs 为空指针表示本次不调整所属分组（保持原样），空切片表示清空全部分组。
	GroupIDs       *[]uuid.UUID
	IdempotencyKey string
	RequestID      string
}

type DeleteRequest struct {
	ID               uuid.UUID
	ExpectedRevision int64
	IdempotencyKey   string
	RequestID        string
}

type ListFilter struct {
	Page             int
	Limit            int
	Search           string
	Protocol         string
	Enabled          *bool
	ListenPort       *int64
	Upstream         string
	DisplayID        *int64
	OwnerDisplayID   *int64
	PublicationState string
	GroupID          *uuid.UUID
	PackageProductID *uuid.UUID
	CNAMEDomain      string
	CNAMEHostname    string
	// 区域 / 线路分组 / 同步状态 / 状态 (stream-be): on the derived line,
	// the delivery state and the admin status, server side.
	RegionID    *uuid.UUID
	NodeGroupID *uuid.UUID
	SyncState   string
	AdminStatus string
}

type ListResult struct {
	Items []Forward `json:"items"`
	Total int64     `json:"total"`
	Page  int       `json:"page"`
	Limit int       `json:"limit"`
}

type WriteResult struct {
	Forward  Forward
	Replayed bool
}

type DeleteResult struct {
	Replayed      bool
	PublishIntent PublishIntent
}

// Group 对应「分组管理」表格的 ID/用户/名称/备注 四列。
type Group struct {
	ID          uuid.UUID       `json:"id"`
	DisplayID   string          `json:"display_id"`
	ScopeID     uuid.UUID       `json:"scope_id"`
	Owner       *OwnerReference `json:"owner"`
	Name        string          `json:"name"`
	Remark      string          `json:"remark"`
	StreamCount int64           `json:"stream_count"`
	Revision    int64           `json:"revision"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
	ownerUserID uuid.UUID
}

type GroupFields struct {
	Name   string `json:"name"`
	Remark string `json:"remark"`
}

type GroupCreateRequest struct {
	TargetScopeID  uuid.UUID
	OwnerUserID    uuid.UUID
	Fields         GroupFields
	IdempotencyKey string
	RequestID      string
}

type GroupUpdateRequest struct {
	ID               uuid.UUID
	ExpectedRevision int64
	Fields           GroupFields
	IdempotencyKey   string
	RequestID        string
}

type GroupDeleteRequest struct {
	ID               uuid.UUID
	ExpectedRevision int64
	IdempotencyKey   string
	RequestID        string
}

type GroupListFilter struct {
	Page   int
	Limit  int
	Search string
}

type GroupListResult struct {
	Items []Group `json:"items"`
	Total int64   `json:"total"`
	Page  int     `json:"page"`
	Limit int     `json:"limit"`
}

type GroupWriteResult struct {
	Group    Group
	Replayed bool
}

// UserDefault 对应「默认设置」表格的 ID/用户/设置项/设置值/生效范围 五列。
type UserDefault struct {
	ID          uuid.UUID       `json:"id"`
	DisplayID   string          `json:"display_id"`
	ScopeID     uuid.UUID       `json:"scope_id"`
	Owner       *OwnerReference `json:"owner"`
	SettingName string          `json:"setting_name"`
	Value       string          `json:"setting_value"`
	ScopeName   string          `json:"scope_name"`
	Group       *GroupReference `json:"group"`
	CreatedAt   time.Time       `json:"created_at"`
	ownerUserID uuid.UUID
}

type UserDefaultFields struct {
	SettingName string     `json:"setting_name"`
	Value       string     `json:"setting_value"`
	ScopeName   string     `json:"scope_name"`
	GroupID     *uuid.UUID `json:"group_id"`
}

type UserDefaultCreateRequest struct {
	TargetScopeID  uuid.UUID
	OwnerUserID    uuid.UUID
	Fields         UserDefaultFields
	IdempotencyKey string
	RequestID      string
}

type UserDefaultDeleteRequest struct {
	ID             uuid.UUID
	IdempotencyKey string
	RequestID      string
}

type UserDefaultListFilter struct {
	Page   int
	Limit  int
	Search string
}

type UserDefaultListResult struct {
	Items []UserDefault `json:"items"`
	Total int64         `json:"total"`
	Page  int           `json:"page"`
	Limit int           `json:"limit"`
}

type UserDefaultWriteResult struct {
	Default  UserDefault
	Replayed bool
}

// FieldDefaults 是建转发时按「默认设置」解析出的待带入值，nil 表示该项未配置默认。
type FieldDefaults struct {
	Protocol             *string `json:"protocol"`
	ProxyProtocolInbound *bool   `json:"proxy_protocol_inbound"`
	BalanceWay           *string `json:"balance_way"`
}
