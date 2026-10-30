package node

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

const (
	StatePending  = "pending"
	StateActive   = "active"
	StateDraining = "draining"
	StateDisabled = "disabled"
	StateRetired  = "retired"

	PurposeInitial      = "initial_enrollment"
	PurposeReEnrollment = "re_enrollment"
)

var (
	ErrNotFound            = errors.New("node not found")
	ErrDuplicateName       = errors.New("node name already exists")
	ErrInvalidInput        = errors.New("invalid node input")
	ErrEnrollmentDenied    = errors.New("node enrollment denied")
	ErrInvalidToken        = errors.New("invalid enrollment token")
	ErrTokenExpired        = errors.New("enrollment token expired")
	ErrTokenConsumed       = errors.New("enrollment token consumed")
	ErrIdempotencyConflict = errors.New("enrollment request conflict")
	ErrRevisionConflict    = errors.New("node revision conflict")
	ErrStateTransition     = errors.New("node state transition denied")
	ErrIdentityRequired    = errors.New("node enrollment authorization required")
	ErrIPConflict          = errors.New("node IP is already used by an enabled node")
	ErrRetired             = errors.New("retired node is immutable")
	ErrInUse               = errors.New("node is still used by a line group, an L2 configuration or unfinished multi-node work")
	// ErrSupplyInUse: the change would leave a node-market supply with a
	// normal subscriber without an online available node (ADR 0012 §18.4,
	// ML-18); it wraps *marketsupplyguard.InUseError.
	ErrSupplyInUse = errors.New("node is the last online node of a market supply with normal subscribers")
	// ErrAddressInUse: an update would drop an address (primary or secondary)
	// that a current line-group revision still publishes for this node.
	ErrAddressInUse = errors.New("node address is still used by a line group endpoint")
	// ErrRegionInUse: a region change would leave the node in the current
	// revision of a line group of another region (line groups only take
	// nodes of their own region); remove it from that line group first.
	ErrRegionInUse = errors.New("node is used by a line group of another region")
	// ErrSchedule302HostnameConflict: another node has this direct hostname
	// (HTTP 302 scheduling).
	ErrSchedule302HostnameConflict = errors.New("node direct hostname already exists")
	// ErrStorageUnsupported: the cache directory, cache limit or log
	// directory changes but the node's Agent does not declare NODE_STORAGE.
	ErrStorageUnsupported = errors.New("node agent does not support storage settings")
	// ErrStorageExceedsDisk: the cache limit is over the size of the disk
	// the node reports for the cache directory.
	ErrStorageExceedsDisk = errors.New("node cache limit exceeds the disk")
)

type Actor struct {
	UserID  uuid.UUID
	ScopeID uuid.UUID
}

type NodeIPLocation struct {
	Country     string `json:"country"`
	Province    string `json:"province"`
	City        string `json:"city"`
	ISP         string `json:"isp"`
	CountryCode string `json:"country_code"`
}

type NodeAutoDisableSettings struct {
	BandwidthLimit     uint64   `json:"bandwidth_limit"`
	BandwidthUnit      string   `json:"bandwidth_unit"`
	TrafficEnabled     bool     `json:"traffic_enabled"`
	TrafficFromDay     int      `json:"traffic_from_day"`
	TrafficFromTime    string   `json:"traffic_from_time"`
	TrafficTotalGB     uint64   `json:"traffic_total_gb"`
	TrafficTypes       []string `json:"traffic_types"`
	ExcludedInterfaces string   `json:"excluded_interfaces"`
	DisabledPeriods    string   `json:"disabled_periods"`
}

type NodeManagementSettings struct {
	SchemaVersion  int                     `json:"schema_version"`
	Sort           int                     `json:"sort"`
	NodeType       string                  `json:"node_type"`
	CacheDirectory string                  `json:"cache_directory"`
	CacheLimitGB   uint64                  `json:"cache_limit_gb"`
	LogDirectory   string                  `json:"log_directory"`
	IPLocation     NodeIPLocation          `json:"ip_location"`
	// IPLocationManual lists the ip_location fields an administrator set;
	// the others follow the automatic resolution (iplocation.go, 547).
	IPLocationManual []string                `json:"ip_location_manual,omitempty"`
	AutoDisable      NodeAutoDisableSettings `json:"auto_disable"`
	SecondaryIPs   []string                `json:"secondary_ips"`
	// ExternalProbe: the node votes as a peer in external probing of other
	// nodes (nodeprobe). The Agent runs probe-only by default (installer);
	// turning this off stops asking it. It never joins the node market.
	ExternalProbe bool `json:"external_probe"`
	// Schedule302Hostname is the node's direct hostname for HTTP 302
	// scheduling (sites with target=hostname redirect here); "" none.
	Schedule302Hostname string `json:"schedule302_hostname,omitempty"`
}

func DefaultNodeManagementSettings() NodeManagementSettings {
	return NodeManagementSettings{
		SchemaVersion: 1,
		Sort:          100,
		NodeType:      "L1",
		AutoDisable: NodeAutoDisableSettings{
			BandwidthUnit:   "Mbps",
			TrafficEnabled:  false, // enforced since 281; off by default like the reference
			TrafficFromDay:  1,
			TrafficFromTime: "00:00:00",
			TrafficTotalGB:  500,
			TrafficTypes:    []string{"outbound"},
		},
		SecondaryIPs:  []string{},
		ExternalProbe: true,
	}
}

type Node struct {
	ID                 uuid.UUID              `json:"id"`
	DisplayID          string                 `json:"display_id"`
	Name               string                 `json:"name"`
	Description        string                 `json:"description"`
	Region             string                 `json:"region"`
	IPv4               *string                `json:"ipv4,omitempty"`
	IPv6               *string                `json:"ipv6,omitempty"`
	AdminState         string                 `json:"admin_state"`
	ManagementSettings NodeManagementSettings `json:"management_settings"`
	Revision           int64                  `json:"revision"`
	CreatedAt          time.Time              `json:"created_at"`
	UpdatedAt          time.Time              `json:"updated_at"`
}

// NetworkInventoryStatus describes automatic address discovery, not port health.
type NetworkInventoryStatus struct {
	SchemaVersion int        `json:"schema_version"`
	IPv4State     string     `json:"ipv4_state"`
	IPv6State     string     `json:"ipv6_state"`
	ReceivedAt    *time.Time `json:"received_at,omitempty"`
}

type TokenMetadata struct {
	ID        uuid.UUID `json:"id"`
	NodeID    uuid.UUID `json:"node_id"`
	Purpose   string    `json:"purpose"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type IssuedToken struct {
	TokenMetadata
	Token string `json:"token"`
}

type Authorization struct {
	ID           uuid.UUID `json:"id"`
	NodeID       uuid.UUID `json:"node_id"`
	Purpose      string    `json:"purpose"`
	RequestID    string    `json:"request_id"`
	AuthorizedAt time.Time `json:"authorized_at"`
}

type CreateRequest struct {
	Name           string
	Description    string
	Region         string
	IPv4           string
	IPv6           string
	IssueToken     bool
	TokenPurpose   string
	TokenTTL       time.Duration
	IdempotencyKey string
	RequestID      string
}

type CreateResult struct {
	Node            Node         `json:"node"`
	EnrollmentToken *IssuedToken `json:"enrollment_token,omitempty"`
	Replayed        bool         `json:"-"`
}

type UpdateFields struct {
	Name               *string                 `json:"name,omitempty"`
	Description        *string                 `json:"description,omitempty"`
	Region             *string                 `json:"region,omitempty"`
	IPv4               *string                 `json:"ipv4,omitempty"`
	IPv6               *string                 `json:"ipv6,omitempty"`
	AdminState         *string                 `json:"admin_state,omitempty"`
	ManagementSettings *NodeManagementSettings `json:"management_settings,omitempty"`
}

type UpdateRequest struct {
	ID               uuid.UUID    `json:"id"`
	ExpectedRevision int64        `json:"expected_revision"`
	Fields           UpdateFields `json:"fields"`
	IdempotencyKey   string       `json:"-"`
	RequestID        string       `json:"-"`
}

type WriteResult struct {
	Node     Node `json:"node"`
	Replayed bool `json:"-"`
}

type BatchAdminStateItem struct {
	ID               uuid.UUID `json:"id"`
	ExpectedRevision int64     `json:"expected_revision"`
}

type BatchAdminStateRequest struct {
	AdminState     string                `json:"admin_state"`
	Items          []BatchAdminStateItem `json:"items"`
	IdempotencyKey string                `json:"-"`
	RequestID      string                `json:"-"`
}

type BatchItemError struct {
	Code string `json:"code"`
	// Counts of a supply_in_use refusal (ADR 0012 ML-18).
	OnlineAvailable     *int `json:"online_available,omitempty"`
	NormalSubscriptions *int `json:"normal_subscriptions,omitempty"`
}

type BatchAdminStateItemResult struct {
	ID     uuid.UUID       `json:"id"`
	Status string          `json:"status"`
	Node   *Node           `json:"node,omitempty"`
	Error  *BatchItemError `json:"error,omitempty"`
}

type BatchAdminStateResult struct {
	Items    []BatchAdminStateItemResult `json:"items"`
	Replayed bool                        `json:"-"`
}

type ListRequest struct {
	ScopeID uuid.UUID
	State   string
	After   *uuid.UUID
	Limit   int
}

type ListResult struct {
	Items      []Node
	NextCursor *uuid.UUID
}

type ConsumeRequest struct {
	Token         string
	Purpose       string
	RequestID     string
	RequestDigest [32]byte
}
