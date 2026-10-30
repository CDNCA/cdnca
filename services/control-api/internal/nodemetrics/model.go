package nodemetrics

import (
	"context"
	"crypto/sha256"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
)

const (
	NodeMonitoringStatusStream   = "NODE_MONITORING_STATUS"
	DefaultConsumerDurable       = "control_api_node_metrics"
	DefaultSubjectPrefix         = "cdnca.agent.node-monitoring.status"
	RecordMetric                 = "metric"
	RecordHostMetric             = "host_metric"
	RecordRecoveryNotification   = "recovery_notification"
	RecordCCAutoSwitch           = "cc_auto_switch"
	RecoveryReasonProbeRecovered = "probe_recovered"
	DispositionAck               = "ack"
	DispositionNak               = "nak"
	DispositionTerm              = "term"
)

var (
	ErrInvalidConfiguration = errors.New("invalid node metrics configuration")
	ErrInvalidDelivery      = errors.New("invalid node metrics delivery")
	ErrInvalidSample        = errors.New("invalid node metrics sample")
	ErrConflict             = errors.New("node metrics replay conflict")
	ErrNoMessage            = errors.New("no node metrics message")
)

type DeliveryMetadata struct {
	Stream           string
	Durable          string
	StreamSequence   uint64
	ConsumerSequence uint64
	NumDelivered     uint64
}

type Delivery interface {
	Subject() string
	Data() []byte
	Metadata() DeliveryMetadata
	Ack(context.Context) error
	Nak(context.Context, time.Duration) error
	Term(context.Context) error
}

type Sample struct {
	EventID               string
	RequestID             string
	NodeID                string
	SchemaVersion         uint8
	ConfigRevision        uint64
	AppliedConfigRevision uint64
	PublicationSequence   uint64
	ObservedAt            time.Time
	Kind                  string
	ActiveConfigRevision  uint64
	ProbePort             uint16
	Healthy               bool
	ProbeSucceeded        bool
	ConsecutiveFailures   uint8
	ConsecutiveSuccesses  uint8
	ProbesTotal           uint64
	ProbeFailuresTotal    uint64
	Recovered             bool
	RecoveryNotified      bool
	RolledBack            bool
	RecoveryReasonCode    string
	Known                 bool
	CPUPercent            float64
	MemoryUsedBytes       uint64
	MemoryTotalBytes      uint64
	ActiveConnections     uint64
	RXBandwidthBPS        uint64
	TXBandwidthBPS        uint64
	PubAckStream          string
	PubAckSequence        uint64
	ConsumerDurable       string
	ConsumerSequence      uint64
	NumDelivered          uint64
	WireSHA256            [sha256.Size]byte
	Telemetry             *Telemetry
	// CCAutoSwitch is set only for RecordCCAutoSwitch, which never reaches
	// node_metric_samples (FX65).
	CCAutoSwitch *CCAutoSwitchEvent
}

// CCAutoSwitchEvent is one CC auto switch engagement of a site on a node, as
// reported by the node (FX65). Trigger* are the observed per-second rates at
// engagement; QPSTotal/QPS5xx are the configured thresholds (0 = unused).
type CCAutoSwitchEvent struct {
	NodeID         string
	TenantScopeID  string
	SiteID         string
	PolicyID       string
	PolicyVersion  uint64
	EngagedAt      time.Time
	TriggerQPS     uint64
	Trigger5xx     uint64
	QPSTotal       uint64
	QPS5xx         uint64
	RecoverSeconds uint64
}

// MonthlyTraffic is the node's natural-calendar-month external NIC counter
// delta. It is deliberately explicit about incomplete evidence so callers do
// not turn a missing or stale counter into a misleading zero.
type MonthlyTraffic struct {
	State                  string     `json:"state"`
	PeriodKey              string     `json:"period_key"`
	PeriodStart            time.Time  `json:"period_start"`
	PeriodEnd              time.Time  `json:"period_end"`
	Timezone               string     `json:"timezone"`
	UsageBytes             uint64     `json:"usage_bytes"`
	SourceFinalizedThrough *time.Time `json:"source_finalized_through"`
	Samples                int        `json:"samples"`
	// CounterResets counts the period's counter restarts (usage includes the
	// traffic after each one; the traffic between the last sample before a
	// restart and the restart itself is not observable).
	CounterResets int `json:"counter_resets"`
}

type NetworkInterface struct {
	Name           string `json:"name"`
	RXBytes        uint64 `json:"rx_bytes"`
	TXBytes        uint64 `json:"tx_bytes"`
	RXBandwidthBPS uint64 `json:"rx_bandwidth_bps"`
	TXBandwidthBPS uint64 `json:"tx_bandwidth_bps"`
}

type SystemLoad struct {
	OneMinute        float64 `json:"one_minute"`
	FiveMinutes      float64 `json:"five_minutes"`
	FifteenMinutes   float64 `json:"fifteen_minutes"`
	RunningProcesses uint32  `json:"running_processes"`
	TotalProcesses   uint32  `json:"total_processes"`
}

type DiskUsage struct {
	Path         string  `json:"path"`
	TotalBytes   uint64  `json:"total_bytes"`
	UsedBytes    uint64  `json:"used_bytes"`
	TotalInodes  uint64  `json:"total_inodes"`
	UsedInodes   uint64  `json:"used_inodes"`
	SpacePercent float64 `json:"space_percent"`
	InodePercent float64 `json:"inode_percent"`
}

type NetworkSelection struct {
	Source     string   `json:"source"`
	Interfaces []string `json:"interfaces"`
}

type Telemetry struct {
	SchemaVersion     uint8              `json:"schema_version"`
	NetworkSelection  *NetworkSelection  `json:"network_selection,omitempty"`
	NetworkInterfaces []NetworkInterface `json:"network_interfaces,omitempty"`
	SystemLoad        *SystemLoad        `json:"system_load,omitempty"`
	Disks             []DiskUsage        `json:"disks,omitempty"`
	TotalRXBytes      uint64             `json:"total_rx_bytes"`
	TotalTXBytes      uint64             `json:"total_tx_bytes"`
	DDoSDrops         []DDoSDrop         `json:"ddos_drops,omitempty"`
	XDP               *XDPStatus         `json:"xdp,omitempty"`
	SiteDrop          *SiteDrop          `json:"site_drop,omitempty"`
	DDoSProtection    *DDoSProtection    `json:"ddos_protection,omitempty"`
	// Mounts and PortGroupOverrides: NODE_TELEMETRY_DETAIL v1.
	Mounts             []Mount             `json:"mounts,omitempty"`
	PortGroupOverrides []PortGroupOverride `json:"port_group_overrides,omitempty"`
	// Storage: the node storage in effect (NODE_STORAGE v1).
	Storage *Storage `json:"storage,omitempty"`
}

// Storage is the node's cache directory, cache limit and log directory in
// effect (NodeStorageV1) and the outcome of the console's settings.
type Storage struct {
	CacheDirectory        string `json:"cache_directory"`
	CacheMaxBytes         uint64 `json:"cache_max_bytes"`
	LogDirectory          string `json:"log_directory"`
	State                 string `json:"state"`
	Reason                string `json:"reason,omitempty"`
	RequestedLogDirectory string `json:"requested_log_directory,omitempty"`
}

func validStorage(storage *Storage) bool {
	return storage == nil || siteobject.ValidNodeStorageReport(storage.CacheDirectory, storage.LogDirectory, storage.State,
		storage.Reason, storage.RequestedLogDirectory, storage.CacheMaxBytes)
}

// Mount is one mount of the node (NodeMountV1): FilterReason says why the
// disk ranking (Disks) leaves it out, empty when it is a disk row.
type Mount struct {
	Path         string `json:"path"`
	Device       string `json:"device"`
	FSType       string `json:"fstype"`
	ReadOnly     bool   `json:"read_only"`
	Bind         bool   `json:"bind"`
	FilterReason string `json:"filter_reason,omitempty"`
}

// PortGroupOverride is whether one layer 4 auto defense port group override
// is in effect on the node (NodePortGroupOverrideV1).
type PortGroupOverride struct {
	PortGroupID string `json:"port_group_id"`
	State       string `json:"state"`
	Reason      string `json:"reason,omitempty"`
}

var (
	mountFilterReasons       = map[string]bool{"bind_duplicate": true, "read_only": true, "squashfs": true, "stat_failed": true, "system_path": true}
	portGroupOverrideStates  = map[string]bool{"applied": true, "failed": true, "inactive": true, "standby": true}
	portGroupOverrideReasons = map[string]bool{"auto_mitigation_off": true, "manual": true, "shared_ports": true, "suggest": true}
	mountDevicePattern       = regexp.MustCompile(`^[0-9]{1,10}:[0-9]{1,10}$`)
	portGroupIDPattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
)

// validMounts mirrors the gateway's check.
func validMounts(mounts []Mount) bool {
	if len(mounts) > 256 {
		return false
	}
	previous := ""
	for _, mount := range mounts {
		if mount.Path == "" || len(mount.Path) > 4096 || mount.Path[0] != '/' || mount.Path <= previous ||
			!utf8.ValidString(mount.Path) || strings.ContainsRune(mount.Path, 0) || !mountDevicePattern.MatchString(mount.Device) ||
			len(mount.FSType) > 64 || strings.ContainsAny(mount.FSType, "\x00\r\n\t ") || !utf8.ValidString(mount.FSType) ||
			(mount.FilterReason != "" && !mountFilterReasons[mount.FilterReason]) {
			return false
		}
		previous = mount.Path
	}
	return true
}

// validPortGroupOverrides mirrors the gateway's check.
func validPortGroupOverrides(overrides []PortGroupOverride) bool {
	if len(overrides) > 256 {
		return false
	}
	previous := ""
	for _, item := range overrides {
		if !portGroupIDPattern.MatchString(item.PortGroupID) || item.PortGroupID <= previous ||
			!portGroupOverrideStates[item.State] || (item.State == "inactive") != (item.Reason != "") ||
			(item.Reason != "" && !portGroupOverrideReasons[item.Reason]) {
			return false
		}
		previous = item.PortGroupID
	}
	return true
}

// DDoSProtection is the node DDoS protection table's state
// (NodeDDoSProtectionV1): applied, off, pending, failed or
// unavailable with the reason; the console shows failed / unavailable as a
// protection fault.
type DDoSProtection struct {
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
	Detail string `json:"detail,omitempty"`
}

var (
	ddosProtectionStates  = map[string]bool{"applied": true, "failed": true, "off": true, "pending": true, "unavailable": true}
	ddosProtectionReasons = map[string]bool{"init_failed": true, "nft_missing": true, "nft_unusable": true, "unsupported_os": true}
)

// validDDoSProtection mirrors the gateway's check.
func validDDoSProtection(value *DDoSProtection) bool {
	if value == nil {
		return true
	}
	unavailable := value.State == "unavailable"
	return ddosProtectionStates[value.State] && unavailable == (value.Reason != "") &&
		(!unavailable || ddosProtectionReasons[value.Reason]) &&
		(value.Detail == "" || unavailable || value.State == "failed") &&
		len(value.Detail) <= 256 && utf8.ValidString(value.Detail) && !strings.ContainsAny(value.Detail, "\x00\r\n")
}

// SiteDrop is the node's level D site drops since its previous sample
// (攻击自动升级), shared by SiteIDs: the node counters are not per site.
type SiteDrop struct {
	SiteIDs []string `json:"site_ids"`
	Packets uint64   `json:"packets"`
	Bytes   uint64   `json:"bytes"`
}

type Store interface {
	Put(context.Context, Sample) (bool, error)
}

// CCAutoSwitchRecorder consumes RecordCCAutoSwitch samples. It returns
// ErrInvalidSample for a sample it can never accept; any other error is
// retried.
type CCAutoSwitchRecorder interface {
	RecordCCAutoSwitch(context.Context, Sample) error
}
