package nodemonitoringconfig

import (
	"encoding/json"
	"errors"

	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
)

const SchemaVersion = "cdnca.node-monitoring/v1"

var ErrInvalidDocument = errors.New("invalid node monitoring category document")

type Artifact struct {
	SchemaVersion               string    `json:"schema_version"`
	ConfigRevision              uint64    `json:"config_revision"`
	PortMode                    string    `json:"port_mode"`
	CustomPort                  *uint16   `json:"custom_port,omitempty"`
	MonitorEnabled              *bool     `json:"monitor_enabled,omitempty"`
	Protocol                    string    `json:"protocol,omitempty"`
	MonitorPort                 *uint16   `json:"monitor_port,omitempty"`
	MonitorGroups               *[]string `json:"monitor_groups,omitempty"`
	MonitorAction               string    `json:"monitor_action,omitempty"`
	FailureRatio                *uint8    `json:"failure_ratio,omitempty"`
	BandwidthOverLimit          *uint8    `json:"bandwidth_over_limit,omitempty"`
	ProbeIntervalMS             uint32    `json:"probe_interval_ms"`
	ProbeTimeoutMS              uint32    `json:"probe_timeout_ms"`
	FailureThreshold            uint8     `json:"failure_threshold"`
	RecoveryThreshold           uint8     `json:"recovery_threshold"`
	FailureDebounceMS           uint32    `json:"failure_debounce_ms"`
	RecoveryDebounceMS          uint32    `json:"recovery_debounce_ms"`
	RecoveryNotificationEnabled bool      `json:"recovery_notification_enabled"`
}

func CompileCategoryDocument(document systemconfig.CategoryDocument) ([]byte, error) {
	value, err := activePolicy(document)
	if err != nil {
		return nil, err
	}
	return compile(value, uint64(document.ActiveRevision))
}

func activePolicy(document systemconfig.CategoryDocument) (systemconfig.NodeMonitoringConfiguration, error) {
	value, ok := document.Value.(systemconfig.NodeMonitoringConfiguration)
	if document.Category != systemconfig.CategoryNodeMonitoring || document.ActiveRevision < 1 ||
		document.Revision != document.ActiveRevision || document.HeadRevision < document.ActiveRevision || !ok ||
		!validPolicy(value) {
		return systemconfig.NodeMonitoringConfiguration{}, ErrInvalidDocument
	}
	return value, nil
}

func compile(value systemconfig.NodeMonitoringConfiguration, revision uint64) ([]byte, error) {
	artifact := Artifact{
		SchemaVersion: SchemaVersion, ConfigRevision: revision,
		PortMode: value.PortMode, CustomPort: clonePort(value.CustomPort),
		MonitorEnabled: cloneBool(value.MonitorEnabled), Protocol: value.Protocol,
		MonitorPort: clonePort(value.MonitorPort), MonitorGroups: cloneStrings(value.MonitorGroups),
		MonitorAction: value.MonitorAction, FailureRatio: cloneUint8(value.FailureRatio),
		BandwidthOverLimit: cloneUint8(value.BandwidthOverLimit),
		ProbeIntervalMS:    uint32(value.ProbeIntervalMS), ProbeTimeoutMS: uint32(value.ProbeTimeoutMS),
		FailureThreshold: uint8(value.FailureThreshold), RecoveryThreshold: uint8(value.RecoveryThreshold),
		FailureDebounceMS: uint32(value.FailureDebounceMS), RecoveryDebounceMS: uint32(value.RecoveryDebounceMS),
		RecoveryNotificationEnabled: value.RecoveryNotificationEnabled,
	}
	return json.Marshal(artifact)
}

func validPolicy(value systemconfig.NodeMonitoringConfiguration) bool {
	validPort := value.PortMode == "default" && value.CustomPort == nil ||
		value.PortMode == "custom" && value.CustomPort != nil && *value.CustomPort > 0
	return validPort && value.ProbeIntervalMS >= 1_000 && value.ProbeIntervalMS <= 300_000 &&
		value.ProbeTimeoutMS >= 100 && value.ProbeTimeoutMS <= 60_000 &&
		value.ProbeTimeoutMS <= value.ProbeIntervalMS &&
		value.FailureThreshold >= 1 && value.FailureThreshold <= 20 &&
		value.RecoveryThreshold >= 1 && value.RecoveryThreshold <= 20 &&
		value.FailureDebounceMS >= 0 && value.FailureDebounceMS <= 3_600_000 &&
		value.RecoveryDebounceMS >= 0 && value.RecoveryDebounceMS <= 3_600_000
}

func clonePort(port *uint16) *uint16 {
	if port == nil {
		return nil
	}
	cloned := *port
	return &cloned
}

func cloneBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneUint8(value *uint8) *uint8 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneStrings(value *[]string) *[]string {
	if value == nil {
		return nil
	}
	cloned := append([]string(nil), (*value)...)
	return &cloned
}
