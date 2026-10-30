package nodemonitoring

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const SchemaVersion = "cdnca.node-monitoring/v1"

const maximumConfigBytes = 16 << 10

var (
	ErrInvalidConfig  = errors.New("invalid node monitoring configuration")
	ErrInvalidOptions = errors.New("invalid node monitoring runtime options")
	ErrConflict       = errors.New("node monitoring configuration revision conflict")
	ErrPreflight      = errors.New("node monitoring preflight failed")
	ErrNoActiveConfig = errors.New("node monitoring has no active configuration")
	ErrCorruptState   = errors.New("corrupt node monitoring runtime state")
	ErrRollback       = errors.New("node monitoring rollback failed")
)

type Config struct {
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

type Status struct {
	ConfigRevision uint64 `json:"config_revision"`
	Healthy        bool   `json:"healthy"`
}

type ApplyResult struct {
	ConfigRevision   uint64 `json:"config_revision"`
	PreviousRevision uint64 `json:"previous_revision,omitempty"`
	Replayed         bool   `json:"replayed"`
}

type RecoveryEvent struct {
	NodeID         string    `json:"node_id"`
	ConfigRevision uint64    `json:"config_revision"`
	RecoveredAt    time.Time `json:"recovered_at"`
}

func decodeConfig(payload []byte) (Config, error) {
	if len(payload) == 0 || len(payload) > maximumConfigBytes {
		return Config{}, ErrInvalidConfig
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("%w: decode: %v", ErrInvalidConfig, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Config{}, ErrInvalidConfig
	}
	if !validConfig(config) {
		return Config{}, ErrInvalidConfig
	}
	config.CustomPort = cloneUint16(config.CustomPort)
	config.MonitorEnabled = cloneBool(config.MonitorEnabled)
	config.MonitorPort = cloneUint16(config.MonitorPort)
	config.MonitorGroups = cloneStrings(config.MonitorGroups)
	config.FailureRatio = cloneUint8(config.FailureRatio)
	config.BandwidthOverLimit = cloneUint8(config.BandwidthOverLimit)
	return config, nil
}

func validConfig(config Config) bool {
	validPort := config.PortMode == "default" && config.CustomPort == nil ||
		config.PortMode == "custom" && config.CustomPort != nil && *config.CustomPort > 0
	if config.MonitorPort != nil && *config.MonitorPort == 0 {
		return false
	}
	if config.Protocol != "" && config.Protocol != "http" && config.Protocol != "tcp" && config.Protocol != "ping" {
		return false
	}
	if config.MonitorAction != "" && config.MonitorAction != "none" && config.MonitorAction != "pause" {
		return false
	}
	if config.FailureRatio != nil && (*config.FailureRatio < 1 || *config.FailureRatio > 100) {
		return false
	}
	if config.BandwidthOverLimit != nil && (*config.BandwidthOverLimit < 1 || *config.BandwidthOverLimit > 20) {
		return false
	}
	return config.SchemaVersion == SchemaVersion && config.ConfigRevision > 0 && validPort &&
		config.ProbeIntervalMS >= 1_000 && config.ProbeIntervalMS <= 300_000 &&
		config.ProbeTimeoutMS >= 100 && config.ProbeTimeoutMS <= 60_000 &&
		config.ProbeTimeoutMS <= config.ProbeIntervalMS &&
		config.FailureThreshold >= 1 && config.FailureThreshold <= 20 &&
		config.RecoveryThreshold >= 1 && config.RecoveryThreshold <= 20 &&
		config.FailureDebounceMS <= 3_600_000 && config.RecoveryDebounceMS <= 3_600_000
}

func cloneConfig(config Config) Config {
	config.CustomPort = cloneUint16(config.CustomPort)
	config.MonitorEnabled = cloneBool(config.MonitorEnabled)
	config.MonitorPort = cloneUint16(config.MonitorPort)
	config.MonitorGroups = cloneStrings(config.MonitorGroups)
	config.FailureRatio = cloneUint8(config.FailureRatio)
	config.BandwidthOverLimit = cloneUint8(config.BandwidthOverLimit)
	return config
}

func cloneUint16(value *uint16) *uint16 {
	if value == nil {
		return nil
	}
	cloned := *value
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
