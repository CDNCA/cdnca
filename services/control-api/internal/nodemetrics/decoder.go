package nodemetrics

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strings"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

type DecoderConfig struct {
	Stream          string
	Durable         string
	SubjectPrefix   string
	MaxMessageBytes int
}

func DefaultDecoderConfig() DecoderConfig {
	return DecoderConfig{Stream: NodeMonitoringStatusStream, Durable: DefaultConsumerDurable,
		SubjectPrefix: DefaultSubjectPrefix, MaxMessageBytes: 64 << 10}
}

type Decoder struct{ config DecoderConfig }

func NewDecoder(config DecoderConfig) *Decoder {
	return &Decoder{config: config}
}

func (decoder *Decoder) Decode(delivery Delivery) (Sample, bool, error) {
	if decoder == nil || delivery == nil || !decoder.config.valid() {
		return Sample{}, false, ErrInvalidConfiguration
	}
	metadata := delivery.Metadata()
	data := delivery.Data()
	if metadata.Stream != decoder.config.Stream || metadata.Durable != decoder.config.Durable ||
		metadata.StreamSequence == 0 || metadata.ConsumerSequence == 0 || metadata.NumDelivered == 0 ||
		len(data) == 0 || len(data) > decoder.config.MaxMessageBytes {
		return Sample{}, false, ErrInvalidDelivery
	}
	report := &agentv1.NodeMonitoringReport{}
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(data, report); err != nil || hasUnknown(report.ProtoReflect()) {
		return Sample{}, false, ErrInvalidDelivery
	}
	canonical, err := (proto.MarshalOptions{Deterministic: true}).Marshal(report)
	if err != nil || !bytes.Equal(canonical, data) {
		return Sample{}, false, ErrInvalidDelivery
	}
	subjectNodeID, ok := strings.CutPrefix(delivery.Subject(), decoder.config.SubjectPrefix+".")
	if !ok || !canonicalUUID(subjectNodeID) || report.NodeId != subjectNodeID ||
		report.Schema != agentv1.NodeMonitoringSchema_NODE_MONITORING_SCHEMA_V1 ||
		(report.ConfigRevision == 0) != unversionedKind(report.Kind) || report.ConfigRevision > math.MaxInt64 ||
		report.PublicationSequence == 0 || report.PublicationSequence > math.MaxInt64 ||
		report.Event == nil || !canonicalUUID(report.Event.EventId) || !canonicalUUID(report.Event.RequestId) ||
		report.Event.OccurredTime == nil || report.Event.OccurredTime.CheckValid() != nil {
		return Sample{}, false, ErrInvalidSample
	}
	if metadata.StreamSequence > math.MaxInt64 || metadata.ConsumerSequence > math.MaxInt64 || metadata.NumDelivered > math.MaxInt64 {
		return Sample{}, false, ErrInvalidDelivery
	}
	sample := Sample{EventID: report.Event.EventId, RequestID: report.Event.RequestId, NodeID: report.NodeId,
		SchemaVersion: 1, ConfigRevision: report.ConfigRevision, PublicationSequence: report.PublicationSequence,
		PubAckStream: metadata.Stream, PubAckSequence: metadata.StreamSequence,
		ConsumerDurable: metadata.Durable, ConsumerSequence: metadata.ConsumerSequence,
		NumDelivered: metadata.NumDelivered, WireSHA256: sha256.Sum256(data)}
	if report.Kind == agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_RECOVERY_NOTIFICATION {
		recovery, err := decodeRecoveryPayload(report)
		if err != nil || report.LoadMetricsV1 != nil || !report.Event.OccurredTime.AsTime().Equal(recovery.RecoveredAt) {
			return Sample{}, false, ErrInvalidSample
		}
		sample.Kind = RecordRecoveryNotification
		sample.ObservedAt = recovery.RecoveredAt
		sample.RecoveryReasonCode = RecoveryReasonProbeRecovered
		return sample, false, nil
	}
	if report.Kind == agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_CC_AUTO_SWITCH {
		event, err := decodeCCAutoSwitchPayload(report)
		if err != nil || report.LoadMetricsV1 != nil || !report.Event.OccurredTime.AsTime().Equal(event.EngagedAt) {
			return Sample{}, false, ErrInvalidSample
		}
		sample.Kind = RecordCCAutoSwitch
		sample.ObservedAt = event.EngagedAt
		sample.CCAutoSwitch = &event
		return sample, false, nil
	}
	var metric metricPayload
	if report.Kind == agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_HOST_METRIC {
		var payload struct {
			SchemaVersion         uint8     `json:"schema_version"`
			NodeID                string    `json:"node_id"`
			ObservedAt            time.Time `json:"observed_at"`
			AppliedConfigRevision uint64    `json:"applied_config_revision,omitempty"`
		}
		input := json.NewDecoder(bytes.NewReader(report.PayloadJson))
		input.DisallowUnknownFields()
		if input.Decode(&payload) != nil || input.Decode(&struct{}{}) != io.EOF || payload.SchemaVersion != 1 ||
			payload.NodeID != report.NodeId || payload.ObservedAt.IsZero() || report.LoadMetricsV1 == nil {
			return Sample{}, false, ErrInvalidSample
		}
		metric.ObservedAt = payload.ObservedAt.UTC()
		sample.AppliedConfigRevision = payload.AppliedConfigRevision
		sample.Kind = RecordHostMetric
	} else if report.Kind == agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_METRIC {
		metric, err = decodeMetricPayload(report)
		if err != nil {
			return Sample{}, false, ErrInvalidSample
		}
		sample.Kind = RecordMetric
	} else {
		return Sample{}, false, ErrInvalidSample
	}
	if !report.Event.OccurredTime.AsTime().Equal(metric.ObservedAt) {
		return Sample{}, false, ErrInvalidSample
	}
	sample.ObservedAt = metric.ObservedAt
	sample.ActiveConfigRevision = metric.ActiveConfigRevision
	sample.ProbePort = metric.ProbePort
	sample.Healthy = metric.Healthy
	sample.ProbeSucceeded = metric.ProbeSucceeded
	sample.ConsecutiveFailures = metric.ConsecutiveFailures
	sample.ConsecutiveSuccesses = metric.ConsecutiveSuccesses
	sample.ProbesTotal = metric.ProbesTotal
	sample.ProbeFailuresTotal = metric.ProbeFailuresTotal
	sample.Recovered = metric.Recovered
	sample.RecoveryNotified = metric.RecoveryNotified
	sample.RolledBack = metric.RolledBack
	load := report.LoadMetricsV1
	if load == nil {
		return sample, false, nil
	}
	if load.ObservedTime == nil || load.ObservedTime.CheckValid() != nil || !load.ObservedTime.AsTime().Equal(metric.ObservedAt) ||
		math.IsNaN(load.CpuPercent) || math.IsInf(load.CpuPercent, 0) || load.CpuPercent < 0 || load.CpuPercent > 100 ||
		load.MemoryTotalBytes == 0 || load.MemoryTotalBytes > math.MaxInt64 ||
		load.MemoryUsedBytes > load.MemoryTotalBytes || load.ActiveConnections > math.MaxInt64 ||
		load.RxBandwidthBps > math.MaxInt64 || load.TxBandwidthBps > math.MaxInt64 {
		return Sample{}, false, ErrInvalidSample
	}
	sample.Known = true
	sample.CPUPercent = load.CpuPercent
	sample.MemoryUsedBytes = load.MemoryUsedBytes
	sample.MemoryTotalBytes = load.MemoryTotalBytes
	sample.ActiveConnections = load.ActiveConnections
	sample.RXBandwidthBPS = load.RxBandwidthBps
	sample.TXBandwidthBPS = load.TxBandwidthBps
	if load.Telemetry != nil {
		telemetry, err := decodeTelemetry(load.Telemetry)
		if err != nil {
			return Sample{}, false, ErrInvalidSample
		}
		sample.Telemetry = telemetry
	}
	return sample, false, nil
}

func decodeTelemetry(value *agentv1.NodeTelemetryV1) (*Telemetry, error) {
	if value == nil || value.SchemaVersion != 1 || len(value.NetworkInterfaces) > 128 || len(value.Disks) > 128 ||
		value.TotalRxBytes > math.MaxInt64 || value.TotalTxBytes > math.MaxInt64 {
		return nil, ErrInvalidSample
	}
	telemetry := &Telemetry{SchemaVersion: uint8(value.SchemaVersion), TotalRXBytes: value.TotalRxBytes, TotalTXBytes: value.TotalTxBytes}
	if selection := value.NetworkSelection; selection != nil {
		telemetry.NetworkSelection = &NetworkSelection{Source: selection.Source, Interfaces: append([]string{}, selection.Interfaces...)}
	}
	previousName := ""
	for _, network := range value.NetworkInterfaces {
		if network == nil || network.Name == "" || len(network.Name) > 128 || previousName >= network.Name ||
			strings.ContainsAny(network.Name, "\x00\r\n\t") || network.RxBytes > math.MaxInt64 || network.TxBytes > math.MaxInt64 ||
			network.RxBandwidthBps > math.MaxInt64 || network.TxBandwidthBps > math.MaxInt64 {
			return nil, ErrInvalidSample
		}
		previousName = network.Name
		telemetry.NetworkInterfaces = append(telemetry.NetworkInterfaces, NetworkInterface{Name: network.Name,
			RXBytes: network.RxBytes, TXBytes: network.TxBytes, RXBandwidthBPS: network.RxBandwidthBps,
			TXBandwidthBPS: network.TxBandwidthBps})
	}
	if !validNetworkSelection(telemetry) {
		return nil, ErrInvalidSample
	}
	if value.SystemLoad != nil {
		load := value.SystemLoad
		for _, metric := range []float64{load.OneMinute, load.FiveMinutes, load.FifteenMinutes} {
			if math.IsNaN(metric) || math.IsInf(metric, 0) || metric < 0 || metric > 1e9 {
				return nil, ErrInvalidSample
			}
		}
		if load.TotalProcesses == 0 || load.RunningProcesses > load.TotalProcesses {
			return nil, ErrInvalidSample
		}
		telemetry.SystemLoad = &SystemLoad{OneMinute: load.OneMinute, FiveMinutes: load.FiveMinutes,
			FifteenMinutes: load.FifteenMinutes, RunningProcesses: load.RunningProcesses,
			TotalProcesses: load.TotalProcesses}
	}
	previousPath := ""
	for _, disk := range value.Disks {
		if disk == nil || disk.Path == "" || len(disk.Path) > 4096 || disk.Path[0] != '/' || previousPath >= disk.Path ||
			disk.TotalBytes > math.MaxInt64 || disk.UsedBytes > disk.TotalBytes || disk.TotalInodes > math.MaxInt64 ||
			disk.UsedInodes > disk.TotalInodes || math.IsNaN(disk.SpacePercent) || math.IsInf(disk.SpacePercent, 0) ||
			disk.SpacePercent < 0 || disk.SpacePercent > 100 || math.IsNaN(disk.InodePercent) ||
			math.IsInf(disk.InodePercent, 0) || disk.InodePercent < 0 || disk.InodePercent > 100 {
			return nil, ErrInvalidSample
		}
		previousPath = disk.Path
		telemetry.Disks = append(telemetry.Disks, DiskUsage{Path: disk.Path, TotalBytes: disk.TotalBytes,
			UsedBytes: disk.UsedBytes, TotalInodes: disk.TotalInodes, UsedInodes: disk.UsedInodes,
			SpacePercent: disk.SpacePercent, InodePercent: disk.InodePercent})
	}
	for _, drop := range value.DdosDrops {
		if drop == nil {
			return nil, ErrInvalidSample
		}
		telemetry.DDoSDrops = append(telemetry.DDoSDrops, DDoSDrop{Kind: drop.Kind, Packets: drop.Packets, Bytes: drop.Bytes})
	}
	if !validDDoSDrops(telemetry.DDoSDrops) {
		return nil, ErrInvalidSample
	}
	if drop := value.SiteDrop; drop != nil {
		telemetry.SiteDrop = &SiteDrop{SiteIDs: append([]string(nil), drop.SiteIds...), Packets: drop.Packets, Bytes: drop.Bytes}
		if !validSiteDrop(telemetry.SiteDrop) {
			return nil, ErrInvalidSample
		}
	}
	if status := value.DdosProtection; status != nil {
		telemetry.DDoSProtection = &DDoSProtection{State: status.State, Reason: status.Reason, Detail: status.Detail}
		if !validDDoSProtection(telemetry.DDoSProtection) {
			return nil, ErrInvalidSample
		}
	}
	for _, mount := range value.Mounts {
		if mount == nil {
			return nil, ErrInvalidSample
		}
		telemetry.Mounts = append(telemetry.Mounts, Mount{Path: mount.Path, Device: mount.Device, FSType: mount.Fstype,
			ReadOnly: mount.ReadOnly, Bind: mount.Bind, FilterReason: mount.FilterReason})
	}
	for _, item := range value.PortGroupOverrides {
		if item == nil {
			return nil, ErrInvalidSample
		}
		telemetry.PortGroupOverrides = append(telemetry.PortGroupOverrides, PortGroupOverride{PortGroupID: item.PortGroupId,
			State: item.State, Reason: item.Reason})
	}
	if storage := value.Storage; storage != nil {
		telemetry.Storage = &Storage{CacheDirectory: storage.CacheDirectory, CacheMaxBytes: storage.CacheMaxBytes,
			LogDirectory: storage.LogDirectory, State: storage.State, Reason: storage.Reason, RequestedLogDirectory: storage.RequestedLogDirectory}
	}
	if !validMounts(telemetry.Mounts) || !validPortGroupOverrides(telemetry.PortGroupOverrides) || !validStorage(telemetry.Storage) {
		return nil, ErrInvalidSample
	}
	if status := value.Xdp; status != nil {
		telemetry.XDP = &XDPStatus{Mode: status.Mode, Reason: status.Reason, Detail: status.Detail,
			Interfaces: append([]string(nil), status.Interfaces...)}
		for _, drop := range status.Drops {
			if drop == nil {
				return nil, ErrInvalidSample
			}
			telemetry.XDP.Drops = append(telemetry.XDP.Drops, DDoSDrop{Kind: drop.Kind, Packets: drop.Packets, Bytes: drop.Bytes})
		}
		if !validXDPStatus(telemetry.XDP) {
			return nil, ErrInvalidSample
		}
	}
	return telemetry, nil
}

func (config DecoderConfig) valid() bool {
	return config.Stream == NodeMonitoringStatusStream && config.Durable == DefaultConsumerDurable &&
		config.SubjectPrefix == DefaultSubjectPrefix && config.MaxMessageBytes > 0 && config.MaxMessageBytes <= 1<<20
}

type metricPayload struct {
	SchemaVersion        uint8     `json:"schema_version"`
	ObservedAt           time.Time `json:"observed_at"`
	NodeID               string    `json:"node_id"`
	ConfigRevision       uint64    `json:"config_revision"`
	ActiveConfigRevision uint64    `json:"active_config_revision"`
	ProbeProtocol        string    `json:"probe_protocol"`
	ProbePort            uint16    `json:"probe_port"`
	Healthy              bool      `json:"healthy"`
	ProbeSucceeded       bool      `json:"probe_succeeded"`
	ConsecutiveFailures  uint8     `json:"consecutive_failures"`
	ConsecutiveSuccesses uint8     `json:"consecutive_successes"`
	ProbesTotal          uint64    `json:"probes_total"`
	ProbeFailuresTotal   uint64    `json:"probe_failures_total"`
	Recovered            bool      `json:"recovered"`
	RecoveryNotified     bool      `json:"recovery_notified"`
	RolledBack           bool      `json:"rolled_back"`
}

func decodeMetricPayload(report *agentv1.NodeMonitoringReport) (metricPayload, error) {
	var payload metricPayload
	decoder := json.NewDecoder(bytes.NewReader(report.PayloadJson))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil || payload.SchemaVersion != 1 || payload.ObservedAt.IsZero() ||
		payload.NodeID != report.NodeId || payload.ConfigRevision != report.ConfigRevision ||
		payload.ActiveConfigRevision == 0 || payload.ProbePort == 0 ||
		payload.ProbeProtocol != "" && payload.ProbeProtocol != "tcp" && payload.ProbeProtocol != "http" && payload.ProbeProtocol != "ping" ||
		payload.ConsecutiveFailures > 20 || payload.ConsecutiveSuccesses > 20 ||
		payload.ProbeFailuresTotal > payload.ProbesTotal ||
		payload.ConsecutiveFailures > 0 && payload.ConsecutiveSuccesses > 0 ||
		payload.Recovered && (!payload.Healthy || !payload.ProbeSucceeded) ||
		payload.RolledBack && (payload.ActiveConfigRevision >= payload.ConfigRevision || payload.ProbeSucceeded) {
		return metricPayload{}, ErrInvalidSample
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return metricPayload{}, ErrInvalidSample
	}
	payload.ObservedAt = payload.ObservedAt.UTC()
	return payload, nil
}

// unversionedKind reports the kinds not bound to a monitoring configuration
// revision (config_revision zero).
func unversionedKind(kind agentv1.NodeMonitoringRecordKind) bool {
	return kind == agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_HOST_METRIC ||
		kind == agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_CC_AUTO_SWITCH
}

// decodeCCAutoSwitchPayload mirrors the gateway's strict schema-v1 check.
func decodeCCAutoSwitchPayload(report *agentv1.NodeMonitoringReport) (CCAutoSwitchEvent, error) {
	var payload struct {
		SchemaVersion  uint8     `json:"schema_version"`
		NodeID         string    `json:"node_id"`
		TenantScopeID  string    `json:"tenant_scope_id"`
		SiteID         string    `json:"site_id"`
		PolicyID       string    `json:"policy_id"`
		PolicyVersion  uint64    `json:"policy_version"`
		EngagedAt      time.Time `json:"engaged_at"`
		TriggerQPS     uint64    `json:"trigger_qps"`
		Trigger5xx     uint64    `json:"trigger_5xx"`
		QPSTotal       uint64    `json:"qps_total"`
		QPS5xx         uint64    `json:"qps_5xx"`
		RecoverSeconds uint64    `json:"recover_seconds"`
	}
	decoder := json.NewDecoder(bytes.NewReader(report.PayloadJson))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil || payload.SchemaVersion != 1 || payload.NodeID != report.NodeId ||
		!canonicalUUID(payload.TenantScopeID) || !canonicalUUID(payload.SiteID) || !canonicalUUID(payload.PolicyID) ||
		payload.PolicyVersion == 0 || payload.PolicyVersion > math.MaxInt64 || payload.EngagedAt.IsZero() ||
		payload.TriggerQPS > math.MaxInt64 || payload.Trigger5xx > math.MaxInt64 || payload.QPSTotal > math.MaxInt64 ||
		payload.QPS5xx > math.MaxInt64 || payload.RecoverSeconds > math.MaxInt64 {
		return CCAutoSwitchEvent{}, ErrInvalidSample
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return CCAutoSwitchEvent{}, ErrInvalidSample
	}
	return CCAutoSwitchEvent{NodeID: payload.NodeID, TenantScopeID: payload.TenantScopeID, SiteID: payload.SiteID,
		PolicyID: payload.PolicyID, PolicyVersion: payload.PolicyVersion, EngagedAt: payload.EngagedAt.UTC(),
		TriggerQPS: payload.TriggerQPS, Trigger5xx: payload.Trigger5xx, QPSTotal: payload.QPSTotal,
		QPS5xx: payload.QPS5xx, RecoverSeconds: payload.RecoverSeconds}, nil
}

type recoveryPayload struct {
	NodeID         string    `json:"node_id"`
	ConfigRevision uint64    `json:"config_revision"`
	RecoveredAt    time.Time `json:"recovered_at"`
}

func decodeRecoveryPayload(report *agentv1.NodeMonitoringReport) (recoveryPayload, error) {
	var payload recoveryPayload
	decoder := json.NewDecoder(bytes.NewReader(report.PayloadJson))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil || payload.NodeID != report.NodeId ||
		payload.ConfigRevision != report.ConfigRevision || payload.RecoveredAt.IsZero() {
		return recoveryPayload{}, ErrInvalidSample
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return recoveryPayload{}, ErrInvalidSample
	}
	payload.RecoveredAt = payload.RecoveredAt.UTC()
	return payload, nil
}

func hasUnknown(message protoreflect.Message) bool {
	if len(message.GetUnknown()) != 0 {
		return true
	}
	unknown := false
	message.Range(func(descriptor protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if descriptor.IsList() && descriptor.Message() != nil {
			list := value.List()
			for index := 0; index < list.Len(); index++ {
				if hasUnknown(list.Get(index).Message()) {
					unknown = true
					return false
				}
			}
		} else if descriptor.Message() != nil && hasUnknown(value.Message()) {
			unknown = true
		}
		return !unknown
	})
	return unknown
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}
