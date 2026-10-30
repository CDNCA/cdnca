package gatewayclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/nodemonitoring"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	nodeMonitoringCarrierVersion = 1
	nodeMonitoringStatusStream   = "NODE_MONITORING_STATUS"
	nodeMonitoringOutboxFile     = "outbox.json"
	maxNodeMonitoringOutbox      = 256
)

type nodeMonitoringRuntime interface {
	Apply(context.Context, []byte) (nodemonitoring.ApplyResult, error)
	Run(context.Context, nodemonitoring.MetricSink) error
	Status() nodemonitoring.Status
}

type nodeMonitoringOutbox struct {
	Version      int                             `json:"version"`
	NextSequence uint64                          `json:"next_sequence"`
	Records      []*agentv1.NodeMonitoringReport `json:"-"`
	Encoded      [][]byte                        `json:"records"`
}

type NodeMonitoringBridge struct {
	mu           sync.Mutex
	stateDir     string
	nodeID       string
	runtime      nodeMonitoringRuntime
	outbox       nodeMonitoringOutbox
	wake         chan struct{}
	acknowledged []*agentv1.NodeMonitoringAck
}

func NewNodeMonitoringBridge(stateRoot, nodeID string) (*NodeMonitoringBridge, error) {
	parsed, err := uuid.Parse(nodeID)
	if err != nil || parsed == uuid.Nil || parsed.String() != nodeID || stateRoot == "" || !filepath.IsAbs(stateRoot) {
		return nil, ErrInvalidConfiguration
	}
	stateDir := filepath.Join(stateRoot, "node-monitoring-carrier")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(stateDir, 0o700); err != nil {
		return nil, err
	}
	bridge := &NodeMonitoringBridge{stateDir: stateDir, nodeID: nodeID, wake: make(chan struct{}, 1)}
	if err := bridge.load(); err != nil {
		return nil, err
	}
	return bridge, nil
}

func (bridge *NodeMonitoringBridge) AttachRuntime(runtime nodeMonitoringRuntime) error {
	if bridge == nil || runtime == nil {
		return ErrInvalidConfiguration
	}
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	if bridge.runtime != nil {
		return ErrInvalidConfiguration
	}
	bridge.runtime = runtime
	return nil
}

func (bridge *NodeMonitoringBridge) ApplyArtifact(ctx context.Context, artifact *agentv1.NodeMonitoringArtifact) error {
	if bridge == nil || ctx == nil || artifact == nil || artifact.Schema != agentv1.NodeMonitoringSchema_NODE_MONITORING_SCHEMA_V1 ||
		artifact.NodeId != bridge.nodeID || artifact.ConfigRevision == 0 || artifact.PublicationSequence != artifact.ConfigRevision ||
		len(artifact.ConfigSha256) != sha256.Size || artifact.Event == nil || !canonicalUUID(artifact.Event.EventId) {
		return ErrInvalidMessage
	}
	digest := sha256.Sum256(artifact.CanonicalConfigJson)
	if !equalDigest(digest[:], artifact.ConfigSha256) {
		return ErrInvalidMessage
	}
	var identity struct {
		SchemaVersion  string `json:"schema_version"`
		ConfigRevision uint64 `json:"config_revision"`
	}
	if err := json.Unmarshal(artifact.CanonicalConfigJson, &identity); err != nil ||
		identity.SchemaVersion != nodemonitoring.SchemaVersion || identity.ConfigRevision != artifact.ConfigRevision {
		return ErrInvalidMessage
	}
	bridge.mu.Lock()
	runtime := bridge.runtime
	bridge.mu.Unlock()
	if runtime == nil {
		return ErrInvalidConfiguration
	}
	result, err := runtime.Apply(ctx, append([]byte(nil), artifact.CanonicalConfigJson...))
	if err != nil {
		return err
	}
	if result.ConfigRevision != artifact.ConfigRevision {
		return ErrInvalidMessage
	}
	bridge.signal()
	return nil
}

func (bridge *NodeMonitoringBridge) ApplyStatus(artifact *agentv1.NodeMonitoringArtifact, applyErr error, now time.Time) *agentv1.NodeMonitoringApplyStatus {
	state := agentv1.NodeMonitoringApplyState_NODE_MONITORING_APPLY_STATE_APPLIED
	errorCode := ""
	activeRevision := artifact.GetConfigRevision()
	if applyErr != nil {
		state = agentv1.NodeMonitoringApplyState_NODE_MONITORING_APPLY_STATE_REJECTED
		errorCode = "apply_failed"
		bridge.mu.Lock()
		if bridge.runtime != nil {
			activeRevision = bridge.runtime.Status().ConfigRevision
		} else {
			activeRevision = 0
		}
		bridge.mu.Unlock()
	}
	eventID := uuid.NewSHA1(uuid.MustParse(bridge.nodeID), []byte("node-monitoring-apply/"+artifact.GetEvent().GetEventId()+"/"+state.String())).String()
	return &agentv1.NodeMonitoringApplyStatus{
		Event: &commonv1.EventMetadata{EventId: eventID,
			RequestId:    uuid.NewSHA1(uuid.MustParse(bridge.nodeID), []byte("node-monitoring-apply-request/"+artifact.GetEvent().GetEventId())).String(),
			OccurredTime: timestamppb.New(now.UTC())},
		Schema: agentv1.NodeMonitoringSchema_NODE_MONITORING_SCHEMA_V1, NodeId: bridge.nodeID,
		ConfigRevision: artifact.GetConfigRevision(), ArtifactEventId: artifact.GetEvent().GetEventId(),
		State: state, ActiveConfigRevision: activeRevision, ErrorCode: errorCode,
	}
}

func (bridge *NodeMonitoringBridge) ReportNodeMonitoring(_ context.Context, report nodemonitoring.MetricReport) error {
	if bridge == nil || report.NodeID != bridge.nodeID {
		return ErrInvalidMessage
	}
	kind := agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_METRIC
	var payloadValue any = report
	if report.ConfigRevision == 0 {
		if report.SchemaVersion != 1 || report.ObservedAt.IsZero() || report.LoadMetrics == nil ||
			report.ProbeProtocol != "" || report.ProbePort != 0 || report.Healthy || report.ProbeSucceeded ||
			report.ConsecutiveFailures != 0 || report.ConsecutiveSuccesses != 0 || report.ProbesTotal != 0 ||
			report.ProbeFailuresTotal != 0 || report.Recovered || report.RecoveryNotified || report.RolledBack {
			return ErrInvalidMessage
		}
		kind = agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_HOST_METRIC
		payloadValue = struct {
			SchemaVersion         uint8     `json:"schema_version"`
			NodeID                string    `json:"node_id"`
			ObservedAt            time.Time `json:"observed_at"`
			AppliedConfigRevision uint64    `json:"applied_config_revision,omitempty"`
		}{1, report.NodeID, report.ObservedAt, report.AppliedConfigRevision}
	}
	payload, err := json.Marshal(payloadValue)
	if err != nil {
		return err
	}
	var load *agentv1.NodeLoadMetricsV1
	requestID := ""
	if report.LoadMetrics != nil {
		metrics := report.LoadMetrics
		if !nodemonitoring.ValidLoadMetrics(metrics, report.ObservedAt) {
			return ErrInvalidMessage
		}
		load = &agentv1.NodeLoadMetricsV1{ObservedTime: timestamppb.New(metrics.ObservedAt.UTC()),
			CpuPercent: metrics.CPUPercent, MemoryUsedBytes: metrics.MemoryUsedBytes,
			MemoryTotalBytes: metrics.MemoryTotalBytes, ActiveConnections: metrics.ActiveConnections,
			RxBandwidthBps: metrics.RXBandwidthBPS, TxBandwidthBps: metrics.TXBandwidthBPS}
		if metrics.Telemetry != nil {
			telemetry := metrics.Telemetry
			load.Telemetry = &agentv1.NodeTelemetryV1{
				SchemaVersion: uint32(telemetry.SchemaVersion), TotalRxBytes: telemetry.TotalRXBytes,
				TotalTxBytes: telemetry.TotalTXBytes,
			}
			if selection := telemetry.NetworkSelection; selection != nil {
				load.Telemetry.NetworkSelection = &agentv1.NodeNetworkSelectionV1{Source: selection.Source, Interfaces: append([]string{}, selection.Interfaces...)}
			}
			if telemetry.SystemLoad != nil {
				load.Telemetry.SystemLoad = &agentv1.NodeSystemLoadV1{
					OneMinute: telemetry.SystemLoad.OneMinute, FiveMinutes: telemetry.SystemLoad.FiveMinutes,
					FifteenMinutes:   telemetry.SystemLoad.FifteenMinutes,
					RunningProcesses: telemetry.SystemLoad.RunningProcesses,
					TotalProcesses:   telemetry.SystemLoad.TotalProcesses,
				}
			}
			for _, network := range telemetry.NetworkInterfaces {
				load.Telemetry.NetworkInterfaces = append(load.Telemetry.NetworkInterfaces, &agentv1.NodeNetworkInterfaceMetricsV1{
					Name: network.Name, RxBytes: network.RXBytes, TxBytes: network.TXBytes,
					RxBandwidthBps: network.RXBandwidthBPS, TxBandwidthBps: network.TXBandwidthBPS,
				})
			}
			for _, disk := range telemetry.Disks {
				load.Telemetry.Disks = append(load.Telemetry.Disks, &agentv1.NodeDiskUsageV1{
					Path: disk.Path, TotalBytes: disk.TotalBytes, UsedBytes: disk.UsedBytes,
					TotalInodes: disk.TotalInodes, UsedInodes: disk.UsedInodes,
					SpacePercent: disk.SpacePercent, InodePercent: disk.InodePercent,
				})
			}
			for _, drop := range telemetry.DDoSDrops {
				load.Telemetry.DdosDrops = append(load.Telemetry.DdosDrops, &agentv1.NodeDDoSDropV1{
					Kind: drop.Kind, Packets: drop.Packets, Bytes: drop.Bytes})
			}
			if drop := telemetry.SiteDrop; drop != nil {
				load.Telemetry.SiteDrop = &agentv1.NodeSiteDropV1{SiteIds: append([]string(nil), drop.SiteIDs...),
					Packets: drop.Packets, Bytes: drop.Bytes}
			}
			if status := telemetry.DDoSProtection; status != nil {
				load.Telemetry.DdosProtection = &agentv1.NodeDDoSProtectionV1{State: status.State, Reason: status.Reason, Detail: status.Detail}
			}
			for _, mount := range telemetry.Mounts {
				load.Telemetry.Mounts = append(load.Telemetry.Mounts, &agentv1.NodeMountV1{Path: mount.Path, Device: mount.Device,
					Fstype: mount.FSType, ReadOnly: mount.ReadOnly, Bind: mount.Bind, FilterReason: mount.FilterReason})
			}
			for _, item := range telemetry.PortGroupOverrides {
				load.Telemetry.PortGroupOverrides = append(load.Telemetry.PortGroupOverrides, &agentv1.NodePortGroupOverrideV1{
					PortGroupId: item.PortGroupID, State: item.State, Reason: item.Reason})
			}
			if storage := telemetry.Storage; storage != nil {
				load.Telemetry.Storage = &agentv1.NodeStorageV1{CacheDirectory: storage.CacheDirectory, CacheMaxBytes: storage.CacheMaxBytes,
					LogDirectory: storage.LogDirectory, State: storage.State, Reason: storage.Reason, RequestedLogDirectory: storage.RequestedLogDirectory}
			}
			if status := telemetry.XDP; status != nil {
				load.Telemetry.Xdp = &agentv1.NodeXDPStatusV1{Mode: status.Mode, Reason: status.Reason,
					Detail: status.Detail, Interfaces: append([]string(nil), status.Interfaces...)}
				for _, drop := range status.Drops {
					load.Telemetry.Xdp.Drops = append(load.Telemetry.Xdp.Drops, &agentv1.NodeDDoSDropV1{
						Kind: drop.Kind, Packets: drop.Packets, Bytes: drop.Bytes})
				}
			}
		}
	}
	if report.ConfigRevision == 0 && report.AppliedConfigRevision > 0 {
		requestID = uuid.NewSHA1(uuid.MustParse(bridge.nodeID), []byte("node-monitoring-stop-receipt/"+strconv.FormatUint(report.AppliedConfigRevision, 10))).String()
	}
	return bridge.enqueue(kind,
		report.ConfigRevision, report.ObservedAt, payload, "", requestID, load)
}

func (bridge *NodeMonitoringBridge) NotifyRecovery(_ context.Context, event nodemonitoring.RecoveryEvent) error {
	if bridge == nil || event.NodeID != bridge.nodeID || event.ConfigRevision == 0 || event.RecoveredAt.IsZero() {
		return ErrInvalidMessage
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	dedup := uuid.NewSHA1(uuid.MustParse(bridge.nodeID), append([]byte("node-monitoring-recovery/"), payload...)).String()
	return bridge.enqueue(agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_RECOVERY_NOTIFICATION,
		event.ConfigRevision, event.RecoveredAt, payload, dedup, "", nil)
}

// CCAutoSwitchEvent is one CC auto switch engagement of a site on this node
// (FX65), the strict schema-v1 payload of
// NODE_MONITORING_RECORD_KIND_CC_AUTO_SWITCH.
type CCAutoSwitchEvent struct {
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

// NotifyCCAutoSwitch queues an engagement. Its event ID is derived from the
// node, site and engage second, so a re-observed engagement (an agent
// restart) is queued once.
func (bridge *NodeMonitoringBridge) NotifyCCAutoSwitch(_ context.Context, event CCAutoSwitchEvent) error {
	if bridge == nil {
		return ErrInvalidMessage
	}
	event.SchemaVersion = 1
	event.EngagedAt = event.EngagedAt.UTC().Truncate(time.Second)
	if event.NodeID != bridge.nodeID || !canonicalUUID(event.TenantScopeID) || !canonicalUUID(event.SiteID) ||
		!canonicalUUID(event.PolicyID) || event.PolicyVersion == 0 || event.EngagedAt.Unix() <= 0 {
		return ErrInvalidMessage
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	dedup := uuid.NewSHA1(uuid.MustParse(bridge.nodeID), []byte("cc-auto-switch/"+event.SiteID+"/"+strconv.FormatInt(event.EngagedAt.Unix(), 10))).String()
	return bridge.enqueue(agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_CC_AUTO_SWITCH,
		0, event.EngagedAt, payload, dedup, "", nil)
}

func (bridge *NodeMonitoringBridge) enqueue(kind agentv1.NodeMonitoringRecordKind, revision uint64, occurred time.Time, payload []byte, fixedEventID, fixedRequestID string, load *agentv1.NodeLoadMetricsV1) error {
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	if fixedEventID != "" {
		for _, record := range bridge.outbox.Records {
			if record.Event.EventId == fixedEventID {
				return nil
			}
		}
	}
	if len(bridge.outbox.Records) >= maxNodeMonitoringOutbox {
		return nodemonitoring.ErrMetricBackpressure
	}
	if bridge.outbox.NextSequence == ^uint64(0) {
		return fmt.Errorf("%w: node monitoring sequence exhausted", ErrInvalidConfiguration)
	}
	sequence := bridge.outbox.NextSequence + 1
	eventID := fixedEventID
	if eventID == "" {
		eventID = uuid.NewSHA1(uuid.MustParse(bridge.nodeID), []byte(fmt.Sprintf("node-monitoring-metric/%d", sequence))).String()
	}
	requestID := fixedRequestID
	if requestID == "" {
		requestID = uuid.NewSHA1(uuid.MustParse(bridge.nodeID), []byte("node-monitoring-report/"+eventID)).String()
	}
	record := &agentv1.NodeMonitoringReport{
		Event: &commonv1.EventMetadata{EventId: eventID,
			RequestId:    requestID,
			OccurredTime: timestamppb.New(occurred.UTC())},
		Schema: agentv1.NodeMonitoringSchema_NODE_MONITORING_SCHEMA_V1, NodeId: bridge.nodeID,
		ConfigRevision: revision, PublicationSequence: sequence, Kind: kind, PayloadJson: append([]byte(nil), payload...),
		LoadMetricsV1: load,
	}
	bridge.outbox.NextSequence = sequence
	bridge.outbox.Records = append(bridge.outbox.Records, record)
	if err := bridge.persistLocked(); err != nil {
		bridge.outbox.NextSequence--
		bridge.outbox.Records = bridge.outbox.Records[:len(bridge.outbox.Records)-1]
		return err
	}
	bridge.signal()
	return nil
}

func (bridge *NodeMonitoringBridge) Pending() []*agentv1.NodeMonitoringReport {
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	result := make([]*agentv1.NodeMonitoringReport, len(bridge.outbox.Records))
	for index, record := range bridge.outbox.Records {
		result[index] = proto.Clone(record).(*agentv1.NodeMonitoringReport)
	}
	return result
}

func (bridge *NodeMonitoringBridge) Acknowledge(ack *agentv1.NodeMonitoringAck) error {
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	if ack == nil || ack.NodeId != bridge.nodeID || cacheControlMessageHasUnknown(ack.ProtoReflect()) ||
		ack.PublishedStream != nodeMonitoringStatusStream || ack.PublishedSequence == 0 ||
		ack.AcceptedTime == nil || ack.AcceptedTime.CheckValid() != nil {
		return ErrInvalidMessage
	}
	for _, acknowledged := range bridge.acknowledged {
		if proto.Equal(ack, acknowledged) {
			return nil
		}
	}
	if len(bridge.outbox.Records) == 0 {
		return ErrInvalidMessage
	}
	record := bridge.outbox.Records[0]
	if ack.EventId != record.Event.EventId || ack.ConfigRevision != record.ConfigRevision ||
		ack.PublicationSequence != record.PublicationSequence {
		return ErrInvalidMessage
	}
	bridge.outbox.Records = bridge.outbox.Records[1:]
	if err := bridge.persistLocked(); err != nil {
		bridge.outbox.Records = append([]*agentv1.NodeMonitoringReport{record}, bridge.outbox.Records...)
		return err
	}
	// Remember only durable, exact confirmations for this Bridge's lifetime.
	// Replays outside this bounded window (or after restart) fail closed.
	accepted := proto.Clone(ack).(*agentv1.NodeMonitoringAck)
	if len(bridge.acknowledged) == maxNodeMonitoringOutbox {
		copy(bridge.acknowledged, bridge.acknowledged[1:])
		bridge.acknowledged[len(bridge.acknowledged)-1] = accepted
	} else {
		bridge.acknowledged = append(bridge.acknowledged, accepted)
	}
	return nil
}

func (bridge *NodeMonitoringBridge) Run(ctx context.Context) error {
	for {
		bridge.mu.Lock()
		runtime := bridge.runtime
		bridge.mu.Unlock()
		if runtime == nil {
			return ErrInvalidConfiguration
		}
		err := runtime.Run(ctx, bridge)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil && !errors.Is(err, nodemonitoring.ErrNoActiveConfig) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-bridge.wake:
		}
	}
}

func (bridge *NodeMonitoringBridge) Wake() <-chan struct{} { return bridge.wake }

func (bridge *NodeMonitoringBridge) signal() {
	select {
	case bridge.wake <- struct{}{}:
	default:
	}
}

func (bridge *NodeMonitoringBridge) load() error {
	payload, err := os.ReadFile(filepath.Join(bridge.stateDir, nodeMonitoringOutboxFile))
	if errors.Is(err, os.ErrNotExist) {
		bridge.outbox = nodeMonitoringOutbox{Version: nodeMonitoringCarrierVersion}
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err != nil || len(payload) == 0 || len(payload) > 1<<20 || decoder.Decode(&bridge.outbox) != nil ||
		decoder.Decode(&struct{}{}) != io.EOF || bridge.outbox.Version != nodeMonitoringCarrierVersion ||
		len(bridge.outbox.Encoded) > maxNodeMonitoringOutbox {
		return ErrInvalidConfiguration
	}
	bridge.outbox.Records = make([]*agentv1.NodeMonitoringReport, len(bridge.outbox.Encoded))
	var previousSequence uint64
	for index, encoded := range bridge.outbox.Encoded {
		record := &agentv1.NodeMonitoringReport{}
		if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(encoded, record); err != nil ||
			len(record.ProtoReflect().GetUnknown()) != 0 || record.NodeId != bridge.nodeID || record.PublicationSequence == 0 ||
			record.PublicationSequence > bridge.outbox.NextSequence || previousSequence != 0 && record.PublicationSequence != previousSequence+1 {
			return ErrInvalidConfiguration
		}
		bridge.outbox.Records[index] = record
		previousSequence = record.PublicationSequence
	}
	if len(bridge.outbox.Records) != 0 && previousSequence != bridge.outbox.NextSequence {
		return ErrInvalidConfiguration
	}
	return nil
}

func (bridge *NodeMonitoringBridge) persistLocked() error {
	encoded := make([][]byte, len(bridge.outbox.Records))
	for index, record := range bridge.outbox.Records {
		payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(record)
		if err != nil {
			return err
		}
		encoded[index] = payload
	}
	disk := bridge.outbox
	disk.Records = nil
	disk.Encoded = encoded
	payload, err := json.Marshal(disk)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(bridge.stateDir, ".outbox-*.tmp")
	if err != nil {
		return err
	}
	path := temporary.Name()
	defer os.Remove(path)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(path, filepath.Join(bridge.stateDir, nodeMonitoringOutboxFile)); err != nil {
		return err
	}
	directory, err := os.Open(bridge.stateDir)
	if err != nil {
		return err
	}
	err = directory.Sync()
	closeErr := directory.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func equalDigest(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var different byte
	for index := range left {
		different |= left[index] ^ right[index]
	}
	return different == 0
}

func nodeMonitoringCapabilityFromFeatures(features []*agentv1.Capability) (bool, error) {
	seen := false
	for _, capability := range features {
		if capability == nil || capability.Name != agentv1.CapabilityName_CAPABILITY_NAME_NODE_MONITORING {
			continue
		}
		if seen || capability.ApiVersion != 1 {
			return false, ErrInvalidMessage
		}
		seen = true
	}
	return seen, nil
}

func WithNodeMonitoringBridge(bridge *NodeMonitoringBridge) ClientOption {
	return func(client *Client) error {
		if bridge == nil || client == nil || bridge.nodeID != client.config.NodeID {
			return ErrInvalidConfiguration
		}
		client.nodeMonitoring = bridge
		return nil
	}
}

func negotiateNodeMonitoringV1(gatewayHello *agentv1.GatewayHello, capabilities *agentv1.AgentCapabilities) (bool, error) {
	agentEnabled, err := nodeMonitoringCapabilityFromFeatures(capabilities.GetFeatures())
	if err != nil {
		return false, err
	}
	gatewayEnabled, err := nodeMonitoringCapabilityFromFeatures(gatewayHello.GetEnabledCapabilities())
	if err != nil {
		return false, err
	}
	if gatewayEnabled && !agentEnabled || agentEnabled && !gatewayEnabled {
		return false, ErrInvalidMessage
	}
	return agentEnabled && gatewayEnabled, nil
}

func (client *Client) sendPendingNodeMonitoringReports(
	stream interface {
		Send(*agentv1.ConnectRequest) error
	},
	sequence uint64,
) (uint64, error) {
	if client.nodeMonitoring == nil {
		return sequence, nil
	}
	for _, report := range client.nodeMonitoring.Pending() {
		sequence++
		if err := sendNodeMonitoringReport(stream, sequence, report, client.now()); err != nil {
			return sequence, err
		}
	}
	return sequence, nil
}

func sendNodeMonitoringReport(stream interface {
	Send(*agentv1.ConnectRequest) error
}, sequence uint64, report *agentv1.NodeMonitoringReport, now time.Time) error {
	return stream.Send(&agentv1.ConnectRequest{Stream: streamMetadata(sequence, now),
		Payload: &agentv1.ConnectRequest_NodeMonitoringReport{NodeMonitoringReport: report}})
}

func sendNodeMonitoringApplyStatus(stream interface {
	Send(*agentv1.ConnectRequest) error
}, sequence uint64, status *agentv1.NodeMonitoringApplyStatus, now time.Time) error {
	return stream.Send(&agentv1.ConnectRequest{Stream: streamMetadata(sequence, now),
		Payload: &agentv1.ConnectRequest_NodeMonitoringApplyStatus{NodeMonitoringApplyStatus: status}})
}
