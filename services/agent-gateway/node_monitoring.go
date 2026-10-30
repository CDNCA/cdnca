package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	NodeMonitoringCommandStream = "NODE_MONITORING_COMMANDS"
	NodeMonitoringStatusStream  = "NODE_MONITORING_STATUS"
	nodeMonitoringAPIVersion    = 1
	nodeMonitoringSchemaVersion = "cdnca.node-monitoring/v1"
	maxNodeMonitoringBytes      = 64 << 10
	maxNodeLoadFutureSkew       = 30 * time.Second
)

type NodeMonitoringPublication struct {
	Stream   string
	Sequence uint64
	Replayed bool
}

type NodeMonitoringBus interface {
	SubscribeNodeMonitoring(context.Context, string) (NodeMonitoringSubscription, error)
	PublishNodeMonitoring(context.Context, string, *agentv1.NodeMonitoringReport) (NodeMonitoringPublication, error)
}

type NodeMonitoringSubscription interface {
	Next(context.Context) (NodeMonitoringDelivery, error)
	Close() error
}

type NodeMonitoringDelivery interface {
	Artifact() *agentv1.NodeMonitoringArtifact
	Ack(context.Context) error
	Nak(context.Context) error
	// NakWithDelay redelivers the artifact after delay without closing the
	// session, so a rejected revision neither hot-loops nor blocks newer ones.
	NakWithDelay(context.Context, time.Duration) error
}

// nodeMonitoringRejectedRetryDelay paces redelivery of an artifact the Agent
// rejected (for example an override probing a port that is not listening).
const nodeMonitoringRejectedRetryDelay = 30 * time.Second

type nodeMonitoringDisposition int

const (
	nodeMonitoringDispositionAck nodeMonitoringDisposition = iota
	nodeMonitoringDispositionRetryLater
)

// nodeMonitoringRejectionDisposition settles a validated apply status. An
// artifact rejected because the Agent already runs a newer revision is
// superseded: Agents never accept a lower revision, so it is acknowledged.
// Any other rejection is redelivered later while the session stays open.
func nodeMonitoringRejectionDisposition(status *agentv1.NodeMonitoringApplyStatus) nodeMonitoringDisposition {
	if status.GetState() == agentv1.NodeMonitoringApplyState_NODE_MONITORING_APPLY_STATE_APPLIED ||
		status.GetActiveConfigRevision() > status.GetConfigRevision() {
		return nodeMonitoringDispositionAck
	}
	return nodeMonitoringDispositionRetryLater
}

type nodeMonitoringReceive struct {
	delivery NodeMonitoringDelivery
	err      error
}

type sessionNodeMonitoringSource struct {
	ctx          context.Context
	cancel       context.CancelFunc
	subscription NodeMonitoringSubscription
	next         <-chan nodeMonitoringReceive
}

func newSessionNodeMonitoringSource(ctx context.Context, bus NodeMonitoringBus, nodeID string) (*sessionNodeMonitoringSource, error) {
	sourceContext, cancel := context.WithCancel(ctx)
	subscription, err := bus.SubscribeNodeMonitoring(sourceContext, nodeID)
	if err != nil {
		cancel()
		return nil, err
	}
	return &sessionNodeMonitoringSource{ctx: sourceContext, cancel: cancel, subscription: subscription}, nil
}

func (source *sessionNodeMonitoringSource) arm() {
	if source == nil || source.next != nil {
		return
	}
	next := make(chan nodeMonitoringReceive, 1)
	source.next = next
	go func() {
		delivery, err := source.subscription.Next(source.ctx)
		next <- nodeMonitoringReceive{delivery: delivery, err: err}
	}()
}

func stopSessionNodeMonitoring(source *sessionNodeMonitoringSource, timeout time.Duration) {
	if source == nil {
		return
	}
	source.cancel()
	_ = source.subscription.Close()
	if source.next == nil {
		return
	}
	select {
	case received := <-source.next:
		if received.delivery != nil {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			_ = received.delivery.Nak(ctx)
			cancel()
		}
	case <-time.After(timeout):
	}
}

func (g *Gateway) applyNodeMonitoringAuthorization(
	ctx context.Context,
	nodeID string,
	source *sessionNodeMonitoringSource,
	pending NodeMonitoringDelivery,
	wasAllowed bool,
	isAllowed bool,
) (*sessionNodeMonitoringSource, NodeMonitoringDelivery, error) {
	if g.nodeMonitoring == nil || wasAllowed == isAllowed {
		return source, pending, nil
	}
	if !isAllowed {
		var dispositionErr error
		if pending != nil {
			operationCtx, cancel := context.WithTimeout(ctx, g.config.CommandOperationTimeout)
			dispositionErr = pending.Nak(operationCtx)
			cancel()
		}
		stopSessionNodeMonitoring(source, g.config.CommandOperationTimeout)
		if dispositionErr != nil {
			return nil, pending, status.Error(codes.Unavailable, "node monitoring artifact revocation could not be persisted")
		}
		return nil, nil, nil
	}
	created, err := newSessionNodeMonitoringSource(ctx, g.nodeMonitoring, nodeID)
	if err != nil {
		return nil, pending, status.Error(codes.Unavailable, "could not subscribe to node monitoring artifacts")
	}
	return created, pending, nil
}

func validateNodeMonitoringArtifact(artifact *agentv1.NodeMonitoringArtifact, nodeID string) error {
	if artifact == nil || proto.Size(artifact) > maxNodeMonitoringBytes || cacheControlMessageHasUnknown(artifact.ProtoReflect()) ||
		artifact.Schema != agentv1.NodeMonitoringSchema_NODE_MONITORING_SCHEMA_V1 || artifact.NodeId != nodeID ||
		artifact.ConfigRevision == 0 || artifact.PublicationSequence != artifact.ConfigRevision ||
		len(artifact.CanonicalConfigJson) == 0 || len(artifact.ConfigSha256) != 32 ||
		artifact.Event == nil || !canonicalUUID(artifact.Event.EventId) || !canonicalUUID(artifact.Event.RequestId) ||
		artifact.Event.OccurredTime == nil || artifact.Event.OccurredTime.CheckValid() != nil {
		return fmt.Errorf("node monitoring artifact is invalid")
	}
	digest := sha256.Sum256(artifact.CanonicalConfigJson)
	var identity struct {
		SchemaVersion  string `json:"schema_version"`
		ConfigRevision uint64 `json:"config_revision"`
	}
	if !bytes.Equal(digest[:], artifact.ConfigSha256) || json.Unmarshal(artifact.CanonicalConfigJson, &identity) != nil ||
		identity.SchemaVersion != nodeMonitoringSchemaVersion || identity.ConfigRevision != artifact.ConfigRevision {
		return fmt.Errorf("node monitoring artifact binding is invalid")
	}
	return nil
}

func publishNodeMonitoringReport(
	ctx context.Context,
	bus NodeMonitoringBus,
	nodeID string,
	report *agentv1.NodeMonitoringReport,
	lastSequence uint64,
	now func() time.Time,
) (*agentv1.NodeMonitoringAck, error) {
	if ctx == nil || bus == nil || now == nil {
		return nil, fmt.Errorf("node monitoring dependencies are invalid")
	}
	acceptedAt := now().UTC()
	if err := validateNodeMonitoringReport(report, nodeID, lastSequence, acceptedAt); err != nil {
		return nil, err
	}
	publication, err := bus.PublishNodeMonitoring(ctx, nodeID, proto.Clone(report).(*agentv1.NodeMonitoringReport))
	if err != nil {
		return nil, err
	}
	if publication.Stream != NodeMonitoringStatusStream || publication.Sequence == 0 {
		return nil, fmt.Errorf("node monitoring PubAck is invalid")
	}
	return &agentv1.NodeMonitoringAck{
		EventId: report.Event.EventId, NodeId: nodeID, ConfigRevision: report.ConfigRevision,
		PublicationSequence: report.PublicationSequence, PublishedStream: publication.Stream,
		PublishedSequence: publication.Sequence, Replayed: publication.Replayed,
		AcceptedTime: timestamppb.New(acceptedAt),
	}, nil
}

// unversionedNodeMonitoringKind reports the kinds not bound to a monitoring
// configuration revision (config_revision zero).
func unversionedNodeMonitoringKind(kind agentv1.NodeMonitoringRecordKind) bool {
	return kind == agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_HOST_METRIC ||
		kind == agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_CC_AUTO_SWITCH
}

func validateNodeMonitoringReport(report *agentv1.NodeMonitoringReport, nodeID string, lastSequence uint64, acceptedAt time.Time) error {
	if report == nil || proto.Size(report) > maxNodeMonitoringBytes || cacheControlMessageHasUnknown(report.ProtoReflect()) ||
		report.Schema != agentv1.NodeMonitoringSchema_NODE_MONITORING_SCHEMA_V1 || report.NodeId != nodeID ||
		(report.ConfigRevision == 0) != unversionedNodeMonitoringKind(report.Kind) || report.PublicationSequence == 0 ||
		lastSequence != 0 && report.PublicationSequence != lastSequence+1 ||
		len(report.PayloadJson) == 0 || len(report.PayloadJson) > maxNodeMonitoringBytes ||
		report.Event == nil || !canonicalUUID(report.Event.EventId) || !canonicalUUID(report.Event.RequestId) ||
		report.Event.OccurredTime == nil || report.Event.OccurredTime.CheckValid() != nil {
		return fmt.Errorf("node monitoring report is invalid")
	}
	if report.Kind != agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_METRIC &&
		report.Kind != agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_RECOVERY_NOTIFICATION &&
		report.Kind != agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_HOST_METRIC &&
		report.Kind != agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_CC_AUTO_SWITCH {
		return fmt.Errorf("node monitoring report kind is unsupported")
	}
	payloadTime, err := validateNodeMonitoringPayload(report, nodeID)
	if err != nil {
		return err
	}
	if report.Kind == agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_CC_AUTO_SWITCH {
		if report.LoadMetricsV1 != nil || !report.Event.OccurredTime.AsTime().Equal(payloadTime) {
			return fmt.Errorf("CC auto switch report is invalid")
		}
		return nil
	}
	load := report.LoadMetricsV1
	if load == nil {
		if report.Kind == agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_HOST_METRIC {
			return fmt.Errorf("host metrics are missing")
		}
		return nil
	}
	if (report.Kind != agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_METRIC &&
		report.Kind != agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_HOST_METRIC) ||
		acceptedAt.IsZero() || load.ObservedTime == nil || load.ObservedTime.CheckValid() != nil ||
		!report.Event.OccurredTime.AsTime().Equal(payloadTime) || !load.ObservedTime.AsTime().Equal(payloadTime) ||
		payloadTime.After(acceptedAt.Add(maxNodeLoadFutureSkew)) || math.IsNaN(load.CpuPercent) ||
		math.IsInf(load.CpuPercent, 0) || load.CpuPercent < 0 || load.CpuPercent > 100 ||
		load.MemoryTotalBytes == 0 || load.MemoryTotalBytes > math.MaxInt64 ||
		load.MemoryUsedBytes > load.MemoryTotalBytes || load.ActiveConnections > math.MaxInt64 ||
		load.RxBandwidthBps > math.MaxInt64 || load.TxBandwidthBps > math.MaxInt64 ||
		!validateNodeTelemetry(load.Telemetry) {
		return fmt.Errorf("node monitoring load metrics are invalid")
	}
	return nil
}

func validateNodeTelemetry(telemetry *agentv1.NodeTelemetryV1) bool {
	if telemetry == nil {
		return true
	}
	if telemetry.SchemaVersion != 1 || telemetry.TotalRxBytes > math.MaxInt64 || telemetry.TotalTxBytes > math.MaxInt64 ||
		len(telemetry.NetworkInterfaces) > 128 || len(telemetry.Disks) > 128 {
		return false
	}
	previousName := ""
	if selection := telemetry.NetworkSelection; selection != nil {
		if selection.Source != "default_route" && selection.Source != "unavailable" ||
			(selection.Source == "default_route") != (len(selection.Interfaces) > 0) || len(selection.Interfaces) > 128 {
			return false
		}
		for _, name := range selection.Interfaces {
			if name <= previousName {
				return false
			}
			found := false
			for _, network := range telemetry.NetworkInterfaces {
				if network != nil && network.Name == name {
					found = true
					break
				}
			}
			if !found {
				return false
			}
			previousName = name
		}
		previousName = ""
	}
	for _, network := range telemetry.NetworkInterfaces {
		if network == nil || network.Name == "" || len(network.Name) > 128 || previousName >= network.Name ||
			strings.ContainsAny(network.Name, "\x00\r\n\t") || network.RxBytes > math.MaxInt64 || network.TxBytes > math.MaxInt64 ||
			network.RxBandwidthBps > math.MaxInt64 || network.TxBandwidthBps > math.MaxInt64 {
			return false
		}
		previousName = network.Name
	}
	if telemetry.SystemLoad != nil {
		load := telemetry.SystemLoad
		if load.TotalProcesses == 0 || load.RunningProcesses > load.TotalProcesses {
			return false
		}
		for _, value := range []float64{load.OneMinute, load.FiveMinutes, load.FifteenMinutes} {
			if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > 1e9 {
				return false
			}
		}
	}
	previousPath := ""
	for _, disk := range telemetry.Disks {
		if disk == nil || disk.Path == "" || len(disk.Path) > 4096 || disk.Path[0] != '/' || previousPath >= disk.Path ||
			disk.TotalBytes > math.MaxInt64 || disk.UsedBytes > disk.TotalBytes || disk.TotalInodes > math.MaxInt64 ||
			disk.UsedInodes > disk.TotalInodes || math.IsNaN(disk.SpacePercent) || math.IsInf(disk.SpacePercent, 0) ||
			disk.SpacePercent < 0 || disk.SpacePercent > 100 || math.IsNaN(disk.InodePercent) ||
			math.IsInf(disk.InodePercent, 0) || disk.InodePercent < 0 || disk.InodePercent > 100 {
			return false
		}
		previousPath = disk.Path
	}
	previousKind := ""
	for _, drop := range telemetry.DdosDrops {
		if drop == nil || drop.Kind <= previousKind || !nodeDDoSDropKinds[drop.Kind] ||
			drop.Packets > math.MaxInt64 || drop.Bytes > math.MaxInt64 {
			return false
		}
		previousKind = drop.Kind
	}
	return validateNodeXDPStatus(telemetry.Xdp) && validateNodeSiteDrop(telemetry.SiteDrop) &&
		validateNodeDDoSProtection(telemetry.DdosProtection) && validateNodeMounts(telemetry.Mounts) &&
		validateNodePortGroupOverrides(telemetry.PortGroupOverrides) && validateNodeStorage(telemetry.Storage)
}

// validateNodeStorage: NodeStorageV1 (NODE_STORAGE v1) is missing or a valid
// report (siteobject.ValidNodeStorageReport).
func validateNodeStorage(storage *agentv1.NodeStorageV1) bool {
	return storage == nil || siteobject.ValidNodeStorageReport(storage.CacheDirectory, storage.LogDirectory, storage.State,
		storage.Reason, storage.RequestedLogDirectory, storage.CacheMaxBytes)
}

// Node telemetry detail vocabulary (NodeMountV1, NodePortGroupOverrideV1;
// NODE_TELEMETRY_DETAIL v1).
var (
	nodeMountFilterReasons       = map[string]bool{"bind_duplicate": true, "read_only": true, "squashfs": true, "stat_failed": true, "system_path": true}
	nodePortGroupOverrideStates  = map[string]bool{"applied": true, "failed": true, "inactive": true, "standby": true}
	nodePortGroupOverrideReasons = map[string]bool{"auto_mitigation_off": true, "manual": true, "shared_ports": true, "suggest": true}
	nodeMountDevicePattern       = regexp.MustCompile(`^[0-9]{1,10}:[0-9]{1,10}$`)
	nodePortGroupIDPattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
)

// validateNodeMounts: at most 256, sorted by path, unique; major:minor
// device; a known filter reason or none.
func validateNodeMounts(mounts []*agentv1.NodeMountV1) bool {
	if len(mounts) > 256 {
		return false
	}
	previous := ""
	for _, mount := range mounts {
		if mount == nil || mount.Path == "" || len(mount.Path) > 4096 || mount.Path[0] != '/' || mount.Path <= previous ||
			!utf8.ValidString(mount.Path) || strings.ContainsRune(mount.Path, 0) || !nodeMountDevicePattern.MatchString(mount.Device) ||
			len(mount.Fstype) > 64 || strings.ContainsAny(mount.Fstype, "\x00\r\n\t ") || !utf8.ValidString(mount.Fstype) ||
			(mount.FilterReason != "" && !nodeMountFilterReasons[mount.FilterReason]) {
			return false
		}
		previous = mount.Path
	}
	return true
}

// validateNodePortGroupOverrides: at most 256, sorted by port group ID,
// unique; a known state; a known reason exactly when inactive.
func validateNodePortGroupOverrides(overrides []*agentv1.NodePortGroupOverrideV1) bool {
	if len(overrides) > 256 {
		return false
	}
	previous := ""
	for _, item := range overrides {
		if item == nil || !nodePortGroupIDPattern.MatchString(item.PortGroupId) || item.PortGroupId <= previous ||
			!nodePortGroupOverrideStates[item.State] || (item.State == "inactive") != (item.Reason != "") ||
			(item.Reason != "" && !nodePortGroupOverrideReasons[item.Reason]) {
			return false
		}
		previous = item.PortGroupId
	}
	return true
}

// Node DDoS protection vocabulary (NodeDDoSProtectionV1).
var (
	nodeDDoSProtectionStates  = map[string]bool{"applied": true, "failed": true, "off": true, "pending": true, "unavailable": true}
	nodeDDoSProtectionReasons = map[string]bool{"init_failed": true, "nft_missing": true, "nft_unusable": true, "unsupported_os": true}
)

// validateNodeDDoSProtection: known state; a known reason exactly when
// unavailable; a bounded single line detail only for failed / unavailable.
func validateNodeDDoSProtection(status *agentv1.NodeDDoSProtectionV1) bool {
	if status == nil {
		return true
	}
	unavailable := status.State == "unavailable"
	return nodeDDoSProtectionStates[status.State] && unavailable == (status.Reason != "") &&
		(!unavailable || nodeDDoSProtectionReasons[status.Reason]) &&
		(status.Detail == "" || unavailable || status.State == "failed") &&
		len(status.Detail) <= 256 && utf8.ValidString(status.Detail) && !strings.ContainsAny(status.Detail, "\x00\r\n")
}

// validateNodeSiteDrop: 1..256 canonical UUIDs, sorted and unique; counters
// within int64 (NodeSiteDropV1).
func validateNodeSiteDrop(drop *agentv1.NodeSiteDropV1) bool {
	if drop == nil {
		return true
	}
	if len(drop.SiteIds) == 0 || len(drop.SiteIds) > 256 || drop.Packets > math.MaxInt64 || drop.Bytes > math.MaxInt64 {
		return false
	}
	previous := ""
	for _, id := range drop.SiteIds {
		parsed, err := uuid.Parse(id)
		if err != nil || parsed.String() != id || id <= previous {
			return false
		}
		previous = id
	}
	return true
}

// nodeDDoSDropKinds are the node DDoS packet filter kinds (NodeDDoSDropV1).
var nodeDDoSDropKinds = map[string]bool{"ct_invalid": true, "tcp_all": true, "tcp_fin": true, "tcp_null": true,
	"tcp_syn_fin": true, "tcp_syn_rst": true, "tcp_xmas": true}

// Node XDP filter vocabulary (NodeXDPStatusV1; agent internal/xdp).
var (
	nodeXDPModes   = map[string]bool{"native": true, "generic": true, "nftables": true, "disabled": true}
	nodeXDPReasons = map[string]bool{"attach_failed": true, "bpf_unavailable": true, "disabled": true, "kernel_too_old": true,
		"load_failed": true, "no_interface": true, "self_test_failed": true, "unsupported_os": true, "update_failed": true, "verify_failed": true}
	nodeXDPDropKinds = map[string]bool{"tcp_all": true, "tcp_null": true, "tcp_syn_fin": true, "tcp_syn_rst": true, "tcp_xmas": true,
		"xdp_ban": true, "xdp_block": true, "xdp_port_ban": true, "xdp_rate": true}
)

// validateNodeXDPStatus: attached modes carry interfaces and no reason; the
// others a known reason and neither interfaces nor drops.
func validateNodeXDPStatus(status *agentv1.NodeXDPStatusV1) bool {
	if status == nil {
		return true
	}
	attached := status.Mode == "native" || status.Mode == "generic"
	if !nodeXDPModes[status.Mode] || len(status.Detail) > 256 || strings.ContainsAny(status.Detail, "\x00\r\n") ||
		len(status.Interfaces) > 64 || attached != (status.Reason == "") || attached != (len(status.Interfaces) != 0) ||
		!attached && (len(status.Drops) != 0 || !nodeXDPReasons[status.Reason]) {
		return false
	}
	previous := ""
	for _, nic := range status.Interfaces {
		name, mode, ok := strings.Cut(nic, "=")
		if !ok || name == "" || len(name) > 15 || strings.ContainsAny(name, "/= \x00\r\n\t") ||
			mode != "native" && mode != "generic" || nic <= previous {
			return false
		}
		previous = nic
	}
	previous = ""
	for _, drop := range status.Drops {
		if drop == nil || drop.Kind <= previous || !nodeXDPDropKinds[drop.Kind] || drop.Packets > math.MaxInt64 || drop.Bytes > math.MaxInt64 {
			return false
		}
		previous = drop.Kind
	}
	return true
}

func validateNodeMonitoringPayload(report *agentv1.NodeMonitoringReport, nodeID string) (time.Time, error) {
	decoder := json.NewDecoder(bytes.NewReader(report.PayloadJson))
	decoder.DisallowUnknownFields()
	switch report.Kind {
	case agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_HOST_METRIC:
		var payload struct {
			SchemaVersion         uint8     `json:"schema_version"`
			NodeID                string    `json:"node_id"`
			ObservedAt            time.Time `json:"observed_at"`
			AppliedConfigRevision uint64    `json:"applied_config_revision,omitempty"`
		}
		if err := decoder.Decode(&payload); err != nil || payload.SchemaVersion != 1 || payload.NodeID != nodeID ||
			payload.ObservedAt.IsZero() || decoder.Decode(&struct{}{}) != io.EOF {
			return time.Time{}, fmt.Errorf("host metric payload is invalid")
		}
		return payload.ObservedAt.UTC(), nil
	case agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_METRIC:
		var payload struct {
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
		if err := decoder.Decode(&payload); err != nil || payload.SchemaVersion != 1 || payload.ObservedAt.IsZero() ||
			payload.NodeID != nodeID || payload.ConfigRevision != report.ConfigRevision || payload.ActiveConfigRevision == 0 || payload.ProbePort == 0 ||
			payload.ProbeProtocol != "" && payload.ProbeProtocol != "tcp" && payload.ProbeProtocol != "http" && payload.ProbeProtocol != "ping" {
			return time.Time{}, fmt.Errorf("node monitoring metric payload is invalid")
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return time.Time{}, fmt.Errorf("node monitoring report payload has trailing data")
		}
		return payload.ObservedAt.UTC(), nil
	case agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_CC_AUTO_SWITCH:
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
		if err := decoder.Decode(&payload); err != nil || payload.SchemaVersion != 1 || payload.NodeID != nodeID ||
			!canonicalUUID(payload.TenantScopeID) || !canonicalUUID(payload.SiteID) || !canonicalUUID(payload.PolicyID) ||
			payload.PolicyVersion == 0 || payload.PolicyVersion > math.MaxInt64 || payload.EngagedAt.IsZero() ||
			payload.TriggerQPS > math.MaxInt64 || payload.Trigger5xx > math.MaxInt64 || payload.QPSTotal > math.MaxInt64 ||
			payload.QPS5xx > math.MaxInt64 || payload.RecoverSeconds > math.MaxInt64 {
			return time.Time{}, fmt.Errorf("CC auto switch payload is invalid")
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return time.Time{}, fmt.Errorf("node monitoring report payload has trailing data")
		}
		return payload.EngagedAt.UTC(), nil
	case agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_RECOVERY_NOTIFICATION:
		var payload struct {
			NodeID         string    `json:"node_id"`
			ConfigRevision uint64    `json:"config_revision"`
			RecoveredAt    time.Time `json:"recovered_at"`
		}
		if err := decoder.Decode(&payload); err != nil || payload.NodeID != nodeID ||
			payload.ConfigRevision != report.ConfigRevision || payload.RecoveredAt.IsZero() {
			return time.Time{}, fmt.Errorf("node monitoring recovery payload is invalid")
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return time.Time{}, fmt.Errorf("node monitoring report payload has trailing data")
		}
		return payload.RecoveredAt.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("node monitoring report kind is unsupported")
}

type nodeMonitoringAckRecord struct {
	digest [sha256.Size]byte
	ack    *agentv1.NodeMonitoringAck
}

func nodeMonitoringReportDigest(report *agentv1.NodeMonitoringReport) ([sha256.Size]byte, error) {
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(report)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(payload), nil
}

func replayNodeMonitoringAck(records map[string]nodeMonitoringAckRecord, report *agentv1.NodeMonitoringReport) (*agentv1.NodeMonitoringAck, bool, error) {
	if report == nil || report.Event == nil {
		return nil, false, nil
	}
	record, exists := records[report.Event.EventId]
	if !exists {
		return nil, false, nil
	}
	digest, err := nodeMonitoringReportDigest(report)
	if err != nil || digest != record.digest {
		return nil, false, fmt.Errorf("node monitoring replay conflicts with accepted event")
	}
	return proto.Clone(record.ack).(*agentv1.NodeMonitoringAck), true, nil
}

func rememberNodeMonitoringAck(records map[string]nodeMonitoringAckRecord, report *agentv1.NodeMonitoringReport, ack *agentv1.NodeMonitoringAck, limit int) error {
	if limit <= 0 || report == nil || report.Event == nil || ack == nil {
		return fmt.Errorf("node monitoring replay window is full")
	}
	digest, err := nodeMonitoringReportDigest(report)
	if err != nil {
		return err
	}
	if existing, ok := records[report.Event.EventId]; ok {
		if existing.digest != digest {
			return fmt.Errorf("node monitoring replay conflicts with accepted event")
		}
		return nil
	}
	if len(records) >= limit {
		oldestEventID := ""
		var oldestSequence uint64
		for eventID, record := range records {
			sequence := record.ack.GetPublicationSequence()
			if oldestEventID == "" || sequence < oldestSequence || sequence == oldestSequence && eventID < oldestEventID {
				oldestEventID = eventID
				oldestSequence = sequence
			}
		}
		delete(records, oldestEventID)
	}
	records[report.Event.EventId] = nodeMonitoringAckRecord{digest: digest, ack: proto.Clone(ack).(*agentv1.NodeMonitoringAck)}
	return nil
}

func validateNodeMonitoringApplyStatus(status *agentv1.NodeMonitoringApplyStatus, artifact *agentv1.NodeMonitoringArtifact, nodeID string) error {
	if status == nil || artifact == nil || cacheControlMessageHasUnknown(status.ProtoReflect()) ||
		status.Schema != agentv1.NodeMonitoringSchema_NODE_MONITORING_SCHEMA_V1 || status.NodeId != nodeID ||
		status.ConfigRevision != artifact.ConfigRevision || status.ArtifactEventId != artifact.Event.GetEventId() ||
		status.Event == nil || !canonicalUUID(status.Event.EventId) || !canonicalUUID(status.Event.RequestId) ||
		status.Event.OccurredTime == nil || status.Event.OccurredTime.CheckValid() != nil {
		return fmt.Errorf("node monitoring apply status is invalid")
	}
	switch status.State {
	case agentv1.NodeMonitoringApplyState_NODE_MONITORING_APPLY_STATE_APPLIED:
		if status.ActiveConfigRevision != status.ConfigRevision || status.ErrorCode != "" {
			return fmt.Errorf("node monitoring applied evidence is invalid")
		}
	case agentv1.NodeMonitoringApplyState_NODE_MONITORING_APPLY_STATE_REJECTED:
		if status.ErrorCode == "" {
			return fmt.Errorf("node monitoring rejection evidence is incomplete")
		}
	default:
		return fmt.Errorf("node monitoring apply state is unsupported")
	}
	return nil
}

func nodeMonitoringCapabilityFromFeatures(features []*agentv1.Capability) (bool, error) {
	seen := false
	for _, capability := range features {
		if capability == nil || capability.Name != agentv1.CapabilityName_CAPABILITY_NAME_NODE_MONITORING {
			continue
		}
		if seen || capability.ApiVersion != nodeMonitoringAPIVersion {
			return false, fmt.Errorf("node monitoring capability is duplicated or unsupported")
		}
		seen = true
	}
	return seen, nil
}

func validNodeMonitoringNodeID(nodeID string) bool {
	parsed, err := uuid.Parse(nodeID)
	return err == nil && parsed != uuid.Nil && parsed.String() == nodeID
}
