package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/autodefense"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Automatic defense channel (ADR 0010 section 8, AD-07, CAPABILITY_NAME_AUTO_DEFENSE v1).
//
// Down: control-api publishes the signed snapshot parts of one node (ConnectResponse 26); the gateway binds each
// carrier to its part (node, revision, digest), relays one part at a time and acknowledges it only after the
// node's receipt (ConnectRequest 23) is published. Parts are delivered whatever the authorization snapshot says
// about deployments: switching a site off or withdrawing a signature must reach a paused node. The gateway never
// verifies the signature (the Agent does).
//
// Up: optional summaries (ConnectRequest 24, cdnca.autodefense.report/v1). Display only: the node decides and
// mitigates on its own, so the gateway rate limits per session, drops what exceeds the budget or the queue and
// never answers. Accepted reports are published to cdnca.security.autodefense.v1.<node> with Nats-Msg-Id
// node/scope/seq. The gateway checks the node identity and the schema; site and tenant ownership are checked by
// the consumer (AD-08) against the node's assignment.

const (
	maxAutoDefenseReceiptBytes = 4096
	// Report budget per session: ADR 0010 section 10.4 gives a node 50 KB/s of upstream; the burst holds four
	// maximal messages so a minute boundary with many sites is not cut.
	autoDefenseReportBytesPerSecond = 64 << 10
	autoDefenseReportBurstBytes     = 4 * autodefense.MaxReportBytes
	autoDefenseReportQueue          = 64
)

type AutoDefensePublication struct {
	Stream   string
	Sequence uint64
	Replayed bool
}

// AutoDefenseBus is the gateway side of the automatic defense streams.
type AutoDefenseBus interface {
	SubscribeAutoDefense(context.Context, string) (AutoDefenseSubscription, error)
	PublishAutoDefenseReceipt(context.Context, string, *agentv1.AutoDefenseReceipt) (AutoDefensePublication, error)
	// PublishAutoDefenseReport publishes one validated report; msgID is its idempotency key.
	PublishAutoDefenseReport(ctx context.Context, nodeID, msgID string, report []byte) (AutoDefensePublication, error)
}

type AutoDefenseSubscription interface {
	Next(context.Context) (AutoDefenseDelivery, error)
	Close() error
}

type AutoDefenseDelivery interface {
	Command() *agentv1.AutoDefenseCommand
	Ack(context.Context) error
	Nak(context.Context) error
}

// AutoDefenseReportStats counts upstream reports since start (display path health).
type AutoDefenseReportStats struct {
	Published, Duplicates, Invalid, RateLimited, QueueFull, PublishFailed uint64
}

type autoDefenseReportCounters struct {
	published, duplicates, invalid, rateLimited, queueFull, publishFailed atomic.Uint64
}

// configuredAutoDefense keeps the report counters with the bus (one Gateway field).
type configuredAutoDefense struct {
	AutoDefenseBus
	counters autoDefenseReportCounters
}

// ConfigureAutoDefense enables the automatic defense channel.
func (g *Gateway) ConfigureAutoDefense(bus AutoDefenseBus) error {
	if g == nil || bus == nil || g.autoDefense != nil {
		return fmt.Errorf("auto defense bus is invalid or already configured")
	}
	g.autoDefense = &configuredAutoDefense{AutoDefenseBus: bus}
	return nil
}

// AutoDefenseReportStats returns the upstream report counters.
func (g *Gateway) AutoDefenseReportStats() AutoDefenseReportStats {
	configured, _ := g.autoDefense.(*configuredAutoDefense)
	if configured == nil {
		return AutoDefenseReportStats{}
	}
	counters := &configured.counters
	return AutoDefenseReportStats{
		Published: counters.published.Load(), Duplicates: counters.duplicates.Load(), Invalid: counters.invalid.Load(),
		RateLimited: counters.rateLimited.Load(), QueueFull: counters.queueFull.Load(), PublishFailed: counters.publishFailed.Load(),
	}
}

func autoDefenseCapabilityFromFeatures(features []*agentv1.Capability) (bool, error) {
	seen := false
	for _, capability := range features {
		if capability == nil || capability.Name != agentv1.CapabilityName_CAPABILITY_NAME_AUTO_DEFENSE {
			continue
		}
		if seen || capability.ApiVersion != autodefense.APIVersion {
			return false, fmt.Errorf("auto defense capability is duplicated or unsupported")
		}
		seen = true
	}
	return seen, nil
}

func autoDefenseCapability() *agentv1.Capability {
	return &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_AUTO_DEFENSE, ApiVersion: autodefense.APIVersion}
}

type autoDefenseReceive struct {
	delivery AutoDefenseDelivery
	err      error
}

type sessionAutoDefense struct {
	ctx            context.Context
	cancel         context.CancelFunc
	subscription   AutoDefenseSubscription
	next           chan autoDefenseReceive
	pending        AutoDefenseDelivery
	pendingCommand *agentv1.AutoDefenseCommand

	reports *autoDefenseReportRelay
}

func (g *Gateway) startSessionAutoDefense(ctx context.Context, nodeID string) (*sessionAutoDefense, error) {
	sourceContext, cancel := context.WithCancel(ctx)
	subscription, err := g.autoDefense.SubscribeAutoDefense(sourceContext, nodeID)
	if err != nil {
		cancel()
		return nil, status.Error(codes.Unavailable, "could not subscribe to auto defense snapshots")
	}
	session := &sessionAutoDefense{ctx: sourceContext, cancel: cancel, subscription: subscription}
	counters := &autoDefenseReportCounters{}
	if configured, ok := g.autoDefense.(*configuredAutoDefense); ok {
		counters = &configured.counters
	}
	session.reports = newAutoDefenseReportRelay(sourceContext, g.autoDefense, nodeID, g.config.CommandOperationTimeout,
		counters, g.now)
	return session, nil
}

// receive is nil while a part waits for its receipt (one in flight).
func (session *sessionAutoDefense) receive() <-chan autoDefenseReceive {
	if session == nil || session.pending != nil {
		return nil
	}
	if session.next == nil {
		next := make(chan autoDefenseReceive, 1)
		session.next = next
		go func() {
			delivery, err := session.subscription.Next(session.ctx)
			next <- autoDefenseReceive{delivery: delivery, err: err}
		}()
	}
	return session.next
}

func (session *sessionAutoDefense) stop(timeout time.Duration) {
	if session == nil {
		return
	}
	if session.pending != nil {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		_ = session.pending.Nak(ctx)
		cancel()
		session.pending, session.pendingCommand = nil, nil
	}
	session.cancel()
	_ = session.subscription.Close()
	session.reports.close()
	if session.next != nil {
		select {
		case received := <-session.next:
			if received.delivery != nil {
				ctx, cancel := context.WithTimeout(context.Background(), timeout)
				_ = received.delivery.Nak(ctx)
				cancel()
			}
		case <-time.After(timeout):
		}
	}
}

func validateAutoDefenseCommand(command *agentv1.AutoDefenseCommand, nodeID string) error {
	if command == nil || proto.Size(command) > autodefense.MaxCarrierBytes || cacheControlMessageHasUnknown(command.ProtoReflect()) ||
		command.NodeId != nodeID || command.Revision == 0 || len(command.SnapshotSha256) != sha256.Size || command.Event == nil ||
		command.Event.OccurredTime == nil || !validAutoDefenseEvent(command.Event) {
		return fmt.Errorf("auto defense command is invalid")
	}
	digest := sha256.Sum256(command.SnapshotJson)
	routeNode, routeRevision, err := autodefense.Route(command.SnapshotJson)
	if !bytes.Equal(digest[:], command.SnapshotSha256) || err != nil || routeNode != nodeID || routeRevision != command.Revision {
		return fmt.Errorf("auto defense command binding is invalid")
	}
	return nil
}

// validAutoDefenseEvent: canonical event and request IDs and a valid time. (S5 has the same check as
// validEventMetadata on the ge-waf branch; a separate name keeps the two branches mergeable.)
func validAutoDefenseEvent(event interface {
	GetEventId() string
	GetRequestId() string
	GetOccurredTime() *timestamppb.Timestamp
}) bool {
	return canonicalUUID(event.GetEventId()) && canonicalUUID(event.GetRequestId()) && event.GetOccurredTime().CheckValid() == nil
}

func validAutoDefenseErrorCode(code string) bool {
	switch code {
	case autodefense.ErrorUntrusted, autodefense.ErrorInvalid, autodefense.ErrorWrongNode, autodefense.ErrorStale,
		autodefense.ErrorIncomplete, autodefense.ErrorRuntime, autodefense.ErrorNotSupported:
		return true
	}
	return false
}

// validateAutoDefenseReceipt binds a receipt to the part in flight: applied with counts and no error, or refused
// with a contract error code and no counts.
func validateAutoDefenseReceipt(receipt *agentv1.AutoDefenseReceipt, command *agentv1.AutoDefenseCommand, nodeID string) error {
	if receipt == nil || command == nil || proto.Size(receipt) > maxAutoDefenseReceiptBytes || cacheControlMessageHasUnknown(receipt.ProtoReflect()) ||
		receipt.NodeId != nodeID || receipt.CommandEventId != command.Event.GetEventId() || receipt.Revision != command.Revision ||
		!bytes.Equal(receipt.SnapshotSha256, command.SnapshotSha256) || receipt.Event == nil || receipt.Event.OccurredTime == nil ||
		!validAutoDefenseEvent(receipt.Event) {
		return fmt.Errorf("auto defense receipt is invalid")
	}
	if receipt.Applied {
		if receipt.ErrorCode != "" {
			return fmt.Errorf("auto defense receipt is invalid")
		}
	} else if !validAutoDefenseErrorCode(receipt.ErrorCode) || receipt.Sites != 0 || receipt.Signatures != 0 || receipt.Mitigations != 0 {
		return fmt.Errorf("auto defense receipt is invalid")
	}
	return nil
}

func (g *Gateway) settleAutoDefenseReceipt(ctx context.Context, session *sessionAutoDefense, nodeID string,
	receipt *agentv1.AutoDefenseReceipt,
) error {
	if err := validateAutoDefenseReceipt(receipt, session.pendingCommand, nodeID); err != nil {
		return status.Error(codes.FailedPrecondition, err.Error())
	}
	operationCtx, cancel := context.WithTimeout(ctx, g.config.CommandOperationTimeout)
	defer cancel()
	publication, err := g.autoDefense.PublishAutoDefenseReceipt(operationCtx, nodeID, proto.Clone(receipt).(*agentv1.AutoDefenseReceipt))
	// The bus checks the acknowledgement against its configured stream.
	if err != nil || publication.Stream == "" || publication.Sequence == 0 {
		return status.Error(codes.Unavailable, "auto defense receipt could not be published")
	}
	if err := session.pending.Ack(operationCtx); err != nil {
		return status.Error(codes.Unavailable, "auto defense command disposition failed")
	}
	session.pending, session.pendingCommand = nil, nil
	return nil
}

// autoDefenseReportKey validates one report for the authenticated node and returns its idempotency key
// (contract section 5: node_id + site_id | port_group + seq).
func autoDefenseReportKey(report *agentv1.AutoDefenseReport, nodeID string) (string, error) {
	if report == nil || cacheControlMessageHasUnknown(report.ProtoReflect()) {
		return "", fmt.Errorf("auto defense report is invalid")
	}
	decoded, err := autodefense.DecodeReport(report.ReportJson)
	if err != nil || decoded.NodeID != nodeID {
		return "", fmt.Errorf("auto defense report is invalid")
	}
	scope := "site:" + decoded.SiteID
	switch {
	case decoded.Kind == autodefense.ReportNodeEvent:
		scope = "node"
	case decoded.Kind == autodefense.ReportCCStats:
		// Node scoped with its own seq.
		scope = "cc_stats"
	case decoded.SiteID == "":
		scope = "port_group:" + decoded.PortGroup
	}
	return nodeID + "/" + scope + "/" + strconv.FormatUint(decoded.Seq, 10), nil
}

// autoDefenseReportRelay publishes accepted reports off the session loop: a slow or failing JetStream never
// delays heartbeats or commands; what does not fit is dropped and counted.
type autoDefenseReportRelay struct {
	bus      AutoDefenseBus
	nodeID   string
	timeout  time.Duration
	counters *autoDefenseReportCounters
	now      func() time.Time
	queue    chan autoDefenseReportItem
	done     chan struct{}
	once     sync.Once

	tokens float64
	last   time.Time
}

type autoDefenseReportItem struct {
	msgID   string
	payload []byte
}

func newAutoDefenseReportRelay(ctx context.Context, bus AutoDefenseBus, nodeID string, timeout time.Duration,
	counters *autoDefenseReportCounters, now func() time.Time,
) *autoDefenseReportRelay {
	relay := &autoDefenseReportRelay{bus: bus, nodeID: nodeID, timeout: timeout, counters: counters, now: now,
		queue: make(chan autoDefenseReportItem, autoDefenseReportQueue), done: make(chan struct{}),
		tokens: autoDefenseReportBurstBytes, last: now()}
	go relay.run(ctx)
	return relay
}

func (relay *autoDefenseReportRelay) run(ctx context.Context) {
	defer close(relay.done)
	for {
		select {
		case <-ctx.Done():
			return
		case item := <-relay.queue:
			operationCtx, cancel := context.WithTimeout(ctx, relay.timeout)
			publication, err := relay.bus.PublishAutoDefenseReport(operationCtx, relay.nodeID, item.msgID, item.payload)
			cancel()
			switch {
			case err != nil || publication.Stream == "" || publication.Sequence == 0:
				relay.counters.publishFailed.Add(1)
			case publication.Replayed:
				relay.counters.duplicates.Add(1)
			default:
				relay.counters.published.Add(1)
			}
		}
	}
}

// offer is called from the session loop only (the token bucket is not shared).
func (relay *autoDefenseReportRelay) offer(report *agentv1.AutoDefenseReport) {
	if relay == nil {
		return
	}
	msgID, err := autoDefenseReportKey(report, relay.nodeID)
	if err != nil {
		relay.counters.invalid.Add(1)
		return
	}
	now := relay.now()
	if elapsed := now.Sub(relay.last).Seconds(); elapsed > 0 {
		relay.tokens = min(autoDefenseReportBurstBytes, relay.tokens+elapsed*autoDefenseReportBytesPerSecond)
	}
	relay.last = now
	size := float64(len(report.ReportJson))
	if relay.tokens < size {
		relay.counters.rateLimited.Add(1)
		return
	}
	select {
	case relay.queue <- autoDefenseReportItem{msgID: msgID, payload: append([]byte(nil), report.ReportJson...)}:
		relay.tokens -= size
	default:
		relay.counters.queueFull.Add(1)
	}
}

// close waits for the publisher to stop (the session context is already cancelled).
func (relay *autoDefenseReportRelay) close() {
	if relay == nil {
		return
	}
	relay.once.Do(func() { <-relay.done })
}
