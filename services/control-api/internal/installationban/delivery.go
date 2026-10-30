package installationban

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	transport "github.com/cdnca/cdnca/libs/edgeconfig/installationban"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// NodeTarget is one active node and whether its latest session declared
// CAPABILITY_NAME_INSTALLATION_BAN_TICKET v1.
type NodeTarget struct {
	ID      string
	Capable bool
}

// Commands publishes commands to agent-gateway and returns node receipts.
type Commands interface {
	Publish(ctx context.Context, command *agentv1.InstallationBanCommand) error
	// NextReceipt waits up to the transport's poll timeout; (nil, nil) when nothing arrived.
	NextReceipt(ctx context.Context) (ReceiptDelivery, error)
}

type ReceiptDelivery interface {
	Receipt() *agentv1.InstallationBanReceipt
	Ack(context.Context) error
	Nak(context.Context) error
}

// DeliveryStore is the node side of the database.
type DeliveryStore interface {
	Current(ctx context.Context, now time.Time) (State, error)
	NodeDeliveries(ctx context.Context) (map[string]NodeDelivery, error)
	RecordReceipt(ctx context.Context, receipt *agentv1.InstallationBanReceipt, now time.Time) error
}

// Failure classes of a node's latest answered revision.
const (
	FailureNone      = ""
	FailureRetryable = "retryable" // the same revision is delivered again after NextRetryAt
	FailurePermanent = "permanent" // the same bytes would be refused again: only a new revision is sent
)

// Retry backoff of a retryable refusal: RetryBackoffBase after the first
// failure, doubling, at most RetryBackoffMax.
const (
	RetryBackoffBase = time.Minute
	RetryBackoffMax  = 30 * time.Minute
)

// NodeDelivery is one node's delivery state (installation_ban_node_state):
// Revision is the latest revision the node answered (delivered),
// AppliedRevision the latest it applied. While they differ the node refused
// Revision with Reason, classified as FailureClass.
type NodeDelivery struct {
	Revision        uint64
	AppliedRevision uint64
	Status          string
	Reason          string
	FailureClass    string
	FailedAttempts  int
	NextRetryAt     *time.Time
}

// RetryBackoff is the wait after the given number of consecutive failures.
func RetryBackoff(attempts int) time.Duration {
	backoff := RetryBackoffBase
	for index := 1; index < attempts && backoff < RetryBackoffMax; index++ {
		backoff *= 2
	}
	return min(backoff, RetryBackoffMax)
}

// NextNodeDelivery folds one receipt into the node's stored state (nil = no
// row yet). ok false: the receipt is older than what is stored, or a refusal
// of a revision the node already applied (a late duplicate), and changes nothing.
func NextNodeDelivery(previous *NodeDelivery, receipt *agentv1.InstallationBanReceipt, now time.Time) (NodeDelivery, bool) {
	var stored NodeDelivery
	if previous != nil {
		stored = *previous
	}
	revision := receipt.GetRevision()
	if revision < stored.Revision || !receipt.GetApplied() && stored.AppliedRevision >= revision {
		return stored, false
	}
	reason := receipt.GetReason()
	if len(reason) > transport.MaxReasonBytes {
		reason = reason[:transport.MaxReasonBytes]
	}
	next := NodeDelivery{Revision: revision, AppliedRevision: stored.AppliedRevision, Status: receipt.GetStatus(), Reason: reason}
	if receipt.GetApplied() {
		next.AppliedRevision = revision
		return next, true
	}
	next.FailedAttempts = 1
	if stored.Revision == revision && stored.FailureClass != FailureNone {
		next.FailedAttempts = stored.FailedAttempts + 1
	}
	if transport.PermanentReason(reason) {
		next.FailureClass = FailurePermanent
		return next, true
	}
	retry := now.UTC().Add(RetryBackoff(next.FailedAttempts))
	next.FailureClass, next.NextRetryAt = FailureRetryable, &retry
	return next, true
}

// deliveryDue reports whether revision should be (re)sent to a node in this state.
func deliveryDue(delivery NodeDelivery, revision uint64, now time.Time) bool {
	switch {
	case delivery.AppliedRevision >= revision:
		return false
	case delivery.Revision != revision:
		return true // never answered this revision (or answered an older one)
	case delivery.FailureClass == FailurePermanent:
		return false
	case delivery.FailureClass == FailureRetryable:
		return delivery.NextRetryAt == nil || !now.Before(*delivery.NextRetryAt)
	}
	return true
}

// Distributor forwards the stored BanNotice and ServiceTicket bytes to every
// active capable node until the node applies their revision (ADR 0014 §5.3).
// A node that refuses a revision for a reason that may pass (it could not
// persist or enforce it) gets the same revision again after a capped backoff;
// one that refuses the bytes themselves gets only a later revision.
// The gateway keeps only the newest command per node, so an offline node
// gets it when it connects.
type Distributor struct {
	Store      DeliveryStore
	Nodes      func(context.Context) ([]NodeTarget, error)
	Commands   Commands
	Interval   time.Duration
	RetryAfter time.Duration
	Logger     *slog.Logger
	Now        func() time.Time
	// Alerts (with AlertPool) tell nodes.manage holders through the
	// notification center when a node permanently refuses a revision.
	Alerts    AlertEnqueuer
	AlertPool *pgxpool.Pool
	// alertRejected replaces AlertRejected in tests.
	alertRejected func(context.Context, RejectedAlert) error
	// TrustApplied (nil: not checked) is the signer trust revision each node
	// enforces. The node verifies the documents only with installation-ban
	// keys of an applied signer trust document, so a node without one is
	// skipped until it reports one (acc-a DA-1); the signer trust
	// distributor wakes this one when a node applies a document.
	TrustApplied func(context.Context) (map[string]uint64, error)

	wake      chan struct{}
	once      sync.Once
	mu        sync.Mutex
	published map[string]publication
	incapable string
}

type publication struct {
	revision uint64
	at       time.Time
}

func (distributor *Distributor) init() {
	distributor.once.Do(func() {
		distributor.wake = make(chan struct{}, 1)
		distributor.published = map[string]publication{}
		if distributor.RetryAfter <= 0 {
			distributor.RetryAfter = 10 * time.Minute
		}
		if distributor.Logger == nil {
			distributor.Logger = slog.Default()
		}
		if distributor.Now == nil {
			distributor.Now = time.Now
		}
	})
}

// Wake runs a publication pass soon (a new revision was accepted).
func (distributor *Distributor) Wake() {
	distributor.init()
	select {
	case distributor.wake <- struct{}{}:
	default:
	}
}

func (distributor *Distributor) Run(ctx context.Context) error {
	distributor.init()
	if distributor.Store == nil || distributor.Nodes == nil || distributor.Commands == nil || distributor.Interval <= 0 {
		return ErrInvalidConfiguration
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ctx.Err() == nil {
			delivery, err := distributor.Commands.NextReceipt(ctx)
			if err != nil {
				if ctx.Err() == nil {
					distributor.Logger.Warn("installation ban receipts unavailable", "error", err)
					select {
					case <-ctx.Done():
					case <-time.After(distributor.Interval):
					}
				}
				continue
			}
			if delivery != nil {
				distributor.HandleReceipt(ctx, delivery)
			}
		}
	}()
	ticker := time.NewTicker(distributor.Interval)
	defer ticker.Stop()
	for {
		if err := distributor.PublishOnce(ctx); err != nil && ctx.Err() == nil {
			distributor.Logger.Warn("installation ban publication pass failed", "error", err)
		}
		select {
		case <-ctx.Done():
			<-done
			return ctx.Err()
		case <-ticker.C:
		case <-distributor.wake:
		}
	}
}

// PublishOnce sends the current documents to every capable node behind them.
func (distributor *Distributor) PublishOnce(ctx context.Context) error {
	distributor.init()
	now := distributor.Now()
	state, err := distributor.Store.Current(ctx, now)
	if err != nil {
		return err
	}
	revision := latestRevision(state)
	if revision == 0 {
		return nil
	}
	nodes, err := distributor.Nodes(ctx)
	if err != nil {
		return fmt.Errorf("list nodes: %w", err)
	}
	deliveries, err := distributor.Store.NodeDeliveries(ctx)
	if err != nil {
		return err
	}
	var trusted map[string]uint64
	if distributor.TrustApplied != nil {
		if trusted, err = distributor.TrustApplied(ctx); err != nil {
			return fmt.Errorf("read node signer trust state: %w", err)
		}
	}
	var failure error
	var incapable []string
	for _, node := range nodes {
		if !deliveryDue(deliveries[node.ID], revision, now) {
			continue
		}
		if !node.Capable {
			incapable = append(incapable, node.ID)
			continue
		}
		if trusted != nil && trusted[node.ID] == 0 {
			continue
		}
		distributor.mu.Lock()
		previous, sent := distributor.published[node.ID]
		recent := sent && previous.revision == revision && now.Before(previous.at.Add(distributor.RetryAfter))
		distributor.mu.Unlock()
		if recent {
			continue
		}
		if err := distributor.Commands.Publish(ctx, NewCommand(node.ID, revision, state)); err != nil {
			failure = errors.Join(failure, fmt.Errorf("publish installation ban to %s: %w", node.ID, err))
			continue
		}
		distributor.mu.Lock()
		distributor.published[node.ID] = publication{revision: revision, at: now}
		distributor.mu.Unlock()
		distributor.Logger.Info("installation ban state published", "node_id", node.ID, "revision", revision)
	}
	key := fmt.Sprint(revision, incapable)
	if key != distributor.incapable && len(incapable) > 0 {
		shown := incapable[:min(len(incapable), 20)]
		distributor.Logger.Warn("installation ban state not delivered: node agent lacks INSTALLATION_BAN_TICKET (upgrade the node)",
			"revision", revision, "nodes", len(incapable), "node_ids", shown)
	}
	distributor.incapable = key
	return failure
}

// NewCommand carries the stored documents' exact bytes to one node.
func NewCommand(nodeID string, revision uint64, state State) *agentv1.InstallationBanCommand {
	command := &agentv1.InstallationBanCommand{
		Event:  &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now()},
		NodeId: nodeID, Revision: revision,
	}
	if state.Notice != nil {
		digest := sha256.Sum256(state.Notice)
		command.NoticeJson, command.NoticeSha256 = append([]byte(nil), state.Notice...), digest[:]
	}
	if state.Ticket != nil {
		digest := sha256.Sum256(state.Ticket)
		command.TicketJson, command.TicketSha256 = append([]byte(nil), state.Ticket...), digest[:]
	}
	return command
}

// HandleReceipt records one node receipt.
func (distributor *Distributor) HandleReceipt(ctx context.Context, delivery ReceiptDelivery) {
	receipt := delivery.Receipt()
	if err := distributor.Store.RecordReceipt(ctx, receipt, distributor.Now()); err != nil {
		distributor.Logger.Warn("installation ban receipt not recorded yet", "node_id", receipt.GetNodeId(), "error", err)
		_ = delivery.Nak(ctx)
		return
	}
	// The receipt decides when this revision goes out again (the stored
	// retry time, or never once applied), not the unanswered-command timer.
	distributor.mu.Lock()
	if previous, sent := distributor.published[receipt.NodeId]; sent && previous.revision == receipt.Revision {
		delete(distributor.published, receipt.NodeId)
	}
	distributor.mu.Unlock()
	attributes := []any{"node_id", receipt.NodeId, "revision", receipt.Revision, "applied", receipt.Applied,
		"status", receipt.Status, "reason", receipt.Reason}
	switch {
	case receipt.Applied:
		distributor.Logger.Info("installation ban receipt", attributes...)
	case transport.PermanentReason(receipt.Reason):
		// Alert: the node will not apply this revision; only a new one is sent.
		distributor.Logger.Error("installation ban state refused by the node; this revision is not sent again", attributes...)
		if nodeID, err := uuid.Parse(receipt.NodeId); err == nil {
			alert := distributor.alertRejected
			if alert == nil {
				alert = func(ctx context.Context, value RejectedAlert) error {
					return AlertRejected(ctx, distributor.AlertPool, distributor.Alerts, value)
				}
			}
			if err := alert(ctx, RejectedAlert{NodeID: nodeID, Revision: receipt.Revision, Reason: receipt.Reason,
				At: distributor.Now()}); err != nil {
				distributor.Logger.Warn("installation ban refusal alert not enqueued", "node_id", receipt.NodeId, "error", err)
			}
		}
	default:
		distributor.Logger.Warn("installation ban state not applied by the node; the same revision is sent again after a backoff",
			attributes...)
	}
	_ = delivery.Ack(ctx)
}

// NodeDeliveries: each node's delivery state (installation_ban_node_state).
func (store *Store) NodeDeliveries(ctx context.Context) (map[string]NodeDelivery, error) {
	rows, err := store.pool.Query(ctx, `SELECT node_id, revision, applied_revision, status, reason, failure_class,
			failed_attempts, next_retry_at FROM installation_ban_node_state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[string]NodeDelivery{}
	for rows.Next() {
		var nodeID uuid.UUID
		delivery, err := scanNodeDelivery(rows.Scan, &nodeID)
		if err != nil {
			return nil, err
		}
		result[nodeID.String()] = delivery
	}
	return result, rows.Err()
}

func scanNodeDelivery(scan func(...any) error, nodeID *uuid.UUID) (NodeDelivery, error) {
	var delivery NodeDelivery
	var revision, applied int64
	if err := scan(nodeID, &revision, &applied, &delivery.Status, &delivery.Reason, &delivery.FailureClass,
		&delivery.FailedAttempts, &delivery.NextRetryAt); err != nil {
		return NodeDelivery{}, err
	}
	delivery.Revision, delivery.AppliedRevision = uint64(revision), uint64(applied)
	return delivery, nil
}

// RecordReceipt folds one node receipt into installation_ban_node_state
// (NextNodeDelivery): revision is the latest one the node answered,
// applied_revision moves only on applied true, and a refusal keeps its
// reason, class, attempt count and retry time.
func (store *Store) RecordReceipt(ctx context.Context, receipt *agentv1.InstallationBanReceipt, now time.Time) error {
	nodeID, err := uuid.Parse(receipt.GetNodeId())
	if err != nil || receipt.Revision == 0 || !transport.Statuses[receipt.Status] {
		return ErrInvalidResponse
	}
	issuedAt, notAfter, err := ReceiptTicketTimes(receipt)
	if err != nil {
		return err
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM nodes WHERE id = $1 FOR KEY SHARE)`, nodeID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return nil // the node was deleted meanwhile
	}
	var previous *NodeDelivery
	var scanned uuid.UUID
	stored, err := scanNodeDelivery(tx.QueryRow(ctx, `SELECT node_id, revision, applied_revision, status, reason,
			failure_class, failed_attempts, next_retry_at FROM installation_ban_node_state WHERE node_id = $1 FOR UPDATE`,
		nodeID).Scan, &scanned)
	switch {
	case err == nil:
		previous = &stored
	case !errors.Is(err, pgx.ErrNoRows):
		return err
	}
	next, ok := NextNodeDelivery(previous, receipt, now)
	if !ok {
		return tx.Commit(ctx)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO installation_ban_node_state (node_id, revision, status, applied, reason, updated_at,
			ticket_issued_at, ticket_not_after, applied_revision, failure_class, failed_attempts, next_retry_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (node_id) DO UPDATE SET revision = excluded.revision, status = excluded.status,
			applied = excluded.applied, reason = excluded.reason, updated_at = excluded.updated_at,
			ticket_issued_at = excluded.ticket_issued_at, ticket_not_after = excluded.ticket_not_after,
			applied_revision = excluded.applied_revision, failure_class = excluded.failure_class,
			failed_attempts = excluded.failed_attempts, next_retry_at = excluded.next_retry_at`,
		nodeID, int64(next.Revision), next.Status, receipt.Applied, next.Reason, now.UTC(), issuedAt, notAfter,
		int64(next.AppliedRevision), next.FailureClass, next.FailedAttempts, next.NextRetryAt); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ReceiptTicketTimes is the node's held ServiceTicket from a receipt (PF09):
// both nil before its first ticket; a half-set or inverted pair is invalid.
func ReceiptTicketTimes(receipt *agentv1.InstallationBanReceipt) (*time.Time, *time.Time, error) {
	issued, notAfter := receipt.GetTicketIssuedTime(), receipt.GetTicketNotAfterTime()
	if issued == nil && notAfter == nil {
		return nil, nil, nil
	}
	if issued == nil || notAfter == nil || issued.CheckValid() != nil || notAfter.CheckValid() != nil ||
		!notAfter.AsTime().After(issued.AsTime()) {
		return nil, nil, ErrInvalidResponse
	}
	issuedAt, notAfterAt := issued.AsTime().UTC(), notAfter.AsTime().UTC()
	return &issuedAt, &notAfterAt, nil
}

// ActiveNodes lists active nodes with the capability of their latest session.
func ActiveNodes(pool *pgxpool.Pool) func(context.Context) ([]NodeTarget, error) {
	return func(ctx context.Context) ([]NodeTarget, error) {
		rows, err := pool.Query(ctx, `SELECT node.id,
				(SELECT facts.capabilities_snapshot FROM node_session_capabilities facts WHERE facts.node_id=node.id
				 ORDER BY facts.session_epoch DESC LIMIT 1)
			FROM nodes node WHERE node.admin_state='active' ORDER BY node.id LIMIT 100000`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		nodes := []NodeTarget{}
		for rows.Next() {
			var id uuid.UUID
			var snapshot []byte
			if err := rows.Scan(&id, &snapshot); err != nil {
				return nil, err
			}
			nodes = append(nodes, NodeTarget{ID: id.String(), Capable: declaresCapability(snapshot)})
		}
		return nodes, rows.Err()
	}
}

func declaresCapability(snapshot []byte) bool {
	var capabilities agentv1.AgentCapabilities
	if len(snapshot) == 0 || proto.Unmarshal(snapshot, &capabilities) != nil {
		return false
	}
	for _, capability := range capabilities.Features {
		if capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_INSTALLATION_BAN_TICKET &&
			capability.GetApiVersion() == transport.APIVersion {
			return true
		}
	}
	return false
}

// NATSCommands publishes to and consumes from the streams agent-gateway owns.
type NATSCommands struct {
	js       nats.JetStreamContext
	timeout  time.Duration
	mu       sync.Mutex
	receipts *nats.Subscription
}

func NewNATSCommands(connection *nats.Conn, timeout time.Duration) (*NATSCommands, error) {
	if connection == nil || connection.IsClosed() || timeout <= 0 {
		return nil, ErrInvalidConfiguration
	}
	js, err := connection.JetStream(nats.MaxWait(timeout))
	if err != nil {
		return nil, err
	}
	return &NATSCommands{js: js, timeout: timeout}, nil
}

func (commands *NATSCommands) Publish(ctx context.Context, command *agentv1.InstallationBanCommand) error {
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(command)
	if err != nil || len(payload) > transport.MaxCarrierBytes {
		return errors.New("encode installation ban command")
	}
	message := nats.NewMsg(transport.CommandSubjectPrefix + "." + command.NodeId)
	message.Data = payload
	message.Header.Set(nats.MsgIdHdr, command.Event.EventId)
	operation, cancel := context.WithTimeout(ctx, commands.timeout)
	defer cancel()
	ack, err := commands.js.PublishMsg(message, nats.Context(operation), nats.ExpectStream(transport.CommandStream))
	if err != nil || ack == nil || ack.Stream != transport.CommandStream || ack.Sequence == 0 {
		return fmt.Errorf("persist installation ban command: %w", err)
	}
	return nil
}

func (commands *NATSCommands) NextReceipt(ctx context.Context) (ReceiptDelivery, error) {
	subscription, err := commands.subscription(ctx)
	if err != nil {
		return nil, err
	}
	operation, cancel := context.WithTimeout(ctx, commands.timeout)
	messages, err := subscription.Fetch(1, nats.Context(operation))
	cancel()
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, nats.ErrTimeout) {
		return nil, nil
	}
	if err != nil || len(messages) != 1 {
		return nil, err
	}
	message := messages[0]
	receipt := &agentv1.InstallationBanReceipt{}
	nodeID := strings.TrimPrefix(message.Subject, transport.StatusSubjectPrefix+".")
	if len(message.Data) > transport.MaxCarrierBytes || proto.Unmarshal(message.Data, receipt) != nil ||
		len(receipt.ProtoReflect().GetUnknown()) != 0 || receipt.NodeId != nodeID {
		_ = message.Term() // the gateway validated it; anything else can never be recorded
		return nil, nil
	}
	return &natsReceipt{message: message, receipt: receipt}, nil
}

func (commands *NATSCommands) subscription(ctx context.Context) (*nats.Subscription, error) {
	commands.mu.Lock()
	defer commands.mu.Unlock()
	if commands.receipts != nil {
		return commands.receipts, nil
	}
	consumer := &nats.ConsumerConfig{Durable: transport.ReceiptConsumer, DeliverPolicy: nats.DeliverAllPolicy,
		AckPolicy: nats.AckExplicitPolicy, AckWait: 2 * time.Minute, MaxDeliver: -1,
		FilterSubject: transport.StatusSubjectPrefix + ".*", ReplayPolicy: nats.ReplayInstantPolicy,
		MaxAckPending: 64, MaxWaiting: 4, MaxRequestBatch: 1}
	operation, cancel := context.WithTimeout(ctx, commands.timeout)
	defer cancel()
	if _, err := commands.js.ConsumerInfo(transport.StatusStream, transport.ReceiptConsumer, nats.Context(operation)); err != nil {
		if !errors.Is(err, nats.ErrConsumerNotFound) {
			return nil, fmt.Errorf("installation ban receipt consumer: %w", err)
		}
		if _, err := commands.js.AddConsumer(transport.StatusStream, consumer, nats.Context(operation)); err != nil {
			return nil, fmt.Errorf("create installation ban receipt consumer: %w", err)
		}
	}
	subscription, err := commands.js.PullSubscribe(consumer.FilterSubject, transport.ReceiptConsumer,
		nats.Bind(transport.StatusStream, transport.ReceiptConsumer))
	if err != nil {
		return nil, fmt.Errorf("subscribe to installation ban receipts: %w", err)
	}
	commands.receipts = subscription
	return subscription, nil
}

type natsReceipt struct {
	message *nats.Msg
	receipt *agentv1.InstallationBanReceipt
}

func (receipt *natsReceipt) Receipt() *agentv1.InstallationBanReceipt { return receipt.receipt }
func (receipt *natsReceipt) Ack(ctx context.Context) error {
	return receipt.message.AckSync(nats.Context(ctx))
}
func (receipt *natsReceipt) Nak(context.Context) error {
	return receipt.message.NakWithDelay(5 * time.Second)
}
