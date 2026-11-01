package nodesshinstall

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	contract "github.com/cdnca/cdnca/libs/edgeconfig/sshaccess"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/natsready"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// "Only the controller may SSH" delivery:
//
//	pending   --publish apply-->  (node) --receipt applied--> applied
//	applied   --controller reaches sshd (FetchHostKey)--> publish confirm
//	          --receipt confirmed--> confirmed
//	applied   --probe fails: no confirm; the node's 5 minute timer reverts--> reverted
//	any       --receipt failed (refused / not_supported)--> failed
//
// A node that does not declare SSH_ACCESS v1 is failed with not_supported
// (the console says the node version does not support it); an offline node
// stays pending until it connects. Receipts of an older revision are ignored.

const (
	AccessFailureNotSupported = contract.FailureNotSupported
	// accessRepublishAfter re-sends an unanswered command (the stream keeps
	// it anyway; this covers a lost stream or a node that reconnected late).
	accessRepublishAfter = time.Minute
	// accessProbeTimeout bounds one sshd reachability probe.
	accessProbeTimeout = 20 * time.Second
)

// AccessTarget is one row the worker acts on.
type AccessTarget struct {
	NodeID             uuid.UUID
	Host               string
	Enabled            bool
	SSHPort            int
	CIDRs              []string // controller egress + allowlist, canonical
	Revision           int64
	State              string
	PublishedRevision  int64
	PublishedOperation string
	PublishedAt        *time.Time
	AppliedAt          *time.Time
	Online             bool
	Capable            bool
}

// AccessAction is what the worker does for one target.
type AccessAction int

const (
	AccessNone AccessAction = iota
	AccessPublishApply
	AccessProbeAndConfirm
	AccessRepublishConfirm
	AccessFailNotSupported
)

// NextAccessAction is the delivery state machine for one row.
func NextAccessAction(target AccessTarget, now time.Time) AccessAction {
	due := target.PublishedAt == nil || !now.Before(target.PublishedAt.Add(accessRepublishAfter))
	switch target.State {
	case AccessPending:
		if !target.Online {
			return AccessNone
		}
		if !target.Capable {
			return AccessFailNotSupported
		}
		if target.PublishedRevision < target.Revision || target.PublishedOperation != contract.OperationApply || due {
			return AccessPublishApply
		}
	case AccessApplied:
		// Past the node's rollback window a confirm can no longer keep it:
		// wait for the node's reverted receipt.
		if target.AppliedAt != nil && !now.Before(target.AppliedAt.Add(contract.RollbackWindow)) {
			return AccessNone
		}
		if !target.Enabled {
			return AccessNone
		}
		if target.PublishedOperation != contract.OperationConfirm {
			return AccessProbeAndConfirm
		}
		if due && target.Online {
			return AccessRepublishConfirm
		}
	}
	return AccessNone
}

// AccessReceiptUpdate is the row change for one receipt (ok false: ignore).
type AccessReceiptUpdate struct {
	State       string
	FailureCode string
	Applied     bool
	Confirmed   bool
}

// AccessReceiptTransition maps a node receipt for the row's current state.
// Only the current revision moves the row; a disabled revision that applied
// is final (nothing to confirm).
func AccessReceiptTransition(current string, enabled bool, receipt *agentv1.SSHAccessReceipt) (AccessReceiptUpdate, bool) {
	switch receipt.GetState() {
	case contract.StateApplied:
		if current != AccessPending {
			return AccessReceiptUpdate{}, false
		}
		if !enabled {
			return AccessReceiptUpdate{State: AccessConfirmed, Applied: true, Confirmed: true}, true
		}
		return AccessReceiptUpdate{State: AccessApplied, Applied: true}, true
	case contract.StateConfirmed:
		if current != AccessApplied && current != AccessPending {
			return AccessReceiptUpdate{}, false
		}
		return AccessReceiptUpdate{State: AccessConfirmed, Applied: current == AccessPending, Confirmed: true}, true
	case contract.StateReverted:
		if current != AccessApplied && current != AccessPending {
			return AccessReceiptUpdate{}, false
		}
		return AccessReceiptUpdate{State: AccessReverted, FailureCode: failureOr(receipt.GetFailureCode(), contract.FailureConfirmationTimeout)}, true
	case contract.StateFailed:
		if current != AccessPending && current != AccessApplied {
			return AccessReceiptUpdate{}, false
		}
		return AccessReceiptUpdate{State: AccessFailed, FailureCode: failureOr(receipt.GetFailureCode(), "apply_failed")}, true
	}
	return AccessReceiptUpdate{}, false
}

func failureOr(code, fallback string) string {
	if code == "" || !contract.ValidFailureCode(code) {
		return fallback
	}
	return code
}

// AccessStore is the persistence the worker needs.
type AccessStore interface {
	DueAccess(ctx context.Context, limit int) ([]AccessTarget, error)
	MarkAccessPublished(ctx context.Context, nodeID uuid.UUID, revision int64, operation string, at time.Time) error
	FailAccess(ctx context.Context, nodeID uuid.UUID, revision int64, code string) error
	ReportAccess(ctx context.Context, nodeID uuid.UUID, receipt *agentv1.SSHAccessReceipt) (bool, error)
}

// AccessTransport carries commands to agent-gateway and receipts back.
type AccessTransport interface {
	Publish(ctx context.Context, command *agentv1.SSHAccessCommand) error
	// NextReceipt waits up to the poll timeout; (nil, nil) when nothing arrived.
	NextReceipt(ctx context.Context) (AccessReceiptDelivery, error)
}

type AccessReceiptDelivery interface {
	Receipt() *agentv1.SSHAccessReceipt
	Ack(context.Context) error
	Nak(context.Context) error
}

// AccessProber checks the controller still reaches sshd (host key read).
type AccessProber interface {
	FetchHostKey(ctx context.Context, host string, port int) (string, error)
}

type AccessDeliveryConfig struct {
	Store     AccessStore
	Transport AccessTransport
	Prober    AccessProber
	Interval  time.Duration
	Logger    *slog.Logger
	Now       func() time.Time
}

// AccessDelivery is the worker.
type AccessDelivery struct {
	config AccessDeliveryConfig
	wake   chan struct{}
}

func NewAccessDelivery(config AccessDeliveryConfig) (*AccessDelivery, error) {
	if config.Store == nil || config.Transport == nil || config.Prober == nil || config.Interval <= 0 {
		return nil, errors.New("SSH access delivery configuration is incomplete")
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &AccessDelivery{config: config, wake: make(chan struct{}, 1)}, nil
}

// Wake runs a pass soon (the wanted state changed or a receipt arrived).
func (d *AccessDelivery) Wake() {
	if d == nil {
		return
	}
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

func (d *AccessDelivery) Run(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.consumeReceipts(ctx)
	}()
	ticker := time.NewTicker(d.config.Interval)
	defer ticker.Stop()
	for {
		if err := d.PublishOnce(ctx); err != nil && ctx.Err() == nil {
			d.config.Logger.Warn("SSH access commands not published", "error", err)
		}
		select {
		case <-ctx.Done():
			<-done
			return ctx.Err()
		case <-ticker.C:
		case <-d.wake:
		}
	}
}

// PublishOnce acts on every due row.
func (d *AccessDelivery) PublishOnce(ctx context.Context) error {
	targets, err := d.config.Store.DueAccess(ctx, 500)
	if err != nil {
		return err
	}
	var errs []error
	for _, target := range targets {
		if err := d.act(ctx, target); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (d *AccessDelivery) act(ctx context.Context, target AccessTarget) error {
	now := d.config.Now().UTC()
	switch NextAccessAction(target, now) {
	case AccessFailNotSupported:
		return d.config.Store.FailAccess(ctx, target.NodeID, target.Revision, AccessFailureNotSupported)
	case AccessPublishApply:
		return d.publish(ctx, target, contract.OperationApply, now)
	case AccessProbeAndConfirm:
		probeCtx, cancel := context.WithTimeout(ctx, accessProbeTimeout)
		_, err := d.config.Prober.FetchHostKey(probeCtx, target.Host, target.SSHPort)
		cancel()
		if err != nil {
			// No confirm: the node removes the rules by itself and reports reverted.
			d.config.Logger.Warn("SSH access not confirmed: the controller cannot reach sshd", "node_id", target.NodeID,
				"revision", target.Revision)
			return nil
		}
		return d.publish(ctx, target, contract.OperationConfirm, now)
	case AccessRepublishConfirm:
		return d.publish(ctx, target, contract.OperationConfirm, now)
	}
	return nil
}

func (d *AccessDelivery) publish(ctx context.Context, target AccessTarget, operation string, now time.Time) error {
	command := AccessCommand(target, operation, now)
	// Record first: a receipt never precedes its bookkeeping.
	if err := d.config.Store.MarkAccessPublished(ctx, target.NodeID, target.Revision, operation, now); err != nil {
		return err
	}
	return d.config.Transport.Publish(ctx, command)
}

// AccessCommand builds the carrier for target.
func AccessCommand(target AccessTarget, operation string, now time.Time) *agentv1.SSHAccessCommand {
	command := &agentv1.SSHAccessCommand{
		Event:  &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.New(now)},
		NodeId: target.NodeID.String(), Revision: uint64(target.Revision), Operation: operation,
	}
	if operation == contract.OperationApply {
		command.Enabled, command.SshPort = target.Enabled, uint32(target.SSHPort)
		if target.Enabled {
			command.Cidrs = append([]string(nil), target.CIDRs...)
		}
	}
	return command
}

func (d *AccessDelivery) consumeReceipts(ctx context.Context) {
	for ctx.Err() == nil {
		delivery, err := d.config.Transport.NextReceipt(ctx)
		if err != nil {
			if ctx.Err() == nil {
				natsready.LogUnbound(d.config.Logger, "SSH access receipts unavailable", err)
				select {
				case <-ctx.Done():
				case <-time.After(d.config.Interval):
				}
			}
			continue
		}
		if delivery != nil {
			d.HandleReceipt(ctx, delivery)
		}
	}
}

// HandleReceipt records one node answer and wakes the publisher (an applied
// revision is probed and confirmed at once).
func (d *AccessDelivery) HandleReceipt(ctx context.Context, delivery AccessReceiptDelivery) {
	receipt := delivery.Receipt()
	nodeID, err := uuid.Parse(receipt.GetNodeId())
	if err != nil || receipt.GetRevision() == 0 || !contract.ValidState(receipt.GetState()) ||
		!contract.ValidFailureCode(receipt.GetFailureCode()) {
		d.config.Logger.Warn("SSH access receipt dropped", "node_id", receipt.GetNodeId())
		_ = delivery.Ack(ctx)
		return
	}
	changed, err := d.config.Store.ReportAccess(ctx, nodeID, receipt)
	if err != nil {
		d.config.Logger.Warn("SSH access receipt not recorded yet", "node_id", nodeID, "error", err)
		_ = delivery.Nak(ctx)
		return
	}
	_ = delivery.Ack(ctx)
	if changed {
		d.Wake()
	}
}

// DueAccess reads the rows the worker acts on, with each node's online state
// and whether its newest session declared SSH_ACCESS v1.
func (service *Service) DueAccess(ctx context.Context, limit int) ([]AccessTarget, error) {
	rows, err := service.pool.Query(ctx, `SELECT access.node_id, COALESCE(host(node.ipv4), host(node.ipv6), ''), access.enabled,
			access.ssh_port, access.controller_cidrs, access.allow_cidrs, access.revision, access.state, access.published_revision,
			access.published_operation, access.published_at, access.applied_at, COALESCE(presence.status = 'online', false),
			(SELECT facts.capabilities_snapshot FROM node_session_capabilities facts WHERE facts.node_id = access.node_id
			 ORDER BY facts.session_epoch DESC LIMIT 1)
		FROM node_ssh_access access JOIN nodes node ON node.id = access.node_id
		LEFT JOIN node_presence presence ON presence.node_id = access.node_id
		WHERE access.state IN ('pending', 'applied') AND node.admin_state <> 'retired'
		ORDER BY access.updated_at, access.node_id LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	targets := []AccessTarget{}
	for rows.Next() {
		var target AccessTarget
		var controller, allow []string
		var snapshot []byte
		if err := rows.Scan(&target.NodeID, &target.Host, &target.Enabled, &target.SSHPort, &controller, &allow, &target.Revision,
			&target.State, &target.PublishedRevision, &target.PublishedOperation, &target.PublishedAt, &target.AppliedAt,
			&target.Online, &snapshot); err != nil {
			return nil, err
		}
		target.CIDRs, err = normalizeCIDRs(append(controller, allow...), contract.MaxCIDRs)
		if err != nil {
			return nil, err
		}
		target.Capable = AccessCapable(snapshot)
		targets = append(targets, target)
	}
	return targets, rows.Err()
}

// AccessCapable reports a session snapshot declaring SSH_ACCESS v1.
func AccessCapable(snapshot []byte) bool {
	var capabilities agentv1.AgentCapabilities
	if len(snapshot) == 0 || proto.Unmarshal(snapshot, &capabilities) != nil {
		return false
	}
	for _, capability := range capabilities.Features {
		if capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_SSH_ACCESS && capability.GetApiVersion() >= contract.APIVersion {
			return true
		}
	}
	return false
}

func (service *Service) MarkAccessPublished(ctx context.Context, nodeID uuid.UUID, revision int64, operation string, at time.Time) error {
	_, err := service.pool.Exec(ctx, `UPDATE node_ssh_access SET published_revision=$2, published_operation=$3, published_at=$4
		WHERE node_id=$1 AND revision=$2`, nodeID, revision, operation, at)
	return err
}

func (service *Service) FailAccess(ctx context.Context, nodeID uuid.UUID, revision int64, code string) error {
	_, err := service.pool.Exec(ctx, `UPDATE node_ssh_access SET state='failed', failure_code=$3, updated_at=$4
		WHERE node_id=$1 AND revision=$2 AND state IN ('pending', 'applied')`, nodeID, revision, code, service.now().UTC())
	return err
}

// ReportAccess applies a receipt of the current revision (older ones are
// acknowledged and ignored). changed: the row moved.
func (service *Service) ReportAccess(ctx context.Context, nodeID uuid.UUID, receipt *agentv1.SSHAccessReceipt) (bool, error) {
	changed := false
	err := pgx.BeginFunc(ctx, service.pool, func(tx pgx.Tx) error {
		var state string
		var enabled bool
		var scopeID uuid.UUID
		err := tx.QueryRow(ctx, `SELECT state, enabled, scope_id FROM node_ssh_access WHERE node_id=$1 AND revision=$2 FOR UPDATE`,
			nodeID, int64(receipt.GetRevision())).Scan(&state, &enabled, &scopeID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		update, ok := AccessReceiptTransition(state, enabled, receipt)
		if !ok {
			return nil
		}
		now := service.now().UTC()
		if _, err := tx.Exec(ctx, `UPDATE node_ssh_access SET state=$3, failure_code=$4,
				applied_at=CASE WHEN $5 THEN $7 ELSE applied_at END,
				confirmed_at=CASE WHEN $6 THEN $7 ELSE confirmed_at END, updated_at=$7
			WHERE node_id=$1 AND revision=$2`, nodeID, int64(receipt.GetRevision()), update.State, update.FailureCode,
			update.Applied, update.Confirmed, now); err != nil {
			return err
		}
		changed = true
		if update.State == AccessReverted || update.State == AccessFailed {
			return service.auditTx(ctx, tx, Actor{ScopeID: scopeID}, "node.ssh_access.update", "node", nodeID.String(), "failure",
				update.FailureCode, map[string]any{"revision": receipt.GetRevision(), "state": update.State})
		}
		return nil
	})
	return changed, err
}

// AccessNATS publishes commands to and consumes receipts from the streams
// agent-gateway owns (libs/edgeconfig/sshaccess names).
type AccessNATS struct {
	js       nats.JetStreamContext
	timeout  time.Duration
	mu       sync.Mutex
	receipts *nats.Subscription
}

func NewAccessNATS(connection *nats.Conn, timeout time.Duration) (*AccessNATS, error) {
	if connection == nil || connection.IsClosed() || timeout <= 0 {
		return nil, errors.New("SSH access NATS transport requires an active connection")
	}
	js, err := connection.JetStream(nats.MaxWait(timeout))
	if err != nil {
		return nil, err
	}
	return &AccessNATS{js: js, timeout: timeout}, nil
}

func (t *AccessNATS) Publish(ctx context.Context, command *agentv1.SSHAccessCommand) error {
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(command)
	if err != nil || len(payload) > contract.MaxCarrierBytes {
		return errors.New("encode SSH access command")
	}
	message := nats.NewMsg(contract.CommandSubjectPrefix + "." + command.NodeId)
	message.Data = payload
	message.Header.Set(nats.MsgIdHdr, command.Event.EventId)
	operation, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	ack, err := t.js.PublishMsg(message, nats.Context(operation), nats.ExpectStream(contract.CommandStream))
	if err != nil || ack == nil || ack.Stream != contract.CommandStream || ack.Sequence == 0 {
		return errors.Join(errors.New("persist SSH access command"), err)
	}
	return nil
}

func (t *AccessNATS) NextReceipt(ctx context.Context) (AccessReceiptDelivery, error) {
	subscription, err := t.subscription(ctx)
	if err != nil {
		return nil, err
	}
	operation, cancel := context.WithTimeout(ctx, t.timeout)
	messages, err := subscription.Fetch(1, nats.Context(operation))
	cancel()
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, nats.ErrTimeout) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(messages) != 1 {
		return nil, nil
	}
	message := messages[0]
	receipt := &agentv1.SSHAccessReceipt{}
	nodeID := strings.TrimPrefix(message.Subject, contract.ReceiptSubjectPrefix+".")
	if len(message.Data) > contract.MaxCarrierBytes || proto.Unmarshal(message.Data, receipt) != nil ||
		len(receipt.ProtoReflect().GetUnknown()) != 0 || receipt.NodeId != nodeID {
		_ = message.Term()
		return nil, nil
	}
	return &accessNATSReceipt{message: message, receipt: receipt}, nil
}

func (t *AccessNATS) subscription(ctx context.Context) (*nats.Subscription, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.receipts != nil {
		return t.receipts, nil
	}
	consumer := &nats.ConsumerConfig{Durable: contract.ReceiptConsumer, DeliverPolicy: nats.DeliverAllPolicy,
		AckPolicy: nats.AckExplicitPolicy, AckWait: 2 * time.Minute, MaxDeliver: -1,
		FilterSubject: contract.ReceiptSubjectPrefix + ".*", ReplayPolicy: nats.ReplayInstantPolicy,
		MaxAckPending: 64, MaxWaiting: 4, MaxRequestBatch: 1}
	operation, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	if _, err := t.js.ConsumerInfo(contract.ReceiptStream, contract.ReceiptConsumer, nats.Context(operation)); err != nil {
		if !errors.Is(err, nats.ErrConsumerNotFound) {
			return nil, err
		}
		if _, err := t.js.AddConsumer(contract.ReceiptStream, consumer, nats.Context(operation)); err != nil {
			return nil, err
		}
	}
	subscription, err := t.js.PullSubscribe(consumer.FilterSubject, contract.ReceiptConsumer,
		nats.Bind(contract.ReceiptStream, contract.ReceiptConsumer))
	if err != nil {
		return nil, err
	}
	t.receipts = subscription
	return subscription, nil
}

type accessNATSReceipt struct {
	message *nats.Msg
	receipt *agentv1.SSHAccessReceipt
}

func (r *accessNATSReceipt) Receipt() *agentv1.SSHAccessReceipt { return r.receipt }
func (r *accessNATSReceipt) Ack(ctx context.Context) error {
	return r.message.AckSync(nats.Context(ctx))
}
func (r *accessNATSReceipt) Nak(context.Context) error {
	return r.message.NakWithDelay(5 * time.Second)
}

var _ AccessStore = (*Service)(nil)
