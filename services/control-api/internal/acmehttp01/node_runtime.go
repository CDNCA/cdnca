package acmehttp01

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

// NodeProvider is the production HTTP-01 provider: Publish returns once every
// target node serves the token (only then may the CA validate); Delete
// withdraws it from every node.
type NodeProvider struct {
	store       *NodeStore
	poll        time.Duration
	cleanupWait time.Duration
	logger      *slog.Logger
}

var _ acmeworker.HTTP01Provider = (*NodeProvider)(nil)

func NewNodeProvider(store *NodeStore, poll, cleanupWait time.Duration, logger *slog.Logger) (*NodeProvider, error) {
	if store == nil || poll <= 0 || poll > time.Minute || cleanupWait < 0 || cleanupWait > time.Minute {
		return nil, ErrInvalidConfig
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &NodeProvider{store: store, poll: poll, cleanupWait: cleanupWait, logger: logger}, nil
}

func (p *NodeProvider) Publish(ctx context.Context, challenge acmeworker.ChallengeIdentity) error {
	if err := p.store.PublishChallenge(ctx, challenge); err != nil {
		var unsupported *NodeUnsupportedError
		switch {
		case errors.As(err, &unsupported):
			p.logger.Warn("ACME HTTP-01 refused: target nodes lack the overlay capability",
				"operation_id", challenge.OperationID, "nodes", joinNodeIDs(unsupported.NodeIDs))
			return &acmeworker.Error{Code: acmeworker.CodeHTTP01NodeUnsupported}
		case errors.Is(err, ErrNoTarget), errors.Is(err, ErrInvalidChallenge):
			p.logger.Warn("ACME HTTP-01 refused: no serving node for the domain",
				"operation_id", challenge.OperationID, "domain", challenge.Identifier)
			return &acmeworker.Error{Code: acmeworker.CodeHTTP01NoServingNode}
		}
		return err
	}
	var last NodeChallengeStatus
	for {
		status, err := p.store.ChallengeStatus(ctx, challenge)
		if err != nil {
			if ctx.Err() != nil && len(last.Pending) != 0 {
				// The wait ended during the status read: same outcome as
				// ending between two reads.
				failure := &NodeDeliveryError{Pending: last.Pending}
				p.logger.Warn("ACME HTTP-01 token not confirmed in time", "operation_id", challenge.OperationID,
					"error", failure.Error())
				return failure
			}
			return err
		}
		last = status
		if status.Withdrawn {
			return ErrChallengeWithdrawn
		}
		if len(status.Pending) == 0 && len(status.Failed) == 0 {
			if len(status.Confirmed) == 0 {
				// Every target left the site's epoch: no node may serve the
				// token, the CA must not validate (no vacuous healthy).
				p.logger.Warn("ACME HTTP-01 token has no required node left", "operation_id", challenge.OperationID,
					"released", joinNodeIDs(status.Released))
				return &acmeworker.Error{Code: acmeworker.CodeHTTP01NoServingNode}
			}
			return nil
		}
		if len(status.Failed) != 0 {
			failure := &NodeDeliveryError{Failed: status.Failed, Pending: status.Pending}
			p.logger.Warn("ACME HTTP-01 token delivery failed", "operation_id", challenge.OperationID, "error", failure.Error())
			return failure
		}
		timer := time.NewTimer(p.poll)
		select {
		case <-ctx.Done():
			timer.Stop()
			failure := &NodeDeliveryError{Pending: status.Pending}
			p.logger.Warn("ACME HTTP-01 token not confirmed in time", "operation_id", challenge.OperationID,
				"error", failure.Error())
			return failure
		case <-timer.C:
		}
	}
}

// Delete records the withdrawal (the durable part: every node drops the token
// from its next generation, retried by the dispatcher and reconciler) and
// waits up to cleanupWait for the nodes to confirm. An offline node does not
// fail the issuance.
func (p *NodeProvider) Delete(ctx context.Context, challenge acmeworker.ChallengeIdentity) error {
	if err := p.store.WithdrawChallenge(ctx, challenge); err != nil {
		return err
	}
	if p.cleanupWait == 0 {
		return nil
	}
	waitCtx, cancel := context.WithTimeout(ctx, p.cleanupWait)
	defer cancel()
	for {
		removed, err := p.store.ChallengeRemoved(waitCtx, challenge)
		if removed {
			return nil
		}
		if waitCtx.Err() != nil {
			return ctx.Err() // nil when only the wait ended
		}
		if err != nil {
			return err
		}
		timer := time.NewTimer(p.poll)
		select {
		case <-waitCtx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// NodeDispatcher reconciles node deliveries and publishes claimed attempts to
// each node's command subject.
type NodeDispatcher struct {
	store     *NodeStore
	artifacts *NodeArtifactStore
	jetstream nats.JetStreamContext
	config    DispatcherConfig
	logger    *slog.Logger
}

func NewNodeDispatcher(store *NodeStore, artifacts *NodeArtifactStore, connection *nats.Conn,
	config DispatcherConfig, logger *slog.Logger) (*NodeDispatcher, error) {
	if store == nil || artifacts == nil || connection == nil || connection.IsClosed() ||
		!validNATSName(config.Stream) || config.BatchSize < 1 || config.BatchSize > 256 ||
		config.PollInterval <= 0 || config.OperationTimeout <= 0 {
		return nil, ErrInvalidConfig
	}
	jetstream, err := connection.JetStream(nats.MaxWait(config.OperationTimeout))
	if err != nil {
		return nil, ErrInvalidConfig
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &NodeDispatcher{store: store, artifacts: artifacts, jetstream: jetstream, config: config, logger: logger}, nil
}

func (d *NodeDispatcher) PublishBatch(ctx context.Context) (int, error) {
	if ctx == nil {
		return 0, ErrInvalidConfig
	}
	reconcileCtx, cancel := context.WithTimeout(ctx, d.config.OperationTimeout)
	_, err := d.store.Reconcile(reconcileCtx, d.config.BatchSize)
	cancel()
	if err != nil {
		return 0, err
	}
	claimCtx, cancel := context.WithTimeout(ctx, d.config.OperationTimeout)
	deliveries, err := d.store.ClaimDeliveries(claimCtx, d.config.BatchSize)
	cancel()
	if err != nil {
		return 0, err
	}
	for index, delivery := range deliveries {
		if err := d.publishOne(ctx, delivery); err != nil {
			return index, err
		}
	}
	return len(deliveries), nil
}

func (d *NodeDispatcher) publishOne(ctx context.Context, delivery NodeDelivery) error {
	command, err := d.artifacts.BuildCommand(ctx, delivery)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, ErrArtifactBinding) || errors.Is(err, ErrArtifactIntegrity) {
			d.logger.Error("ACME HTTP-01 node overlay artifact is inconsistent", "generation_id", delivery.GenerationID)
			return d.complete(delivery, false, false, "artifact_integrity")
		}
		return d.complete(delivery, false, true, "artifact_unavailable")
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(command)
	if err != nil {
		return d.complete(delivery, false, false, "command_encoding")
	}
	defer clear(payload)
	message := nats.NewMsg(commandSubjectPrefix + "." + delivery.NodeID.String())
	message.Data = payload
	message.Header.Set(nats.MsgIdHdr, command.Event.EventId)
	publishCtx, cancel := context.WithTimeout(ctx, d.config.OperationTimeout)
	acknowledgement, err := d.jetstream.PublishMsg(message, nats.Context(publishCtx), nats.ExpectStream(d.config.Stream))
	cancel()
	if err != nil || acknowledgement == nil || acknowledgement.Stream != d.config.Stream {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return d.complete(delivery, false, true, "publish_unavailable")
	}
	return d.complete(delivery, true, false, "")
}

func (d *NodeDispatcher) complete(delivery NodeDelivery, published, retryable bool, code string) error {
	ctx, cancel := context.WithTimeout(context.Background(), d.config.OperationTimeout)
	defer cancel()
	err := d.store.CompleteDelivery(ctx, delivery, published, retryable, code)
	if errors.Is(err, ErrLostClaim) {
		return nil
	}
	return err
}

func (d *NodeDispatcher) Run(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidConfig
	}
	for {
		count, err := d.PublishBatch(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			d.logger.Warn("ACME HTTP-01 node overlay dispatch failed", "error", err)
		}
		if count > 0 && err == nil {
			continue
		}
		timer := time.NewTimer(d.config.PollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// NodeStatusConsumer records agent overlay statuses against node deliveries.
type NodeStatusConsumer struct {
	store        *NodeStore
	subscription *nats.Subscription
	config       StatusConfig
	logger       *slog.Logger
}

// NewNodeStatusConsumer binds the durable status consumer, creating it when
// the installation's NATS profile predates it.
func NewNodeStatusConsumer(store *NodeStore, connection *nats.Conn, config StatusConfig, logger *slog.Logger) (*NodeStatusConsumer, error) {
	if store == nil || connection == nil || connection.IsClosed() ||
		!validNATSName(config.Stream) || !validNATSName(config.Durable) || !validSubjectPrefix(config.SubjectPrefix) ||
		config.AckWait <= 3*config.OperationTimeout || config.FetchTimeout <= 0 || config.OperationTimeout <= 0 ||
		config.NakDelay <= 0 || config.MaxAckPending <= 0 || config.MaxWaiting <= 0 || config.MaxBytes <= 0 {
		return nil, ErrInvalidConfig
	}
	jetstream, err := connection.JetStream(nats.MaxWait(config.OperationTimeout))
	if err != nil {
		return nil, ErrInvalidConfig
	}
	operationCtx, cancel := context.WithTimeout(context.Background(), config.OperationTimeout)
	defer cancel()
	info, err := jetstream.ConsumerInfo(config.Stream, config.Durable, nats.Context(operationCtx))
	if errors.Is(err, nats.ErrConsumerNotFound) {
		info, err = jetstream.AddConsumer(config.Stream, &nats.ConsumerConfig{
			Durable: config.Durable, FilterSubject: config.SubjectPrefix + ".*",
			DeliverPolicy: nats.DeliverAllPolicy, AckPolicy: nats.AckExplicitPolicy, AckWait: config.AckWait,
			MaxDeliver: -1, ReplayPolicy: nats.ReplayInstantPolicy, MaxAckPending: config.MaxAckPending,
			MaxWaiting: config.MaxWaiting, MaxRequestBatch: 1, MaxRequestExpires: config.FetchTimeout,
		}, nats.Context(operationCtx))
	}
	if err != nil || !sameOverlayStatusConsumer(info, config) {
		return nil, fmt.Errorf("%w: ACME HTTP-01 status consumer %s is missing or differs", ErrInvalidConfig, config.Durable)
	}
	subscription, err := jetstream.PullSubscribe(config.SubjectPrefix+".*", config.Durable, nats.Bind(config.Stream, config.Durable))
	if err != nil {
		return nil, ErrInvalidConfig
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &NodeStatusConsumer{store: store, subscription: subscription, config: config, logger: logger}, nil
}

func (c *NodeStatusConsumer) Run(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidConfig
	}
	for {
		fetchCtx, cancel := context.WithTimeout(ctx, c.config.FetchTimeout)
		messages, err := c.subscription.Fetch(1, nats.Context(fetchCtx))
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, nats.ErrTimeout) {
				// A NATS outage: the client reconnects; keep consuming.
				c.logger.Warn("ACME HTTP-01 node status fetch failed", "error", err)
				timer := time.NewTimer(c.config.NakDelay)
				select {
				case <-ctx.Done():
					timer.Stop()
					return ctx.Err()
				case <-timer.C:
				}
			}
			continue
		}
		for _, message := range messages {
			if err := c.process(ctx, message); err != nil && ctx.Err() != nil {
				return ctx.Err()
			}
		}
	}
}

func (c *NodeStatusConsumer) process(ctx context.Context, message *nats.Msg) error {
	status, nodeID, err := decodeOverlayStatus(message, c.config)
	if err != nil {
		return settle(message, c.config, "term")
	}
	receipt, record, err := nodeReceiptFor(nodeID, status)
	if err != nil {
		return settle(message, c.config, "term")
	}
	if record {
		operationCtx, cancel := context.WithTimeout(ctx, c.config.OperationTimeout)
		err = c.store.RecordReceipt(operationCtx, receipt)
		cancel()
		if errors.Is(err, ErrArtifactBinding) || errors.Is(err, ErrInvalidConfig) {
			return settle(message, c.config, "term")
		}
		if err != nil {
			c.logger.Warn("ACME HTTP-01 node receipt not recorded", "generation_id", receipt.GenerationID, "error", err)
			return settle(message, c.config, "nak")
		}
	}
	return settle(message, c.config, "ack")
}

// nodeReceiptFor validates the status identity a node command produced
// (deployment = version = generation id, derived event identities) and maps
// its state; delivered/staged/prechecked/reverting are progress only.
func nodeReceiptFor(nodeID uuid.UUID, status *agentv1.AcmeHTTP01OverlayStatus) (NodeReceipt, bool, error) {
	generationID, _ := canonicalUUID(status.OverlayDeploymentId)
	if status.OverlayVersionId != status.OverlayDeploymentId || status.Attempt > 1000 ||
		status.OverlayRevision > 9007199254740991 ||
		status.Event.CorrelationId != generationID.String() ||
		status.Event.RequestId != nodeRequestID(generationID).String() ||
		status.Event.GetCausationId() != nodeCommandEventID(generationID, int(status.Attempt)).String() {
		return NodeReceipt{}, false, ErrArtifactBinding
	}
	receipt := NodeReceipt{
		GenerationID: generationID, NodeID: nodeID, Generation: int64(status.OverlayRevision), Attempt: int(status.Attempt),
	}
	switch status.State {
	case agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_ACTIVATED,
		agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_HEALTHY:
		if status.GetActiveOverlayVersionId() != status.OverlayVersionId || status.ActiveOverlayRevision != status.OverlayRevision ||
			status.ActiveOverlayUnchanged {
			return NodeReceipt{}, false, ErrArtifactBinding
		}
		receipt.State = "applied"
		if status.State == agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_HEALTHY {
			receipt.State = "healthy"
		}
		return receipt, true, nil
	case agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_FAILED,
		agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_REVERTED,
		agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_ROLLBACK_FAILED:
		receipt.State, receipt.FailureCode, receipt.ActiveRevision = "failed", overlayFailureCode(status.ResultCode), status.ActiveOverlayRevision
		return receipt, true, nil
	}
	return receipt, false, nil
}

func settle(message *nats.Msg, config StatusConfig, action string) error {
	ctx, cancel := context.WithTimeout(context.Background(), config.OperationTimeout)
	defer cancel()
	switch action {
	case "ack":
		return message.AckSync(nats.Context(ctx))
	case "nak":
		return message.NakWithDelay(config.NakDelay, nats.Context(ctx))
	default:
		return message.Term(nats.Context(ctx))
	}
}

func (c *NodeStatusConsumer) Close() error {
	if c == nil || c.subscription == nil {
		return nil
	}
	return c.subscription.Unsubscribe()
}

// NodeRuntime runs the node overlay dispatcher and status consumer on one
// NATS connection.
type NodeRuntime struct {
	dispatcher *NodeDispatcher
	status     *NodeStatusConsumer
	connection *nats.Conn
	closeOnce  sync.Once
	closeErr   error
	active     atomic.Bool
}

func NewNodeRuntime(dispatcher *NodeDispatcher, status *NodeStatusConsumer, connection *nats.Conn) (*NodeRuntime, error) {
	if dispatcher == nil || status == nil || connection == nil || connection.IsClosed() {
		return nil, ErrInvalidConfig
	}
	return &NodeRuntime{dispatcher: dispatcher, status: status, connection: connection}, nil
}

func (r *NodeRuntime) Run(ctx context.Context) error {
	if ctx == nil || !r.active.CompareAndSwap(false, true) {
		return errors.New("ACME HTTP-01 node overlay runtime is not runnable")
	}
	defer r.active.Store(false)
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, 2)
	go func() { results <- r.dispatcher.Run(runCtx) }()
	go func() { results <- r.status.Run(runCtx) }()
	first := <-results
	cancel()
	<-results
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if first == nil || errors.Is(first, context.Canceled) {
		return errors.New("ACME HTTP-01 node overlay runtime stopped unexpectedly")
	}
	return first
}

func (r *NodeRuntime) Ready() error {
	if r == nil || !r.active.Load() || r.connection == nil || !r.connection.IsConnected() {
		return errors.New("ACME HTTP-01 node overlay runtime is not ready")
	}
	return nil
}

func (r *NodeRuntime) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		r.active.Store(false)
		r.closeErr = r.status.Close()
		if !r.connection.IsClosed() {
			if err := r.connection.Drain(); err != nil && r.closeErr == nil {
				r.closeErr = err
			}
			r.connection.Close()
		}
	})
	return r.closeErr
}
