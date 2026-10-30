package nodeporttransition

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

const (
	portTransitionCommandStream = "AGENT_COMMANDS"
	portTransitionStatusStream  = "AGENT_DEPLOYMENT_STATUS"
	portTransitionStatusPrefix  = "cdnca.agent.deployment-status.gateway-port"
	portTransitionConsumer      = "control_gateway_port_transitions"
)

type NATSRuntimeConfig struct {
	OperationTimeout time.Duration
	FetchTimeout     time.Duration
	ClaimLease       time.Duration
	PollInterval     time.Duration
	RetryDelay       time.Duration
	BatchSize        int
	MaxPayloadBytes  int
}

func DefaultNATSRuntimeConfig() NATSRuntimeConfig {
	return NATSRuntimeConfig{
		OperationTimeout: 5 * time.Second, FetchTimeout: 2 * time.Second, ClaimLease: 30 * time.Second,
		PollInterval: 500 * time.Millisecond, RetryDelay: time.Second, BatchSize: 32, MaxPayloadBytes: 1 << 20,
	}
}

type NATSRuntime struct {
	store      *PostgresStore
	service    *Service
	connection *nats.Conn
	js         nats.JetStreamContext
	statuses   *nats.Subscription
	config     NATSRuntimeConfig
	workerID   uuid.UUID
	now        func() time.Time
}

func NewNATSRuntime(store *PostgresStore, service *Service, connection *nats.Conn, config NATSRuntimeConfig, now func() time.Time) (*NATSRuntime, error) {
	if store == nil || service == nil || connection == nil || connection.IsClosed() || now == nil ||
		config.OperationTimeout <= 0 || config.FetchTimeout <= 0 || config.ClaimLease <= config.OperationTimeout ||
		config.PollInterval <= 0 || config.RetryDelay <= 0 || config.BatchSize < 1 || config.BatchSize > 128 ||
		config.MaxPayloadBytes < 1 || config.MaxPayloadBytes > 1<<20 {
		return nil, ErrInvalidInput
	}
	js, err := connection.JetStream(nats.MaxWait(config.OperationTimeout))
	if err != nil {
		return nil, fmt.Errorf("create gateway port transition JetStream context: %w", err)
	}
	consumer := &nats.ConsumerConfig{
		Durable: portTransitionConsumer, Name: portTransitionConsumer, DeliverPolicy: nats.DeliverAllPolicy,
		AckPolicy: nats.AckExplicitPolicy, AckWait: config.ClaimLease, MaxDeliver: -1,
		FilterSubject: portTransitionStatusPrefix + ".*", ReplayPolicy: nats.ReplayInstantPolicy,
		MaxAckPending: config.BatchSize, MaxWaiting: 16, MaxRequestBatch: 1, MaxRequestExpires: config.FetchTimeout,
		MaxRequestMaxBytes: config.MaxPayloadBytes,
	}
	opCtx, cancel := context.WithTimeout(context.Background(), config.OperationTimeout)
	_, err = js.AddConsumer(portTransitionStatusStream, consumer, nats.Context(opCtx))
	cancel()
	if err != nil {
		opCtx, cancel = context.WithTimeout(context.Background(), config.OperationTimeout)
		info, infoErr := js.ConsumerInfo(portTransitionStatusStream, portTransitionConsumer, nats.Context(opCtx))
		cancel()
		if infoErr != nil || !samePortTransitionConsumer(info, consumer) {
			return nil, fmt.Errorf("bind gateway port transition status consumer: %w", err)
		}
	}
	statuses, err := js.PullSubscribe(consumer.FilterSubject, consumer.Durable,
		nats.Bind(portTransitionStatusStream, consumer.Durable))
	if err != nil {
		return nil, fmt.Errorf("subscribe gateway port transition statuses: %w", err)
	}
	return &NATSRuntime{store: store, service: service, connection: connection, js: js, statuses: statuses,
		config: config, workerID: uuid.New(), now: now}, nil
}

func samePortTransitionConsumer(info *nats.ConsumerInfo, expected *nats.ConsumerConfig) bool {
	if info == nil || expected == nil {
		return false
	}
	actual := info.Config
	return info.Stream == portTransitionStatusStream && actual.Durable == expected.Durable && actual.Name == expected.Name &&
		actual.DeliverPolicy == expected.DeliverPolicy && actual.AckPolicy == expected.AckPolicy && actual.AckWait == expected.AckWait &&
		actual.MaxDeliver == expected.MaxDeliver && actual.FilterSubject == expected.FilterSubject && actual.ReplayPolicy == expected.ReplayPolicy &&
		actual.MaxAckPending == expected.MaxAckPending && actual.MaxWaiting == expected.MaxWaiting &&
		actual.MaxRequestBatch == expected.MaxRequestBatch && actual.MaxRequestExpires == expected.MaxRequestExpires &&
		actual.MaxRequestMaxBytes == expected.MaxRequestMaxBytes
}

func (runtime *NATSRuntime) Run(ctx context.Context) error {
	if runtime == nil || ctx == nil {
		return ErrInvalidInput
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errorsChannel := make(chan error, 2)
	go func() { errorsChannel <- runtime.runPublisher(ctx) }()
	go func() { errorsChannel <- runtime.runStatuses(ctx) }()
	err := <-errorsChannel
	cancel()
	<-errorsChannel
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func (runtime *NATSRuntime) Close() error {
	if runtime == nil {
		return nil
	}
	if runtime.statuses != nil {
		_ = runtime.statuses.Unsubscribe()
	}
	if runtime.connection == nil {
		return nil
	}
	if err := runtime.connection.Drain(); err != nil {
		runtime.connection.Close()
		return err
	}
	return nil
}

func (runtime *NATSRuntime) runPublisher(ctx context.Context) error {
	ticker := time.NewTicker(runtime.config.PollInterval)
	defer ticker.Stop()
	for {
		commands, err := runtime.store.ClaimCommands(ctx, runtime.workerID, runtime.config.BatchSize, runtime.config.ClaimLease)
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				continue
			}
		}
		for _, command := range commands {
			if err := runtime.publishCommand(ctx, command); err != nil && ctx.Err() == nil {
				if releaseErr := runtime.store.ReleaseCommand(ctx, command, runtime.now().Add(runtime.config.RetryDelay), "publish_outcome_unknown"); releaseErr != nil {
					// Retain the lease after an uncertain database write. The next claim
					// retries only after lease expiry and publishing uses a stable message ID.
					break
				}
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (runtime *NATSRuntime) publishCommand(ctx context.Context, command CommandOutbox) error {
	if command.Subject != portTransitionCommandSubjectPrefix+"."+command.NodeID.String() ||
		!strings.HasPrefix(command.MessageID, "node-port-transition-v1-") || len(command.Payload) == 0 ||
		len(command.Payload) > runtime.config.MaxPayloadBytes {
		return ErrConflict
	}
	message := nats.NewMsg(command.Subject)
	message.Data = append([]byte(nil), command.Payload...)
	message.Header.Set(nats.MsgIdHdr, command.MessageID)
	opCtx, cancel := context.WithTimeout(ctx, runtime.config.OperationTimeout)
	ack, err := runtime.js.PublishMsg(message, nats.Context(opCtx), nats.ExpectStream(portTransitionCommandStream))
	cancel()
	if err != nil {
		return err
	}
	if ack == nil || ack.Stream != portTransitionCommandStream || ack.Sequence == 0 {
		return ErrConflict
	}
	return runtime.store.MarkCommandPublished(ctx, command, ack.Stream, ack.Sequence)
}

func (runtime *NATSRuntime) runStatuses(ctx context.Context) error {
	for {
		fetchCtx, cancel := context.WithTimeout(ctx, runtime.config.FetchTimeout)
		messages, err := runtime.statuses.Fetch(1, nats.Context(fetchCtx))
		cancel()
		if ctx.Err() != nil {
			return nil
		}
		if errors.Is(err, nats.ErrTimeout) || errors.Is(err, context.DeadlineExceeded) {
			continue
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if len(messages) != 1 || messages[0] == nil {
			return ErrConflict
		}
		if err := runtime.applyStatus(ctx, messages[0]); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			// The database may have committed even if its acknowledgement was lost.
			// Replay the durable receipt after a bounded delay; never acknowledge uncertainty.
			_ = messages[0].NakWithDelay(runtime.config.RetryDelay)
			timer := time.NewTimer(runtime.config.RetryDelay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-timer.C:
			}
		}
	}
}

func (runtime *NATSRuntime) applyStatus(ctx context.Context, message *nats.Msg) error {
	metadata, err := message.Metadata()
	if err != nil || metadata.Stream != portTransitionStatusStream || metadata.Sequence.Stream == 0 ||
		!strings.HasPrefix(message.Subject, portTransitionStatusPrefix+".") || len(message.Data) == 0 ||
		len(message.Data) > runtime.config.MaxPayloadBytes {
		return message.Term()
	}
	status := new(agentv1.GatewayPortTransitionStatus)
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(message.Data, status); err != nil ||
		status.Schema != agentv1.GatewayPortTransitionSchema_GATEWAY_PORT_TRANSITION_SCHEMA_V1 ||
		status.Event == nil || status.Event.OccurredTime == nil || status.Event.OccurredTime.CheckValid() != nil ||
		message.Subject != fmt.Sprintf("%s.%s_%s_%d", portTransitionStatusPrefix,
			status.NodeId, status.TransitionId, status.StatusRevision) {
		return message.Term()
	}
	transitionID, transitionErr := uuid.Parse(status.TransitionId)
	nodeID, nodeErr := uuid.Parse(status.NodeId)
	eventID, eventErr := uuid.Parse(status.Event.EventId)
	state, stateErr := controlState(status.State)
	if transitionErr != nil || nodeErr != nil || eventErr != nil || stateErr != nil {
		return message.Term()
	}
	payloadSHA := sha256.Sum256(message.Data)
	report := StatusReport{PayloadSHA256: payloadSHA[:],
		TransitionID: transitionID, NodeID: nodeID, Revision: status.Revision, StatusRevision: status.StatusRevision,
		State: state, ActiveEndpoint: Endpoint{Address: status.GetActiveEndpoint().GetAddress(), ServerName: status.GetActiveEndpoint().GetServerName()},
		CertificateSHA256: status.CertificateSha256, ErrorCode: status.ErrorCode, EventID: eventID,
		PubAckStream: metadata.Stream, PubAckSequence: metadata.Sequence.Stream, ObservedAt: status.Event.OccurredTime.AsTime(),
	}
	if _, err := runtime.service.ApplyStatus(ctx, report); err != nil {
		if errors.Is(err, ErrInvalidInput) || errors.Is(err, ErrConflict) || errors.Is(err, ErrUnauthenticated) || errors.Is(err, ErrNotFound) {
			return message.Term()
		}
		return err
	}
	opCtx, cancel := context.WithTimeout(ctx, runtime.config.OperationTimeout)
	err = message.AckSync(nats.Context(opCtx))
	cancel()
	return err
}

func controlState(state agentv1.GatewayPortTransitionState) (State, error) {
	switch state {
	case agentv1.GatewayPortTransitionState_GATEWAY_PORT_TRANSITION_STATE_SWITCHED:
		return StateSwitched, nil
	case agentv1.GatewayPortTransitionState_GATEWAY_PORT_TRANSITION_STATE_FAILED:
		return StateFailed, nil
	case agentv1.GatewayPortTransitionState_GATEWAY_PORT_TRANSITION_STATE_ROLLED_BACK:
		return StateRolledBack, nil
	case agentv1.GatewayPortTransitionState_GATEWAY_PORT_TRANSITION_STATE_FINALIZED:
		return StateFinalized, nil
	default:
		return "", ErrInvalidInput
	}
}
