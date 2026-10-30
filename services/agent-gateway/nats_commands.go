package gateway

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

type NATSCommandBusConfig struct {
	CommandStream                      string
	StatusStream                       string
	FirewallCommandStream              string
	FirewallStatusStream               string
	HeartbeatStream                    string
	CommandSubjectPrefix               string
	StatusSubjectPrefix                string
	FirewallCommandSubjectPrefix       string
	FirewallStatusSubjectPrefix        string
	DrainCommandSubjectPrefix          string
	DrainStatusSubjectPrefix           string
	PortTransitionCommandSubjectPrefix string
	PortTransitionStatusSubjectPrefix  string
	OverlayCommandSubjectPrefix        string
	OverlayStatusSubjectPrefix         string
	HeartbeatSubjectPrefix             string
	ConsumerPrefix                     string
	FirewallConsumerPrefix             string
	DrainConsumerPrefix                string
	PortTransitionConsumerPrefix       string
	OverlayConsumerPrefix              string
	MaxCommandBytes                    int
	MaxStatusBytes                     int
	MaxFirewallCommandBytes            int
	MaxFirewallStatusBytes             int
	MaxDrainCommandBytes               int
	MaxDrainStatusBytes                int
	MaxPortTransitionCommandBytes      int
	MaxPortTransitionStatusBytes       int
	MaxHeartbeatBytes                  int
	MaxAckPending                      int
	MaxWaiting                         int
	AckWait                            time.Duration
	OperationTimeout                   time.Duration
}

func DefaultNATSCommandBusConfig() NATSCommandBusConfig {
	return NATSCommandBusConfig{
		CommandStream:                      "AGENT_COMMANDS",
		StatusStream:                       "AGENT_DEPLOYMENT_STATUS",
		FirewallCommandStream:              "AGENT_FIREWALL_COMMANDS",
		FirewallStatusStream:               "AGENT_FIREWALL_STATUS",
		HeartbeatStream:                    "AGENT_HEARTBEATS",
		CommandSubjectPrefix:               "cdnca.agent.commands",
		StatusSubjectPrefix:                "cdnca.agent.deployment-status",
		FirewallCommandSubjectPrefix:       "cdnca.agent.firewall.commands",
		FirewallStatusSubjectPrefix:        "cdnca.agent.firewall.status",
		DrainCommandSubjectPrefix:          "cdnca.agent.commands.drain",
		DrainStatusSubjectPrefix:           "cdnca.agent.deployment-status.drain",
		PortTransitionCommandSubjectPrefix: "cdnca.agent.commands.gateway-port",
		PortTransitionStatusSubjectPrefix:  "cdnca.agent.deployment-status.gateway-port",
		OverlayCommandSubjectPrefix:        "cdnca.agent.commands.acme-http01",
		OverlayStatusSubjectPrefix:         "cdnca.agent.deployment-status.acme-http01",
		HeartbeatSubjectPrefix:             "cdnca.agent.heartbeats",
		ConsumerPrefix:                     "node",
		FirewallConsumerPrefix:             "firewall",
		DrainConsumerPrefix:                "drain",
		PortTransitionConsumerPrefix:       "gateway_port",
		OverlayConsumerPrefix:              "node_acme_http01",
		MaxCommandBytes:                    defaultMaxMessageBytes,
		MaxStatusBytes:                     defaultMaxMessageBytes,
		MaxFirewallCommandBytes:            defaultMaxMessageBytes,
		MaxFirewallStatusBytes:             defaultMaxMessageBytes,
		MaxDrainCommandBytes:               defaultMaxMessageBytes,
		MaxDrainStatusBytes:                defaultMaxMessageBytes,
		MaxPortTransitionCommandBytes:      defaultMaxMessageBytes,
		MaxPortTransitionStatusBytes:       defaultMaxMessageBytes,
		MaxHeartbeatBytes:                  defaultMaxMessageBytes,
		MaxAckPending:                      defaultMaxPendingCommands,
		MaxWaiting:                         32,
		AckWait:                            2 * time.Minute,
		OperationTimeout:                   5 * time.Second,
	}
}

func (c NATSCommandBusConfig) validate() error {
	if !validNATSName(c.CommandStream) || !validNATSName(c.StatusStream) || !validNATSName(c.FirewallCommandStream) ||
		!validNATSName(c.FirewallStatusStream) || !validNATSName(c.HeartbeatStream) ||
		!validNATSName(c.ConsumerPrefix) || !validNATSName(c.FirewallConsumerPrefix) || !validNATSName(c.DrainConsumerPrefix) ||
		!validNATSName(c.PortTransitionConsumerPrefix) || !validNATSName(c.OverlayConsumerPrefix) {
		return fmt.Errorf("NATS stream and consumer names must contain only letters, digits, dash, or underscore")
	}
	if !validSubjectPrefix(c.CommandSubjectPrefix) || !validSubjectPrefix(c.StatusSubjectPrefix) ||
		!validSubjectPrefix(c.FirewallCommandSubjectPrefix) || !validSubjectPrefix(c.FirewallStatusSubjectPrefix) ||
		!validSubjectPrefix(c.DrainCommandSubjectPrefix) || !validSubjectPrefix(c.DrainStatusSubjectPrefix) ||
		!validSubjectPrefix(c.PortTransitionCommandSubjectPrefix) || !validSubjectPrefix(c.PortTransitionStatusSubjectPrefix) ||
		!validSubjectPrefix(c.OverlayCommandSubjectPrefix) || !validSubjectPrefix(c.OverlayStatusSubjectPrefix) ||
		!validSubjectPrefix(c.HeartbeatSubjectPrefix) {
		return fmt.Errorf("NATS subject prefixes must contain only literal tokens")
	}
	if c.OverlayCommandSubjectPrefix == c.CommandSubjectPrefix || c.OverlayStatusSubjectPrefix == c.StatusSubjectPrefix ||
		c.FirewallCommandSubjectPrefix == c.CommandSubjectPrefix || c.FirewallStatusSubjectPrefix == c.StatusSubjectPrefix ||
		c.FirewallCommandSubjectPrefix == c.OverlayCommandSubjectPrefix || c.FirewallStatusSubjectPrefix == c.OverlayStatusSubjectPrefix ||
		c.DrainCommandSubjectPrefix == c.CommandSubjectPrefix || c.DrainCommandSubjectPrefix == c.OverlayCommandSubjectPrefix ||
		c.DrainStatusSubjectPrefix == c.StatusSubjectPrefix || c.DrainStatusSubjectPrefix == c.OverlayStatusSubjectPrefix ||
		c.PortTransitionCommandSubjectPrefix == c.CommandSubjectPrefix || c.PortTransitionCommandSubjectPrefix == c.OverlayCommandSubjectPrefix ||
		c.PortTransitionCommandSubjectPrefix == c.DrainCommandSubjectPrefix ||
		c.PortTransitionStatusSubjectPrefix == c.StatusSubjectPrefix || c.PortTransitionStatusSubjectPrefix == c.OverlayStatusSubjectPrefix ||
		c.PortTransitionStatusSubjectPrefix == c.DrainStatusSubjectPrefix {
		return fmt.Errorf("overlay and ordinary NATS subject prefixes must be distinct")
	}
	if c.MaxCommandBytes <= 0 || c.MaxStatusBytes <= 0 || c.MaxFirewallCommandBytes <= 0 || c.MaxFirewallStatusBytes <= 0 ||
		c.MaxDrainCommandBytes <= 0 || c.MaxDrainStatusBytes <= 0 || c.MaxPortTransitionCommandBytes <= 0 || c.MaxPortTransitionStatusBytes <= 0 ||
		c.MaxHeartbeatBytes <= 0 || c.MaxAckPending <= 0 || c.MaxWaiting <= 0 || c.AckWait <= 0 || c.OperationTimeout <= 0 {
		return fmt.Errorf("NATS command limits and durations must be positive")
	}
	return nil
}

func validNATSName(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' || char == '_' {
			continue
		}
		return false
	}
	return true
}

func validSubjectPrefix(value string) bool {
	if value == "" || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, token := range strings.Split(value, ".") {
		if !validNATSName(token) {
			return false
		}
	}
	return true
}

type NATSCommandBus struct {
	js                nats.JetStreamContext
	config            NATSCommandBusConfig
	correlationHealth *CorrelationHealth
}

func NewNATSCommandBus(connection *nats.Conn, config NATSCommandBusConfig) (*NATSCommandBus, error) {
	if connection == nil || connection.IsClosed() {
		return nil, fmt.Errorf("an active NATS connection is required")
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	js, err := connection.JetStream(nats.MaxWait(config.OperationTimeout))
	if err != nil {
		return nil, fmt.Errorf("create JetStream context: %w", err)
	}
	return &NATSCommandBus{js: js, config: config, correlationHealth: NewCorrelationHealth()}, nil
}

func (b *NATSCommandBus) CorrelationHealth() *CorrelationHealth {
	if b == nil {
		return nil
	}
	return b.correlationHealth
}

func (b *NATSCommandBus) Subscribe(ctx context.Context, nodeID string) (CommandSubscription, error) {
	if ctx == nil {
		return nil, fmt.Errorf("command subscription context is required")
	}
	parsed, err := uuid.Parse(nodeID)
	if err != nil || parsed.String() != nodeID {
		return nil, fmt.Errorf("node ID must be a canonical UUID")
	}
	subject := b.config.CommandSubjectPrefix + "." + nodeID
	durable := b.config.ConsumerPrefix + "_" + strings.ReplaceAll(nodeID, "-", "_")
	consumer := &nats.ConsumerConfig{
		Durable:           durable,
		DeliverPolicy:     nats.DeliverAllPolicy,
		AckPolicy:         nats.AckExplicitPolicy,
		AckWait:           b.config.AckWait,
		MaxDeliver:        -1,
		FilterSubject:     subject,
		ReplayPolicy:      nats.ReplayInstantPolicy,
		MaxWaiting:        b.config.MaxWaiting,
		MaxAckPending:     b.config.MaxAckPending,
		MaxRequestBatch:   1,
		MaxRequestExpires: b.config.OperationTimeout,
	}
	operationCtx, cancel := context.WithTimeout(ctx, b.config.OperationTimeout)
	_, err = b.js.AddConsumer(b.config.CommandStream, consumer, nats.Context(operationCtx))
	cancel()
	if err != nil {
		operationCtx, cancel = context.WithTimeout(ctx, b.config.OperationTimeout)
		info, infoErr := b.js.ConsumerInfo(b.config.CommandStream, durable, nats.Context(operationCtx))
		cancel()
		if infoErr != nil || !sameConsumerConfig(info, consumer) {
			return nil, fmt.Errorf("bind durable node command consumer: %w", err)
		}
	}
	subscription, err := b.js.PullSubscribe(subject, durable, nats.Bind(b.config.CommandStream, durable))
	if err != nil {
		return nil, fmt.Errorf("subscribe to durable node commands: %w", err)
	}
	return &natsCommandSubscription{
		subscription: subscription, maxCommandBytes: b.config.MaxCommandBytes,
		fetchTimeout: b.config.OperationTimeout, operationTimeout: b.config.OperationTimeout,
	}, nil
}

func firewallCommandSubject(config NATSCommandBusConfig, nodeID string) string {
	return config.FirewallCommandSubjectPrefix + "." + nodeID
}

func firewallStatusSubject(config NATSCommandBusConfig, nodeID, taskID string, commandSHA256 []byte) string {
	return config.FirewallStatusSubjectPrefix + "." + nodeID + "." + taskID + "." + hex.EncodeToString(commandSHA256)
}

func (b *NATSCommandBus) SubscribeFirewall(ctx context.Context, nodeID string) (FirewallCommandSubscription, error) {
	if ctx == nil {
		return nil, fmt.Errorf("firewall command subscription context is required")
	}
	parsed, err := uuid.Parse(nodeID)
	if err != nil || parsed == uuid.Nil || parsed.String() != nodeID {
		return nil, fmt.Errorf("firewall node ID must be a canonical UUID")
	}
	subject := firewallCommandSubject(b.config, nodeID)
	durable := b.config.FirewallConsumerPrefix + "_" + strings.ReplaceAll(nodeID, "-", "_")
	consumer := &nats.ConsumerConfig{
		Durable: durable, DeliverPolicy: nats.DeliverAllPolicy, AckPolicy: nats.AckExplicitPolicy,
		AckWait: b.config.AckWait, MaxDeliver: -1, FilterSubject: subject,
		ReplayPolicy: nats.ReplayInstantPolicy, MaxWaiting: b.config.MaxWaiting,
		MaxAckPending: b.config.MaxAckPending, MaxRequestBatch: 1,
		MaxRequestExpires: b.config.OperationTimeout,
	}
	operationCtx, cancel := context.WithTimeout(ctx, b.config.OperationTimeout)
	_, err = b.js.AddConsumer(b.config.FirewallCommandStream, consumer, nats.Context(operationCtx))
	cancel()
	if err != nil {
		operationCtx, cancel = context.WithTimeout(ctx, b.config.OperationTimeout)
		info, infoErr := b.js.ConsumerInfo(b.config.FirewallCommandStream, durable, nats.Context(operationCtx))
		cancel()
		if infoErr != nil || !sameConsumerConfig(info, consumer) {
			return nil, fmt.Errorf("bind durable firewall command consumer: %w", err)
		}
	}
	subscription, err := b.js.PullSubscribe(subject, durable, nats.Bind(b.config.FirewallCommandStream, durable))
	if err != nil {
		return nil, fmt.Errorf("subscribe to durable firewall commands: %w", err)
	}
	return &natsFirewallCommandSubscription{subscription: subscription,
		maxCommandBytes: b.config.MaxFirewallCommandBytes, fetchTimeout: b.config.OperationTimeout,
		operationTimeout: b.config.OperationTimeout}, nil
}

func sameConsumerConfig(info *nats.ConsumerInfo, expected *nats.ConsumerConfig) bool {
	if info == nil {
		return false
	}
	actual := info.Config
	return actual.Durable == expected.Durable &&
		actual.DeliverPolicy == expected.DeliverPolicy &&
		actual.AckPolicy == expected.AckPolicy &&
		actual.AckWait == expected.AckWait &&
		actual.MaxDeliver == expected.MaxDeliver &&
		actual.FilterSubject == expected.FilterSubject &&
		actual.ReplayPolicy == expected.ReplayPolicy &&
		actual.MaxWaiting == expected.MaxWaiting &&
		actual.MaxAckPending == expected.MaxAckPending &&
		actual.MaxRequestBatch == expected.MaxRequestBatch &&
		actual.MaxRequestExpires == expected.MaxRequestExpires
}

func (b *NATSCommandBus) PublishStatus(ctx context.Context, nodeID string,
	status *agentv1.DeploymentStatus,
) (DeploymentStatusPublication, error) {
	if ctx == nil {
		return DeploymentStatusPublication{}, fmt.Errorf("status publication context is required")
	}
	parsed, err := uuid.Parse(nodeID)
	if err != nil || parsed == uuid.Nil || parsed.String() != nodeID {
		return DeploymentStatusPublication{}, fmt.Errorf("node ID must be a canonical UUID")
	}
	if err := validateDeploymentStatusCorrelation(status); err != nil {
		b.correlationHealth.RecordRejected()
		return DeploymentStatusPublication{}, err
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(status)
	if err != nil {
		return DeploymentStatusPublication{}, fmt.Errorf("marshal deployment status: %w", err)
	}
	if len(payload) > b.config.MaxStatusBytes {
		return DeploymentStatusPublication{}, fmt.Errorf("deployment status exceeds its size limit")
	}
	subject := b.config.StatusSubjectPrefix + ".generic-v2." + nodeID + "." + status.Event.EventId
	if publication, found, err := b.loadDeploymentStatusPublication(ctx, subject, status.Event.EventId, payload); err != nil {
		return DeploymentStatusPublication{}, err
	} else if found {
		b.correlationHealth.RecordReplayed()
		return publication, nil
	}
	message := nats.NewMsg(subject)
	message.Data = payload
	message.Header = deploymentStatusCorrelationHeaders(status, b.config)
	operationCtx, cancel := context.WithTimeout(ctx, b.config.OperationTimeout)
	ack, err := b.js.PublishMsg(message, nats.Context(operationCtx), nats.ExpectStream(b.config.StatusStream),
		nats.ExpectLastSequencePerSubject(0))
	cancel()
	if err != nil {
		if publication, found, loadErr := b.loadDeploymentStatusPublication(ctx, subject, status.Event.EventId, payload); loadErr != nil {
			return DeploymentStatusPublication{}, loadErr
		} else if found {
			b.correlationHealth.RecordReplayed()
			return publication, nil
		}
		b.correlationHealth.RecordPublishFailed()
		return DeploymentStatusPublication{}, fmt.Errorf("publish deployment status: %w", err)
	}
	if ack == nil || ack.Stream != b.config.StatusStream || ack.Sequence == 0 {
		b.correlationHealth.RecordPublishFailed()
		return DeploymentStatusPublication{}, fmt.Errorf("publish deployment status returned an invalid acknowledgement")
	}
	publication, found, readErr := b.loadDeploymentStatusPublication(ctx, subject, status.Event.EventId, payload)
	if readErr != nil || !found || publication.Stream != ack.Stream || publication.Sequence != ack.Sequence {
		b.correlationHealth.RecordPublishFailed()
		return DeploymentStatusPublication{}, fmt.Errorf("publish deployment status acknowledgement does not match durable state")
	}
	b.correlationHealth.RecordAccepted()
	switch status.State {
	case agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTED:
		b.correlationHealth.RecordTerminalSucceeded()
	case agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ROLLBACK_FAILED:
		b.correlationHealth.RecordTerminalFailed()
	}
	return publication, nil
}

const (
	deploymentStatusRequestIDHeader     = "Cdnca-Request-Id"
	deploymentStatusTaskIDHeader        = "Cdnca-Task-Id"
	deploymentStatusTraceparentHeader   = "traceparent"
	deploymentStatusCorrelationIDHeader = "Cdnca-Correlation-Id"
)

func validateDeploymentStatusCorrelation(status *agentv1.DeploymentStatus) error {
	if status == nil || status.Event == nil || proto.Size(status.Event) > defaultMaxMetadataBytes ||
		!canonicalUUID(status.Event.EventId) || !canonicalUUID(status.Event.RequestId) ||
		len(status.Event.Traceparent) > defaultMaxIdentifierBytes ||
		len(status.Event.CorrelationId) > defaultMaxIdentifierBytes ||
		(status.Event.TaskId != nil && status.Event.GetTaskId() == "") ||
		len(status.Event.GetTaskId()) > defaultMaxIdentifierBytes {
		return fmt.Errorf("deployment status correlation metadata is invalid")
	}
	return nil
}

func deploymentStatusCorrelationHeaders(status *agentv1.DeploymentStatus, config NATSCommandBusConfig) nats.Header {
	header := nats.Header{}
	header.Set(nats.MsgIdHdr, status.Event.EventId)
	header.Set(deploymentStatusRequestIDHeader, status.Event.RequestId)
	header.Set(deploymentStatusTraceparentHeader, status.Event.Traceparent)
	header.Set(deploymentStatusCorrelationIDHeader, status.Event.CorrelationId)
	if status.Event.GetTaskId() != "" {
		header.Set(deploymentStatusTaskIDHeader, status.Event.GetTaskId())
	}
	header.Set(nats.ExpectedStreamHdr, config.StatusStream)
	header.Set(nats.ExpectedLastSubjSeqHdr, "0")
	return header
}

func (b *NATSCommandBus) PublishFirewallStatus(ctx context.Context, nodeID string,
	status *agentv1.FirewallStatus,
) (FirewallStatusPublication, error) {
	if ctx == nil {
		return FirewallStatusPublication{}, fmt.Errorf("firewall status publication context is required")
	}
	if err := validateFirewallStatusEnvelope(status, nodeID); err != nil {
		return FirewallStatusPublication{}, err
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(status)
	if err != nil {
		return FirewallStatusPublication{}, fmt.Errorf("marshal firewall status: %w", err)
	}
	if len(payload) > b.config.MaxFirewallStatusBytes {
		return FirewallStatusPublication{}, fmt.Errorf("firewall status exceeds its size limit")
	}
	subject := firewallStatusSubject(b.config, nodeID, status.TaskId, status.CommandSha256)
	if publication, found, err := b.loadFirewallStatusPublication(ctx, subject, payload); err != nil {
		return FirewallStatusPublication{}, err
	} else if found {
		return FirewallStatusPublication{Stream: publication.Stream, Sequence: publication.Sequence, Replayed: true}, nil
	}
	message := nats.NewMsg(subject)
	message.Data = payload
	message.Header.Set(nats.MsgIdHdr, hex.EncodeToString(status.CommandSha256))
	operationCtx, cancel := context.WithTimeout(ctx, b.config.OperationTimeout)
	ack, err := b.js.PublishMsg(message, nats.Context(operationCtx), nats.ExpectStream(b.config.FirewallStatusStream),
		nats.ExpectLastSequencePerSubject(0))
	cancel()
	if err != nil {
		if publication, found, loadErr := b.loadFirewallStatusPublication(ctx, subject, payload); loadErr != nil {
			return FirewallStatusPublication{}, loadErr
		} else if found {
			return FirewallStatusPublication{Stream: publication.Stream, Sequence: publication.Sequence, Replayed: true}, nil
		}
		return FirewallStatusPublication{}, fmt.Errorf("publish firewall status: %w", err)
	}
	if ack == nil || ack.Stream != b.config.FirewallStatusStream || ack.Sequence == 0 {
		return FirewallStatusPublication{}, fmt.Errorf("publish firewall status returned an invalid acknowledgement")
	}
	return FirewallStatusPublication{Stream: ack.Stream, Sequence: ack.Sequence}, nil
}

func (b *NATSCommandBus) loadFirewallStatusPublication(ctx context.Context, subject string, payload []byte) (DeploymentStatusPublication, bool, error) {
	operationCtx, cancel := context.WithTimeout(ctx, b.config.OperationTimeout)
	message, err := b.js.GetLastMsg(b.config.FirewallStatusStream, subject, nats.Context(operationCtx))
	cancel()
	if errors.Is(err, nats.ErrMsgNotFound) {
		return DeploymentStatusPublication{}, false, nil
	}
	if err != nil {
		return DeploymentStatusPublication{}, false, fmt.Errorf("load firewall status publication: %w", err)
	}
	var persisted, candidate agentv1.FirewallStatus
	if message == nil || message.Subject != subject || message.Sequence == 0 ||
		(proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(message.Data, &persisted) != nil ||
		(proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(payload, &candidate) != nil ||
		validateFirewallStatusEnvelope(&persisted, candidate.NodeId) != nil ||
		validateFirewallStatusEnvelope(&candidate, candidate.NodeId) != nil ||
		!firewallStatusEqual(&persisted, &candidate) {
		return DeploymentStatusPublication{}, false, fmt.Errorf("firewall status conflicts with durable state")
	}
	return DeploymentStatusPublication{Stream: b.config.FirewallStatusStream, Sequence: message.Sequence}, true, nil
}

func (b *NATSCommandBus) loadDeploymentStatusPublication(ctx context.Context, subject, eventID string,
	payload []byte,
) (DeploymentStatusPublication, bool, error) {
	operationCtx, cancel := context.WithTimeout(ctx, b.config.OperationTimeout)
	message, err := b.js.GetLastMsg(b.config.StatusStream, subject, nats.Context(operationCtx))
	cancel()
	if errors.Is(err, nats.ErrMsgNotFound) {
		return DeploymentStatusPublication{}, false, nil
	}
	if err != nil {
		b.correlationHealth.RecordPublishFailed()
		return DeploymentStatusPublication{}, false, fmt.Errorf("load deployment status publication: %w", err)
	}
	if message == nil || message.Subject != subject || message.Sequence == 0 ||
		!bytes.Equal(message.Data, payload) || !b.exactDeploymentStatusHeaders(message.Header, eventID, payload) {
		b.correlationHealth.RecordRejected()
		return DeploymentStatusPublication{}, false, fmt.Errorf("deployment status event conflicts with durable state")
	}
	return DeploymentStatusPublication{Stream: b.config.StatusStream, Sequence: message.Sequence}, true, nil
}

func (b *NATSCommandBus) exactDeploymentStatusHeaders(header nats.Header, eventID string, payload []byte) bool {
	var status agentv1.DeploymentStatus
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(payload, &status); err != nil ||
		validateDeploymentStatusCorrelation(&status) != nil || status.Event.EventId != eventID {
		return false
	}
	expected := deploymentStatusCorrelationHeaders(&status, b.config)
	allowed := map[string]bool{
		nats.MsgIdHdr: true, deploymentStatusRequestIDHeader: true,
		deploymentStatusTraceparentHeader: true, deploymentStatusCorrelationIDHeader: true, deploymentStatusTaskIDHeader: true,
		nats.ExpectedStreamHdr: true, nats.ExpectedLastSubjSeqHdr: true,
	}
	for key := range header {
		if !allowed[key] {
			return false
		}
	}
	for _, key := range []string{nats.MsgIdHdr, deploymentStatusRequestIDHeader,
		deploymentStatusTraceparentHeader, deploymentStatusCorrelationIDHeader, deploymentStatusTaskIDHeader,
		nats.ExpectedStreamHdr, nats.ExpectedLastSubjSeqHdr} {
		actualValues, expectedValues := header.Values(key), expected.Values(key)
		if len(actualValues) != len(expectedValues) {
			return false
		}
		for index := range actualValues {
			if actualValues[index] != expectedValues[index] {
				return false
			}
		}
	}
	return true
}

func (b *NATSCommandBus) SubscribeOverlay(ctx context.Context, nodeID string) (OverlayCommandSubscription, error) {
	if ctx == nil {
		return nil, fmt.Errorf("overlay command subscription context is required")
	}
	parsed, err := uuid.Parse(nodeID)
	if err != nil || parsed.String() != nodeID {
		return nil, fmt.Errorf("node ID must be a canonical UUID")
	}
	subject := b.config.OverlayCommandSubjectPrefix + "." + nodeID
	durable := b.config.OverlayConsumerPrefix + "_" + strings.ReplaceAll(nodeID, "-", "_")
	consumer := &nats.ConsumerConfig{
		Durable: durable, DeliverPolicy: nats.DeliverAllPolicy, AckPolicy: nats.AckExplicitPolicy,
		AckWait: b.config.AckWait, MaxDeliver: -1, FilterSubject: subject,
		ReplayPolicy: nats.ReplayInstantPolicy, MaxWaiting: b.config.MaxWaiting,
		MaxAckPending: b.config.MaxAckPending, MaxRequestBatch: 1,
		MaxRequestExpires: b.config.OperationTimeout,
	}
	operationCtx, cancel := context.WithTimeout(ctx, b.config.OperationTimeout)
	_, err = b.js.AddConsumer(b.config.CommandStream, consumer, nats.Context(operationCtx))
	cancel()
	if err != nil {
		operationCtx, cancel = context.WithTimeout(ctx, b.config.OperationTimeout)
		info, infoErr := b.js.ConsumerInfo(b.config.CommandStream, durable, nats.Context(operationCtx))
		cancel()
		if infoErr != nil || !sameConsumerConfig(info, consumer) {
			return nil, fmt.Errorf("bind durable node overlay command consumer: %w", err)
		}
	}
	subscription, err := b.js.PullSubscribe(subject, durable, nats.Bind(b.config.CommandStream, durable))
	if err != nil {
		return nil, fmt.Errorf("subscribe to durable node overlay commands: %w", err)
	}
	return &natsOverlayCommandSubscription{
		subscription: subscription, maxCommandBytes: b.config.MaxCommandBytes,
		fetchTimeout: b.config.OperationTimeout, operationTimeout: b.config.OperationTimeout,
	}, nil
}

func (b *NATSCommandBus) PublishOverlayStatus(ctx context.Context, nodeID string, status *agentv1.AcmeHTTP01OverlayStatus) error {
	if ctx == nil {
		return fmt.Errorf("overlay status publication context is required")
	}
	parsed, err := uuid.Parse(nodeID)
	if err != nil || parsed.String() != nodeID {
		return fmt.Errorf("node ID must be a canonical UUID")
	}
	if status == nil || status.Event == nil || status.Event.EventId == "" {
		return fmt.Errorf("overlay status event ID is required")
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(status)
	if err != nil {
		return fmt.Errorf("marshal overlay status: %w", err)
	}
	if len(payload) > b.config.MaxStatusBytes {
		return fmt.Errorf("overlay status exceeds its size limit")
	}
	message := nats.NewMsg(b.config.OverlayStatusSubjectPrefix + "." + nodeID)
	message.Data = payload
	message.Header.Set(nats.MsgIdHdr, status.Event.EventId)
	operationCtx, cancel := context.WithTimeout(ctx, b.config.OperationTimeout)
	defer cancel()
	if _, err := b.js.PublishMsg(message, nats.Context(operationCtx), nats.ExpectStream(b.config.StatusStream)); err != nil {
		return fmt.Errorf("publish overlay status: %w", err)
	}
	return nil
}

type natsCommandSubscription struct {
	subscription     *nats.Subscription
	maxCommandBytes  int
	fetchTimeout     time.Duration
	operationTimeout time.Duration
}

func (s *natsCommandSubscription) Next(ctx context.Context) (CommandDelivery, error) {
	var messages []*nats.Msg
	for {
		fetchCtx, cancel := context.WithTimeout(ctx, s.fetchTimeout)
		var err error
		messages, err = s.subscription.Fetch(1, nats.Context(fetchCtx))
		cancel()
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, nats.ErrTimeout) {
			continue
		}
		return nil, err
	}
	if len(messages) != 1 {
		return nil, fmt.Errorf("pull consumer returned an unexpected command batch")
	}
	message := messages[0]
	delivery := &natsCommandDelivery{message: message}
	if len(message.Data) == 0 || len(message.Data) > s.maxCommandBytes {
		nakCtx, cancel := context.WithTimeout(context.Background(), s.operationTimeout)
		_ = delivery.Nak(nakCtx)
		cancel()
		return nil, fmt.Errorf("command payload is missing or exceeds its size limit")
	}
	command := new(agentv1.DeploymentCommand)
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(message.Data, command); err != nil {
		nakCtx, cancel := context.WithTimeout(context.Background(), s.operationTimeout)
		_ = delivery.Nak(nakCtx)
		cancel()
		return nil, fmt.Errorf("decode deployment command: %w", err)
	}
	delivery.command = command
	return delivery, nil
}

func (s *natsCommandSubscription) Close() error {
	return s.subscription.Unsubscribe()
}

type natsCommandDelivery struct {
	message *nats.Msg
	command *agentv1.DeploymentCommand
}

type natsOverlayCommandSubscription struct {
	subscription     *nats.Subscription
	maxCommandBytes  int
	fetchTimeout     time.Duration
	operationTimeout time.Duration
}

func (s *natsOverlayCommandSubscription) Next(ctx context.Context) (OverlayCommandDelivery, error) {
	for {
		fetchCtx, cancel := context.WithTimeout(ctx, s.fetchTimeout)
		messages, err := s.subscription.Fetch(1, nats.Context(fetchCtx))
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, nats.ErrTimeout) {
				continue
			}
			return nil, err
		}
		if len(messages) != 1 {
			return nil, fmt.Errorf("pull consumer returned an unexpected overlay command batch")
		}
		delivery := &natsOverlayCommandDelivery{message: messages[0]}
		if len(messages[0].Data) == 0 || len(messages[0].Data) > s.maxCommandBytes {
			nakCtx, cancel := context.WithTimeout(context.Background(), s.operationTimeout)
			_ = delivery.Nak(nakCtx)
			cancel()
			return nil, fmt.Errorf("overlay command payload is missing or exceeds its size limit")
		}
		command := new(agentv1.AcmeHTTP01OverlayCommand)
		if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(messages[0].Data, command); err != nil {
			nakCtx, cancel := context.WithTimeout(context.Background(), s.operationTimeout)
			_ = delivery.Nak(nakCtx)
			cancel()
			return nil, fmt.Errorf("decode overlay command: %w", err)
		}
		delivery.command = command
		return delivery, nil
	}
}

func (s *natsOverlayCommandSubscription) Close() error { return s.subscription.Unsubscribe() }

type natsOverlayCommandDelivery struct {
	message *nats.Msg
	command *agentv1.AcmeHTTP01OverlayCommand
}

func (d *natsOverlayCommandDelivery) Command() *agentv1.AcmeHTTP01OverlayCommand { return d.command }

func (d *natsOverlayCommandDelivery) Ack(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("overlay command acknowledgement context is required")
	}
	if err := d.message.AckSync(nats.Context(ctx)); err != nil {
		return fmt.Errorf("acknowledge overlay command: %w", err)
	}
	return nil
}

func (d *natsOverlayCommandDelivery) Nak(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("overlay command negative acknowledgement context is required")
	}
	if err := d.message.Nak(nats.Context(ctx)); err != nil && !errors.Is(err, nats.ErrMsgAlreadyAckd) {
		return fmt.Errorf("negative acknowledge overlay command: %w", err)
	}
	return nil
}

func (d *natsCommandDelivery) Command() *agentv1.DeploymentCommand {
	return d.command
}

func (d *natsCommandDelivery) Ack(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("command acknowledgement context is required")
	}
	if err := d.message.AckSync(nats.Context(ctx)); err != nil {
		return fmt.Errorf("acknowledge deployment command: %w", err)
	}
	return nil
}

func (d *natsCommandDelivery) Nak(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("command negative acknowledgement context is required")
	}
	if err := d.message.Nak(nats.Context(ctx)); err != nil && !errors.Is(err, nats.ErrMsgAlreadyAckd) {
		return fmt.Errorf("negative acknowledge deployment command: %w", err)
	}
	return nil
}

type natsFirewallCommandSubscription struct {
	subscription     *nats.Subscription
	maxCommandBytes  int
	fetchTimeout     time.Duration
	operationTimeout time.Duration
}

func (s *natsFirewallCommandSubscription) Next(ctx context.Context) (FirewallCommandDelivery, error) {
	for {
		fetchCtx, cancel := context.WithTimeout(ctx, s.fetchTimeout)
		messages, err := s.subscription.Fetch(1, nats.Context(fetchCtx))
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, nats.ErrTimeout) {
				continue
			}
			return nil, err
		}
		if len(messages) != 1 {
			return nil, fmt.Errorf("pull consumer returned an unexpected firewall command batch")
		}
		message := messages[0]
		delivery := &natsFirewallCommandDelivery{message: message}
		if len(message.Data) == 0 || len(message.Data) > s.maxCommandBytes {
			nakCtx, cancel := context.WithTimeout(context.Background(), s.operationTimeout)
			_ = delivery.Nak(nakCtx)
			cancel()
			return nil, fmt.Errorf("firewall command payload is missing or exceeds its size limit")
		}
		command := new(agentv1.FirewallCommand)
		if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(message.Data, command); err != nil {
			nakCtx, cancel := context.WithTimeout(context.Background(), s.operationTimeout)
			_ = delivery.Nak(nakCtx)
			cancel()
			return nil, fmt.Errorf("decode firewall command: %w", err)
		}
		delivery.command = command
		return delivery, nil
	}
}

func (s *natsFirewallCommandSubscription) Close() error { return s.subscription.Unsubscribe() }

type natsFirewallCommandDelivery struct {
	message *nats.Msg
	command *agentv1.FirewallCommand
}

func (d *natsFirewallCommandDelivery) Command() *agentv1.FirewallCommand { return d.command }

func (d *natsFirewallCommandDelivery) Ack(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("firewall command acknowledgement context is required")
	}
	if err := d.message.AckSync(nats.Context(ctx)); err != nil && !errors.Is(err, nats.ErrMsgAlreadyAckd) {
		return fmt.Errorf("acknowledge firewall command: %w", err)
	}
	return nil
}

func (d *natsFirewallCommandDelivery) Nak(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("firewall command negative acknowledgement context is required")
	}
	if err := d.message.Nak(nats.Context(ctx)); err != nil && !errors.Is(err, nats.ErrMsgAlreadyAckd) {
		return fmt.Errorf("negative acknowledge firewall command: %w", err)
	}
	return nil
}
