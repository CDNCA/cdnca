package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/sched302"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/nats-io/nats.go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// HTTP 302 scheduling tables (CAPABILITY_NAME_SCHED302 v1):
// control-api publishes the newest signed table per node to JetStream; one
// durable pull consumer per node delivers it on the node's Connect session.
// A table is acknowledged as soon as it was written to the session (no
// receipt: a newer table supersedes it and control-api resends an unchanged
// one well within the node's hold). The Agent verifies the signature.

type Sched302Bus interface {
	SubscribeSched302(context.Context, string) (Sched302Subscription, error)
}

type Sched302Subscription interface {
	Next(context.Context) (Sched302Delivery, error)
	Close() error
}

type Sched302Delivery interface {
	Table() *agentv1.Sched302Table
	Ack(context.Context) error
	Term() error
}

func (g *Gateway) ConfigureSched302(bus Sched302Bus) error {
	if g == nil || bus == nil || g.sched302 != nil {
		return fmt.Errorf("schedule302 bus is invalid or already configured")
	}
	g.sched302 = bus
	return nil
}

func sched302CapabilityFromFeatures(features []*agentv1.Capability) bool {
	for _, capability := range features {
		if capability != nil && capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_SCHED302 &&
			capability.ApiVersion == sched302.APIVersion {
			return true
		}
	}
	return false
}

type sched302Receive struct {
	delivery Sched302Delivery
	err      error
}

type sessionSched302 struct {
	ctx          context.Context
	cancel       context.CancelFunc
	subscription Sched302Subscription
	next         chan sched302Receive
}

func (g *Gateway) startSessionSched302(ctx context.Context, nodeID string) (*sessionSched302, error) {
	sourceContext, cancel := context.WithCancel(ctx)
	subscription, err := g.sched302.SubscribeSched302(sourceContext, nodeID)
	if err != nil {
		cancel()
		return nil, status.Error(codes.Unavailable, "could not subscribe to schedule302 tables")
	}
	return &sessionSched302{ctx: sourceContext, cancel: cancel, subscription: subscription}, nil
}

func (session *sessionSched302) receive() <-chan sched302Receive {
	if session == nil {
		return nil
	}
	if session.next == nil {
		next := make(chan sched302Receive, 1)
		session.next = next
		go func() {
			delivery, err := session.subscription.Next(session.ctx)
			next <- sched302Receive{delivery: delivery, err: err}
		}()
	}
	return session.next
}

func (session *sessionSched302) stop() {
	if session == nil {
		return
	}
	session.cancel()
	_ = session.subscription.Close()
}

func validateSched302Table(table *agentv1.Sched302Table, nodeID string) error {
	if table == nil || proto.Size(table) > sched302.MaxCarrierBytes || cacheControlMessageHasUnknown(table.ProtoReflect()) ||
		table.Schema != agentv1.Sched302Schema_SCHED302_SCHEMA_V1 || table.NodeId != nodeID || table.Revision == 0 ||
		len(table.TableSha256) != sha256.Size || len(table.Signature) == 0 || table.SigningKeyId == "" ||
		table.SignatureAlgorithm != agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519 ||
		table.Event == nil || !canonicalUUID(table.Event.EventId) || !canonicalUUID(table.Event.RequestId) ||
		table.Event.OccurredTime == nil || table.Event.OccurredTime.CheckValid() != nil {
		return fmt.Errorf("schedule302 table is invalid")
	}
	digest := sha256.Sum256(table.TableJson)
	if !bytes.Equal(digest[:], table.TableSha256) {
		return fmt.Errorf("schedule302 table digest is invalid")
	}
	decoded, err := sched302.Decode(table.TableJson)
	if err != nil || decoded.NodeID != nodeID || decoded.Revision != table.Revision {
		return fmt.Errorf("schedule302 table binding is invalid")
	}
	return nil
}

// NATSSched302Bus is the JetStream side (the gateway owns the stream).
type NATSSched302Bus struct {
	js      nats.JetStreamContext
	timeout time.Duration
}

// Sched302StreamConfig keeps the newest table per node for a day.
func Sched302StreamConfig() *nats.StreamConfig {
	return &nats.StreamConfig{Name: sched302.CommandStream, Subjects: []string{sched302.CommandSubjectPrefix + ".*"},
		Retention: nats.WorkQueuePolicy, MaxMsgsPerSubject: 1, Discard: nats.DiscardOld, MaxAge: 24 * time.Hour,
		MaxMsgSize: int32(sched302.MaxCarrierBytes), Storage: nats.FileStorage, Replicas: 1, Duplicates: 2 * time.Minute}
}

func NewNATSSched302Bus(ctx context.Context, connection *nats.Conn, timeout time.Duration) (*NATSSched302Bus, error) {
	if ctx == nil || connection == nil || connection.IsClosed() || timeout <= 0 {
		return nil, fmt.Errorf("an active NATS connection is required")
	}
	js, err := connection.JetStream(nats.MaxWait(timeout))
	if err != nil {
		return nil, err
	}
	expected := Sched302StreamConfig()
	op, cancel := context.WithTimeout(ctx, timeout)
	info, err := js.StreamInfo(expected.Name, nats.Context(op))
	if errors.Is(err, nats.ErrStreamNotFound) {
		info, err = js.AddStream(expected, nats.Context(op))
	}
	cancel()
	if err != nil {
		return nil, fmt.Errorf("ensure schedule302 stream: %w", err)
	}
	if len(info.Config.Subjects) != 1 || info.Config.Subjects[0] != expected.Subjects[0] ||
		info.Config.Retention != expected.Retention || max(info.Config.MaxMsgsPerSubject, 0) != expected.MaxMsgsPerSubject {
		return nil, fmt.Errorf("schedule302 stream configuration does not match")
	}
	return &NATSSched302Bus{js: js, timeout: timeout}, nil
}

func (bus *NATSSched302Bus) SubscribeSched302(ctx context.Context, nodeID string) (Sched302Subscription, error) {
	if bus == nil || ctx == nil || !validNodeMonitoringNodeID(nodeID) {
		return nil, fmt.Errorf("invalid schedule302 subscription")
	}
	subject := sched302.CommandSubjectPrefix + "." + nodeID
	durable := sched302.GatewayConsumerPrefix + "_" + strings.ReplaceAll(nodeID, "-", "_")
	consumer := &nats.ConsumerConfig{Durable: durable, DeliverPolicy: nats.DeliverAllPolicy,
		AckPolicy: nats.AckExplicitPolicy, AckWait: 30 * time.Second, MaxDeliver: -1,
		FilterSubject: subject, ReplayPolicy: nats.ReplayInstantPolicy,
		MaxAckPending: 1, MaxWaiting: 1, MaxRequestBatch: 1, MaxRequestExpires: bus.timeout}
	op, cancel := context.WithTimeout(ctx, bus.timeout)
	_, err := bus.js.AddConsumer(sched302.CommandStream, consumer, nats.Context(op))
	cancel()
	if err != nil {
		op, cancel = context.WithTimeout(ctx, bus.timeout)
		info, infoErr := bus.js.ConsumerInfo(sched302.CommandStream, durable, nats.Context(op))
		cancel()
		if infoErr != nil || !sameConsumerConfig(info, consumer) {
			return nil, fmt.Errorf("bind durable schedule302 consumer: %w", err)
		}
	}
	subscription, err := bus.js.PullSubscribe(subject, durable, nats.Bind(sched302.CommandStream, durable))
	if err != nil {
		return nil, fmt.Errorf("subscribe to schedule302 tables: %w", err)
	}
	return &natsSched302Subscription{subscription: subscription, timeout: bus.timeout}, nil
}

type natsSched302Subscription struct {
	subscription *nats.Subscription
	timeout      time.Duration
}

func (subscription *natsSched302Subscription) Next(ctx context.Context) (Sched302Delivery, error) {
	for {
		fetchContext, cancel := context.WithTimeout(ctx, subscription.timeout)
		messages, err := subscription.subscription.Fetch(1, nats.Context(fetchContext))
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
			return nil, fmt.Errorf("schedule302 delivery returned %d messages", len(messages))
		}
		table := &agentv1.Sched302Table{}
		if len(messages[0].Data) == 0 || len(messages[0].Data) > sched302.MaxCarrierBytes ||
			proto.Unmarshal(messages[0].Data, table) != nil || cacheControlMessageHasUnknown(table.ProtoReflect()) {
			_ = messages[0].Term()
			continue
		}
		return &natsSched302Delivery{message: messages[0], table: table}, nil
	}
}

func (subscription *natsSched302Subscription) Close() error {
	if subscription == nil || subscription.subscription == nil {
		return nil
	}
	return subscription.subscription.Unsubscribe()
}

type natsSched302Delivery struct {
	message *nats.Msg
	table   *agentv1.Sched302Table
}

func (delivery *natsSched302Delivery) Table() *agentv1.Sched302Table {
	return proto.Clone(delivery.table).(*agentv1.Sched302Table)
}

func (delivery *natsSched302Delivery) Ack(ctx context.Context) error {
	return delivery.message.AckSync(nats.Context(ctx))
}

func (delivery *natsSched302Delivery) Term() error { return delivery.message.Term() }
