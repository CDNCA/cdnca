package securityban

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	contract "github.com/cdnca/cdnca/libs/edgeconfig/securityban"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// NATSTransport publishes snapshots to and consumes receipts from the
// streams agent-gateway owns (libs/edgeconfig/securityban names). Until the
// gateway has created them every call fails and the distributor retries.
type NATSTransport struct {
	js       nats.JetStreamContext
	timeout  time.Duration
	mu       sync.Mutex
	receipts *nats.Subscription
}

func NewNATSTransport(connection *nats.Conn, timeout time.Duration) (*NATSTransport, error) {
	if connection == nil || connection.IsClosed() || timeout <= 0 {
		return nil, errors.New("security ban NATS transport requires an active connection")
	}
	js, err := connection.JetStream(nats.MaxWait(timeout))
	if err != nil {
		return nil, err
	}
	return &NATSTransport{js: js, timeout: timeout}, nil
}

func (transport *NATSTransport) PublishList(ctx context.Context, nodeID string, revision uint64, encoded []byte) error {
	routeNode, routeRevision, err := contract.Route(encoded)
	if err != nil || routeNode != nodeID || routeRevision != revision {
		return fmt.Errorf("security ban list does not belong to %s", nodeID)
	}
	eventID := uuid.NewString()
	carrier := &agentv1.SecurityBanCommand{
		Event:  &commonv1.EventMetadata{EventId: eventID, RequestId: uuid.NewString(), OccurredTime: timestamppb.Now()},
		NodeId: nodeID, Revision: revision, ListJson: encoded, ListSha256: contract.Digest(encoded),
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(carrier)
	if err != nil || len(payload) > contract.MaxCarrierBytes {
		return errors.New("encode security ban command")
	}
	message := nats.NewMsg(contract.CommandSubjectPrefix + "." + nodeID)
	message.Data = payload
	message.Header.Set(nats.MsgIdHdr, eventID)
	operation, cancel := context.WithTimeout(ctx, transport.timeout)
	defer cancel()
	ack, err := transport.js.PublishMsg(message, nats.Context(operation), nats.ExpectStream(contract.CommandStream))
	if err != nil || ack == nil || ack.Stream != contract.CommandStream || ack.Sequence == 0 {
		return fmt.Errorf("persist security ban command: %w", err)
	}
	return nil
}

func (transport *NATSTransport) NextReceipt(ctx context.Context) (ReceiptDelivery, error) {
	subscription, err := transport.receiptSubscription(ctx)
	if err != nil {
		return nil, err
	}
	operation, cancel := context.WithTimeout(ctx, transport.timeout)
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
	report := &agentv1.SecurityBanStatus{}
	nodeID := strings.TrimPrefix(message.Subject, contract.StatusSubjectPrefix+".")
	if len(message.Data) > contract.MaxCarrierBytes || proto.Unmarshal(message.Data, report) != nil ||
		len(report.ProtoReflect().GetUnknown()) != 0 || report.NodeId != nodeID {
		// The gateway validated it before publishing; anything else can never be recorded.
		_ = message.Term()
		return nil, nil
	}
	return &natsReceipt{message: message, report: report}, nil
}

func (transport *NATSTransport) receiptSubscription(ctx context.Context) (*nats.Subscription, error) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.receipts != nil {
		return transport.receipts, nil
	}
	consumer := &nats.ConsumerConfig{Durable: contract.ReceiptConsumer, DeliverPolicy: nats.DeliverAllPolicy,
		AckPolicy: nats.AckExplicitPolicy, AckWait: 2 * time.Minute, MaxDeliver: -1,
		FilterSubject: contract.StatusSubjectPrefix + ".*", ReplayPolicy: nats.ReplayInstantPolicy,
		MaxAckPending: 64, MaxWaiting: 4, MaxRequestBatch: 1}
	operation, cancel := context.WithTimeout(ctx, transport.timeout)
	defer cancel()
	if _, err := transport.js.ConsumerInfo(contract.StatusStream, contract.ReceiptConsumer, nats.Context(operation)); err != nil {
		if !errors.Is(err, nats.ErrConsumerNotFound) {
			return nil, fmt.Errorf("security ban receipt consumer: %w", err)
		}
		if _, err := transport.js.AddConsumer(contract.StatusStream, consumer, nats.Context(operation)); err != nil {
			return nil, fmt.Errorf("create security ban receipt consumer: %w", err)
		}
	}
	subscription, err := transport.js.PullSubscribe(consumer.FilterSubject, contract.ReceiptConsumer,
		nats.Bind(contract.StatusStream, contract.ReceiptConsumer))
	if err != nil {
		return nil, fmt.Errorf("subscribe to security ban receipts: %w", err)
	}
	transport.receipts = subscription
	return subscription, nil
}

type natsReceipt struct {
	message *nats.Msg
	report  *agentv1.SecurityBanStatus
}

func (receipt *natsReceipt) Status() *agentv1.SecurityBanStatus { return receipt.report }
func (receipt *natsReceipt) Ack(ctx context.Context) error {
	return receipt.message.AckSync(nats.Context(ctx))
}
func (receipt *natsReceipt) Nak(context.Context) error {
	return receipt.message.NakWithDelay(5 * time.Second)
}
