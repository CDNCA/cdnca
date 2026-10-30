package nodegatewayaddr

import (
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	contract "github.com/cdnca/cdnca/libs/edgeconfig/gatewayaddr"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Transport carries documents to agent-gateway and receipts back.
type Transport interface {
	Publish(ctx context.Context, nodeID string, revision uint64, encoded []byte) error
	// NextReceipt waits up to the poll timeout; (nil, nil) when nothing arrived.
	NextReceipt(ctx context.Context) (ReceiptDelivery, error)
}

type ReceiptDelivery interface {
	Receipt() *agentv1.GatewayAddressChangeReceipt
	Ack(context.Context) error
	Nak(context.Context) error
}

// DistributorStore is what the distributor needs from Store.
type DistributorStore interface {
	Due(ctx context.Context, republishBefore time.Time, limit int) ([]PendingDocument, error)
	MarkPublished(ctx context.Context, document PendingDocument, digest []byte, issuedAt time.Time) error
	MarkExpired(ctx context.Context, document PendingDocument) error
	Report(ctx context.Context, report Report) (bool, error)
}

type DistributorConfig struct {
	Store     DistributorStore
	Transport Transport
	KeyID     string
	Sign      func(context.Context, []byte) ([]byte, error)
	Interval  time.Duration
	// RepublishAfter republishes a delivered, unanswered document (default 10
	// minutes); the stream keeps it anyway, this covers a lost stream.
	RepublishAfter time.Duration
	Logger         *slog.Logger
	Now            func() time.Time
}

type Distributor struct {
	config DistributorConfig
	wake   chan struct{}
	once   sync.Once
}

func NewDistributor(config DistributorConfig) (*Distributor, error) {
	if config.Store == nil || config.Transport == nil || config.KeyID == "" || config.Sign == nil || config.Interval <= 0 {
		return nil, errors.New("gateway address distributor configuration is incomplete")
	}
	if config.RepublishAfter <= 0 {
		config.RepublishAfter = 10 * time.Minute
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Distributor{config: config, wake: make(chan struct{}, 1)}, nil
}

// Wake runs a pass soon (a change was created or retried).
func (d *Distributor) Wake() {
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

func (d *Distributor) Run(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.consumeReceipts(ctx)
	}()
	ticker := time.NewTicker(d.config.Interval)
	defer ticker.Stop()
	for {
		if err := d.PublishOnce(ctx); err != nil && ctx.Err() == nil {
			d.config.Logger.Warn("gateway address changes not published", "error", err)
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

// PublishOnce signs and publishes due documents. A delivered row whose
// document lifetime ran out is failed (undelivered: the node stayed away).
func (d *Distributor) PublishOnce(ctx context.Context) error {
	now := d.config.Now().UTC()
	due, err := d.config.Store.Due(ctx, now.Add(-d.config.RepublishAfter), 500)
	if err != nil {
		return err
	}
	for _, document := range due {
		if document.State == StateDelivered && document.Published != nil && !now.Before(document.Published.Add(DocumentLifetime)) {
			if err := d.config.Store.MarkExpired(ctx, document); err != nil {
				return err
			}
			continue
		}
		if err := d.publish(ctx, document, now); err != nil {
			return err
		}
	}
	return nil
}

func (d *Distributor) publish(ctx context.Context, document PendingDocument, now time.Time) error {
	issued := now.Truncate(time.Second)
	if document.Published != nil {
		issued = document.Published.UTC().Truncate(time.Second) // same bytes as the first publication
	}
	change := contract.Change{Schema: contract.Schema, NodeID: document.NodeID.String(), ChangeID: document.ChangeID.String(),
		Revision: document.Revision, Address: document.Address, ServerName: document.ServerName,
		IssuedAt: issued.Unix(), ExpiresAt: issued.Add(DocumentLifetime).Unix(), Algorithm: contract.Algorithm, KeyID: d.config.KeyID}
	payload, err := contract.SigningPayload(change)
	if err != nil {
		return err
	}
	signature, err := d.config.Sign(ctx, payload)
	if err != nil {
		return err
	}
	encoded, err := contract.Seal(change, signature)
	if err != nil {
		return err
	}
	// Record first: the receipt matches the digest stored here.
	if err := d.config.Store.MarkPublished(ctx, document, contract.Digest(encoded), issued); err != nil {
		return err
	}
	if err := d.config.Transport.Publish(ctx, document.NodeID.String(), document.Revision, encoded); err != nil {
		return err
	}
	d.config.Logger.Info("gateway address change published", "node_id", document.NodeID, "revision", document.Revision)
	return nil
}

func (d *Distributor) consumeReceipts(ctx context.Context) {
	for ctx.Err() == nil {
		delivery, err := d.config.Transport.NextReceipt(ctx)
		if err != nil {
			if ctx.Err() == nil {
				d.config.Logger.Warn("gateway address change receipts unavailable", "error", err)
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

var receiptStates = map[string]bool{contract.StateProbing: true, contract.StateSwitched: true, contract.StateFailed: true}

// HandleReceipt records one node answer.
func (d *Distributor) HandleReceipt(ctx context.Context, delivery ReceiptDelivery) {
	receipt := delivery.Receipt()
	nodeID, err := uuid.Parse(receipt.GetNodeId())
	if err != nil || receipt.GetRevision() == 0 || len(receipt.GetDocumentSha256()) != sha256.Size ||
		!receiptStates[receipt.GetState()] || (receipt.GetState() == contract.StateFailed) != (receipt.GetErrorCode() != "") ||
		!validErrorCode(receipt.GetErrorCode()) || len(receipt.GetActiveAddress()) > 255 {
		d.config.Logger.Warn("gateway address change receipt dropped", "node_id", receipt.GetNodeId())
		_ = delivery.Ack(ctx)
		return
	}
	if _, err := d.config.Store.Report(ctx, Report{NodeID: nodeID, Revision: receipt.GetRevision(),
		DocumentSHA256: receipt.GetDocumentSha256(), State: receipt.GetState(), ErrorCode: receipt.GetErrorCode(),
		ActiveAddress: receipt.GetActiveAddress()}); err != nil {
		d.config.Logger.Warn("gateway address change receipt not recorded yet", "node_id", nodeID, "error", err)
		_ = delivery.Nak(ctx)
		return
	}
	_ = delivery.Ack(ctx)
}

// NATS publishes documents to and consumes receipts from the streams
// agent-gateway owns (libs/edgeconfig/gatewayaddr names).
type NATS struct {
	js       nats.JetStreamContext
	timeout  time.Duration
	mu       sync.Mutex
	receipts *nats.Subscription
}

func NewNATS(connection *nats.Conn, timeout time.Duration) (*NATS, error) {
	if connection == nil || connection.IsClosed() || timeout <= 0 {
		return nil, errors.New("gateway address NATS transport requires an active connection")
	}
	js, err := connection.JetStream(nats.MaxWait(timeout))
	if err != nil {
		return nil, err
	}
	return &NATS{js: js, timeout: timeout}, nil
}

// Carrier wraps a document for one node.
func Carrier(nodeID string, revision uint64, encoded []byte) (*agentv1.GatewayAddressChangeCommand, error) {
	routeNode, routeRevision, err := contract.Route(encoded)
	if err != nil || routeNode != nodeID || routeRevision != revision {
		return nil, errors.New("gateway address change document does not belong to the node")
	}
	return &agentv1.GatewayAddressChangeCommand{
		Event:  &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now()},
		NodeId: nodeID, Revision: revision, DocumentJson: encoded, DocumentSha256: contract.Digest(encoded),
	}, nil
}

func (t *NATS) Publish(ctx context.Context, nodeID string, revision uint64, encoded []byte) error {
	carrier, err := Carrier(nodeID, revision, encoded)
	if err != nil {
		return err
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(carrier)
	if err != nil || len(payload) > contract.MaxCarrierBytes {
		return errors.New("encode gateway address change command")
	}
	message := nats.NewMsg(contract.CommandSubjectPrefix + "." + nodeID)
	message.Data = payload
	message.Header.Set(nats.MsgIdHdr, carrier.Event.EventId)
	operation, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	ack, err := t.js.PublishMsg(message, nats.Context(operation), nats.ExpectStream(contract.CommandStream))
	if err != nil || ack == nil || ack.Stream != contract.CommandStream || ack.Sequence == 0 {
		return errors.Join(errors.New("persist gateway address change command"), err)
	}
	return nil
}

func (t *NATS) NextReceipt(ctx context.Context) (ReceiptDelivery, error) {
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
	receipt := &agentv1.GatewayAddressChangeReceipt{}
	nodeID := strings.TrimPrefix(message.Subject, contract.ReceiptSubjectPrefix+".")
	if len(message.Data) > contract.MaxCarrierBytes || proto.Unmarshal(message.Data, receipt) != nil ||
		len(receipt.ProtoReflect().GetUnknown()) != 0 || receipt.NodeId != nodeID {
		_ = message.Term()
		return nil, nil
	}
	return &natsReceipt{message: message, receipt: receipt}, nil
}

func (t *NATS) subscription(ctx context.Context) (*nats.Subscription, error) {
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

type natsReceipt struct {
	message *nats.Msg
	receipt *agentv1.GatewayAddressChangeReceipt
}

func (r *natsReceipt) Receipt() *agentv1.GatewayAddressChangeReceipt { return r.receipt }
func (r *natsReceipt) Ack(ctx context.Context) error                 { return r.message.AckSync(nats.Context(ctx)) }
func (r *natsReceipt) Nak(context.Context) error                     { return r.message.NakWithDelay(5 * time.Second) }
