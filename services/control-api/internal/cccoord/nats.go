package cccoord

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/nats-io/nats.go"
)

const (
	CoordinationStream        = "SECURITY_CC_COORDINATION_V1"
	CoordinationSubjectPrefix = "cdnca.security.cccoord.v1"
	CoordinationDurable       = "control_api_cc_coordination_v1"
)

type NATSConfig struct {
	Stream           string
	SubjectPrefix    string
	Durable          string
	AckWait          time.Duration
	FetchTimeout     time.Duration
	OperationTimeout time.Duration
	NakDelay         time.Duration
	MaxAckPending    int
}

func DefaultNATSConfig() NATSConfig {
	return NATSConfig{
		Stream: CoordinationStream, SubjectPrefix: CoordinationSubjectPrefix, Durable: CoordinationDurable,
		AckWait: 2 * time.Minute, FetchTimeout: 5 * time.Second, OperationTimeout: 5 * time.Second,
		NakDelay: time.Second, MaxAckPending: 256,
	}
}

type envelopeObserver interface {
	Observe(context.Context, Envelope) (ObserveResult, error)
}

type NATSConsumer struct {
	subscription *nats.Subscription
	observer     envelopeObserver
	config       NATSConfig
}

func NewNATSConsumer(connection *nats.Conn, observer envelopeObserver, config NATSConfig) (*NATSConsumer, error) {
	if connection == nil || connection.IsClosed() || observer == nil || !validNATSConfig(config) {
		return nil, ErrInvalidInput
	}
	js, err := connection.JetStream(nats.MaxWait(config.OperationTimeout))
	if err != nil {
		return nil, fmt.Errorf("create CC coordination JetStream context: %w", err)
	}
	operationCtx, cancel := context.WithTimeout(context.Background(), config.OperationTimeout)
	info, err := js.ConsumerInfo(config.Stream, config.Durable, nats.Context(operationCtx))
	cancel()
	if err != nil || !sameCoordinationConsumer(info, config) {
		return nil, fmt.Errorf("pre-created CC coordination consumer does not match: %w", err)
	}
	subscription, err := js.PullSubscribe(config.SubjectPrefix+".*.*", config.Durable, nats.Bind(config.Stream, config.Durable))
	if err != nil {
		return nil, fmt.Errorf("bind CC coordination consumer: %w", err)
	}
	return &NATSConsumer{subscription: subscription, observer: observer, config: config}, nil
}

func (consumer *NATSConsumer) RunOnce(ctx context.Context) (ObserveResult, error) {
	if consumer == nil || consumer.subscription == nil || consumer.observer == nil || ctx == nil {
		return ObserveResult{}, ErrUnavailable
	}
	fetchCtx, cancel := context.WithTimeout(ctx, consumer.config.FetchTimeout)
	messages, err := consumer.subscription.Fetch(1, nats.Context(fetchCtx))
	cancel()
	if err != nil {
		if ctx.Err() != nil {
			return ObserveResult{}, ctx.Err()
		}
		return ObserveResult{}, err
	}
	if len(messages) != 1 || messages[0] == nil {
		return ObserveResult{}, ErrUnavailable
	}
	message := messages[0]
	envelope, err := decodeCoordinationEnvelope(message.Subject, message.Header, message.Data)
	if err != nil {
		_ = message.Term()
		return ObserveResult{}, err
	}
	operationCtx, cancel := context.WithTimeout(ctx, consumer.config.OperationTimeout)
	result, err := consumer.observer.Observe(operationCtx, envelope)
	cancel()
	if err != nil {
		if errors.Is(err, ErrInvalidInput) || errors.Is(err, ErrScopeMismatch) || errors.Is(err, ErrCapacity) {
			_ = message.Term()
		} else {
			_ = message.NakWithDelay(consumer.config.NakDelay)
		}
		return ObserveResult{}, err
	}
	ackCtx, cancel := context.WithTimeout(ctx, consumer.config.OperationTimeout)
	err = message.AckSync(nats.Context(ackCtx))
	cancel()
	if err != nil {
		return ObserveResult{}, fmt.Errorf("ack CC coordination event: %w", err)
	}
	return result, nil
}

func (consumer *NATSConsumer) Close() error {
	if consumer == nil || consumer.subscription == nil {
		return nil
	}
	return consumer.subscription.Unsubscribe()
}

func decodeCoordinationEnvelope(subject string, headers nats.Header, payload []byte) (Envelope, error) {
	if len(payload) == 0 || len(payload) > 1<<20 || duplicateJSONKey(payload) || headers == nil {
		return Envelope{}, ErrInvalidInput
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var envelope Envelope
	if err := decoder.Decode(&envelope); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return Envelope{}, ErrInvalidInput
	}
	wantSubject := CoordinationSubjectPrefix + "." + envelope.TenantScopeID.String() + "." + envelope.SiteID.String()
	if subject != wantSubject || headers.Get(nats.MsgIdHdr) != envelope.MessageID ||
		headers.Get("Cdnca-Tenant-Id") != envelope.TenantScopeID.String() ||
		headers.Get("Cdnca-Site-Id") != envelope.SiteID.String() ||
		headers.Get("Cdnca-Node-Id") != envelope.NodeID.String() ||
		headers.Get("Cdnca-Config-Version-Id") != envelope.ConfigVersionID.String() {
		return Envelope{}, ErrScopeMismatch
	}
	return envelope, nil
}

func validNATSConfig(config NATSConfig) bool {
	return validNATSName(config.Stream) && validNATSName(config.Durable) &&
		config.SubjectPrefix == CoordinationSubjectPrefix && config.AckWait > 0 && config.FetchTimeout > 0 &&
		config.OperationTimeout > 0 && config.NakDelay > 0 && config.MaxAckPending > 0
}

func sameCoordinationConsumer(info *nats.ConsumerInfo, config NATSConfig) bool {
	if info == nil {
		return false
	}
	actual := info.Config
	return actual.Durable == config.Durable && actual.FilterSubject == config.SubjectPrefix+".*.*" &&
		len(actual.FilterSubjects) == 0 && actual.DeliverPolicy == nats.DeliverAllPolicy &&
		actual.AckPolicy == nats.AckExplicitPolicy && actual.AckWait == config.AckWait && actual.MaxDeliver == -1 &&
		actual.ReplayPolicy == nats.ReplayInstantPolicy && actual.MaxAckPending == config.MaxAckPending &&
		actual.MaxRequestBatch == 1 && actual.MaxRequestExpires == config.FetchTimeout
}

func validNATSName(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}

func duplicateJSONKey(payload []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok {
					return ErrInvalidInput
				}
				if _, exists := seen[name]; exists {
					return ErrIdempotencyConflict
				}
				seen[name] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return ErrInvalidInput
		}
	}
	if err := walk(); err != nil {
		return true
	}
	return decoder.Decode(&struct{}{}) != io.EOF
}
