package l4drain

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

type PublisherConfig struct {
	Stream           string
	SubjectPrefix    string
	MaxCommandBytes  int
	OperationTimeout time.Duration
}

func DefaultPublisherConfig() PublisherConfig {
	return PublisherConfig{Stream: "AGENT_COMMANDS", SubjectPrefix: "cdnca.agent.commands.drain",
		MaxCommandBytes: 1 << 20, OperationTimeout: 5 * time.Second}
}

func (config PublisherConfig) validate() error {
	if !validNATSName(config.Stream) || !validSubjectPrefix(config.SubjectPrefix) || config.MaxCommandBytes < 1 ||
		config.MaxCommandBytes > 1<<20 || config.OperationTimeout <= 0 || config.OperationTimeout > time.Minute {
		return ErrInvalidInput
	}
	return nil
}

type Publication struct {
	Stream    string
	Sequence  uint64
	Duplicate bool
}

type Publisher struct {
	js     nats.JetStreamContext
	config PublisherConfig
}

func NewPublisher(connection *nats.Conn, config PublisherConfig) (*Publisher, error) {
	if connection == nil || connection.IsClosed() || config.validate() != nil {
		return nil, ErrInvalidInput
	}
	js, err := connection.JetStream(nats.MaxWait(config.OperationTimeout))
	if err != nil {
		return nil, fmt.Errorf("create L4 drain JetStream context: %w", err)
	}
	return &Publisher{js: js, config: config}, nil
}

func (publisher *Publisher) Publish(ctx context.Context, command *agentv1.DrainCommand) (Publication, error) {
	if ctx == nil || publisher == nil || publisher.js == nil || command == nil || !canonicalUUID(command.NodeId) ||
		!canonicalUUID(command.CommandId) || command.Schema != agentv1.DrainSchema_DRAIN_SCHEMA_V1 {
		return Publication{}, ErrInvalidInput
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(command)
	if err != nil || len(payload) == 0 || len(payload) > publisher.config.MaxCommandBytes {
		return Publication{}, ErrInvalidInput
	}
	message := nats.NewMsg(publisher.config.SubjectPrefix + "." + command.NodeId)
	message.Data = payload
	message.Header.Set(nats.MsgIdHdr, command.CommandId)
	operationCtx, cancel := context.WithTimeout(ctx, publisher.config.OperationTimeout)
	ack, err := publisher.js.PublishMsg(message, nats.Context(operationCtx), nats.ExpectStream(publisher.config.Stream))
	cancel()
	if err != nil {
		return Publication{}, fmt.Errorf("publish L4 drain command: %w", err)
	}
	if ack == nil || ack.Stream != publisher.config.Stream || ack.Sequence == 0 {
		return Publication{}, errors.New("publish L4 drain command returned an invalid acknowledgement")
	}
	return Publication{Stream: ack.Stream, Sequence: ack.Sequence, Duplicate: ack.Duplicate}, nil
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

func validSubjectPrefix(value string) bool {
	if strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, token := range strings.Split(value, ".") {
		if !validNATSName(token) {
			return false
		}
	}
	return true
}
