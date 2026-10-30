package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

type upgradeStatusPublishStub struct {
	nats.JetStreamContext
	message      *nats.Msg
	messages     map[uint64]*nats.RawStreamMsg
	last         map[string]*nats.RawStreamMsg
	nextSequence uint64
	ack          *nats.PubAck
	err          error
}

type panicUpgradeContext struct{}

func (*panicUpgradeContext) Deadline() (time.Time, bool) { panic("typed-nil context used") }
func (*panicUpgradeContext) Done() <-chan struct{}       { panic("typed-nil context used") }
func (*panicUpgradeContext) Err() error                  { panic("typed-nil context used") }
func (*panicUpgradeContext) Value(any) any               { panic("typed-nil context used") }

func typedNilUpgradeContext() context.Context {
	var ctx *panicUpgradeContext
	return ctx
}

func (stub *upgradeStatusPublishStub) PublishMsg(message *nats.Msg, _ ...nats.PubOpt) (*nats.PubAck, error) {
	if !strings.HasPrefix(message.Subject, UpgradeStatusIdentitySubjectPrefix+".") {
		stub.message = message
	}
	if stub.ack != nil && stub.ack.Sequence != 0 && stub.err == nil {
		if stub.messages == nil {
			stub.messages = make(map[uint64]*nats.RawStreamMsg)
		}
		if stub.last == nil {
			stub.last = make(map[string]*nats.RawStreamMsg)
		}
		if stub.nextSequence < stub.ack.Sequence {
			stub.nextSequence = stub.ack.Sequence - 1
		}
		stub.nextSequence++
		stored := &nats.RawStreamMsg{Subject: message.Subject, Sequence: stub.nextSequence,
			Header: cloneUpgradeHeader(message.Header), Data: append([]byte(nil), message.Data...)}
		stub.messages[stored.Sequence] = stored
		stub.last[stored.Subject] = stored
		ack := *stub.ack
		ack.Sequence = stored.Sequence
		return &ack, nil
	}
	return stub.ack, stub.err
}

func (stub *upgradeStatusPublishStub) GetLastMsg(_, subject string, _ ...nats.JSOpt) (*nats.RawStreamMsg, error) {
	message := stub.last[subject]
	if message == nil {
		return nil, nats.ErrMsgNotFound
	}
	return cloneUpgradeRawMessage(message), nil
}

func (stub *upgradeStatusPublishStub) GetMsg(_ string, sequence uint64, _ ...nats.JSOpt) (*nats.RawStreamMsg, error) {
	message := stub.messages[sequence]
	if message == nil {
		return nil, nats.ErrMsgNotFound
	}
	return cloneUpgradeRawMessage(message), nil
}

func (*upgradeStatusPublishStub) StreamInfo(stream string, _ ...nats.JSOpt) (*nats.StreamInfo, error) {
	return &nats.StreamInfo{Config: nats.StreamConfig{Name: stream}}, nil
}

func TestSameUpgradeConsumerConfigRejectsBehaviorDrift(t *testing.T) {
	expected := upgradeConsumerConfig("00000000-0000-4000-8000-000000000014", 2*time.Minute, 32, 8, 5*time.Second)
	base := &nats.ConsumerInfo{Config: *expected}
	if !sameUpgradeConsumerConfig(base, expected) {
		t.Fatal("exact consumer configuration was rejected")
	}
	tests := []struct {
		name   string
		mutate func(*nats.ConsumerConfig)
	}{
		{"deliver policy", func(c *nats.ConsumerConfig) { c.DeliverPolicy = nats.DeliverLastPolicy }},
		{"ack policy", func(c *nats.ConsumerConfig) { c.AckPolicy = nats.AckNonePolicy }},
		{"max deliver", func(c *nats.ConsumerConfig) { c.MaxDeliver = 8 }},
		{"backoff", func(c *nats.ConsumerConfig) { c.BackOff = []time.Duration{time.Second} }},
		{"rate limit", func(c *nats.ConsumerConfig) { c.RateLimit = 1 }},
		{"headers only", func(c *nats.ConsumerConfig) { c.HeadersOnly = true }},
		{"inactive", func(c *nats.ConsumerConfig) { c.InactiveThreshold = time.Minute }},
		{"replicas", func(c *nats.ConsumerConfig) { c.Replicas = 2 }},
		{"memory", func(c *nats.ConsumerConfig) { c.MemoryStorage = true }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := *expected
			test.mutate(&actual)
			if sameUpgradeConsumerConfig(&nats.ConsumerInfo{Config: actual}, expected) {
				t.Fatal("behavior-changing mismatch was accepted")
			}
		})
	}
}

func TestUpgradeSameMetadataValidatesNATSServerMetadata(t *testing.T) {
	serverMetadata := map[string]string{
		"_nats.req.level": "0",
		"_nats.level":     "1",
		"_nats.ver":       "2.11.4",
	}
	for _, test := range []struct {
		name     string
		actual   map[string]string
		expected map[string]string
		want     bool
	}{
		{name: "stub without server metadata", want: true},
		{name: "exact server metadata", actual: serverMetadata, want: true},
		{name: "user metadata remains exact", actual: map[string]string{
			"owner": "gateway", "_nats.req.level": "0", "_nats.level": "1", "_nats.ver": "2.11.4",
		}, expected: map[string]string{"owner": "gateway"}, want: true},
		{name: "unknown reserved key", actual: map[string]string{
			"_nats.req.level": "0", "_nats.level": "1", "_nats.ver": "2.11.4", "_nats.future": "1",
		}},
		{name: "required level nonzero", actual: map[string]string{
			"_nats.req.level": "1", "_nats.level": "1", "_nats.ver": "2.11.4",
		}},
		{name: "required level noncanonical", actual: map[string]string{
			"_nats.req.level": "00", "_nats.level": "1", "_nats.ver": "2.11.4",
		}},
		{name: "server level noncanonical", actual: map[string]string{
			"_nats.req.level": "0", "_nats.level": "01", "_nats.ver": "2.11.4",
		}},
		{name: "server version malformed", actual: map[string]string{
			"_nats.req.level": "0", "_nats.level": "1", "_nats.ver": "2.11",
		}},
		{name: "pinned native production server", actual: map[string]string{
			"_nats.req.level": "0", "_nats.level": "3", "_nats.ver": "2.12.15-cdnca.1",
		}, want: true},
		{name: "native server with e2e api level", actual: map[string]string{
			"_nats.req.level": "0", "_nats.level": "1", "_nats.ver": "2.12.15-cdnca.1",
		}},
		{name: "e2e server with native api level", actual: map[string]string{
			"_nats.req.level": "0", "_nats.level": "3", "_nats.ver": "2.11.4",
		}},
		{name: "server version wrong", actual: map[string]string{
			"_nats.req.level": "0", "_nats.level": "1", "_nats.ver": "2.11.5",
		}},
		{name: "unpatched production minor", actual: map[string]string{
			"_nats.req.level": "0", "_nats.level": "1", "_nats.ver": "2.12.15",
		}},
		{name: "partial server metadata", actual: map[string]string{
			"_nats.req.level": "0", "_nats.level": "1",
		}},
		{name: "user metadata mismatch", actual: map[string]string{
			"owner": "other", "_nats.req.level": "0", "_nats.level": "1", "_nats.ver": "2.11.4",
		}, expected: map[string]string{"owner": "gateway"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := upgradeSameMetadata(test.actual, test.expected); got != test.want {
				t.Fatalf("upgradeSameMetadata() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestUpgradeCommandNATSWireLiteralCompatibility(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	digest := sha256.Sum256(command.Encoded)
	message := nats.NewMsg(UpgradeCommandSubjectPrefix + "." + command.NodeID)
	message.Data = append([]byte(nil), command.Encoded...)
	message.Header.Set(nats.MsgIdHdr, "control-upgrade-v1-"+hex.EncodeToString(digest[:]))
	message.Header.Set(nats.ExpectedStreamHdr, "AGENT_COMMANDS")
	message.Header.Set("X-CDNCA-Payload-SHA256", hex.EncodeToString(digest[:]))
	message.Header.Set("X-CDNCA-Message-Key", command.CommandID)

	got, err := validateUpgradeCommandMessage(message, command.NodeID)
	if err != nil || got.CommandID != command.CommandID || got.SHA256 != command.SHA256 {
		t.Fatalf("validateUpgradeCommandMessage() = (%#v, %v)", got, err)
	}
	mutations := []struct {
		name   string
		mutate func(*nats.Msg)
	}{
		{"subject", func(value *nats.Msg) { value.Subject += ".other" }},
		{"message id", func(value *nats.Msg) { value.Header.Set(nats.MsgIdHdr, command.CommandID) }},
		{"stream", func(value *nats.Msg) { value.Header.Set(nats.ExpectedStreamHdr, "OTHER") }},
		{"digest", func(value *nats.Msg) {
			value.Header.Set(UpgradePayloadSHA256Header, hex.EncodeToString(make([]byte, sha256.Size)))
		}},
		{"key", func(value *nats.Msg) { value.Header.Set(UpgradeMessageKeyHeader, command.PlanID) }},
		{"duplicate", func(value *nats.Msg) { value.Header.Add(UpgradeMessageKeyHeader, command.CommandID) }},
		{"extra", func(value *nats.Msg) { value.Header.Set("X-CDNCA-Extra", "forbidden") }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			candidate := nats.NewMsg(message.Subject)
			candidate.Data = append([]byte(nil), message.Data...)
			candidate.Header = make(nats.Header, len(message.Header))
			for key, values := range message.Header {
				candidate.Header[key] = append([]string(nil), values...)
			}
			mutation.mutate(candidate)
			if _, err := validateUpgradeCommandMessage(candidate, command.NodeID); err == nil {
				t.Fatal("invalid command wire was accepted")
			}
		})
	}
}

func TestUpgradeStatusNATSWireLiteralCompatibility(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	status := validUpgradeStatusRecord(t, command)
	stub := &upgradeStatusPublishStub{ack: &nats.PubAck{Stream: UpgradeStatusStream, Sequence: 41}}
	bus := &NATSUpgradeCommandBus{js: stub, operationTimeout: time.Second}

	publication, err := bus.PublishUpgradeStatus(context.Background(), command.NodeID, status.Encoded)
	if err != nil || publication.Stream != UpgradeStatusStream || publication.Sequence != 43 {
		t.Fatalf("PublishUpgradeStatus() = (%#v, %v)", publication, err)
	}
	if stub.message == nil || stub.message.Subject != UpgradeStatusV2SubjectPrefix+"."+status.StatusID ||
		!bytes.Equal(stub.message.Data, status.Encoded) || !exactUpgradeHeaders(stub.message.Header, map[string]string{
		nats.MsgIdHdr:               upgradeStatusV2MessageIDPrefix + status.StatusID,
		nats.ExpectedStreamHdr:      UpgradeStatusStream,
		nats.ExpectedLastSubjSeqHdr: "0",
		UpgradePayloadSHA256Header:  hex.EncodeToString(status.SHA256[:]),
		UpgradeMessageKeyHeader:     status.StatusID,
	}) {
		t.Fatalf("published status wire = %#v", stub.message)
	}

	stub.last = make(map[string]*nats.RawStreamMsg)
	stub.ack = &nats.PubAck{Stream: "OTHER", Sequence: 41}
	if _, err := bus.PublishUpgradeStatus(context.Background(), command.NodeID, status.Encoded); err == nil {
		t.Fatal("wrong-stream PubAck was accepted")
	}
	stub.err = errors.New("unavailable")
	if _, err := bus.PublishUpgradeStatus(context.Background(), command.NodeID, status.Encoded); err == nil {
		t.Fatal("publish failure was accepted")
	}
}

func TestNATSUpgradeCommandBusNilReceiverFailsClosed(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	statusRecord := validUpgradeStatusRecord(t, command)
	var bus *NATSUpgradeCommandBus
	assertNoPanic := func(name string, call func() error) {
		t.Helper()
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("%s panicked: %v", name, recovered)
			}
		}()
		if err := call(); err == nil {
			t.Fatalf("%s accepted a nil receiver", name)
		}
	}
	assertNoPanic("PublishUpgradeStatus", func() error {
		_, err := bus.PublishUpgradeStatus(context.Background(), command.NodeID, statusRecord.Encoded)
		return err
	})
	assertNoPanic("SubscribeUpgrade", func() error {
		_, err := bus.SubscribeUpgrade(context.Background(), command.NodeID)
		return err
	})
}

func TestNATSUpgradeMessagingTypedNilDependenciesFailClosed(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	statusRecord := validUpgradeStatusRecord(t, command)
	assertErrorWithoutPanic := func(name string, call func() error) {
		t.Helper()
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("%s panicked: %v", name, recovered)
			}
		}()
		if err := call(); err == nil {
			t.Fatalf("%s accepted a typed-nil dependency", name)
		}
	}

	var nilJetStream *upgradeProofJetStream
	busWithNilJS := &NATSUpgradeCommandBus{js: nilJetStream, operationTimeout: time.Second}
	assertErrorWithoutPanic("PublishUpgradeStatus js", func() error {
		_, err := busWithNilJS.PublishUpgradeStatus(context.Background(), command.NodeID, statusRecord.Encoded)
		return err
	})
	assertErrorWithoutPanic("SubscribeUpgrade js", func() error {
		_, err := busWithNilJS.SubscribeUpgrade(context.Background(), command.NodeID)
		return err
	})

	bus := &NATSUpgradeCommandBus{js: &upgradeProofJetStream{}, operationTimeout: time.Second}
	assertErrorWithoutPanic("PublishUpgradeStatus ctx", func() error {
		_, err := bus.PublishUpgradeStatus(typedNilUpgradeContext(), command.NodeID, statusRecord.Encoded)
		return err
	})
	assertErrorWithoutPanic("SubscribeUpgrade ctx", func() error {
		_, err := bus.SubscribeUpgrade(typedNilUpgradeContext(), command.NodeID)
		return err
	})
	assertErrorWithoutPanic("subscription Next ctx", func() error {
		_, err := (&natsUpgradeCommandSubscription{subscription: &nats.Subscription{}, fetchTimeout: time.Second}).Next(typedNilUpgradeContext())
		return err
	})
	var nilSubscription *natsUpgradeCommandSubscription
	assertErrorWithoutPanic("subscription Close receiver", nilSubscription.Close)
	delivery := &natsUpgradeCommandDelivery{message: &nats.Msg{}}
	assertErrorWithoutPanic("delivery Ack ctx", func() error { return delivery.Ack(typedNilUpgradeContext()) })
	assertErrorWithoutPanic("delivery Nak ctx", func() error { return delivery.Nak(typedNilUpgradeContext()) })
	var nilDelivery *natsUpgradeCommandDelivery
	if command := nilDelivery.Command(); command.CommandID != "" || command.Encoded != nil || command.SHA256 != [sha256.Size]byte{} {
		t.Fatalf("nil delivery returned a command: %+v", command)
	}
	assertErrorWithoutPanic("delivery Ack receiver", func() error { return nilDelivery.Ack(context.Background()) })
	assertErrorWithoutPanic("delivery Nak receiver", func() error { return nilDelivery.Nak(context.Background()) })

	var nilBus *NATSUpgradeCommandBus
	assertErrorWithoutPanic("ConfigureUpgradeMessaging bus", func() error {
		return (&Gateway{}).ConfigureUpgradeMessaging(nilBus)
	})
}
