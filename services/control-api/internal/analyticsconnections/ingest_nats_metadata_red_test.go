package analyticsconnections

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

func TestNATSDeliveryUsesAuthoritativeJetStreamMetadata(t *testing.T) {
	message := validConnectionsNATSMessage(t)
	message.Header.Set("Cdnca-Connections-PubAck-Stream", "forged")
	message.Header.Set("Cdnca-Connections-PubAck-Sequence", "999")
	message.Header.Set("Cdnca-Connections-PubAck-Duplicate", "true")
	delivery, err := deliveryFromNATSMessage(message, "CONNECTIONS_INGEST_V1", "control_api_connections")
	if err != nil {
		t.Fatalf("delivery: %v", err)
	}
	if delivery.Stream != "CONNECTIONS_INGEST_V1" || delivery.Durable != "control_api_connections" ||
		delivery.StreamSequence != 11 || delivery.ConsumerSequence != 9 ||
		delivery.PubAck.Stream != "CONNECTIONS_INGEST_V1" || delivery.PubAck.Sequence != 11 || delivery.PubAck.Duplicate {
		t.Fatalf("delivery metadata = %#v", delivery)
	}
}

func TestNATSDeliveryRejectsMetadataAndEnvelopeDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*nats.Msg)
	}{
		{name: "stream", mutate: func(message *nats.Msg) { message.Reply = "$JS.ACK.OTHER.control_api_connections.1.11.9.123456789.0" }},
		{name: "consumer", mutate: func(message *nats.Msg) { message.Reply = "$JS.ACK.CONNECTIONS_INGEST_V1.other.1.11.9.123456789.0" }},
		{name: "stream sequence", mutate: func(message *nats.Msg) {
			message.Reply = "$JS.ACK.CONNECTIONS_INGEST_V1.control_api_connections.1.0.9.123456789.0"
		}},
		{name: "consumer sequence", mutate: func(message *nats.Msg) {
			message.Reply = "$JS.ACK.CONNECTIONS_INGEST_V1.control_api_connections.1.11.0.123456789.0"
		}},
		{name: "batch", mutate: func(message *nats.Msg) { message.Header.Del(connectionsBatchHeader) }},
		{name: "receipt", mutate: func(message *nats.Msg) { message.Header.Set(connectionsReceiptHeader, "other") }},
		{name: "message id", mutate: func(message *nats.Msg) { message.Header.Set(nats.MsgIdHdr, "other") }},
		{name: "subject", mutate: func(message *nats.Msg) { message.Subject += ".other" }},
		{name: "schema", mutate: func(message *nats.Msg) { message.Header.Set(connectionsSchemaHeader, "2") }},
		{name: "payload", mutate: func(message *nats.Msg) { message.Data = append(message.Data, 0) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			message := validConnectionsNATSMessage(t)
			test.mutate(message)
			if _, err := deliveryFromNATSMessage(message, "CONNECTIONS_INGEST_V1", "control_api_connections"); err == nil {
				t.Fatal("drift was accepted")
			}
		})
	}
}

func validConnectionsNATSMessage(t *testing.T) *nats.Msg {
	t.Helper()
	delivery := validConnectionsDelivery()
	payload, err := (proto.MarshalOptions{Deterministic: true}).Marshal(delivery.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	payloadDigest := sha256.Sum256(payload)
	message := nats.NewMsg(ConnectionsSubjectPrefix + "." + delivery.Envelope.GetInstallationId() + "." + delivery.ReceiptID)
	message.Sub = &nats.Subscription{}
	message.Data = payload
	message.Reply = "$JS.ACK.CONNECTIONS_INGEST_V1.control_api_connections.1.11.9.123456789.0"
	message.Header.Set(connectionsBatchHeader, delivery.BatchID)
	message.Header.Set(connectionsReceiptHeader, delivery.ReceiptID)
	message.Header.Set(connectionsSchemaHeader, "1")
	message.Header.Set(connectionsPayloadDigestHeader, hex.EncodeToString(payloadDigest[:]))
	message.Header.Set(nats.MsgIdHdr, delivery.ReceiptID+":"+hex.EncodeToString(payloadDigest[:]))
	return message
}
