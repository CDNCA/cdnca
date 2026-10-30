package telemetryclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/proto"
)

const analyticsSubjectPrefix = "cdnca.analytics.ingest.v1."
const connectionsSubjectPrefix = "cdnca.connections.v1."
const l4SubjectPrefix = "cdnca.l4.sessions.v1."

type Publisher struct {
	nodeID string
	sender Sender
}

func NewPublisher(nodeID string, sender Sender) (*Publisher, error) {
	if !canonicalUUID(nodeID) || sender == nil {
		return nil, fmt.Errorf("%w: publisher identity and sender are required", ErrInvalidConfiguration)
	}
	return &Publisher{nodeID: nodeID, sender: sender}, nil
}

func (p *Publisher) Publish(ctx context.Context, publications []eventspool.Publication) (eventspool.PublishAck, error) {
	if p == nil || p.sender == nil || len(publications) == 0 {
		return eventspool.PublishAck{}, ErrInvalidPublication
	}
	if strings.HasPrefix(publications[0].Subject, connectionsSubjectPrefix) {
		return p.publishConnections(ctx, publications)
	}
	records := make([]Record, len(publications))
	for index := range publications {
		record, err := p.record(publications[index])
		if err != nil {
			return eventspool.PublishAck{}, err
		}
		if index > 0 && record.FirstSequence != records[index-1].LastSequence+1 {
			return eventspool.PublishAck{}, ErrInvalidPublication
		}
		records[index] = record
	}
	ack, err := p.sender.Send(ctx, Batch{Records: records})
	if ack.Accepted < 0 || ack.Accepted > len(records) {
		return eventspool.PublishAck{}, ErrInvalidResponse
	}
	if ack.Accepted != len(records) && err == nil {
		err = ErrPartialAcknowledged
	}
	return eventspool.PublishAck{Acknowledged: ack.Accepted}, err
}

func (p *Publisher) publishConnections(ctx context.Context, publications []eventspool.Publication) (eventspool.PublishAck, error) {
	records := make([]ConnectionsRecord, len(publications))
	for index, publication := range publications {
		record, err := p.connectionsRecord(publication)
		if err != nil {
			return eventspool.PublishAck{}, err
		}
		if index > 0 && record.Sequence != records[index-1].Sequence+1 {
			return eventspool.PublishAck{}, ErrInvalidPublication
		}
		records[index] = record
	}
	ack, err := p.sender.Send(ctx, Batch{Connections: records})
	if ack.Accepted < 0 || ack.Accepted > len(records) {
		return eventspool.PublishAck{}, ErrInvalidResponse
	}
	if ack.Accepted != len(records) && err == nil {
		err = ErrPartialAcknowledged
	}
	return eventspool.PublishAck{Acknowledged: ack.Accepted}, err
}

func (p *Publisher) connectionsRecord(publication eventspool.Publication) (ConnectionsRecord, error) {
	if !eventspool.ValidConnectionsPublication(publication) {
		return ConnectionsRecord{}, ErrInvalidPublication
	}
	var envelope agentv1.ConnectionsMetricEnvelopeV1
	if err := proto.Unmarshal(publication.Payload, &envelope); err != nil {
		return ConnectionsRecord{}, ErrInvalidPublication
	}
	return ConnectionsRecord{
		ReceiptID: publication.MessageID,
		Sequence:  publication.FirstSequence,
		Envelope:  &envelope,
	}, nil
}

type analyticsEnvelopeHeader struct {
	SchemaVersion         uint16            `json:"schema_version"`
	Type                  string            `json:"type"`
	MessageID             string            `json:"message_id"`
	ProducedAt            time.Time         `json:"produced_at"`
	TenantID              string            `json:"tenant_id"`
	InstallationID        string            `json:"installation_id,omitempty"`
	PackageSubscriptionID string            `json:"package_subscription_id,omitempty"`
	NodeID                string            `json:"node_id"`
	Events                []json.RawMessage `json:"events"`
}

type analyticsEventIdentity struct {
	EventID               string `json:"event_id"`
	SiteID                string `json:"site_id"`
	ConfigVersion         string `json:"config_version_id"`
	InstallationID        string `json:"installation_id,omitempty"`
	PackageSubscriptionID string `json:"package_subscription_id,omitempty"`
}

func (p *Publisher) record(publication eventspool.Publication) (Record, error) {
	if eventspool.ValidAccessWindowPublication(publication) {
		if publication.Subject != analyticsSubjectPrefix+strings.ToLower(p.nodeID) {
			return Record{}, ErrInvalidPublication
		}
		return Record{Kind: "access_window.v1", MessageID: publication.MessageID, FirstSequence: publication.FirstSequence,
			LastSequence: publication.LastSequence, LastEventID: publication.LastEventID, EventCount: 1, Payload: append([]byte(nil), publication.Payload...)}, nil
	}
	if eventspool.ValidSubscriptionMinutePublication(publication) {
		if publication.Subject != analyticsSubjectPrefix+strings.ToLower(p.nodeID) {
			return Record{}, ErrInvalidPublication
		}
		return Record{Kind: "subscription_minute.v1", MessageID: publication.MessageID, FirstSequence: publication.FirstSequence,
			LastSequence: publication.LastSequence, LastEventID: publication.LastEventID, EventCount: 1, Payload: append([]byte(nil), publication.Payload...)}, nil
	}
	if strings.HasPrefix(publication.Subject, l4SubjectPrefix) {
		if publication.Subject != l4SubjectPrefix+strings.ToLower(p.nodeID) || !eventspool.ValidL4Publication(publication) {
			return Record{}, ErrInvalidPublication
		}
		return Record{Kind: "l4_session.v1", MessageID: publication.MessageID,
			FirstSequence: publication.FirstSequence, LastSequence: publication.LastSequence,
			LastEventID: publication.LastEventID, EventCount: publication.EventCount,
			Payload: append([]byte(nil), publication.Payload...)}, nil
	}
	if publication.Subject != analyticsSubjectPrefix+strings.ToLower(p.nodeID) || publication.MessageID == "" ||
		publication.FirstSequence == 0 || publication.LastSequence < publication.FirstSequence || publication.EventCount < 1 ||
		publication.EventCount != int(publication.LastSequence-publication.FirstSequence+1) || publication.LastEventID == "" ||
		len(publication.Payload) == 0 || len(publication.Payload) > 1<<20 {
		return Record{}, ErrInvalidPublication
	}
	decoder := json.NewDecoder(bytes.NewReader(publication.Payload))
	decoder.DisallowUnknownFields()
	var envelope analyticsEnvelopeHeader
	if err := decoder.Decode(&envelope); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return Record{}, ErrInvalidPublication
	}
	legacy := envelope.SchemaVersion == 1 && (envelope.Type == "access.v1" || envelope.Type == "security.v1")
	v2 := envelope.SchemaVersion == 2 && (envelope.Type == "access.v2" || envelope.Type == "security.v2")
	if (!legacy && !v2) || envelope.MessageID != publication.MessageID || envelope.InstallationID != "" || envelope.NodeID != p.nodeID ||
		!canonicalUUID(envelope.TenantID) || len(envelope.Events) != publication.EventCount || envelope.ProducedAt.IsZero() {
		return Record{}, ErrInvalidPublication
	}
	var first, last analyticsEventIdentity
	if err := json.Unmarshal(envelope.Events[0], &first); err != nil || first.EventID == "" ||
		!canonicalUUID(first.SiteID) || !canonicalUUID(first.ConfigVersion) {
		return Record{}, ErrInvalidPublication
	}
	if err := json.Unmarshal(envelope.Events[len(envelope.Events)-1], &last); err != nil ||
		last.EventID != publication.LastEventID || last.SiteID != first.SiteID || last.ConfigVersion != first.ConfigVersion {
		return Record{}, ErrInvalidPublication
	}
	for _, raw := range envelope.Events {
		var event analyticsEventIdentity
		if err := json.Unmarshal(raw, &event); err != nil || event.InstallationID != "" || event.SiteID != first.SiteID ||
			event.ConfigVersion != first.ConfigVersion || event.PackageSubscriptionID != first.PackageSubscriptionID {
			return Record{}, ErrInvalidPublication
		}
	}
	if envelope.PackageSubscriptionID != first.PackageSubscriptionID ||
		(first.PackageSubscriptionID != "" && !canonicalUUID(first.PackageSubscriptionID)) {
		return Record{}, ErrInvalidPublication
	}
	legacyMessageID := telemetryMessageID(p.nodeID, envelope.TenantID, first.SiteID, first.ConfigVersion,
		envelope.Type, first.EventID, last.EventID)
	if legacy && publication.MessageID != legacyMessageID && !eventspool.ValidPublicationMessageID(publication) ||
		v2 && !eventspool.ValidPublicationMessageID(publication) {
		return Record{}, ErrInvalidPublication
	}
	return Record{
		Kind: envelope.Type, MessageID: publication.MessageID,
		FirstSequence: publication.FirstSequence, LastSequence: publication.LastSequence,
		LastEventID: publication.LastEventID, EventCount: publication.EventCount,
		Payload: append([]byte(nil), publication.Payload...),
	}, nil
}

func telemetryMessageID(nodeID, tenantID, siteID, configVersionID, kind, firstEventID, lastEventID string) string {
	digest := sha256.Sum256([]byte(nodeID + "\x00" + tenantID + "\x00" + siteID + "\x00" + configVersionID + "\x00" +
		kind + "\x00" + firstEventID + "\x00" + lastEventID))
	return "msg_" + hex.EncodeToString(digest[:])
}

func batchID(records []Record) string {
	hash := sha256.New()
	for _, record := range records {
		_, _ = hash.Write([]byte(record.MessageID))
		_, _ = hash.Write([]byte{0})
		_, _ = fmt.Fprintf(hash, "%d:%d:%s\n", record.FirstSequence, record.LastSequence, record.LastEventID)
	}
	return "batch_" + hex.EncodeToString(hash.Sum(nil))
}

var _ eventspool.Publisher = (*Publisher)(nil)
