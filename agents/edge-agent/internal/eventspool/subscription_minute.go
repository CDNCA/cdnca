package eventspool

import (
	"encoding/json"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// subscription_minute.v1 (ADR 0012 §6.2, ML-07): one subscription's minute
// statistics on this node, stored like any other record (acknowledged, then
// deleted; the event ID is deterministic per node, subscription and minute,
// so a minute appended twice is one record). Published one record per
// message on the analytics subject.

// SubscriptionMinute is the record's payload; Envelope carries the identity
// (tenant, the bound site and its config version, node, minute).
type SubscriptionMinute struct {
	SubscriptionID string `json:"subscription_id"`
	edgeconfig.SubscriptionMinuteCounters
}

func NewSubscriptionMinuteRecord(event edgeconfig.SubscriptionMinuteEvent) (Envelope, error) {
	if !edgeconfig.ValidSubscriptionMinuteEvent(event) || event.InstallationID != "" || event.PackageSubscriptionID != "" {
		return Envelope{}, ErrInvalidEvent
	}
	return Envelope{SchemaVersion: SchemaVersion, Type: EventSubscriptionMinute, EventID: event.EventID, OccurredAt: event.Minute,
		TenantID: event.TenantID, SiteID: event.SiteID, NodeID: event.NodeID, ConfigVersionID: event.ConfigVersionID,
		SubscriptionMinute: &SubscriptionMinute{SubscriptionID: event.SubscriptionID, SubscriptionMinuteCounters: event.SubscriptionMinuteCounters}}, nil
}

func subscriptionMinuteEvent(envelope Envelope) edgeconfig.SubscriptionMinuteEvent {
	event := edgeconfig.SubscriptionMinuteEvent{MetricVersion: 1, EventID: envelope.EventID, Minute: envelope.OccurredAt,
		TenantID: envelope.TenantID, SiteID: envelope.SiteID, NodeID: envelope.NodeID, ConfigVersionID: envelope.ConfigVersionID}
	if minute := envelope.SubscriptionMinute; minute != nil {
		event.SubscriptionID, event.SubscriptionMinuteCounters = minute.SubscriptionID, minute.SubscriptionMinuteCounters
	}
	return event
}

// validSubscriptionMinuteRecord: only the identity and the payload are set.
func validSubscriptionMinuteRecord(envelope Envelope) bool {
	if envelope.SubscriptionMinute == nil || !edgeconfig.ValidSubscriptionMinuteEvent(subscriptionMinuteEvent(envelope)) {
		return false
	}
	return envelope.Host == "" && envelope.Path == "" && envelope.ClientIP == "" && envelope.Method == "" && envelope.Protocol == "" &&
		envelope.StatusCode == 0 && envelope.RequestBytes == 0 && envelope.ResponseBytes == 0 && envelope.DurationUS == 0 &&
		envelope.SecurityType == "" && envelope.Action == "" && envelope.Severity == "" && envelope.RuleID == "" &&
		envelope.CacheStatus == "" && envelope.UpstreamResult == "" && envelope.StreamID == "" && envelope.ListenerID == "" &&
		envelope.SessionID == "" && envelope.ConfigRevision == 0 && envelope.ListenPort == 0 && envelope.RequestHeaders == nil &&
		envelope.ResponseHeaders == nil && envelope.RequestBody == nil && envelope.ResponseBody == nil &&
		envelope.StartedAt.IsZero() && envelope.FinalizedAt.IsZero() && envelope.ErrorCode == "" && envelope.EvidenceSHA256 == ""
}

func encodeSubscriptionMinutePublication(records []Record) (Publication, error) {
	if len(records) != 1 || validateEnvelope(records[0].envelope, identityStored) != nil {
		return Publication{}, ErrInvalidEvent
	}
	record := records[0]
	event := subscriptionMinuteEvent(record.envelope)
	envelope := edgeconfig.SubscriptionMinuteEnvelope{SchemaVersion: 1, Type: edgeconfig.SubscriptionMinuteType, ProducedAt: event.Minute,
		TenantID: event.TenantID, NodeID: event.NodeID, Events: []edgeconfig.SubscriptionMinuteEvent{event}}
	envelope.MessageID = edgeconfig.SubscriptionMinuteMessageID(envelope)
	payload, err := json.Marshal(envelope)
	if err != nil {
		return Publication{}, ErrInvalidEvent
	}
	return Publication{Subject: analyticsSubjectPrefix + "." + event.NodeID, MessageID: envelope.MessageID, Payload: payload,
		FirstSequence: record.Sequence, LastSequence: record.Sequence, LastEventID: record.EventID, EventCount: 1}, nil
}

// ValidSubscriptionMinutePublication recognises the publications
// encodeSubscriptionMinutePublication makes (telemetryclient).
func ValidSubscriptionMinutePublication(publication Publication) bool {
	var envelope edgeconfig.SubscriptionMinuteEnvelope
	if publication.EventCount != 1 || publication.FirstSequence == 0 || publication.FirstSequence != publication.LastSequence ||
		!decodePublicationEnvelope(publication.Payload, &envelope) || envelope.SchemaVersion != 1 ||
		envelope.Type != edgeconfig.SubscriptionMinuteType || len(envelope.Events) != 1 ||
		envelope.InstallationID != "" || envelope.PackageSubscriptionID != "" {
		return false
	}
	event := envelope.Events[0]
	return edgeconfig.ValidSubscriptionMinuteEvent(event) && event.InstallationID == "" && event.PackageSubscriptionID == "" &&
		event.NodeID == envelope.NodeID && event.TenantID == envelope.TenantID && envelope.ProducedAt.Equal(event.Minute) &&
		publication.Subject == analyticsSubjectPrefix+"."+event.NodeID && event.EventID == publication.LastEventID &&
		envelope.MessageID == publication.MessageID && envelope.MessageID == edgeconfig.SubscriptionMinuteMessageID(envelope)
}
