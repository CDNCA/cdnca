package eventspool

import (
	"encoding/json"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// rum_minute.v1: one site's real user monitoring minute on
// this node, stored like any other record (acknowledged, then deleted; the
// event ID is deterministic per node, site and minute, so a minute appended
// twice is one record). Published one record per message on the analytics
// subject. Never sampled out: the node already sampled the page views.

// RUMMinute is the record's payload; Envelope carries the identity (tenant,
// site and its config version, node, minute).
type RUMMinute struct {
	edgeconfig.RUMMinuteData
}

func NewRUMMinuteRecord(event edgeconfig.RUMMinuteEvent) (Envelope, error) {
	if !edgeconfig.ValidRUMMinuteEvent(event) || event.InstallationID != "" || event.PackageSubscriptionID != "" {
		return Envelope{}, ErrInvalidEvent
	}
	return Envelope{SchemaVersion: SchemaVersion, Type: EventRUMMinute, EventID: event.EventID, OccurredAt: event.Minute,
		TenantID: event.TenantID, SiteID: event.SiteID, NodeID: event.NodeID, ConfigVersionID: event.ConfigVersionID,
		RUMMinute: &RUMMinute{RUMMinuteData: event.RUMMinuteData}}, nil
}

func rumMinuteEvent(envelope Envelope) edgeconfig.RUMMinuteEvent {
	event := edgeconfig.RUMMinuteEvent{MetricVersion: 1, EventID: envelope.EventID, Minute: envelope.OccurredAt,
		TenantID: envelope.TenantID, SiteID: envelope.SiteID, NodeID: envelope.NodeID, ConfigVersionID: envelope.ConfigVersionID}
	if minute := envelope.RUMMinute; minute != nil {
		event.RUMMinuteData = minute.RUMMinuteData
	}
	return event
}

// validRUMMinuteRecord: only the identity and the payload are set.
func validRUMMinuteRecord(envelope Envelope) bool {
	if envelope.RUMMinute == nil || envelope.SubscriptionMinute != nil || !edgeconfig.ValidRUMMinuteEvent(rumMinuteEvent(envelope)) {
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

func encodeRUMMinutePublication(records []Record) (Publication, error) {
	if len(records) != 1 || validateEnvelope(records[0].envelope, identityStored) != nil {
		return Publication{}, ErrInvalidEvent
	}
	record := records[0]
	event := rumMinuteEvent(record.envelope)
	envelope := edgeconfig.RUMMinuteEnvelope{SchemaVersion: 1, Type: edgeconfig.RUMMinuteType, ProducedAt: event.Minute,
		TenantID: event.TenantID, NodeID: event.NodeID, Events: []edgeconfig.RUMMinuteEvent{event}}
	envelope.MessageID = edgeconfig.RUMMinuteMessageID(envelope)
	payload, err := json.Marshal(envelope)
	if err != nil {
		return Publication{}, ErrInvalidEvent
	}
	return Publication{Subject: analyticsSubjectPrefix + "." + event.NodeID, MessageID: envelope.MessageID, Payload: payload,
		FirstSequence: record.Sequence, LastSequence: record.Sequence, LastEventID: record.EventID, EventCount: 1}, nil
}

// ValidRUMMinutePublication recognises the publications
// encodeRUMMinutePublication makes (telemetryclient).
func ValidRUMMinutePublication(publication Publication) bool {
	var envelope edgeconfig.RUMMinuteEnvelope
	if publication.EventCount != 1 || publication.FirstSequence == 0 || publication.FirstSequence != publication.LastSequence ||
		!decodePublicationEnvelope(publication.Payload, &envelope) || envelope.SchemaVersion != 1 ||
		envelope.Type != edgeconfig.RUMMinuteType || len(envelope.Events) != 1 ||
		envelope.InstallationID != "" || envelope.PackageSubscriptionID != "" {
		return false
	}
	event := envelope.Events[0]
	return edgeconfig.ValidRUMMinuteEvent(event) && event.InstallationID == "" && event.PackageSubscriptionID == "" &&
		event.NodeID == envelope.NodeID && event.TenantID == envelope.TenantID && envelope.ProducedAt.Equal(event.Minute) &&
		publication.Subject == analyticsSubjectPrefix+"."+event.NodeID && event.EventID == publication.LastEventID &&
		envelope.MessageID == publication.MessageID && envelope.MessageID == edgeconfig.RUMMinuteMessageID(envelope)
}
