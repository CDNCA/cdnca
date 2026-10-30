package eventspool

import (
	"encoding/json"
	"github.com/cdnca/cdnca/libs/edgeconfig"
)

func NewAccessWindowRecord(event edgeconfig.AccessWindowEvent) (Envelope, error) {
	if !edgeconfig.ValidAccessWindowEvent(event) || event.InstallationID != "" || event.PackageSubscriptionID != "" {
		return Envelope{}, ErrInvalidEvent
	}
	return Envelope{SchemaVersion: 1, Type: EventAccessWindow, EventID: event.EventID, OccurredAt: event.WindowEnd,
		TenantID: event.TenantID, SiteID: event.SiteID, NodeID: event.NodeID, ConfigVersionID: event.ConfigVersionID,
		Host: event.Host, ListenPort: event.ListenPort, StartedAt: event.WindowStart, FinalizedAt: event.WindowEnd,
		SourceWatermark: event.SourceWatermark, EvidenceSHA256: event.EvidenceSHA256}, nil
}

func accessWindowEvent(envelope Envelope) edgeconfig.AccessWindowEvent {
	return edgeconfig.AccessWindowEvent{MetricVersion: 1, EventID: envelope.EventID, WindowStart: envelope.StartedAt,
		WindowEnd: envelope.FinalizedAt, TenantID: envelope.TenantID, SiteID: envelope.SiteID, NodeID: envelope.NodeID,
		ConfigVersionID: envelope.ConfigVersionID, Host: envelope.Host, ListenPort: envelope.ListenPort,
		SourceWatermark: envelope.SourceWatermark, FinalizedThrough: envelope.FinalizedAt, DependencyState: "ready", EvidenceSHA256: envelope.EvidenceSHA256}
}

func validAccessWindowRecord(envelope Envelope) bool {
	if !edgeconfig.ValidAccessWindowEvent(accessWindowEvent(envelope)) || !envelope.OccurredAt.Equal(envelope.FinalizedAt) {
		return false
	}
	if envelope.Path != "" || envelope.ClientIP != "" || envelope.Method != "" || envelope.Protocol != "" || envelope.StatusCode != 0 ||
		envelope.RequestBytes != 0 || envelope.ResponseBytes != 0 || envelope.DurationUS != 0 || envelope.SecurityType != "" ||
		envelope.Action != "" || envelope.Severity != "" || envelope.RuleID != "" || envelope.CacheStatus != "" || envelope.StreamID != "" ||
		envelope.ListenerID != "" || envelope.SessionID != "" || envelope.ConfigRevision != 0 || envelope.RequestHeaders != nil ||
		envelope.ResponseHeaders != nil || envelope.RequestBody != nil || envelope.ResponseBody != nil {
		return false
	}
	return true
}

func encodeAccessWindowPublication(records []Record) (Publication, error) {
	if len(records) != 1 || validateEnvelope(records[0].envelope, identityStored) != nil {
		return Publication{}, ErrInvalidEvent
	}
	record := records[0]
	event := accessWindowEvent(record.envelope)
	envelope := edgeconfig.AccessWindowEnvelope{SchemaVersion: 1, Type: edgeconfig.AccessWindowType, ProducedAt: event.WindowEnd,
		TenantID: event.TenantID, NodeID: event.NodeID, Events: []edgeconfig.AccessWindowEvent{event}}
	envelope.MessageID = edgeconfig.AccessWindowMessageID(envelope)
	payload, err := json.Marshal(envelope)
	if err != nil {
		return Publication{}, ErrInvalidEvent
	}
	return Publication{Subject: analyticsSubjectPrefix + "." + event.NodeID, MessageID: envelope.MessageID, Payload: payload,
		FirstSequence: record.Sequence, LastSequence: record.Sequence, LastEventID: record.EventID, EventCount: 1}, nil
}

func ValidAccessWindowPublication(publication Publication) bool {
	var envelope edgeconfig.AccessWindowEnvelope
	if publication.EventCount != 1 || publication.FirstSequence == 0 || publication.FirstSequence != publication.LastSequence ||
		!decodePublicationEnvelope(publication.Payload, &envelope) || envelope.SchemaVersion != 1 || envelope.Type != edgeconfig.AccessWindowType ||
		len(envelope.Events) != 1 || envelope.InstallationID != "" || envelope.PackageSubscriptionID != "" {
		return false
	}
	event := envelope.Events[0]
	return edgeconfig.ValidAccessWindowEvent(event) && event.InstallationID == "" && event.PackageSubscriptionID == "" &&
		event.NodeID == envelope.NodeID && event.TenantID == envelope.TenantID && envelope.ProducedAt.Equal(event.WindowEnd) &&
		publication.Subject == analyticsSubjectPrefix+"."+event.NodeID && event.EventID == publication.LastEventID &&
		envelope.MessageID == publication.MessageID && envelope.MessageID == edgeconfig.AccessWindowMessageID(envelope)
}
