package gateway

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// validateSubscriptionMinuteTelemetry: one subscription_minute.v1 record of
// this node (ADR 0012 §6.2). The record names the site it is bound to; that
// site's authorization must carry the record's subscription, so a node can
// only report minutes of subscriptions it serves.
func validateSubscriptionMinuteTelemetry(record *agentv1.TelemetryRecord, nodeID string, authority telemetryAuthorization, now time.Time) ([]string, string, string, error) {
	var envelope edgeconfig.SubscriptionMinuteEnvelope
	if decodeStrictTelemetryJSON(record.Payload, &envelope) != nil || envelope.SchemaVersion != 1 || envelope.Type != edgeconfig.SubscriptionMinuteType ||
		record.EventCount != 1 || len(envelope.Events) != 1 || envelope.NodeID != nodeID || envelope.TenantID != authority.tenantID ||
		envelope.InstallationID != "" || envelope.PackageSubscriptionID != "" || envelope.MessageID != record.MessageId ||
		envelope.MessageID != edgeconfig.SubscriptionMinuteMessageID(envelope) {
		return nil, "", "", fmt.Errorf("subscription minute envelope is invalid")
	}
	event := envelope.Events[0]
	scope := telemetryScopeKey{siteID: event.SiteID, configVersionID: event.ConfigVersionID}
	if !edgeconfig.ValidSubscriptionMinuteEvent(event) || event.InstallationID != "" || event.PackageSubscriptionID != "" ||
		event.NodeID != nodeID || event.TenantID != authority.tenantID || authority.configBySite[scope] != authority.tenantID ||
		authority.subscriptionBySite[scope] != event.SubscriptionID ||
		event.EventID != record.LastEventId || !envelope.ProducedAt.Equal(event.Minute) || event.Minute.After(now.UTC()) ||
		event.Minute.Before(now.UTC().Add(-30*24*time.Hour)) {
		return nil, "", "", fmt.Errorf("subscription minute authority is invalid")
	}
	return []string{event.EventID}, event.SiteID, event.ConfigVersionID, nil
}

func bindSubscriptionMinuteTelemetry(record *agentv1.TelemetryRecord, subscriptionID, installationID string) error {
	var envelope edgeconfig.SubscriptionMinuteEnvelope
	if decodeStrictTelemetryJSON(record.Payload, &envelope) != nil || len(envelope.Events) != 1 ||
		subscriptionID == "" || envelope.Events[0].SubscriptionID != subscriptionID {
		return fmt.Errorf("subscription minute binding is invalid")
	}
	envelope.PackageSubscriptionID, envelope.InstallationID = subscriptionID, installationID
	envelope.Events[0].PackageSubscriptionID, envelope.Events[0].InstallationID = subscriptionID, installationID
	payload, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	record.Payload = payload
	return nil
}
