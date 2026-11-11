package gateway

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// validateRUMMinuteTelemetry: one rum_minute.v1 record of this node (ADR
// 0031). The record names its site; that site's authorization must be this
// node's, so a node can only report minutes of sites it serves.
func validateRUMMinuteTelemetry(record *agentv1.TelemetryRecord, nodeID string, authority telemetryAuthorization, now time.Time) ([]string, string, string, error) {
	var envelope edgeconfig.RUMMinuteEnvelope
	if decodeStrictTelemetryJSON(record.Payload, &envelope) != nil || envelope.SchemaVersion != 1 || envelope.Type != edgeconfig.RUMMinuteType ||
		record.EventCount != 1 || len(envelope.Events) != 1 || envelope.NodeID != nodeID || envelope.TenantID != authority.tenantID ||
		envelope.InstallationID != "" || envelope.PackageSubscriptionID != "" || envelope.MessageID != record.MessageId ||
		envelope.MessageID != edgeconfig.RUMMinuteMessageID(envelope) {
		return nil, "", "", fmt.Errorf("rum minute envelope is invalid")
	}
	event := envelope.Events[0]
	scope := telemetryScopeKey{siteID: event.SiteID, configVersionID: event.ConfigVersionID}
	if !edgeconfig.ValidRUMMinuteEvent(event) || event.InstallationID != "" || event.PackageSubscriptionID != "" ||
		event.NodeID != nodeID || event.TenantID != authority.tenantID || authority.configBySite[scope] != authority.tenantID ||
		event.EventID != record.LastEventId || !envelope.ProducedAt.Equal(event.Minute) || event.Minute.After(now.UTC()) ||
		event.Minute.Before(now.UTC().Add(-30*24*time.Hour)) {
		return nil, "", "", fmt.Errorf("rum minute authority is invalid")
	}
	return []string{event.EventID}, event.SiteID, event.ConfigVersionID, nil
}

// bindRUMMinuteTelemetry writes the gateway's installation and the site's
// package subscription ("" for a site without one).
func bindRUMMinuteTelemetry(record *agentv1.TelemetryRecord, subscriptionID, installationID string) error {
	var envelope edgeconfig.RUMMinuteEnvelope
	if decodeStrictTelemetryJSON(record.Payload, &envelope) != nil || len(envelope.Events) != 1 || installationID == "" {
		return fmt.Errorf("rum minute binding is invalid")
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
