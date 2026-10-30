package gateway

import (
	"encoding/json"
	"fmt"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"time"
)

func validateAccessWindowTelemetry(record *agentv1.TelemetryRecord, nodeID string, authority telemetryAuthorization, now time.Time) ([]string, string, string, error) {
	var envelope edgeconfig.AccessWindowEnvelope
	if decodeStrictTelemetryJSON(record.Payload, &envelope) != nil || envelope.SchemaVersion != 1 || envelope.Type != edgeconfig.AccessWindowType ||
		record.EventCount != 1 || len(envelope.Events) != 1 || envelope.NodeID != nodeID || envelope.TenantID != authority.tenantID ||
		envelope.InstallationID != "" || envelope.PackageSubscriptionID != "" || envelope.MessageID != record.MessageId ||
		envelope.MessageID != edgeconfig.AccessWindowMessageID(envelope) {
		return nil, "", "", fmt.Errorf("access source window envelope is invalid")
	}
	event := envelope.Events[0]
	scope := telemetryScopeKey{siteID: event.SiteID, configVersionID: event.ConfigVersionID}
	if !edgeconfig.ValidAccessWindowEvent(event) || event.InstallationID != "" || event.PackageSubscriptionID != "" ||
		event.NodeID != nodeID || event.TenantID != authority.tenantID || authority.configBySite[scope] != authority.tenantID ||
		event.EventID != record.LastEventId || !envelope.ProducedAt.Equal(event.WindowEnd) || event.WindowEnd.After(now.UTC()) ||
		event.WindowEnd.Before(now.UTC().Add(-30*24*time.Hour)) {
		return nil, "", "", fmt.Errorf("access source window authority is invalid")
	}
	return []string{event.EventID}, event.SiteID, event.ConfigVersionID, nil
}

func bindAccessWindowTelemetry(record *agentv1.TelemetryRecord, subscriptionID, installationID string) error {
	var envelope edgeconfig.AccessWindowEnvelope
	if decodeStrictTelemetryJSON(record.Payload, &envelope) != nil || len(envelope.Events) != 1 {
		return fmt.Errorf("access window binding is invalid")
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
