package gateway

import (
	"testing"
	"time"
)

func TestObservedConnectionsV2BindsExactConfigurationAndAllowsUnbilledZero(t *testing.T) {
	value := validConnectionsTelemetryEnvelope()
	value.SchemaVersion = 2
	value.Connections = 0
	value.PackageSubscriptionId = ""
	value.ConfigVersionId = testTelemetryConfigVersionID
	key := telemetryScopeKey{siteID: value.SiteId, configVersionID: value.ConfigVersionId}
	authority := telemetryAuthorization{tenantID: value.TenantId, installationID: value.InstallationId,
		configBySite: map[telemetryScopeKey]string{key: value.TenantId}, subscriptionBySite: map[telemetryScopeKey]string{key: ""}}
	if err := validateConnectionsTelemetryEnvelope(value, testNodeID, authority, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	value.ConfigVersionId = "10000000-0000-4000-8000-000000000009"
	if err := validateConnectionsTelemetryEnvelope(value, testNodeID, authority, time.Now().UTC()); err == nil {
		t.Fatal("wrong config accepted")
	}
	value.ConfigVersionId = ""
	value.SchemaVersion = 1
	if err := validateConnectionsTelemetryEnvelope(value, testNodeID, authority, time.Now().UTC()); err == nil {
		t.Fatal("legacy zero was silently accepted")
	}
}
