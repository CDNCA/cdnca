package gateway

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/google/uuid"
)

func TestTelemetryPublicationCarriesVerifiedSiteAndConfigAuthority(t *testing.T) {
	publication := reflect.TypeOf(TelemetryPublication{})
	for _, field := range []string{"SiteID", "ConfigVersionID"} {
		if _, ok := publication.FieldByName(field); !ok {
			t.Errorf("TelemetryPublication is missing authoritative %s", field)
		}
	}
}

func TestTelemetryAuthorityIsBoundBeforePublication(t *testing.T) {
	authorization := reflect.TypeOf(telemetryAuthorization{})
	if _, ok := authorization.FieldByName("configBySite"); !ok {
		t.Error("telemetry authorization is missing authoritative site-to-config binding")
	}
	validated := reflect.TypeOf(validatedTelemetryRecord{})
	for _, field := range []string{"siteID", "configVersionID"} {
		if _, ok := validated.FieldByName(field); !ok {
			t.Errorf("validated telemetry record is missing %s", field)
		}
	}
}

func TestTelemetryValidationRejectsMissingConfigAuthority(t *testing.T) {
	authorization := telemetryAuthorization{
		installationID: testTelemetryInstallationID,
		tenantID:       testTelemetryTenantID,
		configBySite:   map[telemetryScopeKey]string{},
	}
	batch := telemetryBatch(t, 1, 1)
	if _, err := validateTelemetryBatch(batch, 1, nodeIdentity{NodeID: testNodeID}, authorization,
		DefaultTelemetryConfig(), time.Now()); err == nil {
		t.Fatal("telemetry payload without an authoritative config binding was accepted")
	}
}

func TestTelemetryAuthorizationRejectsLegacyAndDuplicateScopes(t *testing.T) {
	response := &controlv1.GetNodeAuthorizationResponse{
		InstallationId: testTelemetryInstallationID,
		TenantId:       testTelemetryTenantID,
		TelemetrySiteScopes: []*controlv1.TelemetrySiteScope{{
			SiteId: testTelemetrySiteID, TenantId: testTelemetryTenantID,
		}},
	}
	if _, err := validateTelemetryAuthorization(response); err == nil {
		t.Fatal("legacy telemetry scope without config_version_id was accepted")
	}
	response.TelemetrySiteScopes[0].ConfigVersionId = testTelemetryConfigVersionID
	response.TelemetrySiteScopes = append(response.TelemetrySiteScopes, response.TelemetrySiteScopes[0])
	if _, err := validateTelemetryAuthorization(response); err == nil {
		t.Fatal("duplicate site/config authorization tuple was accepted")
	}
}

func TestTelemetryValidationRejectsMixedAuthorizedTuplesInOneRecord(t *testing.T) {
	secondSiteID := uuid.NewString()
	secondConfigID := uuid.NewString()
	authorization := telemetryAuthorization{
		installationID: testTelemetryInstallationID,
		tenantID:       testTelemetryTenantID,
		configBySite: map[telemetryScopeKey]string{
			{siteID: testTelemetrySiteID, configVersionID: testTelemetryConfigVersionID}: testTelemetryTenantID,
			{siteID: secondSiteID, configVersionID: secondConfigID}:                      testTelemetryTenantID,
		},
	}
	batch := telemetryBatch(t, 1, 1)
	record := batch.Records[0]
	var envelope telemetryAccessEnvelope
	if err := json.Unmarshal(record.Payload, &envelope); err != nil {
		t.Fatal(err)
	}
	second := envelope.Events[0]
	second.EventID = "event_" + uuid.NewString()
	second.SiteID = secondSiteID
	second.ConfigVersion = secondConfigID
	envelope.Events = append(envelope.Events, second)
	envelope.MessageID = telemetryMessageID(testNodeID, testTelemetryTenantID, testTelemetrySiteID,
		testTelemetryConfigVersionID, "access.v1", envelope.Events[0].EventID, second.EventID)
	record.MessageId = envelope.MessageID
	record.LastSequence = 2
	record.LastEventId = second.EventID
	record.EventCount = 2
	record.Payload = marshalTelemetryEnvelope(t, envelope)
	batch.LastSequence = 2
	batch.BatchId = telemetryBatchID(batch.Records)
	if _, err := validateTelemetryBatch(batch, 1, nodeIdentity{NodeID: testNodeID}, authorization,
		DefaultTelemetryConfig(), time.Now()); err == nil {
		t.Fatal("one record containing two authorized site/config tuples was accepted")
	}
}
