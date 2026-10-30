package gateway

import (
	"context"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// A platform node owned by testTelemetryTenantID that also carries one site of
// a second tenant.
// Configuration scope IDs (access_scopes.id) differ from tenant IDs, exactly
// as identity.CreateManagedUser allocates them; tests must never pass when the
// two are confused.
const (
	testSecondTenantID      = "018f47a2-5b9c-7d31-8a60-104c9c0b7201"
	testSecondSiteID        = "018f47a2-5b9c-7d31-8a60-104c9c0b7202"
	testSecondConfigVersion = "018f47a2-5b9c-7d31-8a60-104c9c0b7203"
	testFirstScopeID        = "018f47a2-5b9c-7d31-8a60-104c9c0b7211"
	testSecondScopeID       = "018f47a2-5b9c-7d31-8a60-104c9c0b7212"
)

func multiTenantTelemetryResponse() *controlv1.GetNodeAuthorizationResponse {
	return &controlv1.GetNodeAuthorizationResponse{
		InstallationId: testConnectionsInstallationID, TenantId: testTelemetryTenantID,
		TelemetrySiteScopes: []*controlv1.TelemetrySiteScope{
			{SiteId: testTelemetrySiteID, TenantId: testTelemetryTenantID, ConfigVersionId: testTelemetryConfigVersionID,
				PackageSubscriptionId: testConnectionsSubscriptionID, ConfigurationScopeId: testFirstScopeID},
			{SiteId: testSecondSiteID, TenantId: testSecondTenantID, ConfigVersionId: testSecondConfigVersion,
				PackageSubscriptionId: testConnectionsSubscriptionID, ConfigurationScopeId: testSecondScopeID},
		},
	}
}

func scopedTelemetryAuthorization(t *testing.T) telemetryAuthorization {
	t.Helper()
	authorization, err := validateTelemetryAuthorization(multiTenantTelemetryResponse(), true)
	if err != nil {
		t.Fatalf("scoped multi-tenant authorization rejected: %v", err)
	}
	return authorization
}

func TestTelemetryAuthorizationMultiTenantRequiresScopedRecords(t *testing.T) {
	if _, err := validateTelemetryAuthorization(multiTenantTelemetryResponse(), false); err == nil {
		t.Fatal("legacy session accepted a multi-tenant authorization")
	}
	authorization := scopedTelemetryAuthorization(t)
	if !authorization.scoped || authorization.configBySite[telemetryScopeKey{siteID: testSecondSiteID, configVersionID: testSecondConfigVersion}] != testSecondTenantID ||
		authorization.tenantByScope[testSecondScopeID] != testSecondTenantID {
		t.Fatalf("scoped authorization = %+v", authorization)
	}
	for name, mutate := range map[string]func(*controlv1.GetNodeAuthorizationResponse){
		"noncanonical site tenant": func(value *controlv1.GetNodeAuthorizationResponse) { value.TelemetrySiteScopes[1].TenantId = "TENANT" },
		"missing site scope": func(value *controlv1.GetNodeAuthorizationResponse) {
			value.TelemetrySiteScopes[1].ConfigurationScopeId = ""
		},
		"noncanonical site scope": func(value *controlv1.GetNodeAuthorizationResponse) {
			value.TelemetrySiteScopes[1].ConfigurationScopeId = "SCOPE"
		},
		"one scope for two tenants": func(value *controlv1.GetNodeAuthorizationResponse) {
			value.TelemetrySiteScopes[1].ConfigurationScopeId = testFirstScopeID
		},
	} {
		invalid := multiTenantTelemetryResponse()
		mutate(invalid)
		if _, err := validateTelemetryAuthorization(invalid, true); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
	// A scoped session no longer depends on the node owner's tenant.
	ownerless := multiTenantTelemetryResponse()
	ownerless.TenantId = ""
	if _, err := validateTelemetryAuthorization(ownerless, true); err != nil {
		t.Fatalf("scoped authorization without a top-level tenant rejected: %v", err)
	}
}

func scopedTelemetryBatch(t *testing.T, tenantID, siteID, configVersionID string, scope *string) *agentv1.TelemetryBatch {
	t.Helper()
	batch := telemetryCaptureBatchFor(t, agentv1.TelemetryKind_TELEMETRY_KIND_ACCESS_V1, tenantID, siteID, configVersionID, map[string]any{
		"capture_policy_revision": uint64(7), "capture_policy_digest": telemetryCapturePolicyDigest,
	})
	batch.Records[0].ConfigurationScopeId = scope
	return batch
}

func TestScopedTelemetryRecordsBindEachSiteToItsTenant(t *testing.T) {
	authorization := scopedTelemetryAuthorization(t)
	validate := func(batch *agentv1.TelemetryBatch, auth telemetryAuthorization) ([]validatedTelemetryRecord, error) {
		return validateTelemetryBatch(batch, 1, nodeIdentity{NodeID: testNodeID}, auth, DefaultTelemetryConfig(), time.Now().UTC())
	}
	for _, test := range []struct {
		scope, tenant, site, config string
	}{
		{testFirstScopeID, testTelemetryTenantID, testTelemetrySiteID, testTelemetryConfigVersionID},
		{testSecondScopeID, testSecondTenantID, testSecondSiteID, testSecondConfigVersion},
	} {
		validated, err := validate(scopedTelemetryBatch(t, test.tenant, test.site, test.config, proto.String(test.scope)), authorization)
		if err != nil || len(validated) != 1 || validated[0].tenantID != test.tenant || validated[0].siteID != test.site {
			t.Fatalf("scoped record for scope %s = (%+v, %v)", test.scope, validated, err)
		}
	}
	for _, test := range []struct {
		name                 string
		tenant, site, config string
		scope                *string
	}{
		{name: "scope missing", tenant: testSecondTenantID, site: testSecondSiteID, config: testSecondConfigVersion},
		// Regression: 2e81d9a6 looked the scope up in a tenant-keyed set.
		{name: "tenant id sent as scope", tenant: testSecondTenantID, site: testSecondSiteID, config: testSecondConfigVersion,
			scope: proto.String(testSecondTenantID)},
		{name: "scope of another tenant", tenant: testSecondTenantID, site: testSecondSiteID, config: testSecondConfigVersion,
			scope: proto.String(testFirstScopeID)},
		{name: "site belongs to another scope", tenant: testSecondTenantID, site: testTelemetrySiteID, config: testTelemetryConfigVersionID,
			scope: proto.String(testSecondScopeID)},
		{name: "payload tenant differs from scope tenant", tenant: testTelemetryTenantID, site: testSecondSiteID, config: testSecondConfigVersion,
			scope: proto.String(testSecondScopeID)},
		{name: "scope not carried by node", tenant: testSecondTenantID, site: testSecondSiteID, config: testSecondConfigVersion,
			scope: proto.String(uuid.NewString())},
		{name: "noncanonical scope", tenant: testSecondTenantID, site: testSecondSiteID, config: testSecondConfigVersion,
			scope: proto.String("SCOPE")},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := validate(scopedTelemetryBatch(t, test.tenant, test.site, test.config, test.scope), authorization); err == nil {
				t.Fatal("misattributed scoped telemetry record was accepted")
			}
		})
	}
}

func scopedConnectionsEnvelope(tenantID, siteID string) *agentv1.ConnectionsMetricEnvelopeV1 {
	envelope := validConnectionsTelemetryEnvelope()
	envelope.TenantId, envelope.SiteId = tenantID, siteID
	return envelope
}

func TestScopedConnectionsRecordsBindEachSiteToItsTenant(t *testing.T) {
	authorization := scopedTelemetryAuthorization(t)
	batchFor := func(envelope *agentv1.ConnectionsMetricEnvelopeV1, scope *string) *agentv1.ConnectionsTelemetryBatchV1 {
		batch := connectionsTelemetryBatch(envelope, "")
		batch.Records[0].ConfigurationScopeId = scope
		return batch
	}
	validate := func(batch *agentv1.ConnectionsTelemetryBatchV1) ([]validatedConnectionsTelemetryRecord, error) {
		return validateConnectionsTelemetryBatch(batch, 1, 0, testNodeID, authorization, DefaultTelemetryConfig(), time.Now().UTC())
	}
	validated, err := validate(batchFor(scopedConnectionsEnvelope(testSecondTenantID, testSecondSiteID), proto.String(testSecondScopeID)))
	if err != nil || len(validated) != 1 || validated[0].tenantID != testSecondTenantID {
		t.Fatalf("scoped connections record = (%+v, %v)", validated, err)
	}
	for name, batch := range map[string]*agentv1.ConnectionsTelemetryBatchV1{
		"scope missing":           batchFor(scopedConnectionsEnvelope(testSecondTenantID, testSecondSiteID), nil),
		"tenant id sent as scope": batchFor(scopedConnectionsEnvelope(testSecondTenantID, testSecondSiteID), proto.String(testSecondTenantID)),
		"scope of other tenant":   batchFor(scopedConnectionsEnvelope(testSecondTenantID, testSecondSiteID), proto.String(testFirstScopeID)),
		"site of other tenant":    batchFor(scopedConnectionsEnvelope(testSecondTenantID, testTelemetrySiteID), proto.String(testSecondScopeID)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := validate(batch); err == nil {
				t.Fatal("misattributed scoped connections record was accepted")
			}
		})
	}
}

// controlPlaneMultiScopeTelemetryResponse is what control-api returns for a
// node holding several configuration scopes: no top-level tenant, and each
// site bound to its own scope and tenant (scope IDs differ from tenant IDs).
func controlPlaneMultiScopeTelemetryResponse() *controlv1.GetNodeAuthorizationResponse {
	response := multiTenantTelemetryResponse()
	response.TenantId = ""
	return response
}

type multiTenantTelemetryControl struct {
	*fakeControl
	response func() *controlv1.GetNodeAuthorizationResponse
}

func (c *multiTenantTelemetryControl) GetNodeAuthorization(
	_ context.Context,
	request *controlv1.GetNodeAuthorizationRequest,
) (*controlv1.GetNodeAuthorizationResponse, error) {
	response := multiTenantTelemetryResponse()
	if c.response != nil {
		response = c.response()
	}
	response.NodeId = request.NodeId
	response.AdministrativeState = controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_ACTIVE
	response.ConnectionAllowed = true
	response.AcceptedProtocolVersions = versionRange(1, 0)
	response.SnapshotExpirationTime = timestamppb.New(time.Now().Add(time.Hour))
	response.ArtifactEncryptionKeyId = "artifact-key"
	return response, nil
}

func scopedConnectionsStream(t *testing.T, scoped bool, batch *agentv1.ConnectionsTelemetryBatchV1) *telemetryTestStream {
	t.Helper()
	hello := telemetryHelloRequest(0, 1)
	hello.GetHello().ScopedRecords = scoped
	return &telemetryTestStream{ctx: authenticatedTestContext(t), requests: []*agentv1.StreamTelemetryRequest{
		hello, {
			Stream:  &commonv1.StreamMetadata{MessageId: uuid.NewString(), SentTime: timestamppb.Now(), Sequence: 2},
			Payload: &agentv1.StreamTelemetryRequest_ConnectionsBatch{ConnectionsBatch: batch},
		},
	}}
}

func TestStreamTelemetryNegotiatesScopedRecordsAndPublishesPerSiteTenant(t *testing.T) {
	publisher := &connectionsTelemetryCapturePublisher{result: TelemetryPublishResult{Stream: ConnectionsTelemetryIngestStream, Sequence: 9}}
	gateway := newTelemetryGateway(t, &multiTenantTelemetryControl{fakeControl: defaultFakeControl()}, publisher)
	batch := connectionsTelemetryBatch(scopedConnectionsEnvelope(testSecondTenantID, testSecondSiteID), "")
	batch.Records[0].ConfigurationScopeId = proto.String(testSecondScopeID)
	stream := scopedConnectionsStream(t, true, batch)
	if err := gateway.StreamTelemetry(stream); err != nil {
		t.Fatalf("scoped StreamTelemetry error = %v", err)
	}
	if len(stream.responses) != 2 || !stream.responses[0].GetHello().GetScopedRecords() || stream.responses[1].GetAck() == nil {
		t.Fatalf("scoped telemetry responses = %+v", stream.responses)
	}
	publications := publisher.publicationsSnapshot()
	if len(publications) != 1 || publications[0].TenantID != testSecondTenantID || publications[0].SiteID != testSecondSiteID {
		t.Fatalf("scoped publication = %+v, want tenant %s", publications, testSecondTenantID)
	}

	legacyPublisher := &connectionsTelemetryCapturePublisher{result: TelemetryPublishResult{Stream: ConnectionsTelemetryIngestStream, Sequence: 9}}
	legacyGateway := newTelemetryGateway(t, &multiTenantTelemetryControl{fakeControl: defaultFakeControl()}, legacyPublisher)
	legacy := scopedConnectionsStream(t, false, connectionsTelemetryBatch(validConnectionsTelemetryEnvelope(), ""))
	if err := legacyGateway.StreamTelemetry(legacy); err == nil {
		t.Fatal("legacy telemetry session was served a multi-tenant authorization")
	}
	if len(legacyPublisher.publicationsSnapshot()) != 0 {
		t.Fatal("legacy session published telemetry under a multi-tenant authorization")
	}
}

func TestControlPlaneMultiScopeAuthorizationAttributesTelemetryPerScope(t *testing.T) {
	response := controlPlaneMultiScopeTelemetryResponse()
	for _, site := range response.TelemetrySiteScopes {
		if site.ConfigurationScopeId == site.TenantId {
			t.Fatal("fixture must keep configuration scope and tenant IDs distinct")
		}
	}
	if _, err := validateTelemetryAuthorization(response, false); err == nil {
		t.Fatal("legacy session accepted a control-plane multi-scope authorization")
	}
	authorization, err := validateTelemetryAuthorization(response, true)
	if err != nil || authorization.tenantID != "" ||
		authorization.tenantByScope[testFirstScopeID] != testTelemetryTenantID ||
		authorization.tenantByScope[testSecondScopeID] != testSecondTenantID {
		t.Fatalf("scoped control-plane multi-scope authorization = (%+v, %v)", authorization, err)
	}

	stream := func(t *testing.T, scoped bool, batch *agentv1.ConnectionsTelemetryBatchV1) ([]TelemetryPublication, error) {
		t.Helper()
		publisher := &connectionsTelemetryCapturePublisher{result: TelemetryPublishResult{Stream: ConnectionsTelemetryIngestStream, Sequence: 9}}
		gateway := newTelemetryGateway(t, &multiTenantTelemetryControl{
			fakeControl: defaultFakeControl(), response: controlPlaneMultiScopeTelemetryResponse,
		}, publisher)
		err := gateway.StreamTelemetry(scopedConnectionsStream(t, scoped, batch))
		return publisher.publicationsSnapshot(), err
	}
	batchFor := func(tenantID, siteID string, scope *string) *agentv1.ConnectionsTelemetryBatchV1 {
		batch := connectionsTelemetryBatch(scopedConnectionsEnvelope(tenantID, siteID), "")
		batch.Records[0].ConfigurationScopeId = scope
		return batch
	}

	t.Run("record of scope A is published under tenant A", func(t *testing.T) {
		publications, err := stream(t, true, batchFor(testTelemetryTenantID, testTelemetrySiteID, proto.String(testFirstScopeID)))
		if err != nil || len(publications) != 1 || publications[0].TenantID != testTelemetryTenantID ||
			publications[0].SiteID != testTelemetrySiteID {
			t.Fatalf("scope A publication = (%+v, %v), want tenant %s", publications, err, testTelemetryTenantID)
		}
	})
	t.Run("record naming scope A with a site of scope B is rejected", func(t *testing.T) {
		publications, err := stream(t, true, batchFor(testTelemetryTenantID, testSecondSiteID, proto.String(testFirstScopeID)))
		if err == nil || len(publications) != 0 {
			t.Fatalf("cross-scope record = (%+v, %v), want rejection", publications, err)
		}
	})
	t.Run("legacy session is rejected", func(t *testing.T) {
		publications, err := stream(t, false, connectionsTelemetryBatch(validConnectionsTelemetryEnvelope(), ""))
		if err == nil || len(publications) != 0 {
			t.Fatalf("legacy session = (%+v, %v), want rejection", publications, err)
		}
	})
}
