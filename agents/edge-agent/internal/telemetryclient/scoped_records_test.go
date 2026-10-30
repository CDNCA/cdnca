package telemetryclient

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

// Each site's configuration scope is a different UUID from its tenant.
type siteScopes map[string]string

func (scopes siteScopes) lookup(siteID string) (string, bool) {
	scope, ok := scopes[siteID]
	return scope, ok
}

func scopedTestRecord(t *testing.T, sequence uint64, kind, tenantID, siteID string) Record {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"schema_version": 1, "tenant_id": tenantID,
		"events": []map[string]any{{"site_id": siteID}}})
	if err != nil {
		t.Fatal(err)
	}
	if kind == "l4_session.v1" {
		payload, err = proto.MarshalOptions{Deterministic: true}.Marshal(&agentv1.L4SessionEnvelopeV1{TenantId: tenantID, SiteId: siteID})
		if err != nil {
			t.Fatal(err)
		}
	}
	return Record{
		Kind: kind, MessageID: "msg_" + uuid.NewString(), FirstSequence: sequence, LastSequence: sequence,
		LastEventID: uuid.NewString(), EventCount: 1, Payload: payload,
	}
}

func TestScopedWireBatchNamesEachRecordsSiteScope(t *testing.T) {
	tenantA, tenantB := uuid.NewString(), uuid.NewString()
	siteA, siteB := uuid.NewString(), uuid.NewString()
	scopeA, scopeB := uuid.NewString(), uuid.NewString()
	scopes := siteScopes{siteA: scopeA, siteB: scopeB}
	limits := sessionLimits{maxRecords: 8, maxRecordBytes: 1 << 20, maxBatchBytes: 4 << 20, scoped: true, scopeForSite: scopes.lookup}
	records := []Record{
		scopedTestRecord(t, 1, "access.v1", tenantA, siteA),
		scopedTestRecord(t, 2, "security.v2", tenantB, siteB),
		scopedTestRecord(t, 3, "l4_session.v1", tenantB, siteB),
	}
	wire, err := buildWireBatch(records, limits)
	if err != nil {
		t.Fatalf("buildWireBatch() error = %v", err)
	}
	for index, want := range []string{scopeA, scopeB, scopeB} {
		if got := wire.Records[index].GetConfigurationScopeId(); got != want {
			t.Fatalf("record %d scope = %q, want site scope %q (never the tenant)", index, got, want)
		}
	}
	if _, err := buildWireBatch([]Record{scopedTestRecord(t, 1, "access.v1", tenantA, uuid.NewString())}, limits); !errors.Is(err, ErrInvalidPublication) {
		t.Fatalf("record of an unknown site error = %v, want ErrInvalidPublication", err)
	}
	legacy, err := buildWireBatch(records, sessionLimits{maxRecords: 8, maxRecordBytes: 1 << 20, maxBatchBytes: 4 << 20})
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range legacy.Records {
		if record.ConfigurationScopeId != nil {
			t.Fatal("legacy session sent a record scope")
		}
	}

	envelope := connectionsTransportEnvelope()
	publication := connectionsTransportPublication(t, envelope)
	connectionsScope := uuid.NewString()
	scopes[envelope.GetSiteId()] = connectionsScope
	connections, err := buildConnectionsWireBatch([]ConnectionsRecord{{
		ReceiptID: publication.MessageID, Sequence: publication.FirstSequence, Envelope: envelope,
	}}, limits)
	if err != nil || connections.Records[0].GetConfigurationScopeId() != connectionsScope {
		t.Fatalf("connections record = (%+v, %v), want site scope %q", connections, err, connectionsScope)
	}
}

// A scoped session needs the Gateway to echo scoped_records; a Gateway that does not (one that predates scoped
// records, not supported from the 1.0.35 baseline) is a protocol violation, as is an echo the Agent did not request.
func TestClientRequiresGatewayToConfirmScopedRecords(t *testing.T) {
	for _, test := range []struct {
		name      string
		request   bool
		echo      bool
		wantScope bool
		wantErr   bool
	}{
		{name: "confirmed", request: true, echo: true, wantScope: true},
		{name: "gateway does not confirm", request: true, echo: false, wantErr: true},
		{name: "unrequested echo", request: false, echo: true, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var hello *agentv1.TelemetryClientHello
			var batch *agentv1.TelemetryBatch
			dialer, cleanup := startGateway(t, func(stream grpc.BidiStreamingServer[agentv1.StreamTelemetryRequest, agentv1.StreamTelemetryResponse]) error {
				request, err := stream.Recv()
				if err != nil {
					return err
				}
				hello = request.GetHello()
				response := validGatewayHello(1, 8)
				response.GetHello().ScopedRecords = test.echo
				if err := stream.Send(response); err != nil {
					return err
				}
				request, err = stream.Recv()
				if err != nil {
					return err
				}
				batch = request.GetBatch()
				last := batch.Records[len(batch.Records)-1]
				return stream.Send(ackResponse(2, batch.BatchId, uint32(len(batch.Records)), 0, last))
			})
			defer cleanup()
			config := DefaultConfig()
			config.NodeID, config.BootID, config.Cursor = testNodeID, uuid.NewString(), &fixedCursor{}
			site, scope := uuid.NewString(), uuid.NewString()
			config.ScopedRecords = test.request
			if test.request {
				config.ScopeForSite = siteScopes{site: scope}.lookup
			}
			client, err := New(config, dialer)
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Send(context.Background(), Batch{Records: []Record{scopedTestRecord(t, 1, "access.v1", uuid.NewString(), site)}})
			if test.wantErr {
				if !errors.Is(err, ErrPermanentProtocol) || batch != nil {
					t.Fatalf("scoped echo mismatch = (batch %v, %v), want ErrPermanentProtocol and no batch", batch != nil, err)
				}
				return
			}
			if err != nil || hello == nil || hello.ScopedRecords != test.request || batch == nil {
				t.Fatalf("session = (hello %+v, batch %+v, %v)", hello, batch, err)
			}
			if got := batch.Records[0].ConfigurationScopeId; test.wantScope && (got == nil || *got != scope) || !test.wantScope && got != nil {
				t.Fatalf("record scope = %v, want scoped=%v (%s)", got, test.wantScope, scope)
			}
		})
	}
}

func TestScopedRecordsRequireASiteScopeResolver(t *testing.T) {
	config := DefaultConfig()
	config.NodeID, config.BootID, config.Cursor = testNodeID, uuid.NewString(), &fixedCursor{}
	config.ScopedRecords = true
	if _, err := New(config, &bufDialer{}); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("scoped client without ScopeForSite error = %v, want ErrInvalidConfiguration", err)
	}
}
