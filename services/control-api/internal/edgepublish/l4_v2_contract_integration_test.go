//go:build integration

package edgepublish

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
)

func newL4V2ContractFixture(t *testing.T) *publishFixture {
	t.Helper()
	fixture := newPublishFixture(t)
	if fixture.tenantID == fixture.scopeID {
		t.Fatal("fixture must distinguish tenant identity from access scope")
	}
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO role_permissions(role_id,permission_name)
		SELECT id,'streams.manage' FROM roles WHERE scope_id=$1 AND name='tenant_owner'
		ON CONFLICT DO NOTHING`, fixture.scopeID); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func CheckL4V2ContractLifecycleFixture(t *testing.T, mutations func(*pgxpool.Pool, uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID) []func() int64) {
	t.Helper()
	fixture := newL4V2ContractFixture(t)
	site := fixture.createSite(t, "l4-lifecycle.example.com", 18081, false).Site
	checkPublication := func(key string, tcpVersion, udpVersion uint32) {
		t.Helper()
		nodeID := uuid.New()
		seedPublishNode(t, fixture.pool, fixture.scopeID, fixture.userID, nodeID)
		result, err := fixture.service.Publish(t.Context(), fixture.publishRequest(key, nodeID))
		if err != nil {
			t.Fatal(err)
		}
		command := readL4V2ContractCommand(t, fixture, result.RolloutID)
		assertL4V2ContractProtocolVersions(t, command.RequiredCapabilities, tcpVersion, udpVersion)
	}
	checkPublication("pure-http", 0, 0)
	steps := mutations(fixture.pool, fixture.scopeID, fixture.userID, fixture.subscriptionID, site.ID)
	var createdRevision int64
	// A live stream requires its protocol at v12 (l4StreamCapabilityVersion,
	// 1.0.35 baseline); a protocol only in the scope's v2 history requires v2
	// to revoke it (loadL4V2LifecycleProtocols). Steps: create tcp, switch it
	// to udp, remove it.
	want := [][2]uint32{{12, 0}, {2, 12}, {2, 2}}
	for index, mutate := range steps {
		revision := mutate()
		if index == 0 {
			createdRevision = revision
		}
		checkPublication(fmt.Sprintf("lifecycle-%d", index), want[index][0], want[index][1])
	}
	tx, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	protocols, err := loadL4V2LifecycleProtocols(t.Context(), tx, fixture.scopeID, createdRevision)
	if err != nil || !slices.Equal(protocols, []l4ProtocolCapability{{"tcp", 2}}) {
		t.Fatalf("future source intents escaped revision bound: %v %v", protocols, err)
	}
	protocols, err = loadL4V2LifecycleProtocols(t.Context(), tx, fixture.platformScopeID, fixture.sourceRevision())
	if err != nil || len(protocols) != 0 {
		t.Fatalf("lifecycle requirements escaped scope: %v %v", protocols, err)
	}
	compiled := fixture.compileSiteRuntimeL4(t, tx, fixture.sourceRevision())
	if len(compiled.Streams) != 0 || compiled.Artifact != nil {
		t.Fatalf("removed listener remains in the release: streams=%+v", compiled.Streams)
	}
	assertL4V2ContractProtocolVersions(t, compiled.Capabilities, 2, 2)
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	fixture.createSite(t, "l4-lifecycle-v2.example.com", 18082, false)
	oldFixture := *fixture
	oldFixture.nodeID = uuid.New()
	seedPublishNode(t, fixture.pool, fixture.scopeID, fixture.userID, oldFixture.nodeID)
	oldFeatures := append(siteRuntimeV2NodeFeatures(),
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY, ApiVersion: 1},
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY, ApiVersion: 1})
	seedSiteRuntimeV2Capabilities(t, &oldFixture, "", oldFeatures)
	oldRequest := siteRuntimeV2PublishRequest(fixture, "lifecycle-http-v2-old", oldFixture.nodeID, siteRuntimeV2Schema)
	if _, err := fixture.service.Publish(t.Context(), oldRequest); !errors.Is(err, ErrTargetIneligible) {
		t.Fatalf("HTTP v2 removal accepted old L4 capability versions: %v", err)
	}
	var oldOutbox int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM edge_command_outbox WHERE node_id=$1`, oldFixture.nodeID).Scan(&oldOutbox); err != nil || oldOutbox != 0 {
		t.Fatalf("old target rejection persisted a command: count=%d err=%v", oldOutbox, err)
	}
	features := append(siteRuntimeV2NodeFeatures(),
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY, ApiVersion: 2},
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY, ApiVersion: 2})
	seedSiteRuntimeV2Capabilities(t, fixture, "", features)
	// Site runtime v2 carries the removed listeners' tcp/udp requirement in
	// its stream runtime (bindSiteRuntimeV2Streams), so a capable node gets
	// the HTTP replacement with the lifecycle capabilities signed in.
	request := siteRuntimeV2PublishRequest(fixture, "lifecycle-http-v2", fixture.nodeID, siteRuntimeV2Schema)
	result, err := fixture.service.Publish(t.Context(), request)
	if err != nil {
		t.Fatalf("HTTP v2 replacement refused a tcp/udp 2 node: %v", err)
	}
	assertL4V2ContractProtocolVersions(t, readL4V2ContractCommand(t, fixture, result.RolloutID).RequiredCapabilities, 2, 2)
	assertPublishState(t, fixture.pool, 5, 5, 5, 5, 5)
}

func TestL4V2ContractPureHTTPV2DoesNotRequireL4(t *testing.T) {
	fixture := newPublishFixture(t)
	fixture.createSite(t, "pure-http-v2.example.com", 18081, false)
	seedSiteRuntimeV2Capabilities(t, fixture, "", siteRuntimeV2NodeFeatures())
	result, err := fixture.service.Publish(t.Context(), siteRuntimeV2PublishRequest(fixture, "pure-http-v2", fixture.nodeID, siteRuntimeV2Schema))
	if err != nil {
		t.Fatal(err)
	}
	command := readL4V2ContractCommand(t, fixture, result.RolloutID)
	assertL4V2ContractProtocolVersions(t, command.RequiredCapabilities, 0, 0)
}

func readL4V2ContractCommand(t *testing.T, fixture *publishFixture, rolloutID uuid.UUID) *agentv1.DeploymentCommand {
	t.Helper()
	var commandBytes, outboxPayload []byte
	if err := fixture.pool.QueryRow(t.Context(), `SELECT deployment.command_bytes,outbox.payload
		FROM node_deployments deployment JOIN edge_command_outbox outbox
		ON outbox.deployment_id=deployment.id AND outbox.deployment_attempt=deployment.attempt
		WHERE deployment.rollout_id=$1`, rolloutID).Scan(&commandBytes, &outboxPayload); err != nil {
		t.Fatal(err)
	}
	command := new(agentv1.DeploymentCommand)
	if err := proto.Unmarshal(commandBytes, command); err != nil || !bytes.Equal(commandBytes, outboxPayload) {
		t.Fatalf("outbox does not carry the exact deployment command: %v", err)
	}
	return command
}

func assertL4V2ContractProtocolVersions(t *testing.T, capabilities []*agentv1.Capability, tcpVersion, udpVersion uint32) {
	t.Helper()
	versions := make(map[agentv1.CapabilityName]uint32)
	for index, capability := range capabilities {
		if index > 0 && capabilities[index-1].Name >= capability.Name {
			t.Fatalf("capabilities not uniquely ordered: %+v", capabilities)
		}
		versions[capability.Name] = capability.ApiVersion
	}
	if versions[agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY] != tcpVersion ||
		versions[agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY] != udpVersion {
		t.Fatalf("TCP/UDP requirements = %v, want %d/%d", versions, tcpVersion, udpVersion)
	}
}

func CheckL4V2ContractMutationFixture(t *testing.T, mutate func(*pgxpool.Pool, uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID) int64) {
	t.Helper()
	fixture := newL4V2ContractFixture(t)
	site := fixture.createSite(t, "l4-contract.example.com", 18081, false).Site
	sourceRevision := mutate(fixture.pool, fixture.scopeID, fixture.userID, fixture.subscriptionID, site.ID)
	readHistory := func() []byte {
		t.Helper()
		var history []byte
		if err := fixture.pool.QueryRow(t.Context(), `SELECT jsonb_build_object(
			'intents',(SELECT jsonb_agg(to_jsonb(intent) ORDER BY version) FROM l4_publish_intents intent WHERE scope_id=$1),
			'receipts',(SELECT jsonb_agg(to_jsonb(receipt) ORDER BY id) FROM l4_write_requests receipt WHERE target_scope_id=$1)
		)::text`, fixture.scopeID).Scan(&history); err != nil {
			t.Fatal(err)
		}
		return history
	}
	historyBefore := readHistory()
	tx, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	sourceStreams, err := loadStreamFacts(t.Context(), tx, fixture.scopeID)
	if err != nil {
		t.Fatal(err)
	}
	if len(sourceStreams) != 2 || sourceRevision == sourceStreams[0].Revision {
		t.Fatalf("fixture must distinguish source and resource revisions: source=%d streams=%+v", sourceRevision, sourceStreams)
	}
	assertSourceSnapshot := func(t *testing.T, snapshot []byte) {
		t.Helper()
		var document siteRuntimeV2Document
		if err := json.Unmarshal(snapshot, &document); err != nil || document.Streams == nil ||
			len(document.Streams.StreamsV2) != len(sourceStreams) {
			t.Fatalf("published streams = %+v err=%v", document.Streams, err)
		}
		for index, stream := range document.Streams.StreamsV2 {
			want := *sourceStreams[index].RuntimeV2
			want.TenantID, want.Geo.TenantID = fixture.tenantID.String(), fixture.tenantID.String()
			if !reflect.DeepEqual(stream, want) {
				t.Fatalf("published stream %d changed immutable stream facts: got=%+v want=%+v", index, stream, want)
			}
		}
	}
	assertBundle := func(t *testing.T, bundle edgeconfig.Bundle) {
		t.Helper()
		var wire struct {
			Revision int64                          `json:"revision"`
			Streams  []edgeconfig.L4StreamRuntimeV2 `json:"streams"`
		}
		if err := json.Unmarshal(bundle.Files[edgeconfig.L4RuntimeV2ArtifactPath], &wire); err != nil ||
			wire.Revision != sourceRevision || len(wire.Streams) != 2 {
			t.Fatalf("invalid projected stream set: %+v err=%v", wire, err)
		}
		for index, stream := range wire.Streams {
			if stream.TenantID != fixture.tenantID.String() || stream.Geo.TenantID != fixture.tenantID.String() ||
				stream.Revision != sourceStreams[index].Revision || stream.Geo.Revision != sourceStreams[index].Revision {
				t.Fatalf("invalid tenant/resource projection: %+v", stream)
			}
		}
	}
	t.Run("site runtime compiler", func(t *testing.T) {
		assertBundle(t, fixture.compileSiteRuntimeL4(t, tx, sourceRevision).Bundle())
	})
	for _, path := range [][]string{{"tenant_id"}, {"geo", "tenant_id"}} {
		t.Run("reject cross scope "+path[0], func(t *testing.T) {
			isolated, err := tx.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer isolated.Rollback(t.Context())
			_, err = isolated.Exec(t.Context(), `INSERT INTO l4_publish_intents(
				id,scope_id,stream_id,version,operation,desired_state,resource_revision,
				configuration_source_revision,runtime_spec,created_by_user_id,created_at)
				SELECT $4,scope_id,stream_id,
				(SELECT max(version)+1 FROM l4_publish_intents WHERE scope_id=$1),
				'update',desired_state,resource_revision,configuration_source_revision,
				jsonb_set(runtime_spec,$2::text[],to_jsonb($3::text)),created_by_user_id,clock_timestamp()
				FROM l4_publish_intents WHERE scope_id=$1 ORDER BY version DESC LIMIT 1`,
				fixture.scopeID, path, uuid.NewString(), uuid.New())
			var postgresError *pgconn.PgError
			if !errors.As(err, &postgresError) || postgresError.Code != "23514" || postgresError.ConstraintName != l4RuntimeSpecConstraint {
				t.Fatalf("cross-scope %v source must be rejected by the existing runtime constraint: %v", path, err)
			}
		})
	}
	t.Run("real publication entry point", func(t *testing.T) {
		request := fixture.publishRequest("l4-v2-contract-publish", fixture.nodeID)
		result, err := fixture.service.Publish(t.Context(), request)
		if err != nil {
			t.Fatalf("real publication of committed L4 v2 mutations failed: %v", err)
		}
		// The node receives the scope's L4 v2 stream set in its scope object.
		release := receivedV2Release(t, fixture, result, fixture.nodeID, fixture.nodeKeys[fixture.nodeID])
		assertSourceSnapshot(t, release.Bundle.Files["site-runtime.v2.json"])
		if release.Scope.Streams == nil {
			t.Fatal("scope object carries no streams")
		}
		_, files, err := edgeconfig.RenderSharedStreamFragment(release.Root.ConfigVersionID, uint64(release.Root.SourceRevision),
			*release.Scope.Streams, 0, nil)
		if err != nil {
			t.Fatal(err)
		}
		assertBundle(t, edgeconfig.Bundle{Files: files})
		command := readL4V2ContractCommand(t, fixture, result.RolloutID)
		assertL4V2ContractProtocolVersions(t, command.RequiredCapabilities, 12, 12)
		replayed, err := fixture.service.Publish(t.Context(), request)
		if err != nil || !replayed.Replayed || replayed.ArtifactSHA256 != result.ArtifactSHA256 || replayed.CanonicalSnapshotSHA256 != result.CanonicalSnapshotSHA256 {
			t.Fatalf("publication replay changed immutable artifact: %+v err=%v", replayed, err)
		}
	})
	if !bytes.Equal(readHistory(), historyBefore) {
		t.Fatal("publication rewrote immutable L4 intents or write receipts")
	}
}
