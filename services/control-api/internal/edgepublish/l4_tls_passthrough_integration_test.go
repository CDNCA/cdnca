//go:build integration

package edgepublish

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
)

// L4TLSPassthroughSaves is a scope the caller saves streams into through the
// real l4forward service. TLSWebsitePort is 0 when the scope has no TLS
// website.
type L4TLSPassthroughSaves struct {
	Pool                             *pgxpool.Pool
	ScopeID, UserID, SubscriptionID  uuid.UUID
	SiteID                           uuid.UUID
	PlainWebsitePort, TLSWebsitePort uint16
}

// NewL4TLSPassthroughScope returns a scope with a plaintext website on 18081
// and, when tlsWebsite, a TLS website on 18443, plus a check that publishes
// the scope as site runtime v2: a node declaring tcp/udp 3 is refused, one
// declaring 12 (every live stream, 1.0.35 baseline) gets a persisted release
// with wantPassthrough passthrough
// streams. Only scopes without the TLS website publish here: this helper does
// not seed a certificate binding for the TLS website. Seeding one does work in
// this package (seedSiteRuntimeV2CertificateBinding, which adds the legacy
// publication intent that migration 116 requires since 570a0dac); a caller that
// needs to publish the TLS scope should seed it the same way.
func NewL4TLSPassthroughScope(t *testing.T, tlsWebsite bool) (L4TLSPassthroughSaves, func(wantPassthrough int)) {
	t.Helper()
	fixture := newL4V2ContractFixture(t)
	saves := L4TLSPassthroughSaves{Pool: fixture.pool, ScopeID: fixture.scopeID, UserID: fixture.userID,
		SubscriptionID: fixture.subscriptionID, PlainWebsitePort: 18081}
	saves.SiteID = fixture.createSite(t, "passthrough-plain.example.com", 18081, false).Site.ID
	if tlsWebsite {
		fixture.createSiteWithPortSets(t, "passthrough-site.example.com", []string{"18082"}, []string{"18443"}, true)
		saves.TLSWebsitePort = 18443
	}
	return saves, func(wantPassthrough int) {
		t.Helper()
		if tlsWebsite {
			t.Fatal("publication check needs a scope without the TLS website")
		}
		checkL4TLSPassthroughPublication(t, fixture, wantPassthrough)
	}
}

// seedNodeSessionCapabilitiesForTest records what nodeID declared on its
// latest Connect session. Only the capability snapshot matters here; the
// fixture node has no certificate row for the session to reference.
func seedNodeSessionCapabilitiesForTest(t *testing.T, pool *pgxpool.Pool, nodeID uuid.UUID, agentVersion string,
	features []*agentv1.Capability) {
	t.Helper()
	sorted := slices.Clone(features)
	slices.SortFunc(sorted, func(left, right *agentv1.Capability) int { return int(left.Name) - int(right.Name) })
	snapshot, err := proto.MarshalOptions{Deterministic: true}.Marshal(&agentv1.AgentCapabilities{
		AgentVersion: agentVersion, BuildId: "test", OperatingSystem: "linux", Architecture: "amd64", Features: sorted})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(snapshot)
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO node_session_capabilities(node_id,session_epoch,certificate_id,
			certificate_sha256,artifact_key_id,selected_protocol_major,selected_protocol_minor,capabilities_snapshot,
			capabilities_sha256,facts_snapshot,facts_sha256,gateway_workload_identity,gateway_instance_id,registered_at)
			VALUES($1,COALESCE((SELECT max(session_epoch)+1 FROM node_session_capabilities WHERE node_id=$1),1),
			$2,$3,'k',1,0,$4,$3,'\x00',$3,'gw','gw-1',now())`, nodeID, uuid.New(), digest[:], snapshot)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func checkL4TLSPassthroughPublication(t *testing.T, fixture *publishFixture, wantPassthrough int) {
	t.Helper()
	features := func(l4 uint32) []*agentv1.Capability {
		return append(siteRuntimeV2CapabilitiesWithoutSiteRuntime(),
			&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME, ApiVersion: edgeconfig.DynamicRoutingSiteRuntimeVersion},
			&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY, ApiVersion: l4},
			&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY, ApiVersion: l4},
			&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_PROXY_PROTOCOL, ApiVersion: 1},
			// The fixture forwards are on the fixture package.
			&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_L4_PACKAGE_ATTRIBUTION, ApiVersion: edgeconfig.L4PackageAttributionAPIVersion})
	}
	// Each node declares its capabilities once, as the other v2 tests do.
	oldNode := *fixture
	oldNode.nodeID = uuid.New()
	seedPublishNode(t, fixture.pool, fixture.scopeID, fixture.userID, oldNode.nodeID)
	seedSiteRuntimeV2Capabilities(t, &oldNode, "", features(3))
	// A 1.0.33 node (tcp/udp 3 at enrollment and on its session) is refused,
	// naming the node and the feature: 1.0.35 forwards need tcp/udp v12.
	seedNodeSessionCapabilitiesForTest(t, fixture.pool, oldNode.nodeID, "1.0.33", features(3))
	_, err := fixture.service.Publish(t.Context(), siteRuntimeV2PublishRequest(fixture, "passthrough-v3", oldNode.nodeID,
		siteRuntimeV2Schema))
	var refusal *TargetCapabilityError
	if !errors.Is(err, ErrTargetIneligible) || !errors.As(err, &refusal) || refusal.NodeID != oldNode.nodeID ||
		refusal.AgentVersion != "1.0.33" || refusal.Required != 12 || refusal.Advertised != 3 {
		t.Fatalf("tcp/udp 3 node: err=%v, want a TargetCapabilityError naming it", err)
	}
	// Enrollment capabilities are frozen at first enrollment (renewal does not
	// refresh them): the node was enrolled by 1.0.33 and upgraded in place to
	// 1.0.35, so it declares tcp/udp 12 only on its session, and must get the release.
	seedSiteRuntimeV2Capabilities(t, fixture, "", features(3))
	seedNodeSessionCapabilitiesForTest(t, fixture.pool, fixture.nodeID, "1.0.35", features(12))
	result, err := fixture.service.Publish(t.Context(), siteRuntimeV2PublishRequest(fixture, "passthrough-v12", fixture.nodeID,
		siteRuntimeV2Schema))
	if err != nil {
		t.Fatalf("tcp/udp 12 node (enrolled at 3, upgraded in place): %v", err)
	}
	var raw []byte
	if err := fixture.pool.QueryRow(t.Context(), `SELECT canonical_snapshot FROM config_versions WHERE id=$1`,
		result.ConfigVersionID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var rollouts int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM node_deployments
		WHERE rollout_id=$1 AND node_id=$2`, result.RolloutID, fixture.nodeID).Scan(&rollouts); err != nil || rollouts != 1 {
		t.Fatalf("v12 node deployments=%d err=%v", rollouts, err)
	}
	// The version's telemetry identity is recorded for node authorization
	// (migration 295): one row per site, with the site's subscription (the
	// fixture site has none).
	var bound, matching int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*),
		count(*) FILTER (WHERE binding.package_subscription_id IS NOT DISTINCT FROM site.package_subscription_id)
		FROM config_version_telemetry_site_bindings binding JOIN sites site ON site.id=binding.site_id
		WHERE binding.config_version_id=$1`, result.ConfigVersionID).Scan(&bound, &matching); err != nil ||
		bound != 1 || matching != 1 {
		t.Fatalf("telemetry site bindings=%d matching the site's subscription=%d err=%v", bound, matching, err)
	}
	var document siteRuntimeV2Document
	if err := json.Unmarshal(raw, &document); err != nil || document.Streams == nil {
		t.Fatalf("compiled document: %v", err)
	}
	got := 0
	for _, stream := range document.Streams.StreamsV2 {
		if stream.TLSPassthrough {
			got++
			if len(stream.ServerNames) == 0 || !slices.IsSorted(stream.ServerNames) {
				t.Fatalf("passthrough stream projection: %+v", stream)
			}
		}
	}
	if got != wantPassthrough {
		t.Fatalf("passthrough streams=%d want %d", got, wantPassthrough)
	}
	if !slices.Contains(document.RequiredCapabilities, siteRuntimeV2Capability{Name: "tcp", APIVersion: 12}) ||
		!slices.Contains(document.RequiredCapabilities, siteRuntimeV2Capability{Name: "udp", APIVersion: 12}) {
		t.Fatalf("required capabilities=%v", document.RequiredCapabilities)
	}
}
