//go:build integration

package edgepublish

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish/capabilitytest"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

func seedDynamicRoutingNode(t *testing.T, fixture *publishFixture, nodeID uuid.UUID) {
	t.Helper()
	if _, seeded := fixture.nodeKeys[nodeID]; seeded {
		t.Fatalf("node %s already has an identity", nodeID)
	}
	features := v2DefaultNodeFeatures()
	for _, feature := range features {
		if feature.Name == agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME {
			feature.ApiVersion = edgeconfig.DynamicRoutingSiteRuntimeVersion
		}
	}
	capabilitytest.SeedNodePublicationIdentityForTest(t, fixture.pool, fixture.scopeID, fixture.userID, nodeID,
		&agentv1.AgentCapabilities{AgentVersion: "1.0.35-d13", BuildId: "v9", OperatingSystem: "linux",
			Architecture: "amd64", Features: features}, publishTestClock.Add(-10*time.Minute), true)
	fixture.nodeKeys[nodeID] = nil
}

// Every target on site_runtime 9: the release is a v2 root requiring 9 whose
// members are the cdnca.edge.site/v2 objects (a v8 target keeps v8:
// TestTargetsRunDynamicRouting).
func TestDynamicRoutingPublicationOnlyForSiteRuntimeNineTargets(t *testing.T) {
	fixture := newPublishFixture(t)
	seedDynamicRoutingNode(t, fixture, fixture.nodeID)
	fixture.createSite(t, "dyn-a.example.test", 8080, false)
	fixture.createSite(t, "dyn-b.example.test", 8081, false)
	first, err := fixture.service.Publish(t.Context(), siteRuntimeV2PublishRequest(fixture, "v9-first", fixture.nodeID, siteRuntimeV2Schema))
	if err != nil {
		t.Fatalf("v9 publish: %v", err)
	}
	var rootWire []byte
	var mediaType string
	if err := fixture.pool.QueryRow(t.Context(), `SELECT wire_bytes,media_type FROM configuration_artifacts
		WHERE config_version_id=$1 AND encryption_algorithm='none'`, first.ConfigVersionID).Scan(&rootWire, &mediaType); err != nil {
		t.Fatal(err)
	}
	root, err := siteobject.ParseRootV2(rootWire)
	if mediaType != siteobject.RootMediaTypeV2 || err != nil {
		t.Fatalf("root %s: %v", mediaType, err)
	}
	var deploymentID uuid.UUID
	var commandBytes []byte
	if err := fixture.pool.QueryRow(t.Context(), `SELECT id,command_bytes FROM node_deployments WHERE rollout_id=$1`,
		first.RolloutID).Scan(&deploymentID, &commandBytes); err != nil {
		t.Fatal(err)
	}
	var members []byte
	if err := fixture.pool.QueryRow(t.Context(), `SELECT member_sha256 FROM edge_site_object_publications
		WHERE config_version_id=$1`, first.ConfigVersionID).Scan(&members); err != nil {
		t.Fatal(err)
	}
	// scope + bucket + 2 sites at least
	if len(members) < 4*32 || len(root.Buckets) != 1 {
		t.Fatalf("%d members, %d buckets", len(members)/32, len(root.Buckets))
	}
	for _, capability := range root.RequiredCapabilities {
		if capability.Name == "site_runtime" && capability.APIVersion != 9 {
			t.Fatalf("root requires site_runtime %d", capability.APIVersion)
		}
	}
	tx, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	required, v2, err := edgedeployment.SiteRuntimeV2ConfigCapabilitiesTx(t.Context(), tx, fixture.scopeID, first.ConfigVersionID)
	_ = tx.Rollback(t.Context())
	if err != nil || !v2 || siteRuntimeCapability(required, agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME) != 9 {
		t.Fatalf("rollout capabilities %v %v %v", required, v2, err)
	}
	command := new(agentv1.DeploymentCommand)
	if err := proto.Unmarshal(commandBytes, command); err != nil || len(command.Artifacts) != 2 ||
		command.Artifacts[0].MediaType != siteobject.RootMediaTypeV2 ||
		siteRuntimeCapability(command.RequiredCapabilities, agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME) != 9 {
		t.Fatalf("deployment %s command: %v", deploymentID, err)
	}

}

// D13-b2 1: an error page / origin auth publication queues the scope's system
// republication only while its latest release is a dynamic routing (v2 root)
// one; the triggers fit the 416 checks (heads, attempts, segments).
func TestSiteFactsRepublicationOnlyForDynamicRoutingScopes(t *testing.T) {
	fixture := newPublishFixture(t)
	fixture.createSite(t, "facts-a.example.test", 8080, false)
	queued := func() []string {
		var triggers []string
		err := fixture.pool.QueryRow(t.Context(), `SELECT triggers FROM edge_system_republication_heads WHERE scope_id=$1`,
			fixture.scopeID).Scan(&triggers)
		if err != nil {
			return nil
		}
		return triggers
	}
	request := func(trigger string) {
		t.Helper()
		tx, err := fixture.pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if err := RequestSiteFactsRepublicationTx(t.Context(), tx, fixture.scopeID, trigger); err != nil {
			_ = tx.Rollback(t.Context())
			t.Fatalf("%s: %v", trigger, err)
		}
		if err := tx.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	// no publication yet: nothing to redeliver
	request(SystemTriggerErrorPagePublished)
	if got := queued(); got != nil {
		t.Fatalf("queued without a publication: %v", got)
	}
	seedDynamicRoutingNode(t, fixture, fixture.nodeID)
	if _, err := fixture.service.Publish(t.Context(), siteRuntimeV2PublishRequest(fixture, "facts-v9", fixture.nodeID, siteRuntimeV2Schema)); err != nil {
		t.Fatalf("v9 publish: %v", err)
	}
	request(SystemTriggerErrorPagePublished)
	request(SystemTriggerOriginAuthPublished)
	got := queued()
	if len(got) != 2 || got[0] != SystemTriggerErrorPagePublished || got[1] != SystemTriggerOriginAuthPublished {
		t.Fatalf("queued triggers %v", got)
	}
	// both triggers are allowed as a revision segment source
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO edge_system_revision_segments(scope_id,from_revision,to_revision,source,recorded_at)
		VALUES($1,1000,1001,$2,clock_timestamp()),($1,1001,1002,$3,clock_timestamp())`, fixture.scopeID,
		SystemTriggerErrorPagePublished, SystemTriggerOriginAuthPublished); err != nil {
		t.Fatalf("segment sources: %v", err)
	}
}
