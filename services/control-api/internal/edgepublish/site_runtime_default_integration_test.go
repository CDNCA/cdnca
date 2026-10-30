//go:build integration

package edgepublish

import (
	"errors"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish/capabilitytest"
	"google.golang.org/protobuf/proto"
)

// 1.0.35 default: a manual publication that does not choose a site runtime
// (the HTTP API never does) is site runtime v2, also for a plain HTTP scope
// that v1 could express; a node without the site runtime the document needs
// is refused by name and nothing is persisted (no fallback to v1).
func TestManualPublishDefaultsToSiteRuntimeV2AndRefusesOlderNodeByName(t *testing.T) {
	t.Run("capable node gets v2", func(t *testing.T) {
		fixture := newPublishFixture(t)
		fixture.createSite(t, "default-v2.example.test", 8080, false)
		key := seedV2DefaultNode(t, fixture, fixture.nodeID)
		request := fixture.publishRequest("default-v2", fixture.nodeID)
		request.SiteRuntimeSchema = ""
		result, err := fixture.service.Publish(t.Context(), request)
		if err != nil {
			t.Fatalf("default publish: %v", err)
		}
		document := decodeReceivedV2Document(t, receivedV2Bundle(t, fixture, result, fixture.nodeID, key))
		if document.Schema != siteRuntimeV2Schema || len(document.Sites) != 1 ||
			document.Sites[0].Domains[0] != "default-v2.example.test" {
			t.Fatalf("default publication document = %+v", document)
		}
	})
	t.Run("site runtime 5 node is refused by name", func(t *testing.T) {
		fixture := newPublishFixture(t)
		fixture.createSite(t, "default-v2-old-node.example.test", 8080, false)
		features := v2DefaultNodeFeatures()
		for index, feature := range features {
			if feature.Name == agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME {
				features[index] = proto.Clone(feature).(*agentv1.Capability)
				features[index].ApiVersion = 5
			}
		}
		capabilitytest.SeedNodePublicationIdentityForTest(t, fixture.pool, fixture.scopeID, fixture.userID, fixture.nodeID,
			&agentv1.AgentCapabilities{AgentVersion: "1.0.34", BuildId: "default-v2-old", OperatingSystem: "linux",
				Architecture: "amd64", Features: features}, publishTestClock.Add(-10*time.Minute), true)
		seedNodeSessionCapabilitiesForTest(t, fixture.pool, fixture.nodeID, "1.0.34", features)
		request := fixture.publishRequest("default-v2-old-node", fixture.nodeID)
		request.SiteRuntimeSchema = ""
		_, err := fixture.service.Publish(t.Context(), request)
		var refusal *TargetCapabilityError
		if !errors.As(err, &refusal) || !errors.Is(err, ErrTargetIneligible) || refusal.NodeID != fixture.nodeID ||
			refusal.AgentVersion != "1.0.34" || refusal.Capability != agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME ||
			refusal.Required < siteRuntimeV6APIVersion || refusal.Advertised != 5 {
			t.Fatalf("site runtime 5 node: err=%v, want a TargetCapabilityError naming it", err)
		}
		assertPublishState(t, fixture.pool, 0, 0, 0, 0, 0)
	})
}

// A publication of the default site runtime can be rolled back: the rollback
// rollout requires exactly the capabilities of the version it restores
// (edgedeployment requireReleasableConfig compares them with the document).
// The command carries no artifact; the node restores its retained version.
func TestSiteRuntimeV2PublicationRollsBackToPreviousVersion(t *testing.T) {
	fixture := newPublishFixture(t)
	fixture.createSite(t, "default-v2-rollback.example.test", 8080, false)
	seedV2DefaultNode(t, fixture, fixture.nodeID)
	publish := func(key string) PublishResult {
		t.Helper()
		request := fixture.publishRequest(key, fixture.nodeID)
		request.SiteRuntimeSchema = ""
		result, err := fixture.service.Publish(t.Context(), request)
		if err != nil {
			t.Fatalf("publish %s: %v", key, err)
		}
		return result
	}
	first := publish("default-v2-rollback-first")
	finishPublishDeployment(t, fixture, first, &first.ConfigVersionID, nil)
	fixture.createSite(t, "default-v2-rollback-second.example.test", 8081, false)
	second := publish("default-v2-rollback-second")
	finishPublishDeployment(t, fixture, second, &second.ConfigVersionID, &first.ConfigVersionID)

	rollback := fixture.rollbackRequest("default-v2-rollback", first.PublicationID, fixture.nodeID)
	result, err := fixture.service.Rollback(t.Context(), rollback)
	if err != nil {
		t.Fatalf("rollback of a site runtime v2 publication: %v", err)
	}
	command := readL4V2ContractCommand(t, fixture, result.RolloutID)
	siteRuntime := uint32(0)
	for _, capability := range command.RequiredCapabilities {
		if capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME {
			siteRuntime = capability.ApiVersion
		}
	}
	if result.ConfigVersionID != first.ConfigVersionID || command.Action != agentv1.DeploymentAction_DEPLOYMENT_ACTION_ROLLBACK ||
		len(command.Artifacts) != 0 || siteRuntime < siteRuntimeV6APIVersion {
		t.Fatalf("rollback config=%s command action=%s artifacts=%d site_runtime=%d",
			result.ConfigVersionID, command.Action, len(command.Artifacts), siteRuntime)
	}
	// Replays return the same rollout.
	replayed, err := fixture.service.Rollback(t.Context(), rollback)
	if err != nil || !replayed.Replayed || replayed.RolloutID != result.RolloutID {
		t.Fatalf("rollback replay = %+v, %v", replayed, err)
	}
}
