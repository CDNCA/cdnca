//go:build integration

package edgepublish

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"github.com/google/uuid"
)

// v2DefaultNodeFeatures is what a 1.0.35 edge agent declares
// (agents/edge-agent/cmd/edge-agent/daemon.go siteRuntimeCapabilities).
func v2DefaultNodeFeatures() []*agentv1.Capability {
	return append(siteRuntimeV2CapabilitiesWithoutSiteRuntime(),
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME, ApiVersion: edgeconfig.MaxSiteRuntimeVersion},
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY, ApiVersion: 12},
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY, ApiVersion: 12},
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_PROXY_PROTOCOL, ApiVersion: 1},
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_CC, ApiVersion: 4},
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_WAF, ApiVersion: 1},
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE, ApiVersion: 1},
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_CONFIG_PRECHECK, ApiVersion: 1},
		// Fixture forwards are on the fixture package.
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_L4_PACKAGE_ATTRIBUTION, ApiVersion: 1})
}

// seedV2DefaultNode declares a 1.0.35 node and returns its artifact private key.
func seedV2DefaultNode(t *testing.T, fixture *publishFixture, nodeID uuid.UUID) []byte {
	t.Helper()
	key := fixture.ensureV2Node(nodeID)
	if key == nil {
		t.Fatalf("node %s was registered outside the fixture; its artifact key is unknown", nodeID)
	}
	return key
}

// receivedV2Bundle is the published v2 document of the release the node
// receives for a rollout (receivedV2Release).
func receivedV2Bundle(t *testing.T, fixture *publishFixture, result PublishResult, nodeID uuid.UUID, privateKey []byte) edgeconfig.Bundle {
	t.Helper()
	return receivedV2Release(t, fixture, result, nodeID, privateKey).Bundle
}

// receivedV2Release opens the dynamic routing release the node receives for
// a rollout, as the node does (OpenSiteObjectReleaseForTest).
func receivedV2Release(t *testing.T, fixture *publishFixture, result PublishResult, nodeID uuid.UUID, privateKey []byte) SiteObjectReleaseForTest {
	t.Helper()
	var deploymentID uuid.UUID
	if err := fixture.pool.QueryRow(t.Context(), `SELECT id FROM node_deployments
		WHERE rollout_id=$1 AND node_id=$2`, result.RolloutID, nodeID).Scan(&deploymentID); err != nil {
		t.Fatalf("node %s has no deployment: %v", nodeID, err)
	}
	release, err := OpenSiteObjectReleaseForTest(t.Context(), fixture.pool, deploymentID, privateKey)
	if err != nil {
		t.Fatalf("node %s cannot assemble its release: %v", nodeID, err)
	}
	return release
}

func decodeReceivedV2Document(t *testing.T, bundle edgeconfig.Bundle) siteRuntimeV2Document {
	t.Helper()
	var document siteRuntimeV2Document
	if err := json.Unmarshal(bundle.Files["site-runtime.v2.json"], &document); err != nil {
		t.Fatal(err)
	}
	return document
}

// Gap 7: like v1's AllowEmpty, an empty scope publishes a v2 withdrawal (the
// node keeps only its health server) and an L4-only scope publishes its
// streams without any website.
func TestSiteRuntimeV2PublishesEmptyWithdrawalAndL4OnlyScope(t *testing.T) {
	t.Run("empty scope", func(t *testing.T) {
		fixture := newPublishFixture(t)
		key := seedV2DefaultNode(t, fixture, fixture.nodeID)
		result, err := fixture.service.Publish(t.Context(), siteRuntimeV2PublishRequest(
			fixture, "v2-empty-withdrawal", fixture.nodeID, siteRuntimeV2Schema))
		if err != nil {
			t.Fatalf("empty v2 withdrawal publish error = %v", err)
		}
		bundle := receivedV2Bundle(t, fixture, result, fixture.nodeID, key)
		document := decodeReceivedV2Document(t, bundle)
		if document.Sites == nil || len(document.Sites) != 0 || document.Streams != nil {
			t.Fatalf("withdrawal document = %+v", document)
		}
		if len(bundle.Files) != 1 {
			t.Fatalf("withdrawal bundle files = %v, want only the runtime document", len(bundle.Files))
		}
	})
	t.Run("L4 only scope", func(t *testing.T) {
		fixture := newPublishFixture(t)
		key := seedV2DefaultNode(t, fixture, fixture.nodeID)
		stream := fixture.createStream(t, "l4-only", 19000, "198.51.100.40", 9000)
		result, err := fixture.service.Publish(t.Context(), siteRuntimeV2PublishRequest(
			fixture, "v2-l4-only", fixture.nodeID, siteRuntimeV2Schema))
		if err != nil {
			t.Fatalf("L4-only v2 publish error = %v", err)
		}
		document := decodeReceivedV2Document(t, receivedV2Bundle(t, fixture, result, fixture.nodeID, key))
		if len(document.Sites) != 0 || document.Streams == nil || len(document.Streams.StreamsV2) != 1 ||
			document.Streams.StreamsV2[0].Listener.Port != 19000 || stream.Forward.ID == uuid.Nil {
			t.Fatalf("L4-only document = %+v", document)
		}
	})
}

// activateTestSystemConfiguration activates a platform system configuration
// with the given worker_processes through the real draft/preflight/activate
// state machine (no edge publisher: the test publishes itself).
func activateTestSystemConfiguration(t *testing.T, fixture *publishFixture, workers int) int64 {
	t.Helper()
	return activateTestSystemConfigurationWith(t, fixture, func(configuration *systemconfig.Configuration) {
		configuration.Nginx.WorkerProcesses = workers
	})
}

func activateTestSystemConfigurationWith(t *testing.T, fixture *publishFixture, mutate func(*systemconfig.Configuration)) int64 {
	t.Helper()
	ctx := t.Context()
	if _, err := fixture.pool.Exec(ctx, `INSERT INTO role_permissions(role_id,permission_name)
		SELECT assignment.role_id,name FROM role_assignments assignment
		CROSS JOIN (VALUES ('system_configuration.read'),('system_configuration.manage')) AS permission(name)
		WHERE assignment.scope_id=$1 AND assignment.user_id=$2 ON CONFLICT DO NOTHING`,
		fixture.platformScopeID, fixture.platformUserID); err != nil {
		t.Fatal(err)
	}
	service, err := systemconfig.NewServiceWithDependencies(fixture.pool, audit.New(fixture.pool), func() time.Time { return time.Now().UTC() })
	if err != nil {
		t.Fatal(err)
	}
	manager, err := systemconfig.NewCategoryManager(service, nil)
	if err != nil {
		t.Fatal(err)
	}
	actor := systemconfig.Actor{UserID: fixture.platformUserID, ScopeID: fixture.platformScopeID, ScopeKind: "platform"}
	head, active := int64(0), int64(0)
	if current, err := service.GetActive(ctx, actor); err == nil {
		active = current.Revision
	}
	_ = fixture.pool.QueryRow(ctx, `SELECT head_revision FROM system_configuration_streams WHERE platform_scope_id=$1`,
		fixture.platformScopeID).Scan(&head)
	configuration := systemconfig.ProjectBootstrapConfiguration()
	mutate(&configuration)
	key := "g11-v2-system-" + uuid.NewString()
	draft, err := service.CreateDraft(ctx, actor, systemconfig.CreateDraftRequest{
		ExpectedHeadRevision: head, Configuration: configuration, IdempotencyKey: key + "-draft", RequestID: key + "-draft"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.PreflightRevision(ctx, actor, systemconfig.PreflightRevisionRequest{Revision: draft.Revision,
		SnapshotSHA256: draft.SnapshotSHA256, IdempotencyKey: key + "-preflight", RequestID: key + "-preflight"}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Activate(ctx, actor, systemconfig.ActivateRequest{Revision: draft.Revision,
		ExpectedActiveRevision: active, IdempotencyKey: key + "-activate", RequestID: key + "-activate"}); err != nil {
		t.Fatal(err)
	}
	return draft.Revision
}

// Gap 6: every v2 publication carries the platform's active system
// configuration, not only the activation's own publication.
func TestSiteRuntimeV2CarriesActiveSystemConfiguration(t *testing.T) {
	fixture := newPublishFixture(t)
	key := seedV2DefaultNode(t, fixture, fixture.nodeID)
	fixture.createSite(t, "system-config-v2.example.test", 80, false)
	first, err := fixture.service.Publish(t.Context(), siteRuntimeV2PublishRequest(
		fixture, "v2-system-none", fixture.nodeID, siteRuntimeV2Schema))
	if err != nil {
		t.Fatal(err)
	}
	if document := decodeReceivedV2Document(t, receivedV2Bundle(t, fixture, first, fixture.nodeID, key)); document.System != nil {
		t.Fatalf("system block without an active system configuration: %+v", document.System)
	}
	revision := activateTestSystemConfiguration(t, fixture, 6)
	fixture.createSite(t, "system-config-v2-second.example.test", 8080, false)
	// The first node still runs its deployment; publish to a second one.
	second := uuid.New()
	seedPublishNode(t, fixture.pool, fixture.scopeID, fixture.userID, second)
	secondKey := seedV2DefaultNode(t, fixture, second)
	result, err := fixture.service.Publish(t.Context(), siteRuntimeV2PublishRequest(
		fixture, "v2-system-active", second, siteRuntimeV2Schema))
	if err != nil {
		t.Fatal(err)
	}
	document := decodeReceivedV2Document(t, receivedV2Bundle(t, fixture, result, second, secondKey))
	if document.System == nil || document.System.Revision != revision ||
		document.System.PlatformScopeID != fixture.platformScopeID.String() || document.System.Nginx.WorkerProcesses != 6 {
		t.Fatalf("tenant publication system block = %+v, want active revision %d", document.System, revision)
	}
}
