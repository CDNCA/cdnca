//go:build integration

package edgepublish

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeartifact"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish/capabilitytest"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// A v2 publication is delivered as dynamic routing site objects: every
// node's command is [shared signed v2 root, its own key envelope] requiring
// site_runtime 9, the node opens the published objects from the stored
// objects, and the next publication stores only the objects that changed.
func TestSiteRuntimeV2PublicationDeliversSiteObjects(t *testing.T) {
	fixture := newPublishFixture(t)
	key := seedV2DefaultNode(t, fixture, fixture.nodeID)
	second := uuid.New()
	insertPublishNode(t, fixture.pool, fixture.scopeID, fixture.userID, second, "site-objects-second")
	secondKey := seedV2DefaultNode(t, fixture, second)
	fixture.createSite(t, "objects-a.example.test", 8080, false)
	fixture.createSite(t, "objects-b.example.test", 8081, false)
	request := siteRuntimeV2PublishRequest(fixture, "v8-objects-first", fixture.nodeID, siteRuntimeV2Schema)
	request.NodeIDs = []uuid.UUID{fixture.nodeID, second}
	first, err := fixture.service.Publish(t.Context(), request)
	if err != nil {
		t.Fatalf("first v8 publish: %v", err)
	}
	var objects, artifacts, roots int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM edge_site_objects WHERE configuration_scope_id=$1),
		(SELECT count(*) FROM configuration_artifacts WHERE config_version_id=$2),
		(SELECT count(*) FROM configuration_artifacts WHERE config_version_id=$2 AND media_type=$3)`,
		fixture.scopeID, first.ConfigVersionID, siteobject.RootMediaTypeV2).Scan(&objects, &artifacts, &roots); err != nil {
		t.Fatal(err)
	}
	// scope + 1 bucket + 2 sites (+ files), one root and one envelope per node.
	if objects < 4 || artifacts != 3 || roots != 1 {
		t.Fatalf("first publication stored %d objects, %d artifacts (%d roots)", objects, artifacts, roots)
	}
	var firstRoot string
	for _, node := range []struct {
		id  uuid.UUID
		key []byte
	}{{fixture.nodeID, key}, {second, secondKey}} {
		var deploymentID uuid.UUID
		if err := fixture.pool.QueryRow(t.Context(), `SELECT id FROM node_deployments WHERE rollout_id=$1 AND node_id=$2`,
			first.RolloutID, node.id).Scan(&deploymentID); err != nil {
			t.Fatal(err)
		}
		release, err := OpenSiteObjectReleaseForTest(t.Context(), fixture.pool, deploymentID, node.key)
		if err != nil {
			t.Fatalf("node %s: %v", node.id, err)
		}
		if siteRuntimeCapability(release.Command.RequiredCapabilities, agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME) !=
			edgeconfig.DynamicRoutingSiteRuntimeVersion || len(decodeReceivedV2Document(t, release.Bundle).Sites) != 2 {
			t.Fatalf("node %s release: capabilities %v", node.id, release.Command.RequiredCapabilities)
		}
		if firstRoot == "" {
			firstRoot = release.RootSHA256
		} else if release.RootSHA256 != firstRoot {
			t.Fatal("the two nodes received different roots")
		}
		// The other node's envelope does not open with this node's key.
		other := key
		if node.id == fixture.nodeID {
			other = secondKey
		}
		if _, err := OpenSiteObjectReleaseForTest(t.Context(), fixture.pool, deploymentID, other); err == nil {
			t.Fatalf("node %s's envelope opened with another node's key", node.id)
		}
	}
	finishPublishDeployment(t, fixture, first, &first.ConfigVersionID, nil)

	// A third site: only it, its bucket, the scope (changed telemetry
	// envelope) and new files are stored; the two old sites are reused.
	fixture.createSite(t, "objects-c.example.test", 8082, false)
	next, err := fixture.service.Publish(t.Context(), siteRuntimeV2PublishRequest(fixture, "v8-objects-second",
		fixture.nodeID, siteRuntimeV2Schema))
	if err != nil {
		t.Fatalf("second v8 publish: %v", err)
	}
	var added int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*)-$2 FROM edge_site_objects WHERE configuration_scope_id=$1`,
		fixture.scopeID, objects).Scan(&added); err != nil {
		t.Fatal(err)
	}
	var siteObjectsReused int
	if err := fixture.pool.QueryRow(t.Context(), `WITH first AS (
			SELECT substring(member_sha256 FROM i*32+1 FOR 32) AS sha256 FROM edge_site_object_publications,
			  generate_series(0, octet_length(member_sha256)/32-1) i WHERE config_version_id=$1),
		next AS (
			SELECT substring(member_sha256 FROM i*32+1 FOR 32) AS sha256 FROM edge_site_object_publications,
			  generate_series(0, octet_length(member_sha256)/32-1) i WHERE config_version_id=$2)
		SELECT count(*) FROM first JOIN next USING (sha256)
		JOIN edge_site_objects object ON object.sha256=first.sha256 AND object.kind='site'`,
		first.ConfigVersionID, next.ConfigVersionID).Scan(&siteObjectsReused); err != nil {
		t.Fatal(err)
	}
	if siteObjectsReused != 2 || added < 2 || added > 6 {
		t.Fatalf("second publication: %d objects added, %d site objects reused", added, siteObjectsReused)
	}
	if release := receivedV2Bundle(t, fixture, next, fixture.nodeID, key); len(decodeReceivedV2Document(t, release).Sites) != 3 {
		t.Fatal("the second release does not carry three sites")
	}
}

// A target node whose agent declares site runtime v7 cannot assemble site
// objects: the publication is refused naming it.
func TestSiteRuntimeV2PublicationRefusesSiteRuntimeV7Node(t *testing.T) {
	fixture := newPublishFixture(t)
	seedV2DefaultNode(t, fixture, fixture.nodeID)
	old := uuid.New()
	insertPublishNode(t, fixture.pool, fixture.scopeID, fixture.userID, old, "site-objects-v7")
	features := v2DefaultNodeFeatures()
	for _, feature := range features {
		if feature.Name == agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME {
			feature.ApiVersion = edgeconfig.LazyCertificateSiteRuntimeVersion
		}
	}
	capabilitytest.SeedNodePublicationIdentityForTest(t, fixture.pool, fixture.scopeID, fixture.userID, old,
		&agentv1.AgentCapabilities{AgentVersion: "1.0.35-g8b", BuildId: "v7", OperatingSystem: "linux",
			Architecture: "amd64", Features: features}, publishTestClock.Add(-10*time.Minute), true)
	fixture.createSite(t, "objects-old.example.test", 8080, false)
	request := siteRuntimeV2PublishRequest(fixture, "v8-objects-old-node", fixture.nodeID, siteRuntimeV2Schema)
	request.NodeIDs = []uuid.UUID{fixture.nodeID, old}
	_, err := fixture.service.Publish(t.Context(), request)
	var refusal *TargetCapabilityError
	if !errors.As(err, &refusal) || refusal.NodeID != old || refusal.Advertised != edgeconfig.LazyCertificateSiteRuntimeVersion ||
		!strings.Contains(err.Error(), fmt.Sprintf("site runtime v%d", edgeconfig.DynamicRoutingSiteRuntimeVersion)) {
		t.Fatalf("publish to a v7 node: %v", err)
	}
	var stored int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM edge_site_objects WHERE configuration_scope_id=$1`,
		fixture.scopeID).Scan(&stored); err != nil || stored != 0 {
		t.Fatalf("a refused publication stored %d objects: %v", stored, err)
	}
}

// Control serves a v8 deployment's objects only to its node, for its root,
// and only publication members; the stream opens and assembles the release.
func TestSiteObjectFetchAuthorizesDeploymentRootAndMembers(t *testing.T) {
	fixture := newPublishFixture(t)
	key := seedV2DefaultNode(t, fixture, fixture.nodeID)
	fixture.createSite(t, "fetch-a.example.test", 8080, false)
	fixture.createSite(t, "fetch-b.example.test", 8081, false)
	result, err := fixture.service.Publish(t.Context(), siteRuntimeV2PublishRequest(fixture, "v8-fetch",
		fixture.nodeID, siteRuntimeV2Schema))
	if err != nil {
		t.Fatal(err)
	}
	var deploymentID, eventID uuid.UUID
	if err := fixture.pool.QueryRow(t.Context(), `SELECT id,command_event_id FROM node_deployments
		WHERE rollout_id=$1 AND node_id=$2`, result.RolloutID, fixture.nodeID).Scan(&deploymentID, &eventID); err != nil {
		t.Fatal(err)
	}
	release, err := OpenSiteObjectReleaseForTest(t.Context(), fixture.pool, deploymentID, key)
	if err != nil {
		t.Fatal(err)
	}
	members := slices.Sorted(maps.Keys(release.Members))
	config := edgeartifact.DefaultConfig()
	config.MaxChunkBytes = 64 // several chunks per object
	store, err := edgeartifact.NewStoreWithClock(fixture.pool, config, func() time.Time { return publishTestClock })
	if err != nil {
		t.Fatal(err)
	}
	request := func(digests ...string) *controlv1.FetchSiteObjectsRequest {
		return &controlv1.FetchSiteObjectsRequest{
			Request: &commonv1.RequestMetadata{RequestId: uuid.NewString(), SentTime: timestamppb.New(publishTestClock)},
			EventId: eventID.String(), NodeId: fixture.nodeID.String(), DeploymentId: deploymentID.String(), Attempt: 1,
			RootSha256: release.RootSHA256, Sha256: digests, GatewayInstanceId: uuid.NewString(),
		}
	}
	fetch := func(value *controlv1.FetchSiteObjectsRequest) (map[string][]byte, error) {
		objects := map[string][]byte{}
		var order []string
		err := store.FetchSiteObjects(t.Context(), value, func(response *controlv1.FetchSiteObjectsResponse) error {
			chunk := response.Chunk
			if uint64(len(objects[chunk.Sha256])) != chunk.Offset || len(chunk.Data) > 64 {
				t.Fatalf("chunk %+v out of sequence", chunk)
			}
			if chunk.Offset == 0 {
				order = append(order, chunk.Sha256)
			}
			objects[chunk.Sha256] = append(objects[chunk.Sha256], chunk.Data...)
			return nil
		})
		if err == nil && !slices.Equal(order, value.Sha256) {
			t.Fatalf("objects streamed in order %v, requested %v", order, value.Sha256)
		}
		return objects, err
	}

	// Every member, in a non-sorted request order, ≤256 per request.
	requested := slices.Clone(members)
	slices.Reverse(requested)
	objects, err := fetch(request(requested...))
	if err != nil || len(objects) != len(members) {
		t.Fatalf("fetch members: %d objects, %v", len(objects), err)
	}
	var scopeID uuid.UUID
	if err := fixture.pool.QueryRow(t.Context(), `SELECT configuration_scope_id FROM config_versions WHERE id=$1`,
		result.ConfigVersionID).Scan(&scopeID); err != nil {
		t.Fatal(err)
	}
	// What was streamed is the stored ciphertext of each object.
	for digest, wire := range objects {
		raw, _ := hex.DecodeString(digest)
		var stored []byte
		if err := fixture.pool.QueryRow(t.Context(), `SELECT ciphertext FROM edge_site_objects
			WHERE configuration_scope_id=$1 AND sha256=$2`, scopeID, raw).Scan(&stored); err != nil || !bytes.Equal(stored, wire) {
			t.Fatalf("object %s differs from the stored ciphertext: %v", digest, err)
		}
	}

	notMember := strings.Repeat("f", 64)
	other := request(members[0])
	other.NodeId = uuid.NewString()
	wrongRoot := request(members[0])
	wrongRoot.RootSha256 = notMember
	wrongEvent := request(members[0])
	wrongEvent.EventId = uuid.NewString()
	for name, test := range map[string]struct {
		value *controlv1.FetchSiteObjectsRequest
		want  error
	}{
		"non-member digest": {request(members[0], notMember), edgeartifact.ErrSiteObjectNotMember},
		"another node":      {other, edgeartifact.ErrBindingConflict},
		"another root":      {wrongRoot, edgeartifact.ErrBindingConflict},
		"another event":     {wrongEvent, edgeartifact.ErrBindingConflict},
		"duplicate digest":  {request(members[0], members[0]), edgeartifact.ErrInvalidRequest},
	} {
		if _, err := fetch(test.value); !errors.Is(err, test.want) {
			t.Fatalf("%s: %v, want %v", name, err, test.want)
		}
	}
	// Once the deployment has moved past delivery nothing is served.
	finishPublishDeployment(t, fixture, result, &result.ConfigVersionID, nil)
	if _, err := fetch(request(members[0])); !errors.Is(err, edgeartifact.ErrDeploymentIneligible) {
		t.Fatalf("fetch after healthy: %v", err)
	}
}
