//go:build integration

package artifactsetdist

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/audit/audittest"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgestatus"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type distHarness struct {
	t           *testing.T
	ctx         context.Context
	pool        *pgxpool.Pool
	distributor *Distributor
	source      *staticSource
	status      *edgestatus.Store
	validator   *edgestatus.Validator
	public      ed25519.PublicKey
	signer      testSigner
	clock       time.Time
	// node runs the simulated agent's object store and active set.
	objects             map[string][]byte
	// reject: item artifact ID -> reason the simulated agent's installer refuses it with
	reject              map[string]string
	active              *artifactset.Set
	activeSHA           string
	nodeID, plainNodeID uuid.UUID
}

func newDistHarness(t *testing.T) *distHarness {
	t.Helper()
	pool := databasetest.ClonedMigratedPool(t, nil)
	if pool == nil {
		t.Skip("TEST_DATABASE_TEMPLATE is required (scripts/control-api-integration-sharded.sh)")
	}
	ctx := t.Context()
	harness := &distHarness{t: t, ctx: ctx, pool: pool, source: &staticSource{}, objects: map[string][]byte{},
		clock: time.Now().UTC(), nodeID: uuid.New(), plainNodeID: uuid.New()}
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	harness.public, harness.signer = public, testSigner{id: "edge-key", private: private}
	deployments, err := edgedeployment.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	harness.distributor, err = New(Config{Pool: pool, Deployments: deployments, Source: harness.source,
		Signer: testSigner{id: "edge-key", private: private}, RetryAfter: 10 * time.Minute,
		Now: func() time.Time { return harness.clock }})
	if err != nil {
		t.Fatal(err)
	}
	if harness.status, err = edgestatus.NewStore(pool); err != nil {
		t.Fatal(err)
	}
	if harness.validator, err = edgestatus.NewValidator(edgestatus.DefaultValidatorConfig()); err != nil {
		t.Fatal(err)
	}
	tenantID, tenantScope, userID := uuid.New(), uuid.New(), uuid.New()
	harness.exec(`INSERT INTO tenants (id, display_name) VALUES ($1, 'artifact set tenant')`, tenantID)
	harness.exec(`INSERT INTO access_scopes (id, kind, tenant_id) VALUES ($1, 'tenant', $2)`, tenantScope, tenantID)
	harness.exec(`INSERT INTO access_scopes (id, kind) SELECT $1, 'platform'
		WHERE NOT EXISTS (SELECT 1 FROM access_scopes WHERE kind='platform')`, uuid.New())
	harness.exec(`INSERT INTO users (id, username, display_name, password_hash) VALUES ($1, $2, 'artifact set', 'unused')`,
		userID, "artifact-set-"+strings.ReplaceAll(userID.String(), "-", "")[:12])
	for index, nodeID := range []uuid.UUID{harness.nodeID, harness.plainNodeID} {
		harness.exec(`INSERT INTO nodes (id, scope_id, name, admin_state, created_by_user_id, display_id)
			VALUES ($1, $2, $3, 'active', $4, $5)`, nodeID, tenantScope, "artifact-set-"+nodeID.String()[:8], userID, index+1)
	}
	harness.session(harness.nodeID, 1, &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_ARTIFACT_SET, ApiVersion: 1})
	harness.session(harness.plainNodeID, 1, &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1, ApiVersion: 1})
	return harness
}

func (harness *distHarness) exec(query string, args ...any) {
	harness.t.Helper()
	if _, err := harness.pool.Exec(harness.ctx, query, args...); err != nil {
		harness.t.Fatal(err)
	}
}

func (harness *distHarness) session(nodeID uuid.UUID, epoch int, features ...*agentv1.Capability) {
	harness.t.Helper()
	harness.sessionWith(nodeID, epoch, &agentv1.AgentCapabilities{AgentVersion: "1.0.35", Features: features})
}

func (harness *distHarness) sessionWith(nodeID uuid.UUID, epoch int, capabilities *agentv1.AgentCapabilities) {
	harness.t.Helper()
	snapshot, err := proto.MarshalOptions{Deterministic: true}.Marshal(capabilities)
	if err != nil {
		harness.t.Fatal(err)
	}
	digest := sha256.Sum256(snapshot)
	if err := pgx.BeginFunc(harness.ctx, harness.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(harness.ctx, `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(harness.ctx, `INSERT INTO node_session_capabilities(node_id,session_epoch,certificate_id,certificate_sha256,
			artifact_key_id,selected_protocol_major,selected_protocol_minor,capabilities_snapshot,capabilities_sha256,facts_snapshot,
			facts_sha256,gateway_workload_identity,gateway_instance_id,registered_at)
			VALUES($1,$2,$3,$4,'x25519:test',1,0,$5,$4,'\x01',$4,'gw','gw-1',now())`, nodeID, epoch, uuid.New(), digest[:], snapshot)
		return err
	}); err != nil {
		harness.t.Fatal(err)
	}
}

func (harness *distHarness) sweep() {
	harness.t.Helper()
	if err := harness.distributor.SweepOnce(harness.ctx); err != nil {
		harness.t.Fatal(err)
	}
}

type queued struct {
	deploymentID uuid.UUID
	nodeID       uuid.UUID
	command      *agentv1.DeploymentCommand
	mediaType    string
	wire         []byte
}

// pending lists node artifact deployments the simulated agents have not
// answered yet.
func (harness *distHarness) pending() []queued {
	harness.t.Helper()
	rows, err := harness.pool.Query(harness.ctx, `SELECT deployment.id, deployment.node_id, deployment.command_bytes,
			artifact.media_type, artifact.wire_bytes
		FROM node_deployments deployment
		JOIN configuration_artifacts artifact ON artifact.config_version_id=deployment.config_version_id
		WHERE deployment.state='queued' ORDER BY deployment.created_at`)
	if err != nil {
		harness.t.Fatal(err)
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (queued, error) {
		var item queued
		var command []byte
		if err := row.Scan(&item.deploymentID, &item.nodeID, &command, &item.mediaType, &item.wire); err != nil {
			return item, err
		}
		item.command = new(agentv1.DeploymentCommand)
		return item, proto.Unmarshal(command, item.command)
	})
	if err != nil {
		harness.t.Fatal(err)
	}
	return items
}

// one returns the single pending deployment and checks its media type.
func (harness *distHarness) one(mediaType string) queued {
	harness.t.Helper()
	items := harness.pending()
	if len(items) != 1 || items[0].mediaType != mediaType || items[0].nodeID != harness.nodeID {
		got := []string{}
		for _, item := range items {
			got = append(got, item.mediaType+"@"+item.nodeID.String())
		}
		harness.t.Fatalf("pending deployments = %v, want one %s to the node", got, mediaType)
	}
	return items[0]
}

func (harness *distHarness) project(item queued, state agentv1.NodeDeploymentState, sequence uint64,
	mutate func(*agentv1.DeploymentStatus)) {
	harness.t.Helper()
	causation := item.command.Event.EventId
	status := &agentv1.DeploymentStatus{Event: &commonv1.EventMetadata{EventId: uuid.NewString(),
		RequestId: item.command.Event.RequestId, OccurredTime: timestamppb.Now(), CausationId: &causation,
		CorrelationId: item.command.Event.CorrelationId}, DeploymentId: item.command.DeploymentId, Attempt: 1,
		ConfigVersionId: item.command.ConfigVersionId, State: state, TransitionSequence: sequence, RunningConfigUnchanged: true}
	if mutate != nil {
		mutate(status)
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(status)
	if err != nil {
		harness.t.Fatal(err)
	}
	envelope, err := harness.validator.Decode(edgestatus.DefaultValidatorConfig().SubjectPrefix+"."+item.nodeID.String(), payload)
	if err != nil {
		harness.t.Fatal(err)
	}
	if _, err := harness.status.Project(harness.ctx, envelope); err != nil {
		harness.t.Fatalf("project %s: %v", state, err)
	}
}

func (harness *distHarness) succeed(item queued, receipt []byte) {
	harness.t.Helper()
	for sequence, state := range []agentv1.NodeDeploymentState{agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED} {
		harness.project(item, state, uint64(sequence+1), nil)
	}
	harness.project(item, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY, 5,
		func(status *agentv1.DeploymentStatus) { status.ArtifactSetReceipt = receipt })
}

// agent answers one deployment like the edge agent: a segment is stored by
// digest; a set is verified and applied when every segment is present and
// intact, otherwise rejected with the last known good kept.
func (harness *distHarness) agent(item queued) artifactset.Receipt {
	harness.t.Helper()
	digest := artifactset.Digest(item.wire)
	if item.mediaType == artifactset.MediaTypeSegment {
		harness.objects[digest] = item.wire
		harness.succeed(item, nil)
		return artifactset.Receipt{}
	}
	set, err := artifactset.Verify(item.wire, func(keyID string) (ed25519.PublicKey, bool) {
		return harness.public, keyID == "edge-key"
	})
	if err != nil || set.NodeID != item.nodeID.String() {
		harness.t.Fatalf("set does not verify for the node: %v", err)
	}
	receipt := artifactset.Receipt{NodeID: set.NodeID, Revision: set.Revision, SetSHA256: digest, ReportedAt: time.Now()}
	rejected := false
	for _, entry := range set.Items {
		var segments [][]byte
		for _, segment := range entry.Segments {
			segments = append(segments, harness.objects[segment.SHA256])
		}
		result := artifactset.ItemResult{ArtifactID: entry.ArtifactID, Version: entry.Version, SHA256: entry.SHA256,
			Result: artifactset.ResultApplied}
		if _, err := entry.Join(segments); err != nil {
			result.Result, result.Reason, rejected = artifactset.ResultRejected, artifactset.ReasonSegmentMismatch, true
		} else if reason := harness.reject[entry.ArtifactID]; reason != "" {
			result.Result, result.Reason, rejected = artifactset.ResultRejected, reason, true
		}
		receipt.Items = append(receipt.Items, result)
	}
	if receipt.Items == nil {
		receipt.Items = []artifactset.ItemResult{}
	}
	if rejected {
		for index := range receipt.Items {
			if receipt.Items[index].Result == artifactset.ResultApplied {
				receipt.Items[index].Result, receipt.Items[index].Reason = artifactset.ResultRejected, artifactset.ReasonSetRejected
			}
		}
		receipt.Result = artifactset.ResultRejected
		if harness.active != nil {
			receipt.ActiveRevision, receipt.ActiveSetSHA256 = harness.active.Revision, harness.activeSHA
		}
		encoded, err := artifactset.EncodeReceipt(receipt)
		if err != nil {
			harness.t.Fatal(err)
		}
		harness.project(item, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED, 1, nil)
		harness.project(item, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED, 2, func(status *agentv1.DeploymentStatus) {
			status.Error = &commonv1.ProtocolError{Code: commonv1.ErrorCode_ERROR_CODE_FAILED_PRECONDITION,
				Message: "node artifact set rejected; the last known good set is kept"}
			status.ArtifactSetReceipt = encoded
		})
		return receipt
	}
	receipt.Result, receipt.ActiveRevision, receipt.ActiveSetSHA256 = artifactset.ResultApplied, set.Revision, digest
	encoded, err := artifactset.EncodeReceipt(receipt)
	if err != nil {
		harness.t.Fatal(err)
	}
	harness.active, harness.activeSHA = &set, digest
	harness.succeed(item, encoded)
	return receipt
}

func (harness *distHarness) count(query string, args ...any) int {
	harness.t.Helper()
	var value int
	if err := harness.pool.QueryRow(harness.ctx, query, args...).Scan(&value); err != nil {
		harness.t.Fatal(err)
	}
	return value
}

func (harness *distHarness) appliedVersion() string {
	harness.t.Helper()
	var version string
	err := harness.pool.QueryRow(harness.ctx, `SELECT version FROM node_artifact_applied_items
		WHERE node_id=$1 AND artifact_id=$2`, harness.nodeID, IPIntelArtifactID).Scan(&version)
	if errors.Is(err, pgx.ErrNoRows) {
		return ""
	}
	if err != nil {
		harness.t.Fatal(err)
	}
	return version
}

// auditEvent is one node.artifact_set.* audit event of the node.
type auditEvent struct {
	action, result string
	payload        map[string]any
	changes        []audit.Change // the changes column
}

func (harness *distHarness) audits() []auditEvent {
	harness.t.Helper()
	rows, err := harness.pool.Query(harness.ctx, `SELECT event.action, event.result, event.payload, event.changes
		FROM audit_events event JOIN access_scopes scope ON scope.id=event.scope_id AND scope.kind='platform'
		WHERE event.action LIKE 'node.artifact_set.%' AND event.resource_type='node_artifact_set' AND event.resource_id=$1
		ORDER BY event.stream_position`, harness.nodeID.String())
	if err != nil {
		harness.t.Fatal(err)
	}
	events, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (auditEvent, error) {
		var event auditEvent
		var changes []byte
		if err := row.Scan(&event.action, &event.result, &event.payload, &changes); err != nil {
			return event, err
		}
		event.changes = audittest.DecodeChanges(harness.t, changes)
		return event, nil
	})
	if err != nil {
		harness.t.Fatal(err)
	}
	return events
}

func (harness *distHarness) gate() error {
	harness.t.Helper()
	var gateErr error
	if err := pgx.BeginFunc(harness.ctx, harness.pool, func(tx pgx.Tx) error {
		gateErr = edgepublish.ValidateFeatureCapabilityTargets(harness.ctx, tx, []uuid.UUID{harness.nodeID},
			[]*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_IP_INTEL, ApiVersion: edgepublish.IPIntelAPIVersion}})
		return nil
	}); err != nil {
		harness.t.Fatal(err)
	}
	return gateErr
}

// The distributor takes a node declaring ARTIFACT_SET from nothing to an
// applied IP library: segments one at a time, then the set; the receipt opens
// the publication gate; a newer library whose set the node rejects (altered
// segment) keeps the last known good, and after RetryAfter the segments are
// resent and the set applies. A node without ARTIFACT_SET gets nothing.
func TestDistributorDeliversTheLibraryThroughTheReceiptGate(t *testing.T) {
	harness := newDistHarness(t)
	harness.sweep()
	if harness.count(`SELECT count(*) FROM node_artifact_sets`) != 0 || len(harness.pending()) != 0 {
		t.Fatal("a set was issued without any desired item")
	}

	harness.source.set(7, randomBytes(t, 5<<20)) // two segments
	harness.sweep()
	if harness.count(`SELECT count(*) FROM node_artifact_segments`) != 2 ||
		harness.count(`SELECT count(*) FROM node_artifact_sets WHERE node_id=$1`, harness.nodeID) != 1 ||
		harness.count(`SELECT count(*) FROM node_artifact_sets WHERE node_id=$1`, harness.plainNodeID) != 0 {
		t.Fatal("first sweep did not prepare two segments and one set for the ARTIFACT_SET node only")
	}
	first := harness.one(artifactset.MediaTypeSegment)
	if capability := first.command.RequiredCapabilities; len(capability) != 1 ||
		capability[0].Name != agentv1.CapabilityName_CAPABILITY_NAME_ARTIFACT_SET {
		t.Fatalf("segment command requires %v", capability)
	}
	harness.sweep() // one delivery in flight per node
	harness.one(artifactset.MediaTypeSegment)
	harness.agent(first)
	harness.sweep()
	harness.agent(harness.one(artifactset.MediaTypeSegment))
	if err := harness.gate(); err == nil {
		t.Fatal("gate passed before the node applied a library")
	}
	harness.sweep()
	receipt := harness.agent(harness.one(artifactset.MediaTypeSet))
	if receipt.Result != artifactset.ResultApplied || harness.appliedVersion() != "7" {
		t.Fatalf("set 1 receipt %s, applied version %q", receipt.Result, harness.appliedVersion())
	}
	// The agent reconnects declaring IP_INTEL v2 once the library is applied.
	harness.session(harness.nodeID, 2, &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_ARTIFACT_SET, ApiVersion: 1},
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_IP_INTEL, ApiVersion: 2})
	if err := harness.gate(); err != nil {
		t.Fatalf("gate after the library applied: %v", err)
	}
	harness.sweep()
	if len(harness.pending()) != 0 || harness.count(`SELECT count(*) FROM node_artifact_applied_items
		WHERE node_id=$1 AND announced_at IS NOT NULL`, harness.nodeID) != 1 {
		t.Fatal("converged node got another delivery or its applied library was not announced")
	}

	// Library revision 8; one of its segments is altered on the node after
	// delivery, so the node rejects set 2 and keeps set 1.
	harness.source.set(8, randomBytes(t, 5<<20))
	harness.sweep()
	harness.agent(harness.one(artifactset.MediaTypeSegment))
	harness.sweep()
	second := harness.one(artifactset.MediaTypeSegment)
	harness.agent(second)
	harness.objects[artifactset.Digest(second.wire)] = []byte("altered on the node")
	harness.sweep()
	receipt = harness.agent(harness.one(artifactset.MediaTypeSet))
	var result string
	var revision, active int64
	if err := harness.pool.QueryRow(harness.ctx, `SELECT revision,result,active_revision FROM node_artifact_set_receipts
		WHERE node_id=$1`, harness.nodeID).Scan(&revision, &result, &active); err != nil {
		t.Fatal(err)
	}
	if receipt.Result != artifactset.ResultRejected || revision != 2 || result != artifactset.ResultRejected || active != 1 ||
		harness.appliedVersion() != "7" {
		t.Fatalf("after the altered segment: receipt (%d %s active %d), applied %q", revision, result, active, harness.appliedVersion())
	}
	if err := harness.gate(); err != nil {
		t.Fatalf("gate after a rejected set (library kept): %v", err)
	}
	harness.sweep()
	if len(harness.pending()) != 0 {
		t.Fatal("rejected set retried before RetryAfter")
	}
	harness.clock = harness.clock.Add(11 * time.Minute)
	harness.sweep()
	harness.agent(harness.one(artifactset.MediaTypeSegment)) // resent, repairs the object store
	harness.sweep()
	harness.agent(harness.one(artifactset.MediaTypeSegment))
	harness.sweep()
	receipt = harness.agent(harness.one(artifactset.MediaTypeSet))
	if receipt.Result != artifactset.ResultApplied || receipt.Revision != 2 || harness.appliedVersion() != "8" {
		t.Fatalf("retried set: %s revision %d, applied %q", receipt.Result, receipt.Revision, harness.appliedVersion())
	}
	harness.sweep()
	if len(harness.pending()) != 0 || harness.count(`SELECT count(*) FROM node_artifact_sets WHERE node_id=$1`, harness.nodeID) != 2 {
		t.Fatal("converged node got another delivery or set")
	}

	// Audit (BATCH-PLUGIN 10): two sets issued, every delivery (2+1, 2+1,
	// retry 2+1), three receipts: applied, rejected (segment_mismatch),
	// applied; system / node actors, changes before -> after.
	counts := map[string]int{}
	var receipts []auditEvent
	for _, event := range harness.audits() {
		counts[event.action+"/"+event.result]++
		if event.payload["node_id"] != harness.nodeID.String() || event.payload["ip"] != "" {
			t.Fatalf("audit %s without node or ip: %v", event.action, event.payload)
		}
		switch event.action {
		case AuditActionIssue, AuditActionDeliver:
			if event.payload["actor_kind"] != "system" {
				t.Fatalf("%s actor: %v", event.action, event.payload)
			}
		case edgestatus.ArtifactSetReceiptAuditAction:
			if event.payload["actor_kind"] != "node" || event.payload["actor_node_id"] != harness.nodeID.String() {
				t.Fatalf("receipt actor: %v", event.payload)
			}
			receipts = append(receipts, event)
		}
	}
	want := map[string]int{AuditActionIssue + "/success": 2, AuditActionDeliver + "/success": 9,
		edgestatus.ArtifactSetReceiptAuditAction + "/success": 2, edgestatus.ArtifactSetReceiptAuditAction + "/failure": 1}
	for key, count := range want {
		if counts[key] != count {
			t.Fatalf("audit counts %v, want %v", counts, want)
		}
	}
	if len(receipts) != 3 || receipts[1].payload["reason_code"] != artifactset.ReasonSegmentMismatch {
		t.Fatalf("receipt audits: %+v", receipts)
	}
	changes := func(event auditEvent) (before, after []any) {
		applied, ok := audittest.Find(event.changes, "applied_items")
		if !ok {
			t.Fatalf("%s audit has no applied_items change: %v", event.action, event.changes)
		}
		before, _ = applied.Before.([]any)
		after, _ = applied.After.([]any)
		return before, after
	}
	version := func(items []any) any {
		if len(items) != 1 {
			return nil
		}
		return items[0].(map[string]any)["version"]
	}
	if before, after := changes(receipts[0]); len(before) != 0 || version(after) != "7" {
		t.Fatalf("first receipt changes: %v -> %v", before, after)
	}
	if before, after := changes(receipts[1]); version(before) != "7" || version(after) != "7" {
		t.Fatalf("rejected receipt changes: %v -> %v", before, after)
	}
	if before, after := changes(receipts[2]); version(before) != "7" || version(after) != "8" {
		t.Fatalf("retried receipt changes: %v -> %v", before, after)
	}
}

// O2 (live-site2 10-22): a new node took 21 minutes for its 21 segments, one
// per 1-minute sweep, although each landed in seconds. With WakeChannel the
// distributor sends the next segment as soon as the node reports the previous
// one (edgestatus notifies on commit), still one delivery in flight per node;
// the sweep interval (an hour here) is only the fallback.
func TestDistributorSendsTheNextSegmentWhenTheNodeTookThePrevious(t *testing.T) {
	harness := newDistHarness(t)
	harness.source.set(7, randomBytes(t, 9<<20)) // three segments
	deployments, err := edgedeployment.NewStore(harness.pool)
	if err != nil {
		t.Fatal(err)
	}
	running, err := New(Config{Pool: harness.pool, Deployments: deployments, Source: harness.source, Signer: harness.signer,
		Interval: time.Hour, WakeChannel: edgestatus.NodeArtifactDeliveryChannel, Now: func() time.Time { return harness.clock }})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(harness.ctx)
	done := make(chan error, 1)
	go func() { done <- running.Run(ctx) }()
	defer func() {
		cancel()
		<-done
	}()
	next := func(mediaType string) queued {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for {
			if items := harness.pending(); len(items) == 1 && items[0].mediaType == mediaType {
				return items[0]
			} else if len(items) > 1 {
				t.Fatalf("%d deliveries in flight to the node, want one", len(items))
			}
			if time.Now().After(deadline) {
				t.Fatalf("no %s delivery within 10s of the previous one ending (sweep interval 1h)", mediaType)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	for range 3 {
		harness.agent(next(artifactset.MediaTypeSegment))
	}
	if receipt := harness.agent(next(artifactset.MediaTypeSet)); receipt.Result != artifactset.ResultApplied {
		t.Fatalf("set receipt %s", receipt.Result)
	}
}

// O2: the publication page's "已收 x/y，预计还需 N 分钟" reads the node's newest
// set and its segment deliveries (edgepublish.NodeArtifactSyncProgressTx):
// nothing before a set exists, then received / total segments and the
// minutes the rest needs (one sweep each before any segment arrived).
func TestNodeArtifactSyncProgressCountsReceivedSegments(t *testing.T) {
	harness := newDistHarness(t)
	progress := func() *edgepublish.ArtifactSyncProgress {
		t.Helper()
		var got *edgepublish.ArtifactSyncProgress
		if err := pgx.BeginFunc(harness.ctx, harness.pool, func(tx pgx.Tx) error {
			var err error
			got, err = edgepublish.NodeArtifactSyncProgressTx(harness.ctx, tx, []uuid.UUID{harness.nodeID, harness.plainNodeID})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := progress(); got != nil {
		t.Fatalf("progress before any set = %+v", got)
	}
	harness.source.set(7, randomBytes(t, 9<<20)) // three segments
	harness.sweep()
	if got := progress(); got == nil || *got != (edgepublish.ArtifactSyncProgress{ReceivedSegments: 0, TotalSegments: 3,
		RemainingMinutes: 4}) {
		t.Fatalf("progress with the set issued = %+v, want 0/3, 4 minutes (3 segments + the set)", got)
	}
	harness.agent(harness.one(artifactset.MediaTypeSegment))
	harness.sweep()
	harness.agent(harness.one(artifactset.MediaTypeSegment))
	if got := progress(); got == nil || got.ReceivedSegments != 2 || got.TotalSegments != 3 || got.RemainingMinutes != 1 {
		t.Fatalf("progress after two segments = %+v, want 2/3 and 1 minute (they arrived in seconds)", got)
	}
}
