package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/cdnca/cdnca/libs/entitlement/enginemodule/enginemoduletest"
	"github.com/cdnca/cdnca/libs/entitlement/ruleintel"
	"github.com/cdnca/cdnca/libs/rulepack"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/artifactsetdist"
	"github.com/cdnca/cdnca/services/control-api/internal/artifactsync"
	"github.com/cdnca/cdnca/services/control-api/internal/artifactsync/artifactsynctest"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgestatus"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
)

// The test platform release key the edge-agent half trusts (agents/edge-agent/cmd/edge-agent artifact_set_e2e_test.go).
const (
	e2ePlatformReleaseSeed  = "artifact-set-e2e platform release key"
	e2ePlatformReleaseKeyID = "platform-e2e"
)

type artifactSetFlow struct {
	t           *testing.T
	pool        *pgxpool.Pool
	nodeID      uuid.UUID
	distributor *artifactsetdist.Distributor
	stateURL    string
}

// run: a node without a library is refused carrier rules (422 naming it); library 1 reaches the node through the
// gateway and the agent installs it, declares IP_INTEL v2 and the gate opens; library 2 whose segment is altered
// on the node after delivery is rejected and the node keeps library 1; after RetryAfter the segments are resent
// and library 2 applies. Then the OWASP CRS engine module (engineModule).
func (flow artifactSetFlow) run() {
	t := flow.t
	flow.waitFor("session declaring ARTIFACT_SET v1", func() bool {
		return flow.declares(agentv1.CapabilityName_CAPABILITY_NAME_ARTIFACT_SET, 1)
	})
	var refusal *edgepublish.TargetCapabilityError
	if err := flow.gate(); !errors.As(err, &refusal) || refusal.NodeID != flow.nodeID {
		t.Fatalf("carrier rules on a node without a library: %v, want a refusal naming the node", err)
	} else {
		t.Logf("PASS no library: publication refused: %v", err)
	}

	// artifactsync downloaded library 1 (the syncer's OnChanged wakes the distributor; the flow sweeps itself).
	entry, content := e2eLibrary(t, 1)
	artifactsynctest.SeedDownloaded(t, flow.pool, entry, content)
	flow.sweepUntil("library 1 applied on the node", func() bool { return flow.appliedRevision() == 1 })
	flow.waitFor("session declaring IP_INTEL v2", func() bool {
		return flow.declares(agentv1.CapabilityName_CAPABILITY_NAME_IP_INTEL, 2)
	})
	if err := flow.gate(); err != nil {
		t.Fatalf("carrier rules after the library applied: %v", err)
	}
	if state := flow.agentState(); !state.IPIntelReady || state.LibraryVersion != 1 || state.ActiveRevision != 1 {
		t.Fatalf("agent after library 1: %+v", state)
	}
	flow.sweepOnce()
	if !flow.exists(`SELECT EXISTS(SELECT 1 FROM node_artifact_applied_items WHERE node_id=$1 AND announced_at IS NOT NULL)`) {
		t.Fatal("applied library was not announced for republication")
	}
	t.Log("PASS library 1: gateway delivered, agent installed and declared IP_INTEL v2, publication gate open, announced")

	entry, content = e2eLibrary(t, 2)
	artifactsynctest.SeedDownloaded(t, flow.pool, entry, content)
	var segments []string
	flow.sweepUntil("library 2 segments on the node", func() bool {
		segments = flow.segmentsOfLatestSet(2)
		return segments != nil
	})
	request, _ := http.NewRequest(http.MethodPost, flow.stateURL+"/tamper?digest="+segments[0], nil)
	response, err := http.DefaultClient.Do(request)
	if err != nil || response.StatusCode != http.StatusNoContent {
		t.Fatalf("tamper segment on the node: %v %v", err, response)
	}
	flow.sweepUntil("receipt for set 2", func() bool { return flow.receiptRevision() == 2 })
	var result, reason string
	var active int64
	if err := flow.pool.QueryRow(t.Context(), `SELECT result, active_revision, receipt->'items'->0->>'reason'
		FROM node_artifact_set_receipts WHERE node_id=$1`, flow.nodeID).Scan(&result, &active, &reason); err != nil {
		t.Fatal(err)
	}
	if result != artifactset.ResultRejected || active != 1 || reason != artifactset.ReasonSegmentMismatch ||
		flow.appliedRevision() != 1 {
		t.Fatalf("altered segment: receipt %s/%s active %d, applied %d", result, reason, active, flow.appliedRevision())
	}
	if state := flow.agentState(); !state.IPIntelReady || state.LibraryVersion != 1 || state.ActiveRevision != 1 {
		t.Fatalf("agent after the rejected set: %+v", state)
	}
	if err := flow.gate(); err != nil {
		t.Fatalf("gate after the rejected set (library 1 kept): %v", err)
	}
	t.Log("PASS altered segment: receipt rejected (segment_mismatch), node keeps library 1, gate still open")

	flow.sweepUntil("library 2 applied after the retry", func() bool { return flow.appliedRevision() == 2 })
	if state := flow.agentState(); !state.IPIntelReady || state.LibraryVersion != 2 || state.ActiveRevision != 2 {
		t.Fatalf("agent after the retry: %+v", state)
	}
	if flow.exists(`SELECT EXISTS(SELECT 1 FROM node_artifact_applied_items WHERE node_id=$1 AND artifact_id<>'ipintel/base')`) {
		t.Fatal("a control-side artifact reached the node's set")
	}
	t.Log("PASS retry: segments resent, set 2 applied, node runs library 2 (ruleset kept off the node)")

	flow.engineModule()

	// Audit (BATCH-PLUGIN 10): both sets issued, deliveries, and the receipts applied / rejected / applied.
	rows, err := flow.pool.Query(t.Context(), `SELECT action, result, COALESCE(payload->>'reason_code','')
		FROM audit_events WHERE action LIKE 'node.artifact_set.%' AND resource_id=$1 ORDER BY occurred_at, stream_position`,
		flow.nodeID.String())
	if err != nil {
		t.Fatal(err)
	}
	counts, receipts := map[string]int{}, []string{}
	for rows.Next() {
		var action, result, reason string
		if err := rows.Scan(&action, &result, &reason); err != nil {
			t.Fatal(err)
		}
		counts[action]++
		if action == edgestatus.ArtifactSetReceiptAuditAction {
			receipts = append(receipts, result+"/"+reason)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if counts[artifactsetdist.AuditActionIssue] != 4 || counts[artifactsetdist.AuditActionDeliver] < 3 ||
		strings.Join(receipts, ",") != "success/,failure/"+artifactset.ReasonSegmentMismatch+",success/,failure/"+
			artifactset.ReasonSignatureInvalid+",success/" {
		t.Fatalf("audit events: %v, receipts %v", counts, receipts)
	}
	t.Logf("PASS audit: %v, receipts %v", counts, receipts)

	flow.officialIntelPack()
}

// officialIntelPack (ADR 0011 RI-12): the license service's published system/crs-tuning arrives as a downloaded
// catalog entry; the production Materialize makes it the current version by itself (official packs auto-enable,
// no site mounts it), the distributor puts it in the node's set, the agent installs it and the receipt says
// applied; the receipt summary (artifactsync PackReceipts) is what the rule intel report (ruleintelreport.Collect)
// carries to the license service as pack_receipts.
func (flow artifactSetFlow) officialIntelPack() {
	t := flow.t
	compiled, err := rulepack.Compile([]byte(`{"schema":"` + rulepack.Schema + `","pack_id":"` + rulepack.CRSTuningPackID +
		`","version":"1.0.0","layer":"system","engine":"modsecurity","engine_min_version":1,"name":"CRS 官方调优",` +
		`"description":"","params_schema":{},"exports":["1"],"defaults":{},"rules":[{"id":"1","name":"排除 1",` +
		`"tuning":{"min_paranoia":1,"rule":942100,"targets":[{"loc":"args","name":"q"}]}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	content := compiled.Canonical
	entry := artifactcatalog.Entry{ArtifactID: artifactcatalog.RulePackArtifactID(rulepack.CRSTuningPackID),
		Kind: artifactcatalog.KindRulePack, Version: "1.0.0", Revision: 1, SHA256: artifactset.Digest(content),
		MediaType: artifactcatalog.MediaTypeRulePack, Resident: true}
	artifactsynctest.SeedDownloaded(t, flow.pool, entry, content)
	// The placeholder ruleset/e2e-rules ("{}", only there to prove control-side kinds stay off the node, asserted
	// above) is no real ruleset: withdraw it so the production Materialize below leaves it alone.
	if _, err := flow.pool.Exec(t.Context(), `UPDATE artifact_catalog_entries SET status='withdrawn',withdrawn_at=now()
		WHERE artifact_id='ruleset/e2e-rules'`); err != nil {
		t.Fatal(err)
	}
	store := artifactsync.NewStore(flow.pool, time.Now)
	if _, err := store.Materialize(t.Context()); err != nil {
		t.Fatal(err)
	}
	var current string
	if err := flow.pool.QueryRow(t.Context(), `SELECT COALESCE(current_version,'') FROM rule_packs WHERE pack_id=$1`,
		rulepack.CRSTuningPackID).Scan(&current); err != nil || current != "1.0.0" {
		t.Fatalf("official pack not enabled on download: current %q %v", current, err)
	}
	if flow.exists(`SELECT EXISTS(SELECT 1 FROM site_security_mounts WHERE $1::uuid IS NOT NULL AND security::text LIKE '%crs-tuning%')`) {
		t.Fatal("a site mounts the official pack; the stage must prove node-wide delivery")
	}
	itemID := artifactsetdist.RulePackArtifactID(entry.SHA256)
	defer func() {
		if t.Failed() {
			var revision int64
			var receipt string
			_ = flow.pool.QueryRow(t.Context(), `SELECT revision, receipt::text FROM node_artifact_set_receipts WHERE node_id=$1`,
				flow.nodeID).Scan(&revision, &receipt)
			var issued int64
			_ = flow.pool.QueryRow(t.Context(), `SELECT COALESCE(max(revision),0) FROM node_artifact_sets WHERE node_id=$1`,
				flow.nodeID).Scan(&issued)
			t.Logf("diagnostics: issued set %d, latest receipt %d %s", issued, revision, receipt)
			// Context of the failed test is done: diagnostics use their own.
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			rows, err := flow.pool.Query(ctx, `SELECT deployment.config_version_id::text, deployment.state,
					deployment.updated_at::text, COALESCE((SELECT event.payload FROM deployment_status_events event
					WHERE event.deployment_id=deployment.id ORDER BY event.received_at DESC LIMIT 1),'\x00'::bytea)
				FROM node_deployments deployment WHERE deployment.node_id=$1 ORDER BY deployment.updated_at DESC LIMIT 8`, flow.nodeID)
			if err != nil {
				t.Logf("diagnostics: read deployments: %v", err)
				return
			}
			defer rows.Close()
			for rows.Next() {
				var config, state, at string
				var payload []byte
				if err := rows.Scan(&config, &state, &at, &payload); err != nil {
					t.Logf("diagnostics: scan deployment: %v", err)
					return
				}
				status := new(agentv1.DeploymentStatus)
				_ = proto.Unmarshal(payload, status)
				t.Logf("diagnostics: deployment %s %s %s last status %s %v", config, state, at, status.GetState(), status.GetError())
			}
			if err := rows.Err(); err != nil {
				t.Logf("diagnostics: deployments: %v", err)
			}
			t.Logf("diagnostics: agent %+v", flow.agentState())
		}
	}()
	flow.sweepUntil("official intel pack applied on the node", func() bool {
		return flow.exists(`SELECT EXISTS(SELECT 1 FROM node_artifact_applied_items WHERE node_id=$1 AND artifact_id='` + itemID + `')`)
	})
	var result, itemResult string
	if err := flow.pool.QueryRow(t.Context(), `SELECT result, COALESCE((SELECT item->>'result' FROM jsonb_array_elements(receipt->'items') item
		WHERE item->>'artifact_id'=$2),'') FROM node_artifact_set_receipts WHERE node_id=$1`, flow.nodeID, itemID).
		Scan(&result, &itemResult); err != nil {
		t.Fatal(err)
	}
	if result != artifactset.ResultApplied || itemResult != artifactset.ResultApplied {
		t.Fatalf("official intel pack receipt %s / item %s", result, itemResult)
	}
	summary, err := store.PackReceipts(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	want := ruleintel.PackReceipt{PackID: rulepack.CRSTuningPackID, Version: "1.0.0", Applied: 1}
	if len(summary) != 1 || summary[0] != want {
		t.Fatalf("pack receipts summary %+v", summary)
	}
	t.Logf("PASS official intel pack: downloaded %s auto-enabled without a site mount, node applied %s, pack_receipts %+v",
		entry.ArtifactID, itemID, summary)
}

func (flow artifactSetFlow) sweepOnce() {
	flow.t.Helper()
	if err := flow.distributor.SweepOnce(flow.t.Context()); err != nil {
		flow.t.Fatal(err)
	}
}

// sweepUntil sweeps until done holds (checked before every sweep, so nothing is delivered after it holds).
func (flow artifactSetFlow) sweepUntil(what string, done func() bool) {
	flow.t.Helper()
	deadline := time.Now().Add(3 * time.Minute)
	for !done() {
		if time.Now().After(deadline) {
			flow.t.Fatalf("timed out waiting for %s", what)
		}
		flow.sweepOnce()
		time.Sleep(250 * time.Millisecond)
	}
}

func (flow artifactSetFlow) waitFor(what string, done func() bool) {
	flow.t.Helper()
	deadline := time.Now().Add(3 * time.Minute)
	for !done() {
		if time.Now().After(deadline) {
			flow.t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func (flow artifactSetFlow) exists(query string) bool {
	flow.t.Helper()
	var found bool
	if err := flow.pool.QueryRow(flow.t.Context(), query, flow.nodeID).Scan(&found); err != nil {
		flow.t.Fatal(err)
	}
	return found
}

func (flow artifactSetFlow) declares(name agentv1.CapabilityName, version uint32) bool {
	flow.t.Helper()
	var snapshot, digest []byte
	err := flow.pool.QueryRow(flow.t.Context(), `SELECT capabilities_snapshot, capabilities_sha256 FROM node_session_capabilities
		WHERE node_id=$1 ORDER BY session_epoch DESC LIMIT 1`, flow.nodeID).Scan(&snapshot, &digest)
	if errors.Is(err, pgx.ErrNoRows) {
		return false
	}
	if err != nil {
		flow.t.Fatal(err)
	}
	actual := sha256.Sum256(snapshot)
	capabilities := new(agentv1.AgentCapabilities)
	if !bytes.Equal(actual[:], digest) || proto.Unmarshal(snapshot, capabilities) != nil {
		return false
	}
	for _, feature := range capabilities.Features {
		if feature.GetName() == name && feature.GetApiVersion() >= version {
			return true
		}
	}
	return false
}

func (flow artifactSetFlow) gate() error {
	flow.t.Helper()
	var gateErr error
	if err := pgx.BeginFunc(flow.t.Context(), flow.pool, func(tx pgx.Tx) error {
		gateErr = edgepublish.ValidateFeatureCapabilityTargets(flow.t.Context(), tx, []uuid.UUID{flow.nodeID},
			[]*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_IP_INTEL, ApiVersion: edgepublish.IPIntelAPIVersion}})
		return nil
	}); err != nil {
		flow.t.Fatal(err)
	}
	return gateErr
}

// appliedRevision is the IP library revision the node's applied set holds (0: none).
func (flow artifactSetFlow) appliedRevision() int64 {
	flow.t.Helper()
	var revision int64
	err := flow.pool.QueryRow(flow.t.Context(), `SELECT item_revision FROM node_artifact_applied_items
		WHERE node_id=$1 AND artifact_id=$2`, flow.nodeID, artifactsetdist.IPIntelArtifactID).Scan(&revision)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		flow.t.Fatal(err)
	}
	return revision
}

func (flow artifactSetFlow) receiptRevision() int64 {
	flow.t.Helper()
	var revision int64
	err := flow.pool.QueryRow(flow.t.Context(), `SELECT revision FROM node_artifact_set_receipts WHERE node_id=$1`,
		flow.nodeID).Scan(&revision)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		flow.t.Fatal(err)
	}
	return revision
}

// segmentsOfLatestSet returns the segment digests of the node's newest set when it is revision and every one of
// them has a healthy delivery to the node (nil otherwise).
func (flow artifactSetFlow) segmentsOfLatestSet(revision int64) []string {
	flow.t.Helper()
	var latest int64
	var wire []byte
	err := flow.pool.QueryRow(flow.t.Context(), `SELECT issued.revision, artifact.wire_bytes FROM node_artifact_sets issued
		JOIN configuration_artifacts artifact ON artifact.config_version_id=issued.config_version_id
		WHERE issued.node_id=$1 ORDER BY issued.revision DESC LIMIT 1`, flow.nodeID).Scan(&latest, &wire)
	if errors.Is(err, pgx.ErrNoRows) || latest != revision {
		return nil
	}
	if err != nil {
		flow.t.Fatal(err)
	}
	set, err := artifactset.Decode(wire)
	if err != nil {
		flow.t.Fatal(err)
	}
	var digests []string
	for _, item := range set.Items {
		for _, segment := range item.Segments {
			var healthy bool
			if err := flow.pool.QueryRow(flow.t.Context(), `SELECT EXISTS(SELECT 1 FROM node_artifact_segments segment
				JOIN node_deployments deployment ON deployment.config_version_id=segment.config_version_id
				WHERE segment.sha256=$1 AND deployment.node_id=$2 AND deployment.state='healthy')`,
				segment.SHA256, flow.nodeID).Scan(&healthy); err != nil {
				flow.t.Fatal(err)
			}
			if !healthy {
				return nil
			}
			digests = append(digests, segment.SHA256)
		}
	}
	return digests
}

func (flow artifactSetFlow) agentState() artifactSetAgentState {
	flow.t.Helper()
	response, err := http.Get(flow.stateURL + "/state")
	if err != nil {
		flow.t.Fatal(err)
	}
	defer response.Body.Close()
	var state artifactSetAgentState
	if err := json.NewDecoder(response.Body).Decode(&state); err != nil {
		flow.t.Fatal(err)
	}
	return state
}

// engineModule: an engine module build signed by a key the node does not trust is delivered and refused
// (signature_invalid, audited install_reject with the module kept absent and library 2 kept); the platform-signed
// build of the node's platform (and not the arm64 one) is then installed by the agent's wafengine installer and
// audited as node.engine_module.install.
func (flow artifactSetFlow) engineModule() {
	t := flow.t
	platformSeed := sha256.Sum256([]byte(e2ePlatformReleaseSeed))
	rogueSeed := sha256.Sum256([]byte("artifact-set-e2e rogue key"))
	platform := enginemoduletest.Signer{KeyID: e2ePlatformReleaseKeyID, Private: ed25519.NewKeyFromSeed(platformSeed[:])}
	rogue := enginemoduletest.Signer{KeyID: e2ePlatformReleaseKeyID, Private: ed25519.NewKeyFromSeed(rogueSeed[:])}
	seed := func(signer enginemoduletest.Signer, revision uint64, options enginemoduletest.Options) artifactcatalog.Entry {
		content := enginemoduletest.Encoded(t, []enginemoduletest.Signer{signer}, options)
		entry, err := artifactcatalog.EngineModuleEntry(content, revision, "")
		if err != nil {
			t.Fatal(err)
		}
		artifactsynctest.SeedDownloaded(t, flow.pool, entry, content)
		return entry
	}
	seed(platform, 1, enginemoduletest.Options{Architecture: "arm64"})
	forged := seed(rogue, 1, enginemoduletest.Options{Module: "rogue"})
	flow.sweepUntil("receipt for the forged engine module", func() bool { return flow.receiptRevision() == 3 })
	var result, reason string
	if err := flow.pool.QueryRow(t.Context(), `SELECT result, COALESCE((SELECT item->>'reason' FROM jsonb_array_elements(receipt->'items') item
		WHERE item->>'artifact_id'=$2),'') FROM node_artifact_set_receipts WHERE node_id=$1`, flow.nodeID, forged.ArtifactID).
		Scan(&result, &reason); err != nil {
		t.Fatal(err)
	}
	if state := flow.agentState(); result != artifactset.ResultRejected || reason != artifactset.ReasonSignatureInvalid ||
		state.EngineArtifactID != "" || state.LibraryVersion != 2 {
		t.Fatalf("forged engine module: receipt %s/%s, agent %+v", result, reason, state)
	}
	t.Log("PASS forged engine module: refused (signature_invalid) by the node, nothing installed, library 2 kept")

	genuine := seed(platform, 2, enginemoduletest.Options{})
	flow.sweepUntil("engine module installed", func() bool {
		return flow.exists(`SELECT EXISTS(SELECT 1 FROM node_artifact_applied_items WHERE node_id=$1 AND artifact_id LIKE 'engine_module/%')`)
	})
	if state := flow.agentState(); state.EngineArtifactID != genuine.ArtifactID || state.EngineVersion != genuine.Version {
		t.Fatalf("agent after the engine module: %+v", state)
	}
	if flow.exists(`SELECT EXISTS(SELECT 1 FROM node_artifact_applied_items WHERE node_id=$1 AND artifact_id LIKE '%linux-arm64')`) {
		t.Fatal("the arm64 build reached an amd64 node")
	}
	rows, err := flow.pool.Query(t.Context(), `SELECT action, result, payload->>'artifact_id' FROM audit_events
		WHERE resource_type='node_engine_module' AND resource_id=$1 ORDER BY stream_position`, flow.nodeID.String())
	if err != nil {
		t.Fatal(err)
	}
	var events []string
	for rows.Next() {
		var action, result, artifactID string
		if err := rows.Scan(&action, &result, &artifactID); err != nil {
			t.Fatal(err)
		}
		events = append(events, action+"/"+result+"/"+artifactID)
	}
	want := []string{edgestatus.EngineModuleRejectAuditAction + "/failure/" + forged.ArtifactID,
		edgestatus.EngineModuleInstallAuditAction + "/success/" + genuine.ArtifactID}
	if strings.Join(events, ",") != strings.Join(want, ",") {
		t.Fatalf("engine module audits %v, want %v", events, want)
	}
	t.Logf("PASS engine module: platform-signed amd64 build installed by the agent, arm64 build kept off, audits %v", events)
}
