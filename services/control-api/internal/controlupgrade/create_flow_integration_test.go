//go:build integration

package controlupgrade

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Service.CreateRollout end to end (Prepare, cohort, License issuance, artifact cache,
// Acquire, Finalize) and the start that follows, against a real database. The fake License service
// signs what the real one returns and, like it, answers a repeated Idempotency-Key with the same body.
type createFlowLicense struct {
	t              *testing.T
	signer         grantTestSigner
	installationID string
	target         string
	forwardSeq     uint64
	rollbackSeq    uint64
	// onIssue runs inside the parent grant call, before the response is written.
	onIssue func(*http.Request)
	// onCommand runs inside the command grant call, before the response is written.
	onCommand func(*http.Request)
	// unavailable answers that many parent grant calls with 503.
	unavailable int
	// commandExpirySkew shifts the command grant response's expires_at off the signed one.
	commandExpirySkew int64
	// legacyExecution numbers command grants from 1 per node as License before 175 did;
	// otherwise the first one is node_receipt_sequence+1.
	legacyExecution bool
	// receiptSequences records node_receipt_sequence of each command grant request.
	receiptSequences []uint64

	mu        sync.Mutex
	responses map[string][]byte
	artifacts map[string][]byte
	calls     map[string]int
}

func newCreateFlowLicense(t *testing.T, installationID, target string, forwardSeq, rollbackSeq uint64) *createFlowLicense {
	return &createFlowLicense{t: t, installationID: installationID, target: target, forwardSeq: forwardSeq,
		rollbackSeq: rollbackSeq, responses: map[string][]byte{}, artifacts: map[string][]byte{}, calls: map[string]int{},
		signer: grantTestSigner{privateKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x6a}, ed25519.SeedSize))}}
}

func (license *createFlowLicense) keys(t *testing.T) *entitlement.KeyRing {
	keys := entitlement.NewKeyRing()
	if err := keys.Add(license.signer.KeyID(), license.signer.privateKey.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	return keys
}

func (license *createFlowLicense) count(kind string) int {
	license.mu.Lock()
	defer license.mu.Unlock()
	return license.calls[kind]
}

func (license *createFlowLicense) RoundTrip(request *http.Request) (*http.Response, error) {
	if err := request.Context().Err(); err != nil {
		return nil, err
	}
	if request.Method == http.MethodGet {
		license.mu.Lock()
		content, found := license.artifacts[request.URL.String()]
		license.mu.Unlock()
		if !found {
			return createFlowResponse(http.StatusNotFound, nil), nil
		}
		return createFlowResponse(http.StatusOK, content), nil
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	kind := request.URL.Path[strings.LastIndex(request.URL.Path, "/")+1:]
	key := kind + "/" + request.Header.Get("Idempotency-Key")
	license.mu.Lock()
	license.calls[kind]++
	cached, replay := license.responses[key]
	refuse := kind == "upgrade-grants:issue" && license.unavailable > 0
	if refuse {
		license.unavailable--
	}
	license.mu.Unlock()
	if refuse {
		return createFlowResponse(http.StatusServiceUnavailable, nil), nil
	}
	if kind == "upgrade-grants:issue" && license.onIssue != nil {
		license.onIssue(request)
	}
	if kind == "upgrade-command-grants:issue" && license.onCommand != nil {
		license.onCommand(request)
	}
	if err := request.Context().Err(); err != nil {
		return nil, err
	}
	if replay {
		return createFlowResponse(http.StatusOK, cached), nil
	}
	var response []byte
	switch kind {
	case "upgrade-grants:issue":
		response = license.issueParent(body)
	case "upgrade-plan-artifact-bundles:issue":
		response = license.issueBundle(body)
	case "upgrade-command-grants:issue":
		response = license.issueCommand(body)
	default:
		return createFlowResponse(http.StatusNotFound, nil), nil
	}
	license.mu.Lock()
	license.responses[key] = response
	license.mu.Unlock()
	return createFlowResponse(http.StatusOK, response), nil
}

func createFlowResponse(status int, body []byte) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body))}
}
func (license *createFlowLicense) artifact(version string, sequence uint64, protocol int,
	label string) entitlement.UpgradePlanArtifact {
	t := license.t
	content := bytes.Repeat([]byte(label), 512)
	digest := sha256.Sum256(content)
	manifest := entitlement.ArtifactManifestV2{Schema: entitlement.ArtifactManifestV3Schema,
		Audience: entitlement.ArtifactManifestAudience, Purpose: entitlement.ArtifactManifestPurpose,
		ArtifactID: uuid.NewSHA1(uuid.NameSpaceURL, []byte(label)).String(), Component: "edge-agent",
		Version: version, ProtocolMin: protocol, ProtocolMax: protocol, ArtifactSizeBytes: int64(len(content)),
		ReleaseSequence: sequence, DigestAlgorithm: "sha256",
		SHA256Digest: base64.RawURLEncoding.EncodeToString(digest[:]),
		DownloadURL:  "https://downloads.example.test/" + label}
	signature, err := entitlement.SignArtifactManifestV3(context.Background(), manifest, license.signer)
	if err != nil {
		t.Error(err)
	}
	license.mu.Lock()
	license.artifacts[manifest.DownloadURL] = content
	license.mu.Unlock()
	return entitlement.UpgradePlanArtifact{Manifest: manifest, SignatureAlgorithm: entitlement.Algorithm,
		SignatureKeyID: license.signer.KeyID(), ManifestSignature: base64.RawURLEncoding.EncodeToString(signature)}
}

// pair is the registry answer for a cohort: a cross-version target has an older rollback
// build, a same-version re-release names the one registered build both ways.
func (license *createFlowLicense) pair(current string, protocol int) (entitlement.UpgradePlanArtifact,
	entitlement.UpgradePlanArtifact, string) {
	forward := license.artifact(license.target, license.forwardSeq, protocol, "forward-"+license.target)
	if license.target == current {
		return forward, forward, entitlement.ReinstallOperation
	}
	return forward, license.artifact(current, license.rollbackSeq, protocol, "rollback-"+current),
		entitlement.UpgradeOperation
}

func (license *createFlowLicense) issueParent(body []byte) []byte {
	t := license.t
	var input struct {
		Component              string `json:"component"`
		CurrentVersion         string `json:"current_version"`
		ProtocolVersion        int    `json:"protocol_version"`
		Proof                  string `json:"proof"`
		CurrentReleaseSequence uint64 `json:"current_release_sequence,omitempty"`
	}
	if err := json.Unmarshal(body, &input); err != nil {
		t.Error(err)
	}
	forward, _, operation := license.pair(input.CurrentVersion, input.ProtocolVersion)
	// As License: the installed release_sequence is kept for a same-version re-release only.
	if input.CurrentVersion != license.target {
		input.CurrentReleaseSequence = 0
	}
	now := time.Now().Unix()
	grant := entitlement.UpgradeGrant{Schema: entitlement.UpgradeGrantSchema, Audience: entitlement.UpgradeGrantAudience,
		Purpose: entitlement.UpgradeGrantPurpose, GrantID: uuid.NewString(), Nonce: uuid.NewString(),
		CustomerID: "00000000-0000-4000-8000-0000000000c1", InstallationID: license.installationID,
		LicenseID: "00000000-0000-4000-8000-0000000000c2", Channel: "stable", ChannelRevision: 3,
		Component: "edge-agent", Operation: operation, CurrentVersion: input.CurrentVersion, Version: license.target,
		CurrentReleaseSequence: input.CurrentReleaseSequence, ProtocolVersion: input.ProtocolVersion,
		ArtifactID: forward.Manifest.ArtifactID, ArtifactProtocolMin: input.ProtocolVersion,
		ArtifactProtocolMax: input.ProtocolVersion, DownloadURL: forward.Manifest.DownloadURL,
		DigestAlgorithm: "sha256", SHA256Digest: forward.Manifest.SHA256Digest,
		ArtifactSignatureAlgorithm: entitlement.Algorithm, ArtifactSignatureKeyID: license.signer.KeyID(),
		IssuedAt: now - 60, ExpiresAt: now + 600}
	// A parent grant carries the release.artifact/v1 signature over its own fields.
	artifactSignature, err := entitlement.SignArtifactManifest(context.Background(), entitlement.ArtifactManifest{
		Schema: entitlement.ArtifactManifestSchema, Audience: entitlement.ArtifactManifestAudience,
		Purpose: entitlement.ArtifactManifestPurpose, ArtifactID: grant.ArtifactID, Component: grant.Component,
		Version: grant.Version, ProtocolMin: grant.ArtifactProtocolMin, ProtocolMax: grant.ArtifactProtocolMax,
		DigestAlgorithm: grant.DigestAlgorithm, SHA256Digest: grant.SHA256Digest, DownloadURL: grant.DownloadURL},
		license.signer)
	if err != nil {
		t.Error(err)
	}
	grant.ArtifactManifestSignature = base64.RawURLEncoding.EncodeToString(artifactSignature)
	signed, err := entitlement.SignUpgradeGrant(context.Background(), grant, license.signer)
	if err != nil {
		t.Error(err)
	}
	response, err := json.Marshal(struct {
		ID          uuid.UUID                      `json:"id"`
		SignedGrant entitlement.SignedUpgradeGrant `json:"signed_grant"`
	}{uuid.MustParse(grant.GrantID), signed})
	if err != nil {
		t.Error(err)
	}
	return response
}

func (license *createFlowLicense) issueBundle(body []byte) []byte {
	t := license.t
	var input IssueUpgradePlanArtifactBundleHTTPBody
	if err := json.Unmarshal(body, &input); err != nil {
		t.Error(err)
	}
	parentBytes, err := base64.RawURLEncoding.DecodeString(input.ParentUpgradeGrant)
	if err != nil {
		t.Error(err)
	}
	signedParent, err := entitlement.DecodeUpgradeGrant(parentBytes)
	if err != nil {
		t.Error(err)
	}
	parent := signedParent.Grant
	parentDigest, err := entitlement.CanonicalUpgradeGrantDigest(parentBytes)
	if err != nil {
		t.Error(err)
	}
	forward, rollback, _ := license.pair(parent.CurrentVersion, parent.ProtocolVersion)
	bundle := entitlement.UpgradePlanArtifactBundle{Schema: entitlement.UpgradePlanArtifactBundleV2Schema,
		Audience: entitlement.UpgradePlanArtifactBundleAudience, Purpose: entitlement.UpgradePlanArtifactBundlePurpose,
		BundleID: uuid.NewString(), PlanID: input.PlanID, InitialPlanRevision: input.InitialPlanRevision,
		ParentGrantID: parent.GrantID, ParentGrantSHA256: parentDigest, ParentGrantIssuedAt: parent.IssuedAt,
		ParentGrantExpiresAt: parent.ExpiresAt, CustomerID: parent.CustomerID, InstallationID: parent.InstallationID,
		LicenseID: parent.LicenseID, Channel: parent.Channel, ChannelRevision: parent.ChannelRevision,
		Component: parent.Component, CurrentVersion: parent.CurrentVersion, Version: parent.Version,
		CurrentReleaseSequence: parent.CurrentReleaseSequence, ProtocolVersion: parent.ProtocolVersion,
		Forward: forward, Rollback: rollback, IssuedAt: time.Now().Unix() - 30,
		CommandIssuanceNotAfter: input.CommandIssuanceNotAfter}
	signed, err := entitlement.SignUpgradePlanArtifactBundle(context.Background(), bundle, license.signer)
	if err != nil {
		t.Error(err)
	}
	encoded, err := signed.Encode()
	if err != nil {
		t.Error(err)
	}
	digest := sha256.Sum256(encoded)
	response, err := json.Marshal(struct {
		ID                      string `json:"id"`
		EncodedBundle           string `json:"encoded_bundle"`
		BundleSHA256            string `json:"bundle_sha256"`
		CommandIssuanceNotAfter int64  `json:"command_issuance_not_after"`
	}{bundle.BundleID, base64.RawURLEncoding.EncodeToString(encoded),
		base64.RawURLEncoding.EncodeToString(digest[:]), input.CommandIssuanceNotAfter})
	if err != nil {
		t.Error(err)
	}
	return response
}
func (license *createFlowLicense) issueCommand(body []byte) []byte {
	t := license.t
	var input IssueUpgradeCommandGrantHTTPBody
	if err := json.Unmarshal(body, &input); err != nil {
		t.Error(err)
	}
	bundleBytes, err := base64.RawURLEncoding.DecodeString(input.UpgradePlanArtifactBundle)
	if err != nil {
		t.Error(err)
	}
	signedBundle, err := entitlement.DecodeUpgradePlanArtifactBundle(bundleBytes)
	if err != nil {
		t.Error(err)
	}
	bundle, artifact := signedBundle.Bundle, signedBundle.Bundle.Forward
	if input.Operation != "forward" {
		t.Errorf("unexpected %s command grant request", input.Operation)
	}
	bundleDigest := sha256.Sum256(bundleBytes)
	profile := input.ForwardProfile
	issuedAt := time.Now().Unix() - 30
	license.mu.Lock()
	license.receiptSequences = append(license.receiptSequences, input.NodeReceiptSequence)
	license.mu.Unlock()
	execution := input.NodeReceiptSequence + 1
	if license.legacyExecution {
		execution = 1
	}
	manifest := artifact.Manifest
	grant := entitlement.UpgradeCommandGrant{Schema: entitlement.UpgradeCommandGrantV3Schema,
		Audience: entitlement.UpgradeCommandGrantAudience, Purpose: entitlement.UpgradeCommandGrantPurpose,
		CommandID: input.CommandID, Nonce: uuid.NewString(), ParentGrantID: bundle.ParentGrantID,
		ParentGrantSHA256: bundle.ParentGrantSHA256, ParentGrantIssuedAt: bundle.ParentGrantIssuedAt,
		ParentGrantExpiresAt: bundle.ParentGrantExpiresAt, PlanID: input.PlanID, PlanRevision: input.PlanRevision,
		BatchID: input.BatchID, ArtifactBundleID: bundle.BundleID,
		ArtifactBundleSHA256:    base64.RawURLEncoding.EncodeToString(bundleDigest[:]),
		CommandIssuanceNotAfter: bundle.CommandIssuanceNotAfter, CustomerID: bundle.CustomerID,
		InstallationID: bundle.InstallationID, LicenseID: bundle.LicenseID, Channel: bundle.Channel,
		ChannelRevision: manifest.ReleaseSequence, ExecutionSequence: execution, ReleaseSequence: manifest.ReleaseSequence,
		CurrentReleaseSequence: bundle.CurrentReleaseSequence, Component: bundle.Component,
		Operation: entitlement.UpgradeOperation, CurrentVersion: bundle.CurrentVersion, Version: bundle.Version,
		ProtocolVersion: bundle.ProtocolVersion, ArtifactID: manifest.ArtifactID,
		ArtifactProtocolMin: manifest.ProtocolMin, ArtifactProtocolMax: manifest.ProtocolMax,
		ArtifactSizeBytes: manifest.ArtifactSizeBytes, DownloadURL: manifest.DownloadURL, DigestAlgorithm: "sha256",
		SHA256Digest: manifest.SHA256Digest, ArtifactSignatureAlgorithm: entitlement.Algorithm,
		ArtifactSignatureKeyID: artifact.SignatureKeyID, ArtifactManifestSignature: artifact.ManifestSignature,
		NodeID: input.NodeID, Platform: profile.Platform, Architecture: profile.Architecture,
		Compatibility: profile.Compatibility, Health: profile.Health, Rollout: profile.Rollout,
		Rollback: profile.Rollback, IssuedAt: issuedAt, NotBefore: issuedAt,
		// As License: the full protocol lifetime.
		ExpiresAt: issuedAt + int64(entitlement.MaxUpgradeGrantLifetime/time.Second)}
	signed, err := entitlement.SignUpgradeCommandGrant(context.Background(), grant, license.signer)
	if err != nil {
		t.Error(err)
	}
	encoded, err := signed.Encode()
	if err != nil {
		t.Error(err)
	}
	digest := sha256.Sum256(encoded)
	// As License: id names the issued_upgrade_command_grants row, never the command.
	response, err := json.Marshal(struct {
		ID           string `json:"id"`
		EncodedGrant string `json:"encoded_grant"`
		GrantSHA256  string `json:"grant_sha256"`
		ExpiresAt    int64  `json:"expires_at"`
	}{uuid.Must(uuid.NewV7()).String(), base64.RawURLEncoding.EncodeToString(encoded),
		base64.RawURLEncoding.EncodeToString(digest[:]), grant.ExpiresAt + license.commandExpirySkew})
	if err != nil {
		t.Error(err)
	}
	return response
}

type createFlowFixture struct {
	pool    *pgxpool.Pool
	service *Service
	license *createFlowLicense
	actor   Actor
	nodeID  string
}

// newCreateFlowFixture seeds one online node at current (re-release capable when installed > 0)
// under an installation whose entitlement row carries the runtime's installation ID, as in production.
func newCreateFlowFixture(t *testing.T, current, target string, installed, forwardSeq,
	rollbackSeq uint64) createFlowFixture {
	t.Helper()
	pool := openRolloutPersistenceIntegrationPool(t)
	installationID := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO control_installation_entitlement(installation_id)
		VALUES($1)`, installationID.String()); err != nil {
		t.Fatal(err)
	}
	actor, nodeID := seedRolloutPlanV3Node(t, pool, current, installed)
	license := newCreateFlowLicense(t, installationID.String(), target, forwardSeq, rollbackSeq)
	client := &http.Client{Transport: license}
	licenseClient, err := NewLicenseClient("https://license.example.test", client, installationID,
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize)), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(licenseClient.Close)
	artifacts, err := NewArtifactCache(t.TempDir(), "https://console.example.test/downloads/sha256", client)
	if err != nil {
		t.Fatal(err)
	}
	keys := license.keys(t)
	runtime, err := NewRolloutRuntime(RolloutRuntimeConfig{License: licenseClient, LicenseKeys: keys,
		CommandGrantKeys: keys, InstallationID: installationID, Artifacts: artifacts,
		ControlSigner:      &executionCountingSigner{id: "control-execution-1", privateKey: executionPrivateKey(0x91)},
		EdgeSigner:         &executionCountingSigner{id: "edge-consumption-1", privateKey: executionPrivateKey(0x92)},
		CommandIssuanceTTL: 6 * time.Hour,
		Profiles: RolloutProfilePolicy{ActivationTimeout: time.Minute, ObservationWindow: time.Minute,
			HealthInterval: time.Second, ProbeTimeout: time.Second, RequiredConsecutiveSuccesses: 1},
		Clock: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(pool, nil, nil, time.Now)
	if err := service.ConfigureRolloutRuntime(runtime); err != nil {
		t.Fatal(err)
	}
	return createFlowFixture{pool: pool, service: service, license: license, actor: actor, nodeID: nodeID}
}

func (fixture createFlowFixture) request(label string) CreateRolloutRequest {
	return CreateRolloutRequest{CreateRolloutBody: CreateRolloutBody{
		Schema: "cdnca.control-upgrade-rollout.create/v1", NodeIDs: []string{fixture.nodeID},
		CanaryNodeIDs: []string{fixture.nodeID}, BatchSize: 1, AutomaticRollback: true},
		IdempotencyKey: "control-upgrade-create-" + label, RequestID: "control-upgrade-request-" + label}
}

// intents counts grant intents by state.
func (fixture createFlowFixture) intents(t *testing.T) map[string]int {
	t.Helper()
	rows, err := fixture.pool.Query(t.Context(), `SELECT state,count(*) FROM control_upgrade_grant_intents_096 GROUP BY state`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	states := map[string]int{}
	for rows.Next() {
		var state string
		var count int
		if err := rows.Scan(&state, &count); err != nil {
			t.Fatal(err)
		}
		states[state] = count
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return states
}

// start applies the operator's start and checks one v3 forward command was persisted.
func (fixture createFlowFixture) start(t *testing.T, created RolloutDetail, label string) {
	t.Helper()
	result, err := fixture.service.ApplyRolloutAction(t.Context(), fixture.actor, RolloutActionRequest{
		RolloutActionBody: RolloutActionBody{ExpectedRevision: created.Revision, Reason: "operator_upgrade"},
		PlanID:            created.ID, Operation: string(PlanStart),
		IdempotencyKey: "control-upgrade-start-" + label, RequestID: "control-upgrade-start-request-" + label})
	if err != nil || result.Replayed || result.Detail.State != PlanCanary {
		t.Fatalf("start = (%+v, %v)", result.Detail.RolloutSummary, err)
	}
	var commands int
	var schema string
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*),min(command_schema)
		FROM control_upgrade_node_commands WHERE plan_id=$1 AND node_id=$2 AND action='upgrade'`,
		created.ID, fixture.nodeID).Scan(&commands, &schema); err != nil {
		t.Fatal(err)
	}
	if commands != 1 || schema != entitlement.UpgradeCommandGrantV3Schema {
		t.Fatalf("start persisted %d forward commands with schema %q", commands, schema)
	}
}

func (fixture createFlowFixture) create(t *testing.T, ctx context.Context, request CreateRolloutRequest) RolloutDetail {
	t.Helper()
	result, err := fixture.service.CreateRollout(ctx, fixture.actor, request)
	if err != nil || result.Replayed || result.Detail.State != PlanQueued {
		t.Fatalf("create = (%+v, %v)", result.Detail.RolloutSummary, err)
	}
	return result.Detail
}

func TestCreateRolloutFlowPostgres(t *testing.T) {
	for _, test := range []struct {
		name, current, target string
		installed             uint64
		wantRollback          bool
	}{
		{name: "cross-version", current: "1.0.24", target: "1.0.27", wantRollback: true},
		{name: "same-version re-release", current: "1.0.27", target: "1.0.27", installed: 124},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCreateFlowFixture(t, test.current, test.target, test.installed, 127, 90)
			request := fixture.request("flow")
			created := fixture.create(t, t.Context(), request)
			if created.CurrentVersion != test.current || created.TargetVersion != test.target ||
				created.SchemaVersion != RolloutPlanSchemaVersion {
				t.Fatalf("created %+v", created.RolloutSummary)
			}
			var rollbackAvailable bool
			if err := fixture.pool.QueryRow(t.Context(), `SELECT rollback_artifact_size_bytes>0
				FROM control_upgrade_rollout_plans WHERE id=$1`, created.ID).Scan(&rollbackAvailable); err != nil {
				t.Fatal(err)
			}
			if rollbackAvailable != test.wantRollback {
				t.Fatalf("plan rollback build stored = %v", rollbackAvailable)
			}
			if states := fixture.intents(t); states["consumed"] != 1 || len(states) != 1 {
				t.Fatalf("grant intents after create = %v", states)
			}
			replay, err := fixture.service.CreateRollout(t.Context(), fixture.actor, request)
			if err != nil || !replay.Replayed || replay.Detail.ID != created.ID {
				t.Fatalf("same request replay = (%v, %v)", replay.Replayed, err)
			}
			fixture.start(t, created, "flow")
			if fixture.license.count("upgrade-grants:issue") != 1 ||
				fixture.license.count("upgrade-plan-artifact-bundles:issue") != 1 ||
				fixture.license.count("upgrade-command-grants:issue") != 1 {
				t.Fatalf("License calls = %v", fixture.license.calls)
			}
		})
	}
}

// The node's helper refuses a v3 execution_sequence at or below its receipt sequence
// (a schema-1 receipt counts the installed release_sequence). Start sends the plan
// target's receipt sequence to License and refuses a grant that does not exceed it, which is what a
// License before 175 issued (1 for the node's first command).
func TestStartIssuesExecutionAboveNodeReceiptSequencePostgres(t *testing.T) {
	for _, test := range []struct {
		name, current string
		installed     uint64
		legacy        bool
		wantExecution uint64
	}{
		{name: "cross-version over release 124", current: "1.0.24", installed: 124, wantExecution: 125},
		{name: "same-version re-release over 124", current: "1.0.27", installed: 124, wantExecution: 125},
		{name: "node reports no release", current: "1.0.24", wantExecution: 1},
		{name: "License before 175", current: "1.0.24", installed: 124, legacy: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCreateFlowFixture(t, test.current, "1.0.27", test.installed, 127, 90)
			fixture.license.legacyExecution = test.legacy
			created := fixture.create(t, t.Context(), fixture.request("execseq"))
			var snapshot, digest []byte
			if err := fixture.pool.QueryRow(t.Context(), `SELECT canonical_snapshot_bytes,canonical_snapshot_sha256
				FROM control_upgrade_rollout_plans WHERE id=$1`, created.ID).Scan(&snapshot, &digest); err != nil {
				t.Fatal(err)
			}
			plan, _, err := decodeRolloutPlan(snapshot, digest)
			if err != nil || plan.Targets[fixture.nodeID].ReceiptSequence != test.installed ||
				(test.installed == 0) == bytes.Contains(snapshot, []byte(`"ReceiptSequence"`)) {
				t.Fatalf("plan target %+v (%v) snapshot %s", plan.Targets[fixture.nodeID], err, snapshot)
			}
			if test.legacy {
				_, err := fixture.service.ApplyRolloutAction(t.Context(), fixture.actor, RolloutActionRequest{
					RolloutActionBody: RolloutActionBody{ExpectedRevision: created.Revision, Reason: "operator_upgrade"},
					PlanID:            created.ID, Operation: string(PlanStart),
					IdempotencyKey: "control-upgrade-start-execseq", RequestID: "control-upgrade-start-request-execseq"})
				var commands int
				if qerr := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM control_upgrade_node_commands
					WHERE plan_id=$1`, created.ID).Scan(&commands); qerr != nil {
					t.Fatal(qerr)
				}
				if !errors.Is(err, ErrGrantInvalid) || commands != 0 {
					t.Fatalf("start with execution 1 over receipt 124 = (%v, %d commands), want %v", err, commands, ErrGrantInvalid)
				}
				return
			}
			fixture.start(t, created, "execseq")
			var execution int64
			if err := fixture.pool.QueryRow(t.Context(), `SELECT execution_sequence FROM control_upgrade_node_commands
				WHERE plan_id=$1 AND node_id=$2`, created.ID, fixture.nodeID).Scan(&execution); err != nil {
				t.Fatal(err)
			}
			if uint64(execution) != test.wantExecution || len(fixture.license.receiptSequences) != 1 ||
				fixture.license.receiptSequences[0] != test.installed {
				t.Fatalf("command execution %d, License saw %v; want %d over %d", execution,
					fixture.license.receiptSequences, test.wantExecution, test.installed)
			}
		})
	}
}

// The community edition keeps no license expiry cache, so the command issuance deadline the control
// plane asks for is now+CommandIssuanceTTL.
func TestCreateRolloutDeadlineIsIssuanceTTLPostgres(t *testing.T) {
	want := func(created time.Time) int64 { return created.Add(6 * time.Hour).Unix() }
	fixture := newCreateFlowFixture(t, "1.0.24", "1.0.27", 0, 127, 90)
	before := time.Now()
	created := fixture.create(t, t.Context(), fixture.request("deadline"))
	after := time.Now()
	var deadline time.Time
	if err := fixture.pool.QueryRow(t.Context(), `SELECT command_issuance_not_after
		FROM control_upgrade_rollout_plans WHERE id=$1`, created.ID).Scan(&deadline); err != nil {
		t.Fatal(err)
	}
	if got := deadline.Unix(); got < want(before) || got > want(after) {
		t.Fatalf("command issuance deadline = %s, want %d..%d", deadline, want(before), want(after))
	}
	fixture.start(t, created, "deadline")
}

// holdLock runs statement in an open transaction until release (or test end).
func holdLock(t *testing.T, pool *pgxpool.Pool, statement string, args ...any) func() {
	t.Helper()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), statement, args...); err != nil {
		_ = tx.Rollback(context.Background())
		t.Fatal(err)
	}
	var once sync.Once
	release := func() { once.Do(func() { _ = tx.Rollback(context.Background()) }) }
	t.Cleanup(release)
	return release
}

// The installation entitlement row is the global mutex of every entitlement-guarded write
// (guard check FOR UPDATE + last_verified_at UPDATE, ACME overlay, error page limits, node
// enrollment, CA epochs, lease sync). Creating and starting a rollout must not depend on it
// being idle: production returned 500 "could not obtain lock on row in relation
// control_installation_entitlement (55P03)".
func TestCreateRolloutWhileEntitlementRowIsLockedPostgres(t *testing.T) {
	for _, test := range []struct{ name, statement string }{
		{name: "guarded write FOR UPDATE",
			statement: `SELECT 1 FROM control_installation_entitlement WHERE singleton FOR UPDATE`},
		{name: "lease validation UPDATE",
			statement: `UPDATE control_installation_entitlement SET updated_at=updated_at WHERE singleton`},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCreateFlowFixture(t, "1.0.24", "1.0.27", 0, 127, 90)
			release := holdLock(t, fixture.pool, test.statement)
			defer release()
			created := fixture.create(t, t.Context(), fixture.request("locked"))
			fixture.start(t, created, "locked")
			if states := fixture.intents(t); states["consumed"] != 1 || len(states) != 1 {
				t.Fatalf("grant intents = %v", states)
			}
		})
	}
}

// A node identity change in flight (certificate renewal, re-enrollment) is a real conflict on
// that node: it is reported as retryable 503, never as a bare database error, and the same
// request then resumes from the acquired intent without asking the License service again.
func TestCreateRolloutNodeIdentityConflictIsRetryablePostgres(t *testing.T) {
	fixture := newCreateFlowFixture(t, "1.0.24", "1.0.27", 0, 127, 90)
	var release func()
	fixture.license.onIssue = func(*http.Request) {
		if release == nil {
			release = holdLock(t, fixture.pool, `SELECT 1 FROM node_identity_state WHERE node_id=$1 FOR UPDATE`,
				uuid.MustParse(fixture.nodeID))
		}
	}
	request := fixture.request("node-conflict")
	_, err := fixture.service.CreateRollout(t.Context(), fixture.actor, request)
	if !errors.Is(err, ErrResourceUnavailable) {
		t.Fatalf("create under node identity lock = %v, want ErrResourceUnavailable", err)
	}
	if states := fixture.intents(t); states["acquired"] != 1 || len(states) != 1 {
		t.Fatalf("grant intents after conflict = %v", states)
	}
	release()
	created := fixture.create(t, t.Context(), request)
	if states := fixture.intents(t); states["consumed"] != 1 || len(states) != 1 {
		t.Fatalf("grant intents after retry = %v", states)
	}
	if fixture.license.count("upgrade-grants:issue") != 1 || fixture.license.count("upgrade-plan-artifact-bundles:issue") != 1 {
		t.Fatalf("retry asked the License service again: %v", fixture.license.calls)
	}
	fixture.start(t, created, "node-conflict")
}

// A failure before the License grants are stored leaves the intent reserved; it is the
// resume point of the same request, which then completes on the same intent.
func TestCreateRolloutReservedIntentResumesPostgres(t *testing.T) {
	fixture := newCreateFlowFixture(t, "1.0.27", "1.0.27", 124, 127, 0)
	fixture.license.unavailable = 1
	request := fixture.request("license-down")
	if _, err := fixture.service.CreateRollout(t.Context(), fixture.actor, request); !errors.Is(err, ErrLicenseUnavailable) {
		t.Fatalf("create with License down = %v", err)
	}
	if states := fixture.intents(t); states["reserved"] != 1 || len(states) != 1 {
		t.Fatalf("grant intents after License failure = %v", states)
	}
	created := fixture.create(t, t.Context(), request)
	if states := fixture.intents(t); states["consumed"] != 1 || len(states) != 1 {
		t.Fatalf("grant intents after retry = %v", states)
	}
	fixture.start(t, created, "license-down")
}

// The browser giving up (production: 8 seconds) must not abandon a create half way: the
// server finishes it and the console's "retry the same request" gets the stored result.
func TestCreateRolloutSurvivesClientDisconnectPostgres(t *testing.T) {
	fixture := newCreateFlowFixture(t, "1.0.24", "1.0.27", 0, 127, 90)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	fixture.license.onIssue = func(*http.Request) { cancel() }
	request := fixture.request("disconnect")
	result, err := fixture.service.CreateRollout(ctx, fixture.actor, request)
	if err != nil || result.Detail.State != PlanQueued {
		t.Fatalf("create after client disconnect = (%+v, %v)", result.Detail.RolloutSummary, err)
	}
	fixture.license.onIssue = nil
	replay, err := fixture.service.CreateRollout(t.Context(), fixture.actor, request)
	if err != nil || !replay.Replayed || replay.Detail.ID != result.Detail.ID {
		t.Fatalf("same request after disconnect = (%v, %v)", replay.Replayed, err)
	}
	if states := fixture.intents(t); states["consumed"] != 1 || len(states) != 1 {
		t.Fatalf("grant intents = %v", states)
	}
}

// Start (and every other rollout action) is detached from the client the same way: the command
// grant and its outbox row are stored, and the console's retry of the same request replays it.
func TestApplyRolloutActionSurvivesClientDisconnectPostgres(t *testing.T) {
	fixture := newCreateFlowFixture(t, "1.0.24", "1.0.27", 0, 127, 90)
	created := fixture.create(t, t.Context(), fixture.request("start-disconnect"))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	fixture.license.onCommand = func(*http.Request) { cancel() }
	request := RolloutActionRequest{
		RolloutActionBody: RolloutActionBody{ExpectedRevision: created.Revision, Reason: "operator_upgrade"},
		PlanID:            created.ID, Operation: string(PlanStart),
		IdempotencyKey: "control-upgrade-start-disconnect", RequestID: "control-upgrade-start-request-disconnect"}
	result, err := fixture.service.ApplyRolloutAction(ctx, fixture.actor, request)
	if err != nil || result.Detail.State != PlanCanary {
		t.Fatalf("start after client disconnect = (%+v, %v)", result.Detail.RolloutSummary, err)
	}
	fixture.license.onCommand = nil
	replay, err := fixture.service.ApplyRolloutAction(t.Context(), fixture.actor, request)
	if err != nil || !replay.Replayed || replay.Detail.Revision != result.Detail.Revision {
		t.Fatalf("same start after disconnect = (%v, %v)", replay.Replayed, err)
	}
	var outbox int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM control_upgrade_outbox WHERE plan_id=$1`,
		created.ID).Scan(&outbox); err != nil {
		t.Fatal(err)
	}
	if outbox != 1 || fixture.license.count("upgrade-command-grants:issue") != 1 {
		t.Fatalf("outbox rows %d, command grant calls %d", outbox, fixture.license.count("upgrade-command-grants:issue"))
	}
}

// The command grant response's expires_at becomes the stored command expiry, so it must
// equal the signed grant's; a start answered otherwise fails without persisting a command.
func TestStartRejectsCommandGrantResponseExpiryMismatchPostgres(t *testing.T) {
	fixture := newCreateFlowFixture(t, "1.0.24", "1.0.27", 0, 127, 90)
	created := fixture.create(t, t.Context(), fixture.request("expiry-mismatch"))
	fixture.license.commandExpirySkew = -1
	_, err := fixture.service.ApplyRolloutAction(t.Context(), fixture.actor, RolloutActionRequest{
		RolloutActionBody: RolloutActionBody{ExpectedRevision: created.Revision, Reason: "operator_upgrade"},
		PlanID:            created.ID, Operation: string(PlanStart),
		IdempotencyKey: "control-upgrade-start-expiry", RequestID: "control-upgrade-start-request-expiry"})
	if !errors.Is(err, ErrGrantInvalid) {
		t.Fatalf("start with mismatched expires_at error = %v, want %v", err, ErrGrantInvalid)
	}
	var commands int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM control_upgrade_node_commands
		WHERE plan_id=$1`, created.ID).Scan(&commands); err != nil {
		t.Fatal(err)
	}
	if commands != 0 {
		t.Fatalf("mismatched start persisted %d commands", commands)
	}
}
