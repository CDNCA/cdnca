//go:build integration

package migrations_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 672: 671 -> 672 -> 671 -> 672. Before 672 the plan trigger rejects every schema 3
// plan (cross-version upgrades and same-version re-releases) with P9302; after it v3 plans bind strictly to
// the v2 plan bundle with v3 manifests, v1/v2 behave as before, and down refuses while v3 plans exist.
func TestUpgradePlanSchemaV3672UpDownUp(t *testing.T) {
	const version = 672
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	identity := seedUpgradePlan672Identity(t, pool)
	accepts := func() bool {
		t.Helper()
		var definition string
		if err := pool.QueryRow(ctx, `SELECT pg_get_functiondef('validate_control_upgrade_plan_093()'::regprocedure)`).
			Scan(&definition); err != nil {
			t.Fatal(err)
		}
		return strings.Contains(definition, "NOT IN (1,2,3)")
	}
	if accepts() {
		t.Fatal("671 plan trigger already accepts schema 3")
	}
	// Reproduces the defect: a valid cross-version v3 plan cannot be written at 671.
	assertUpgradePlan672Code(t, pool, identity, upgradePlan672V3(identity, false), "P9302")
	for _, step := range []struct {
		direction string
		present   bool
	}{{"up", true}, {"down", false}, {"up", true}} {
		if err := migrateVersionIsolated(ctx, pool, step.direction, version); err != nil {
			t.Fatalf("%s %d: %v", step.direction, version, err)
		}
		if accepts() != step.present {
			t.Fatalf("after %s: plan trigger accepts schema 3 = %v", step.direction, !step.present)
		}
	}

	t.Run("v1 and v2 unchanged", func(t *testing.T) {
		assertUpgradePlan672Code(t, pool, identity, upgradePlan672V1(identity), "")
		assertUpgradePlan672Code(t, pool, identity, upgradePlan672V2(identity), "")
		v2 := upgradePlan672V2(identity)
		v2.snapshot["RollbackReleaseSequence"] = 3
		assertUpgradePlan672Code(t, pool, identity, v2, "P9302")
		v4 := upgradePlan672V3(identity, false)
		v4.schema, v4.snapshot["SchemaVersion"] = 4, 4
		assertUpgradePlan672Code(t, pool, identity, v4, "P9302")
	})
	t.Run("v3 valid", func(t *testing.T) {
		assertUpgradePlan672Code(t, pool, identity, upgradePlan672V3(identity, false), "")
		assertUpgradePlan672Code(t, pool, identity, upgradePlan672V3(identity, true), "")
	})
	for _, test := range []struct {
		name   string
		same   bool
		tamper func(*upgradePlan672)
	}{
		{"release sequence not forward manifest", false, func(p *upgradePlan672) { p.snapshot["ReleaseSequence"] = 13 }},
		{"rollback sequence not rollback manifest", false, func(p *upgradePlan672) { p.snapshot["RollbackReleaseSequence"] = 5 }},
		{"rollback sequence not below forward", false, func(p *upgradePlan672) {
			p.snapshot["RollbackReleaseSequence"] = 12
			p.rollbackManifest()["release_sequence"] = 12
		}},
		{"rollback sequence zero", false, func(p *upgradePlan672) {
			p.snapshot["RollbackReleaseSequence"] = 0
			p.rollbackManifest()["release_sequence"] = 0
		}},
		{"bundle schema v1", false, func(p *upgradePlan672) {
			p.bundle()["schema"] = "cdnca.upgrade.plan-artifact-bundle/v1"
		}},
		{"forward manifest v2", false, func(p *upgradePlan672) { p.forwardManifest()["schema"] = "cdnca.release.artifact/v2" }},
		{"rollback manifest v2", false, func(p *upgradePlan672) { p.rollbackManifest()["schema"] = "cdnca.release.artifact/v2" }},
		{"cross-version without rollback", false, func(p *upgradePlan672) {
			p.snapshot["Safety"] = map[string]any{"RollbackAvailable": false}
		}},
		{"rollback artifact", false, func(p *upgradePlan672) { p.snapshot["RollbackArtifactID"] = uuid.NewString() }},
		{"rollback digest", false, func(p *upgradePlan672) { p.snapshot["RollbackSHA256Digest"] = digest672("other") }},
		{"rollback grant digest", false, func(p *upgradePlan672) { p.snapshot["RollbackGrantDigest"] = digest672("other") }},
		{"rollback size column", false, func(p *upgradePlan672) { p.rollbackSize = 99 }},
		{"forward artifact", false, func(p *upgradePlan672) { p.snapshot["ArtifactID"] = uuid.NewString() }},
		{"forward size column", false, func(p *upgradePlan672) { p.artifactSize = 99 }},
		{"snapshot claims re-release", false, func(p *upgradePlan672) { p.snapshot["CurrentReleaseSequence"] = 4 }},
		{"bundle claims re-release", false, func(p *upgradePlan672) { p.bundle()["current_release_sequence"] = 4 }},
		{"cross-version same versions", false, func(p *upgradePlan672) {
			p.snapshot["TargetVersion"] = "1.0.34"
			p.bundle()["version"] = "1.0.34"
			p.forwardManifest()["version"] = "1.0.34"
		}},
		{"plan bundle id", false, func(p *upgradePlan672) { p.bundle()["plan_id"] = uuid.NewString() }},
		{"current sequence not bundle", true, func(p *upgradePlan672) { p.snapshot["CurrentReleaseSequence"] = 9 }},
		{"current sequence string", true, func(p *upgradePlan672) { p.snapshot["CurrentReleaseSequence"] = "10" }},
		{"bundle current sequence missing", true, func(p *upgradePlan672) { delete(p.bundle(), "current_release_sequence") }},
		{"forward not above current", true, func(p *upgradePlan672) {
			p.snapshot["CurrentReleaseSequence"] = 12
			p.bundle()["current_release_sequence"] = 12
		}},
		{"re-release rollback available", true, func(p *upgradePlan672) {
			p.snapshot["Safety"] = map[string]any{"RollbackAvailable": true}
		}},
		{"re-release rollback artifact", true, func(p *upgradePlan672) {
			p.snapshot["RollbackArtifactID"] = p.forwardManifest()["artifact_id"]
		}},
		{"re-release rollback grant digest", true, func(p *upgradePlan672) {
			p.snapshot["RollbackGrantDigest"] = p.snapshot["GrantDigest"]
		}},
		{"re-release rollback sequence", true, func(p *upgradePlan672) { p.snapshot["RollbackReleaseSequence"] = 12 }},
		{"re-release rollback size", true, func(p *upgradePlan672) {
			p.rollbackSize = 4096
			p.snapshot["RollbackArtifactSizeBytes"] = 4096
		}},
		{"re-release forward differs from rollback", true, func(p *upgradePlan672) {
			p.rollbackManifest()["sha256_digest"] = digest672("other")
		}},
		{"re-release versions differ", true, func(p *upgradePlan672) {
			p.snapshot["CurrentVersion"] = "1.0.34"
			p.bundle()["current_version"] = "1.0.34"
			p.rollbackManifest()["version"] = "1.0.34"
		}},
	} {
		t.Run("v3 tamper "+test.name, func(t *testing.T) {
			plan := upgradePlan672V3(identity, test.same)
			test.tamper(&plan)
			assertUpgradePlan672Code(t, pool, identity, plan, "P9302")
		})
	}

	t.Run("down refuses schema 3 plans", func(t *testing.T) {
		plan := upgradePlan672V3(identity, true)
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := insertUpgradePlan672(ctx, tx, identity, plan); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		err = migrateVersionIsolated(ctx, pool, "down", version)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "P6722" {
			t.Fatalf("down with a schema 3 plan: %v", err)
		}
		if !accepts() {
			t.Fatal("refused down still replaced the plan trigger")
		}
	})
}

type upgradePlan672Identity struct{ scopeID, userID, installationID string }

// upgradePlan672 is one control_upgrade_rollout_plans row: the canonical snapshot and plan bundle as
// JSON objects (the trigger compares jsonb values, signatures are verified in Go before the write).
type upgradePlan672 struct {
	id                         string
	schema                     int
	snapshot                   map[string]any
	bundleDocument             map[string]any
	artifactSize, rollbackSize int64
	parentExpires, notAfter    int64
}

func (p upgradePlan672) bundle() map[string]any { return p.bundleDocument["bundle"].(map[string]any) }
func (p upgradePlan672) forwardManifest() map[string]any {
	return p.bundle()["forward"].(map[string]any)["manifest"].(map[string]any)
}
func (p upgradePlan672) rollbackManifest() map[string]any {
	return p.bundle()["rollback"].(map[string]any)["manifest"].(map[string]any)
}

func digest672(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

var (
	upgradePlan672Parent  = []byte(`{"grant":"planv3-parent"}`)
	upgradePlan672Profile = map[string]any{"Platform": "linux", "Architecture": "amd64"}
)

func upgradePlan672V1(identity upgradePlan672Identity) upgradePlan672 {
	id := uuid.NewString()
	return upgradePlan672{id: id, schema: 1, snapshot: map[string]any{"ID": id, "SchemaVersion": 1,
		"Revision": 1, "State": "queued", "ResumeState": "", "Completion": "", "ActiveBatch": -1}}
}

// upgradePlan672V2 is the pre-672 shape: a v1 plan bundle whose channel_revision is the plan
// ReleaseSequence, and rollback sequence equal to it.
func upgradePlan672V2(identity upgradePlan672Identity) upgradePlan672 {
	plan := upgradePlan672Base(identity, 2, "1.0.34", "1.0.35")
	plan.bundle()["schema"] = "cdnca.upgrade.plan-artifact-bundle/v1"
	plan.forwardManifest()["schema"] = "cdnca.release.artifact/v2"
	plan.rollbackManifest()["schema"] = "cdnca.release.artifact/v2"
	delete(plan.forwardManifest(), "release_sequence")
	delete(plan.rollbackManifest(), "release_sequence")
	plan.bundle()["channel_revision"] = 7
	plan.snapshot["ReleaseSequence"], plan.snapshot["RollbackReleaseSequence"] = 7, 7
	return plan
}

// upgradePlan672V3 mirrors controlupgrade.newRolloutPlanFromArtifacts for a plan-artifact-bundle/v2:
// cross-version (forward 12, rollback 4) or same-version re-release (installed 10, forward 12).
func upgradePlan672V3(identity upgradePlan672Identity, sameVersion bool) upgradePlan672 {
	if !sameVersion {
		return upgradePlan672Base(identity, 3, "1.0.34", "1.0.35")
	}
	plan := upgradePlan672Base(identity, 3, "1.0.35", "1.0.35")
	bundle := plan.bundle()
	bundle["current_release_sequence"] = 10
	rollback := map[string]any{}
	for key, value := range bundle["forward"].(map[string]any) {
		rollback[key] = value
	}
	manifest := map[string]any{}
	for key, value := range plan.forwardManifest() {
		manifest[key] = value
	}
	rollback["manifest"] = manifest
	bundle["rollback"] = rollback
	plan.snapshot["CurrentReleaseSequence"] = 10
	plan.snapshot["RollbackReleaseSequence"] = 0
	plan.snapshot["RollbackGrantDigest"], plan.snapshot["RollbackArtifactID"] = "", ""
	plan.snapshot["RollbackSHA256Digest"], plan.snapshot["RollbackArtifactSizeBytes"] = "", 0
	plan.snapshot["Safety"] = map[string]any{"RollbackAvailable": false}
	plan.rollbackSize = 0
	return plan
}

func upgradePlan672Base(identity upgradePlan672Identity, schema int, current, target string) upgradePlan672 {
	id, bundleID, parentID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	forwardID, rollbackID := uuid.NewString(), uuid.NewString()
	now := time.Now().Unix()
	parentExpires, notAfter := now+3600, now+7200
	manifest := func(artifactID, version, digest string, size int64, sequence int) map[string]any {
		return map[string]any{"manifest": map[string]any{"schema": "cdnca.release.artifact/v3",
			"artifact_id": artifactID, "component": "edge-agent", "version": version,
			"artifact_size_bytes": size, "release_sequence": sequence, "sha256_digest": digest}}
	}
	grantDigest := digest672(string(upgradePlan672Parent))
	bundleDocument := map[string]any{"bundle": map[string]any{
		"schema": "cdnca.upgrade.plan-artifact-bundle/v2", "bundle_id": bundleID, "plan_id": id,
		"initial_plan_revision": 1, "parent_grant_id": parentID, "parent_grant_sha256": grantDigest,
		"parent_grant_expires_at": parentExpires, "installation_id": identity.installationID,
		"channel_revision": 3, "component": "edge-agent", "current_version": current, "version": target,
		"forward":                    manifest(forwardID, target, digest672("forward"), 8192, 12),
		"rollback":                   manifest(rollbackID, current, digest672("rollback"), 4096, 4),
		"command_issuance_not_after": notAfter}}
	plan := upgradePlan672{id: id, schema: schema, bundleDocument: bundleDocument,
		artifactSize: 8192, rollbackSize: 4096, parentExpires: parentExpires, notAfter: notAfter}
	plan.snapshot = map[string]any{"ID": id, "SchemaVersion": schema, "Revision": 1, "State": "queued",
		"ResumeState": "", "Completion": "", "ActiveBatch": -1, "ParentGrantID": parentID,
		"GrantDigest": grantDigest, "ParentGrantExpiresAt": parentExpires, "ArtifactBundleID": bundleID,
		"CommandIssuanceNotAfter": notAfter,
		"ReleaseSequence":         12, "Component": "edge-agent", "ArtifactID": forwardID,
		"SHA256Digest": digest672("forward"), "ArtifactSizeBytes": 8192, "RollbackGrantDigest": grantDigest,
		"RollbackReleaseSequence": 4, "RollbackArtifactID": rollbackID, "RollbackSHA256Digest": digest672("rollback"),
		"RollbackArtifactSizeBytes": 4096, "CurrentVersion": current, "TargetVersion": target,
		"ForwardProfile": upgradePlan672Profile, "RollbackProfile": upgradePlan672Profile,
		"Safety": map[string]any{"RollbackAvailable": true}}
	return plan
}

func seedUpgradePlan672Identity(t *testing.T, pool *pgxpool.Pool) upgradePlan672Identity {
	t.Helper()
	tenantID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO tenants(id,display_name) VALUES($1,'planv3 tenant')`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO users(id,username,display_name,password_hash)
		VALUES($1,$2,'planv3 operator','test-only')`, userID, "planv3-"+userID.String()[:8]); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID); err != nil {
		t.Fatal(err)
	}
	return upgradePlan672Identity{scopeID: scopeID.String(), userID: userID.String(), installationID: uuid.NewString()}
}

type upgradePlan672Execer interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func insertUpgradePlan672(ctx context.Context, tx upgradePlan672Execer, identity upgradePlan672Identity,
	plan upgradePlan672) error {
	sum := func(value []byte) []byte { digest := sha256.Sum256(value); return digest[:] }
	var bundle []byte
	if plan.schema != 1 {
		var err error
		if bundle, err = json.Marshal(plan.bundleDocument); err != nil {
			return err
		}
		// Bound to the final bundle bytes so a tamper is judged on the field it changed.
		plan.snapshot["ArtifactBundleSHA256"] = base64.RawURLEncoding.EncodeToString(sum(bundle))
	}
	snapshot, err := json.Marshal(plan.snapshot)
	if err != nil {
		return err
	}
	if plan.schema == 1 {
		_, err = tx.Exec(ctx, `INSERT INTO control_upgrade_rollout_plans(id,actor_scope_id,actor_user_id,
			installation_id,schema_version,revision,state,resume_state,completion,active_batch,
			canonical_snapshot_bytes,canonical_snapshot_sha256,created_at,updated_at)
			VALUES($1,$2,$3,$4,1,1,'queued','','',-1,$5,$6,now(),now())`, plan.id, identity.scopeID,
			identity.userID, identity.installationID, snapshot, sum(snapshot))
		return err
	}
	profile, _ := json.Marshal(upgradePlan672Profile)
	_, err = tx.Exec(ctx, `INSERT INTO control_upgrade_rollout_plans(id,actor_scope_id,actor_user_id,
		installation_id,schema_version,revision,state,resume_state,completion,active_batch,
		canonical_snapshot_bytes,canonical_snapshot_sha256,created_at,updated_at,parent_grant_id,
		parent_grant_bytes,parent_grant_sha256,parent_grant_expires_at,artifact_bundle_id,artifact_bundle_bytes,
		artifact_bundle_sha256,command_issuance_not_after,forward_profile_bytes,forward_profile_sha256,
		rollback_profile_bytes,rollback_profile_sha256,artifact_size_bytes,rollback_artifact_size_bytes)
		VALUES($1,$2,$3,$4,$5,1,'queued','','',-1,$6,$7,now(),now(),$8,$9,$10,to_timestamp($11),$12,$13,$14,
		to_timestamp($15),$16,$17,$16,$17,$18,$19)`, plan.id, identity.scopeID, identity.userID,
		identity.installationID, plan.schema, snapshot, sum(snapshot), plan.snapshot["ParentGrantID"],
		upgradePlan672Parent, sum(upgradePlan672Parent), plan.parentExpires, plan.snapshot["ArtifactBundleID"],
		bundle, sum(bundle), plan.notAfter, profile, sum(profile), plan.artifactSize, plan.rollbackSize)
	return err
}

// assertUpgradePlan672Code inserts plan in a rolled-back transaction; code "" means accepted.
func assertUpgradePlan672Code(t *testing.T, pool *pgxpool.Pool, identity upgradePlan672Identity,
	plan upgradePlan672, code string) {
	t.Helper()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	err = insertUpgradePlan672(t.Context(), tx, identity, plan)
	var pgErr *pgconn.PgError
	switch {
	case code == "" && err != nil:
		t.Fatalf("schema %d plan rejected: %v", plan.schema, err)
	case code != "" && (!errors.As(err, &pgErr) || pgErr.Code != code):
		t.Fatalf("schema %d plan error = %v, want %s", plan.schema, err, code)
	}
}
