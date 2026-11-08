package challengepolicy

import (
	"context"
	"io/fs"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/jackc/pgx/v5"
)

// pow_difficulty (migration 646) round-trips through revision, document,
// projection and publication snapshot; NULL keeps the document without the
// key; state transitions cannot change it; 646 down refuses explicit facts.
func TestChallengePolicyPoWDifficultyRoundTripAndGuards(t *testing.T) {
	ctx := context.Background()
	fixture := newFixture(t, allowGate())
	config := validConfig(ModeSlider)
	difficulty := 20
	config.PowDifficulty = &difficulty
	created, err := fixture.service.Create(ctx, fixture.ownerA, CreateRequest{
		TargetScopeID: fixture.tenantA, SiteID: fixture.siteA, Host: "a.example.test", Enabled: true,
		Config: config, WriteMetadata: metadata("pow-create"),
	})
	if err != nil || created.Policy.PowDifficulty == nil || *created.Policy.PowDifficulty != 20 {
		t.Fatalf("create with pow_difficulty = (%#v, %v)", created.Policy.PowDifficulty, err)
	}
	read, err := fixture.service.Get(ctx, fixture.ownerA, fixture.tenantA, created.Policy.ID)
	if err != nil || read.PowDifficulty == nil || *read.PowDifficulty != 20 {
		t.Fatalf("get pow_difficulty = (%v, %v)", read.PowDifficulty, err)
	}
	var column *int
	var documentValue *string
	if err := fixture.pool.QueryRow(ctx, `SELECT pow_difficulty, document->>'pow_difficulty'
		FROM challenge_policy_revisions WHERE policy_id=$1 AND revision=1`, created.Policy.ID).
		Scan(&column, &documentValue); err != nil || column == nil || *column != 20 ||
		documentValue == nil || *documentValue != "20" {
		t.Fatalf("revision 1 pow_difficulty column=%v document=%v err=%v", column, documentValue, err)
	}
	var snapshotDifficulty *int
	if err := fixture.service.ReadPublicationSnapshot(ctx, fixture.ownerA, fixture.tenantA, created.Policy.ID,
		func(_ context.Context, _ pgx.Tx, snapshot PublicationSnapshot) error {
			snapshotDifficulty = snapshot.PowDifficulty
			return nil
		}); err != nil || snapshotDifficulty == nil || *snapshotDifficulty != 20 {
		t.Fatalf("publication snapshot pow_difficulty = (%v, %v)", snapshotDifficulty, err)
	}

	// A disable revision that also changes pow_difficulty is refused even with a matching audit.
	assertAuditedStatePoWTamperRejected(t, fixture, created.Policy, 1)

	// Back to the default: NULL column and no key in the document.
	updated, err := fixture.service.Update(ctx, fixture.ownerA, UpdateRequest{
		TargetScopeID: fixture.tenantA, ID: created.Policy.ID, ExpectedRevision: 1,
		Config: validConfig(ModeSlider), WriteMetadata: metadata("pow-default"),
	})
	if err != nil || updated.Policy.PowDifficulty != nil || updated.Policy.Revision != 2 {
		t.Fatalf("update to default = (%#v, %v)", updated.Policy, err)
	}
	var hasKey bool
	if err := fixture.pool.QueryRow(ctx, `SELECT pow_difficulty IS NULL AND NOT document ? 'pow_difficulty'
		FROM challenge_policy_revisions WHERE policy_id=$1 AND revision=2`, created.Policy.ID).Scan(&hasKey); err != nil || !hasKey {
		t.Fatalf("default revision keeps pow_difficulty: ok=%v err=%v", hasKey, err)
	}

	// external may not carry a difficulty, at the database too.
	var definition string
	if err := fixture.pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint
		WHERE conname='challenge_policy_revisions_pow_difficulty_646'`).Scan(&definition); err != nil ||
		!strings.Contains(definition, "<> 'external'") {
		t.Fatalf("646 constraint = %q err=%v", definition, err)
	}

	script, err := fs.ReadFile(migrations.FS, "646_challenge_pow_difficulty.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(ctx, string(script)); err == nil ||
		!strings.Contains(err.Error(), "explicit pow_difficulty facts") {
		t.Fatalf("646 down with explicit facts error = %v", err)
	}
	if err := fixture.pool.QueryRow(ctx, `SELECT pow_difficulty FROM challenge_policy_revisions
		WHERE policy_id=$1 AND revision=1`, created.Policy.ID).Scan(&column); err != nil || column == nil || *column != 20 {
		t.Fatalf("failed 646 down changed facts: %v %v", column, err)
	}
}

func assertAuditedStatePoWTamperRejected(t *testing.T, fixture *testFixture, policy Policy, expectedRevision int64) {
	t.Helper()
	ctx := context.Background()
	tx, err := fixture.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	actorUserID := fixture.ownerA.UserID
	if err := audit.New(fixture.pool).Append(ctx, tx, audit.Event{
		ScopeID: policy.TenantScopeID, ActorUserID: &actorUserID,
		Action: "challenge_policy.disable", ResourceType: "challenge_policy",
		ResourceID: policy.ID.String(), RequestID: "direct-pow-tamper", Result: "success",
		Payload: map[string]any{"trace_id": "direct-pow-tamper-trace", "revision": expectedRevision + 1},
	}); err != nil {
		t.Fatalf("append tamper audit: %v", err)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO challenge_policy_revisions (
			policy_id, tenant_scope_id, tenant_id, site_id, host, revision, action,
			priority, mode, min_delay_seconds, challenge_ttl_seconds, pass_ttl_seconds,
			clock_skew_seconds, attempts_per_nonce, failure_window_seconds, max_failures_per_window,
			ip_binding, bind_user_agent, bypass_routes, key_reference, external_provider,
			external_app_reference, enabled, deleted, document, created_by_scope_id,
			created_by_user_id, request_id, trace_id, created_at, pow_difficulty
		)
		SELECT policy_id, tenant_scope_id, tenant_id, site_id, host, revision+1, 'disable',
		       priority, mode, min_delay_seconds, challenge_ttl_seconds, pass_ttl_seconds,
		       clock_skew_seconds, attempts_per_nonce, failure_window_seconds, max_failures_per_window,
		       ip_binding, bind_user_agent, bypass_routes, key_reference, external_provider,
		       external_app_reference, false, false,
		       jsonb_set(jsonb_set(jsonb_set(document, '{revision}', to_jsonb((revision+1)::bigint)),
		           '{enabled}', 'false'::jsonb), '{pow_difficulty}', '24'::jsonb),
		       $2, $3, 'direct-pow-tamper', 'direct-pow-tamper-trace', now(), 24
		FROM challenge_policy_revisions WHERE policy_id=$1 AND revision=$4`,
		policy.ID, fixture.ownerA.ScopeID, fixture.ownerA.UserID, expectedRevision)
	if err == nil || !strings.Contains(err.Error(), "cannot change configuration") {
		t.Fatalf("disable that changes pow_difficulty error = %v", err)
	}
}
