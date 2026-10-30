//go:build integration

package securityrulecatalog

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/cdnca/cdnca/services/control-api/internal/artifactsync"
	"github.com/cdnca/cdnca/services/control-api/internal/artifactsync/artifactsynctest"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// The management UI view of the system rules artifactsync materialized from
// the artifact catalog: kinds and counts, tenant visibility, withdrawn rules
// frozen, the local overlay and the read-only table.
func TestSecurityRuleCatalogQueries(t *testing.T) {
	pool := databasetest.ClonedMigratedPool(t, nil)
	if pool == nil {
		t.Skip("TEST_DATABASE_TEMPLATE is not set (scripts/control-api-integration-sharded.sh)")
	}
	ctx := context.Background()
	installationID := uuid.MustParse("00000000-0000-4000-8000-0000000000a1")
	now := time.Now().UTC()
	clock := func() time.Time { return now }
	license := artifactsynctest.NewLicense(t, installationID, clock)
	syncer, err := artifactsync.NewSyncer(artifactsync.SyncerConfig{Client: license, Store: artifactsync.NewStore(pool, clock),
		Trust: license.Trust(), InstallationID: installationID, PrivateKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)),
		ControlVersion: "1.0.35", Now: clock, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	sync := func() {
		t.Helper()
		if err := syncer.SyncOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}
	store := NewStore(pool, clock)
	platform := Viewer{UserID: uuid.New(), ScopeID: uuid.New(), Platform: true}
	tenant := Viewer{UserID: uuid.New(), ScopeID: uuid.New()}
	// The production IAM check takes FOR SHARE row locks inside the caller's
	// transaction, so the authorizer stand-in does the same.
	allow := func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "SELECT 1 FROM security_system_rules ORDER BY system_key LIMIT 1 FOR SHARE")
		return err
	}
	count := func(viewer Viewer, kind string) int {
		rules, err := store.List(ctx, viewer, kind, allow)
		if err != nil {
			t.Fatal(err)
		}
		return len(rules)
	}
	if status, err := store.Status(ctx, allow); err != nil || status.Synced || status.ActiveCount != 0 {
		t.Fatalf("status before the first sync = %+v, %v", status, err)
	}

	// 1. Fresh install, no tenants: the seed catalog shows 11/3/17 at once.
	for _, item := range rulecatalog.CompetitorSeed() {
		license.PublishRule(item, "", true)
	}
	sync()
	if count(platform, rulecatalog.KindCCRuleGroup) != 11 || count(platform, rulecatalog.KindCCMatcher) != 3 || count(platform, rulecatalog.KindCCFilter) != 17 {
		t.Fatalf("fresh install counts = %d/%d/%d", count(platform, rulecatalog.KindCCRuleGroup), count(platform, rulecatalog.KindCCMatcher), count(platform, rulecatalog.KindCCFilter))
	}
	// 临时白名单 is hidden (competitor is_show=0): tenants see 10 groups.
	if count(tenant, rulecatalog.KindCCRuleGroup) != 10 {
		t.Fatalf("tenant rule groups = %d, want 10", count(tenant, rulecatalog.KindCCRuleGroup))
	}
	status, err := store.Status(ctx, allow)
	if err != nil || !status.Synced || status.ScopeRevision != 1 || status.DeliveryID != license.Last().Envelope.DeliveryID ||
		status.ActiveCount != 31 || status.WithdrawnCount != 0 || status.Stale || status.LastErrorCode != "" {
		t.Fatalf("status after the first sync = %+v, %v", status, err)
	}

	// 2. The catalog drops 宽松 and its filter: they stay frozen as withdrawn.
	if _, err := store.SetTenantEnabled(ctx, tenant, "cc_rule:6", true, allow); err != nil {
		t.Fatal(err)
	}
	license.Withdraw("ruleset/cc_rule:6")
	license.Withdraw("ruleset/cc_filter:9")
	sync()
	rules, _ := store.List(ctx, tenant, rulecatalog.KindCCRuleGroup, allow)
	var relaxed *Rule
	for index := range rules {
		if rules[index].SystemKey == "cc_rule:6" {
			relaxed = &rules[index]
		}
	}
	if relaxed == nil || relaxed.Status != "withdrawn" || relaxed.Selectable || !relaxed.Enabled || relaxed.Name != "宽松" ||
		relaxed.Body.CCRuleGroup.Entries[0].Filter1Key != "cc_filter:9" {
		t.Fatalf("withdrawn 宽松 = %+v", relaxed)
	}
	if _, err := store.SetTenantEnabled(ctx, tenant, "cc_rule:6", false, allow); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetTenantEnabled(ctx, tenant, "cc_rule:6", true, allow); !errors.Is(err, ErrWithdrawnRule) {
		t.Fatalf("re-enable withdrawn error = %v", err)
	}

	// 3. License service outage after expiry: rules are kept, status is stale.
	now = now.Add(8 * 24 * time.Hour)
	license.ResolveErr = errors.New("unavailable")
	if err := syncer.SyncOnce(ctx); err == nil {
		t.Fatal("outage did not surface an error")
	}
	status, err = store.Status(ctx, allow)
	if err != nil || !status.Stale || status.ActiveCount != 29 || status.WithdrawnCount != 2 || status.LastErrorCode != "resolve_failed" {
		t.Fatalf("status during outage = %+v, %v", status, err)
	}

	// 4. Admin overlay: hide 关闭 for everyone (10 -> 9), then show JS验证 only
	// to the other tenant (tenant 8, other 9).
	other := Viewer{UserID: uuid.New(), ScopeID: uuid.New()}
	if _, err := store.SetVisibility(ctx, platform, "cc_rule:10002", false, nil, allow); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetVisibility(ctx, platform, "cc_rule:1", true, []uuid.UUID{other.ScopeID}, allow); err != nil {
		t.Fatal(err)
	}
	if count(tenant, rulecatalog.KindCCRuleGroup) != 8 || count(other, rulecatalog.KindCCRuleGroup) != 9 {
		t.Fatalf("overlay counts tenant=%d other=%d", count(tenant, rulecatalog.KindCCRuleGroup), count(other, rulecatalog.KindCCRuleGroup))
	}
	if _, err := store.SetTenantEnabled(ctx, tenant, "cc_rule:1", false, allow); !errors.Is(err, ErrNotFound) {
		t.Fatalf("toggle invisible rule error = %v", err)
	}

	// 5. System rule rows are read-only outside artifactsync materialization.
	var pgError *pgconn.PgError
	if _, err := pool.Exec(ctx, `UPDATE security_system_rules SET name='x' WHERE system_key='cc_rule:1'`); !errors.As(err, &pgError) || pgError.Code != "P2821" {
		t.Fatalf("direct update error = %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM security_system_rules`); !errors.As(err, &pgError) || pgError.Code != "P2821" {
		t.Fatalf("direct delete error = %v", err)
	}
}
