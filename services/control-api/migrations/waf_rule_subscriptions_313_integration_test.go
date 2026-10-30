//go:build integration

package migrations_test

import (
	"testing"

	"github.com/google/uuid"
)

// TestWAFRuleSubscriptionsMigration rolls 313 up, down and up, checks the
// https-only URL and snapshot invariants, and that rollback refuses to drop
// configured libraries.
func TestWAFRuleSubscriptionsMigration(t *testing.T) {
	const version = 313
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	userID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'waf-sub','WAF sub','test-only')`, userID); err != nil {
		t.Fatal(err)
	}
	insert := `INSERT INTO waf_rule_subscriptions(id,name,source_url,interval_minutes,enabled,next_fetch_at,
		created_by_user_id,updated_by_user_id,created_at,updated_at) VALUES($1,'feed',$2,$3,true,now(),$4,$4,now(),now())`
	if _, err := pool.Exec(ctx, insert, uuid.New(), "http://feed.example/rules.json", 360, userID); err == nil {
		t.Fatal("http subscription URL accepted")
	}
	if _, err := pool.Exec(ctx, insert, uuid.New(), "https://feed.example/rules.json", 4, userID); err == nil {
		t.Fatal("interval below 5 minutes accepted")
	}
	id := uuid.New()
	if _, err := pool.Exec(ctx, insert, id, "https://feed.example/rules.json", 360, userID); err != nil {
		t.Fatalf("valid subscription rejected: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE waf_rule_subscriptions SET revision=1 WHERE id=$1`, id); err == nil {
		t.Fatal("revision without snapshot accepted")
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err == nil {
		t.Fatal("rollback dropped a configured subscription")
	}
}
