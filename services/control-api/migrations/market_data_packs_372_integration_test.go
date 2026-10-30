//go:build integration

package migrations_test

import (
	"crypto/sha256"
	"testing"

	"github.com/google/uuid"
)

// TestMarketDataPacks372: market rule packs must be developer packs, market
// themes are market.<plugin id> with source market; down refuses while any
// market artifact exists.
func TestMarketDataPacks372(t *testing.T) {
	const version = 372
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	userID := uuid.New()
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'market-361','Market 361','unused')`, userID)
	theme := func(id, source string) error {
		raw := []byte(id + source)
		digest := sha256.Sum256(raw)
		_, err := pool.Exec(ctx, `INSERT INTO theme_packages(package_sha256,theme_id,version,source,package_body,css_sha256,css_body,json_sha256,json_body,downloaded_by_user_id,downloaded_at)
			VALUES($1,$2,'1.0.0',$3,$4,sha256('c'::bytea),'c'::bytea,sha256('j'::bytea),'j'::bytea,$5,now())`, digest[:], id, source, raw, userID)
		return err
	}
	for _, bad := range [][2]string{{"market.io.x.dark", "upload"}, {"custom.x", "market"}, {"official.x", "market"}, {"market.io", "market"}} {
		if err := theme(bad[0], bad[1]); sqlState(err) != "23514" {
			t.Fatalf("theme %s as %s: %v, want 23514", bad[0], bad[1], err)
		}
	}
	for _, good := range [][2]string{{"market.io.x.dark", "market"}, {"custom.y", "upload"}, {"official.z", "builtin"}} {
		if err := theme(good[0], good[1]); err != nil {
			t.Fatalf("theme %s as %s: %v", good[0], good[1], err)
		}
	}
	pack := func(id, layer, source string) error {
		if _, err := pool.Exec(ctx, `INSERT INTO rule_packs(pack_id,layer,owner_scope_id,current_version,update_policy,
			created_by_user_id,updated_by_user_id,created_at,updated_at) VALUES($1,$2,NULL,NULL,'manual',$3,$3,now(),now())
			ON CONFLICT DO NOTHING`, id, layer, userID); err != nil {
			return err
		}
		digest := sha256.Sum256([]byte(id))
		_, err := pool.Exec(ctx, `INSERT INTO rule_pack_artifacts(pack_id,version,engine,engine_min_version,name,sha256,size_bytes,
			content,source,state,downloaded_at,created_by_user_id,created_at)
			VALUES($1,'1.0.0','waf_v2',1,'x',encode($2,'hex'),1,'x','`+source+`','downloaded',now(),$3,now())`, id, digest[:], userID)
		return err
	}
	if err := pack("system/market-x", "system", "market"); sqlState(err) != "23514" {
		t.Fatalf("system pack from market: %v, want 23514", err)
	}
	if err := pack("dev/io.x/sqli", "developer", "market"); err != nil {
		t.Fatalf("developer pack from market: %v", err)
	}
	mustExec(t, pool, `INSERT INTO market_data_pack_sources(artifact_id,kind,plugin_id,version,revision,sha256,local_name,status,materialized_at,updated_at)
		VALUES('market_rule_pack/io.x.sqli','market_rule_pack','io.x.sqli','1.0.0',1,repeat('a',64),'dev/io.x/sqli','active',now(),now())`)
	if _, err := pool.Exec(ctx, `INSERT INTO market_data_pack_sources(artifact_id,kind,plugin_id,version,revision,sha256,local_name,status,materialized_at,updated_at)
		VALUES('market_theme/io.x.dark','market_theme','io.x.dark','1.0.0',1,repeat('a',64),'market.io.x.other','active',now(),now())`); sqlState(err) != "23514" {
		t.Fatalf("theme source naming another theme: %v, want 23514", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P3722" {
		t.Fatalf("down with market artifacts: %v, want P3722", err)
	}
}
