//go:build integration

package migrations_test

import (
	"testing"

	"github.com/jackc/pgx/v5"
)

// TestHTTPPolicyRefererCheck406: the HTTP policy document contract accepts
// referer_check (null or a check that restricts something) and refuses the
// rest; up, down and up again; down refuses once a revision carries it.
func TestHTTPPolicyRefererCheck406(t *testing.T) {
	const version = 406
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	base := `jsonb_build_object('schema_version','cdnca.control.http-policy/v1','policy_id',gen_random_uuid(),
		'tenant_scope_id',gen_random_uuid(),'site_id',gen_random_uuid(),'site_owner_user_id',gen_random_uuid(),'revision',1,
		'max_upload_bytes',1024,'request_headers','[]'::jsonb,'response_headers','[]'::jsonb,'rewrites','[]'::jsonb,
		'redirect_allowed_hosts','[]'::jsonb,'redirects','[]'::jsonb,'cors','null'::jsonb,'enabled',true,'deleted',false)`
	for check, want := range map[string]bool{
		`null`: true,
		`{"allow_empty":false,"allow_same_domain":true,"allowed_domains":["*.partner.example.test"],"denied_domains":["bad.partner.example.test"],"check_origin":true,"extensions":["jpg"]}`: true,
		`{"allow_empty":true,"allow_same_domain":false,"allowed_domains":[],"denied_domains":[],"check_origin":false,"extensions":[]}`:                                                       false,
		`{"allow_empty":true,"allow_same_domain":false,"allowed_domains":["a.example.test"],"denied_domains":["a.example.test"],"check_origin":false,"extensions":[]}`:                       false,
		`{"allow_empty":true,"allow_same_domain":false,"allowed_domains":["*.test"],"denied_domains":[],"check_origin":false,"extensions":[]}`:                                               false,
		`{"allow_empty":true,"allow_same_domain":true,"allowed_domains":[],"denied_domains":[],"check_origin":false,"extensions":["JPG"]}`:                                                   false,
	} {
		var got bool
		if err := pool.QueryRow(ctx, `SELECT http_policy_document_valid_056(`+base+`||jsonb_build_object('referer_check',$1::jsonb))`,
			check).Scan(&got); err != nil || got != want {
			t.Errorf("referer_check %s: valid=%v err=%v, want %v", check, got, err, want)
		}
	}
	var withoutKey bool
	if err := pool.QueryRow(ctx, `SELECT http_policy_document_valid_056(`+base+`)`).Scan(&withoutKey); err != nil || withoutKey {
		t.Fatalf("document without referer_check: valid=%v err=%v, want refused", withoutKey, err)
	}
	// down refuses while a revision carries referer_check. The fact is
	// written with triggers and foreign keys off (replica role) and only
	// stands for "some revision has the key".
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO http_policy_revisions(policy_id,tenant_scope_id,tenant_id,site_id,site_owner_user_id,
			revision,action,enabled,deleted,document,created_by_scope_id,created_by_user_id,request_id,trace_id,created_at)
			SELECT gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),1,'create',true,false,
			`+base+`||jsonb_build_object('referer_check','null'::jsonb),gen_random_uuid(),gen_random_uuid(),'r406','t406',now()`)
		return err
	}); err != nil {
		t.Fatalf("seed revision fact: %v", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P4062" {
		t.Fatalf("down with referer_check revisions: %v, want P4062", err)
	}
}
