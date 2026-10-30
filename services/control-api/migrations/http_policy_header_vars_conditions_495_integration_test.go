//go:build integration

package migrations_test

import (
	"testing"

	"github.com/jackc/pgx/v5"
)

// TestHTTPPolicyHeaderVarsConditions495: the HTTP policy document contract
// accepts header variables, allow_duplicate (add only) and rule conditions
// and refuses the rest; up, down and up again; down refuses once a revision
// carries any of them.
func TestHTTPPolicyHeaderVarsConditions495(t *testing.T) {
	const version = 495
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	document := func(requestHeaders, rewrites, redirects string) string {
		return `jsonb_build_object('schema_version','cdnca.control.http-policy/v1','policy_id',gen_random_uuid(),
		'tenant_scope_id',gen_random_uuid(),'site_id',gen_random_uuid(),'site_owner_user_id',gen_random_uuid(),'revision',1,
		'max_upload_bytes',1024,'request_headers','` + requestHeaders + `'::jsonb,'response_headers','[]'::jsonb,
		'rewrites','` + rewrites + `'::jsonb,'redirect_allowed_hosts','["a.example.test"]'::jsonb,'redirects','` + redirects + `'::jsonb,
		'cors','null'::jsonb,'referer_check','null'::jsonb,'enabled',true,'deleted',false)`
	}
	rewrite := func(id, conditions string) string {
		return `{"rule_id":"` + id + `","priority":1,"match_kind":"prefix","match_path":"/app/","target_path":"/m/","preserve_query":true,"preserve_cookie":true` + conditions + `}`
	}
	cond := `,"conditions":[{"source":"user_agent","pattern":"iPhone|Android"}]`
	for name, item := range map[string]struct {
		headers, rewrites, redirects string
		want                         bool
	}{
		"plain":                  {`[]`, `[]`, `[]`, true},
		"variables":              {`[{"kind":"set","name":"x-client","values":["$remote_addr $$ $tls_fp-$country"]}]`, `[]`, `[]`, true},
		"allow duplicate add":    {`[{"kind":"add","name":"x-a","values":["v"],"allow_duplicate":true}]`, `[]`, `[]`, true},
		"allow duplicate on set": {`[{"kind":"set","name":"x-a","values":["v"],"allow_duplicate":true}]`, `[]`, `[]`, false},
		"unknown variable":       {`[{"kind":"set","name":"x-a","values":["$nope"]}]`, `[]`, `[]`, false},
		"name run too long":      {`[{"kind":"set","name":"x-a","values":["$hostx"]}]`, `[]`, `[]`, false},
		"rewrite condition":      {`[]`, `[` + rewrite("r1", cond) + `]`, `[]`, true},
		// two same-priority overlapping rewrites: refused without
		// conditions, allowed when one has conditions
		"overlap no conditions":   {`[]`, `[` + rewrite("r1", "") + `,` + rewrite("r2", "") + `]`, `[]`, false},
		"overlap with conditions": {`[]`, `[` + rewrite("r1", cond) + `,` + rewrite("r2", "") + `]`, `[]`, true},
		"redirect condition":      {`[]`, `[]`, `[{"rule_id":"d1","priority":2,"match_kind":"prefix","match_path":"/","status":302,"target_url":"https://a.example.test/x","preserve_query":false,"preserve_path":false,"conditions":[{"source":"header","name":"x-beta","pattern":"^1$"}]}]`, true},
		"header without name":     {`[]`, `[` + rewrite("r1", `,"conditions":[{"source":"header","pattern":"x"}]`) + `]`, `[]`, false},
		"empty conditions":        {`[]`, `[` + rewrite("r1", `,"conditions":[]`) + `]`, `[]`, false},
		"unknown source":          {`[]`, `[` + rewrite("r1", `,"conditions":[{"source":"body","pattern":"x"}]`) + `]`, `[]`, false},
	} {
		var got bool
		if err := pool.QueryRow(ctx, `SELECT http_policy_document_valid_056(`+document(item.headers, item.rewrites, item.redirects)+`)`).Scan(&got); err != nil || got != item.want {
			t.Errorf("%s: valid=%v err=%v, want %v", name, got, err, item.want)
		}
	}
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO http_policy_revisions(policy_id,tenant_scope_id,tenant_id,site_id,site_owner_user_id,
			revision,action,enabled,deleted,document,created_by_scope_id,created_by_user_id,request_id,trace_id,created_at)
			SELECT gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),1,'create',true,false,
			`+document(`[{"kind":"set","name":"x-client","values":["$remote_addr"]}]`, `[]`, `[]`)+`,gen_random_uuid(),gen_random_uuid(),'r495','t495',now()`)
		return err
	}); err != nil {
		t.Fatalf("seed revision fact: %v", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P4952" {
		t.Fatalf("down with header variable revisions: %v, want P4952", err)
	}
}
