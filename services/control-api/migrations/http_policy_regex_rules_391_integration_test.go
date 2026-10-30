//go:build integration

package migrations_test

import "testing"

// TestHTTPPolicyRegexRulesMigration rolls 391 up, down and up and checks the
// stored-document validator: regex rules and preserve_path are accepted only
// while it is applied, and the malformed forms are refused.
func TestHTTPPolicyRegexRulesMigration(t *testing.T) {
	const version = 391
	pool := migrationPoolAt(t, version-1)
	base := `'{"schema_version":"cdnca.control.http-policy/v1","policy_id":"018f47a2-5b9c-7d31-8a60-104c9c0b7101",
		"tenant_scope_id":"018f47a2-5b9c-7d31-8a60-104c9c0b7102","site_id":"018f47a2-5b9c-7d31-8a60-104c9c0b7103",
		"site_owner_user_id":"018f47a2-5b9c-7d31-8a60-104c9c0b7104","revision":1,"max_upload_bytes":16,
		"request_headers":[],"response_headers":[],
		"rewrites":[{"rule_id":"rx","priority":30,"match_kind":"regex","match_path":"^/item/([0-9]+)$",
			"target_path":"/items/$1","preserve_query":false,"preserve_cookie":false}],
		"redirect_allowed_hosts":["redirect.example.test"],
		"redirects":[{"rule_id":"rd-fixed","priority":10,"match_kind":"exact","match_path":"/gone","status":308,
			"target_url":"https://redirect.example.test/moved","preserve_query":true,"preserve_path":false},
			{"rule_id":"rd-rx","priority":40,"match_kind":"regex","match_path":"^/u/(\\w+)$","status":301,
			"target_url":"https://redirect.example.test/users/$1","preserve_query":false,"preserve_path":false},
			{"rule_id":"rd-keep","priority":50,"match_kind":"prefix","match_path":"/docs/","status":302,
			"target_url":"https://redirect.example.test/manual/","preserve_query":true,"preserve_path":true}],
		"cors":null,"enabled":true,"deleted":false}'::jsonb`
	cases := map[string]struct {
		expression string
		valid      bool
	}{
		"regex and preserve_path":   {base, true},
		"missing preserve_path":     {`(` + base + ` #- '{redirects,0,preserve_path}')`, false},
		"unanchored regex":          {`jsonb_set(` + base + `,'{rewrites,0,match_path}','"item"')`, false},
		"bare dollar":               {`jsonb_set(` + base + `,'{rewrites,0,target_path}','"/items/$"')`, false},
		"group zero":                {`jsonb_set(` + base + `,'{rewrites,0,target_path}','"/items/$0"')`, false},
		"target traversal":          {`jsonb_set(` + base + `,'{rewrites,0,target_path}','"/a/../$1"')`, false},
		"regex same priority":       {`jsonb_set(` + base + `,'{rewrites,0,priority}','10')`, false},
		"preserve_path on exact":    {`jsonb_set(` + base + `,'{redirects,0,preserve_path}','true')`, false},
		"preserve_path on regex":    {`jsonb_set(` + base + `,'{redirects,1,preserve_path}','true')`, false},
		"preserve_path file target": {`jsonb_set(` + base + `,'{redirects,2,target_url}','"https://redirect.example.test/manual"')`, false},
	}
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(t.Context(), pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
		applied := step == "up"
		var table, status bool
		if err := pool.QueryRow(t.Context(), `SELECT to_regclass('site_access_settings') IS NOT NULL,
			EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='sites' AND column_name='https_redirect_status')`).
			Scan(&table, &status); err != nil || table != applied || status != applied {
			t.Fatalf("after %s: site_access_settings=%v https_redirect_status=%v (%v)", step, table, status, err)
		}
		// A pooled session keeps its compiled PL/pgSQL functions across
		// CREATE OR REPLACE; each check uses a session opened after the step.
		connection, err := pool.Acquire(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if err := connection.Conn().Close(t.Context()); err != nil {
			t.Fatal(err)
		}
		connection.Release()
		pool.Reset()
		var current, legacy bool
		if err := pool.QueryRow(t.Context(), `SELECT
			system_configuration_v2_default_other('{"load_balancing":"round_robin","gzip_enabled":true,
				"gzip_types":["text/css"],"websocket_enabled":false}'),
			system_configuration_v2_default_other('{"load_balancing":"round_robin","crawler_policy":"allow",
				"gzip_enabled":true,"gzip_types":["text/css"],"websocket_enabled":false,"block_transparent_proxy":false,
				"realtime_response_enabled":false,"realtime_send_enabled":false}')`).Scan(&current, &legacy); err != nil {
			t.Fatal(err)
		}
		if current != applied || legacy == applied {
			t.Fatalf("after %s: website other current=%v legacy=%v", step, current, legacy)
		}
		var mismatch421 bool
		if err := pool.QueryRow(t.Context(), `SELECT pg_get_constraintdef(oid) LIKE '%421%' FROM pg_constraint
			WHERE conrelid='error_page_rule_revisions'::regclass AND contype='c'
			  AND pg_get_constraintdef(oid) LIKE '%unknown_site%'`).Scan(&mismatch421); err != nil || mismatch421 != applied {
			t.Fatalf("after %s: unknown_site 421 allowed=%v (%v)", step, mismatch421, err)
		}
		for name, test := range cases {
			var valid bool
			if err := pool.QueryRow(t.Context(), `SELECT http_policy_document_valid_056(`+test.expression+`)`).Scan(&valid); err != nil {
				t.Fatalf("after %s, %s: %v", step, name, err)
			}
			// Without 391 nothing regex or preserve_path is valid.
			if want := test.valid && applied; valid != want {
				t.Errorf("after %s, %s: valid=%v want %v", step, name, valid, want)
			}
		}
	}
}
