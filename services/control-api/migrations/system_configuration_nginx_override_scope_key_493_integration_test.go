//go:build integration

package migrations_test

import "testing"

// TestSystemConfigurationNginxOverrideScopeKey493: before 493 the database
// rejects every nginx block with an override (the scope key raised and was
// swallowed as false), after it accepts one and still refuses a duplicate
// scope; down brings the refusal back.
func TestSystemConfigurationNginxOverrideScopeKey493(t *testing.T) {
	// Keep equal to migration493Version and
	// migration493PreviousVersion in system_configuration_nginx_override_scope_key_493_contract_test.go.
	const version, previous = 493, 492
	pool := migrationPoolAt(t, previous)
	ctx := t.Context()
	// The bootstrap nginx block of the canonical snapshot (systemconfig.ProjectBootstrapConfiguration).
	const nginx = `{"http":{"server":"cdnca","gzip_vary":true,"default_type":"text/plain","log_not_found":true,
		"proxy_buffering":true,"proxy_cache_min_free_bytes":5368709120,"server_tokens":false,"gzip_comp_level":6,
		"gzip_http_version":"1.1","keepalive_requests":10000,"proxy_cache_methods":["GET","HEAD"],
		"proxy_http_version":"1.1","server_addr_outgoing":false,"keepalive_timeout_ms":75000,
		"proxy_next_upstream":["error","timeout"],"proxy_read_timeout_ms":60000,"proxy_send_timeout_ms":60000,
		"client_max_body_size_bytes":104857600,"gzip_min_length_bytes":1024,"proxy_connect_timeout_ms":10000,
		"proxy_request_buffering":true,"proxy_cache_max_size_bytes":107374182400,"server_names_hash_max_size":4096,
		"large_client_header_buffers":{"count":4,"size_bytes":8192},"client_body_buffer_size_bytes":16384,
		"proxy_max_temp_file_size_bytes":1073741824,"server_names_hash_bucket_size":64},
		"stream":{"proxy_timeout_ms":300000,"proxy_connect_timeout_ms":10000},
		"worker":{"logs_dir":"/var/log/cdnca/nginx","worker_processes":0,"worker_connections":4096,
		"worker_rlimit_nofile":65536,"worker_shutdown_timeout_ms":30000},"overrides":%s}`
	region := `{"id":"region-east1","scope":"region","scope_id":"12","values":{"http":{"gzip_comp_level":9}}}`
	node := `{"id":"node-a00001","scope":"node","scope_id":"00000000-0000-4000-8000-0000000000a1","values":{"worker":{"worker_connections":8192}}}`
	valid := func(overrides string) bool {
		t.Helper()
		var ok bool
		if err := pool.QueryRow(ctx, `SELECT system_configuration_v2_nginx_is_valid(format($1,$2::text)::jsonb)`,
			nginx, overrides).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if !valid(`[]`) || valid(`[` + region + `]`) {
		t.Fatal("before 493: an empty override list must pass and any override fail (the defect this fixes)")
	}
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	if !valid(`[]`) || !valid(`[`+region+`,`+node+`]`) {
		t.Fatal("after 493: region and node overrides must pass")
	}
	duplicate := `{"id":"region-east2","scope":"region","scope_id":"12","values":{"http":{"gzip_comp_level":8}}}`
	if valid(`[` + region + `,` + duplicate + `]`) {
		t.Fatal("after 493: two overrides of one region accepted")
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatal(err)
	}
	if valid(`[` + region + `]`) {
		t.Fatal("down did not restore 219's function")
	}
}
