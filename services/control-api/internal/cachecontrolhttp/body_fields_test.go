package cachecontrolhttp

import "testing"

// The publish body accepts the document fields cachecontrol decodes: the
// ge-cache extensions (stale_if_error, background_update, min/max object
// bytes, slice_bytes: rejected with 400 before ge36) and the ge36 rule
// conditions path_regex / content_types; anything else stays refused.
func TestPublishBodyAcceptsPolicyExtensionsAndRuleConditions(t *testing.T) {
	for _, raw := range []string{
		`{"expected_revision":1,"document":{"mode":"override","rules":[{"order":1,"ttl_seconds":60}],"query_mode":"preserve","query_names":[],"vary_headers":[],"disk_quota_bytes":67108864,"stale_if_error":true,"background_update":true,"min_object_bytes":1,"max_object_bytes":9,"slice_bytes":262144}}`,
		`{"expected_revision":1,"document":{"schema_version":2,"mode":"override","rules":[{"order":1,"action":"cache","ttl_seconds":60,"browser_ttl_seconds":0,"path_regex":"^/a","content_types":["image/*"]}],"query_mode":"preserve","query_names":[],"vary_headers":[],"disk_quota_bytes":67108864}}`,
	} {
		if err := validateBodyFields([]byte(raw), &publishBody{}); err != nil {
			t.Errorf("%s: %v", raw, err)
		}
	}
	for _, raw := range []string{
		`{"expected_revision":1,"document":{"mode":"override","rules":[],"query_mode":"preserve","query_names":[],"vary_headers":[],"disk_quota_bytes":67108864,"unknown":1}}`,
		`{"expected_revision":1,"document":{"mode":"override","rules":[{"order":1,"ttl_seconds":60,"path_regexp":"^/a"}],"query_mode":"preserve","query_names":[],"vary_headers":[],"disk_quota_bytes":67108864}}`,
	} {
		if validateBodyFields([]byte(raw), &publishBody{}) == nil {
			t.Errorf("accepted %s", raw)
		}
	}
}

// CU-SITE-03: the schema v2 rule extras (edgeconfig.CacheRuleExtras) pass the
// HTTP field allowlist, so a normal directory rule with force_cache:false is
// no longer refused before Normalize; unknown and case-folded duplicate rule
// keys stay refused. Value validation (schema v1 refusal, bad slice/path)
// stays with cachecontrol.Normalize (rule_extras_test.go).
func TestPublishBodyAcceptsCacheRuleExtras(t *testing.T) {
	const head = `{"expected_revision":1,"document":{"schema_version":2,"mode":"override","query_mode":"preserve","query_names":[],"vary_headers":[],"disk_quota_bytes":67108864,"rules":[{"order":1,"action":"cache","ttl_seconds":600,"browser_ttl_seconds":0,`
	const tail = `}]}}`
	for _, extra := range []string{
		`"path_prefix":"/review-codex/","force_cache":false`,
		`"path_exact":"/index.html"`,
		`"path_prefix":"/a/","ignore_query":true`,
		`"path_prefix":"/v/","slice_bytes":1048576`,
		`"path_prefix":"/a/","ignore_vary":true`,
		`"path_prefix":"/a/","no_cache":[{"source":"header","name":"Cookie","pattern":"wordpress_logged_in"}]`,
	} {
		if err := validateBodyFields([]byte(head+extra+tail), &publishBody{}); err != nil {
			t.Errorf("%s: %v", extra, err)
		}
	}
	for _, extra := range []string{
		`"path_prefix":"/a/","force_cachee":false`,
		`"path_prefix":"/a/","Force_Cache":false`,
	} {
		if validateBodyFields([]byte(head+extra+tail), &publishBody{}) == nil {
			t.Errorf("accepted %s", extra)
		}
	}
	duplicate := head + `"path_prefix":"/a/","force_cache":false,"FORCE_CACHE":true` + tail
	if rejectDuplicateKeys([]byte(duplicate)) == nil {
		t.Errorf("accepted case-folded duplicate")
	}
}
