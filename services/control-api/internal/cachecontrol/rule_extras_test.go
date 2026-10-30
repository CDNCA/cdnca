package cachecontrol

import (
	"encoding/json"
	"testing"
)

// Per-rule settings round-trip through the v2 document and
// are refused on schema v1 and on a no_cache rule.
func TestPolicyRuleExtras(t *testing.T) {
	raw := `{"schema_version":2,"mode":"override","query_mode":"preserve","query_names":[],"vary_headers":[],"disk_quota_bytes":67108864,
	 "rules":[{"order":1,"action":"cache","ttl_seconds":86400,"browser_ttl_seconds":0,"path_exact":"/","force_cache":true},
	          {"order":2,"action":"cache","ttl_seconds":3600,"browser_ttl_seconds":0,"path_prefix":"/","ignore_query":true,"slice_bytes":1048576,"ignore_vary":true,
	           "no_cache":[{"source":"header","name":"Cookie","pattern":"wordpress_logged_in"}]}]}`
	var document PolicyDocument
	if err := json.Unmarshal([]byte(raw), &document); err != nil {
		t.Fatal(err)
	}
	normalized, err := NormalizePolicyDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	first, second := normalized.Rules[0], normalized.Rules[1]
	if first.PathExact != "/" || first.ForceCache == nil || !*first.ForceCache || !second.IgnoreQuery || !second.IgnoreVary ||
		second.SliceBytes == nil || *second.SliceBytes != 1<<20 || second.NoCache[0].Name != "cookie" {
		t.Fatalf("normalized %+v / %+v", first, second)
	}
	encoded, _ := json.Marshal(normalized)
	var again PolicyDocument
	if err := json.Unmarshal(encoded, &again); err != nil {
		t.Fatal(err)
	}
	if _, err := NormalizePolicyDocument(again); err != nil {
		t.Fatalf("round trip: %v %s", err, encoded)
	}
	if rule := MatchRule(normalized, RequestFacts{Path: "/"}); rule == nil || rule.Order != 1 {
		t.Fatalf("match / = %+v", rule)
	}
	if rule := MatchRule(normalized, RequestFacts{Path: "/a"}); rule == nil || rule.Order != 2 {
		t.Fatalf("match /a = %+v", rule)
	}
	for name, body := range map[string]string{
		"v1":               `{"mode":"override","query_mode":"preserve","disk_quota_bytes":67108864,"rules":[{"order":1,"ttl_seconds":60,"path_exact":"/"}]}`,
		"no_cache rule":    `{"schema_version":2,"mode":"override","query_mode":"preserve","query_names":[],"vary_headers":[],"disk_quota_bytes":67108864,"rules":[{"order":1,"action":"no_cache","ttl_seconds":0,"browser_ttl_seconds":0,"ignore_vary":true}]}`,
		"exact and prefix": `{"schema_version":2,"mode":"override","query_mode":"preserve","query_names":[],"vary_headers":[],"disk_quota_bytes":67108864,"rules":[{"order":1,"action":"cache","ttl_seconds":60,"browser_ttl_seconds":0,"path_prefix":"/a/","path_exact":"/a/b"}]}`,
		"bad pattern":      `{"schema_version":2,"mode":"override","query_mode":"preserve","query_names":[],"vary_headers":[],"disk_quota_bytes":67108864,"rules":[{"order":1,"action":"cache","ttl_seconds":60,"browser_ttl_seconds":0,"no_cache":[{"source":"uri","pattern":"(a*)*"}]}]}`,
		"null field":       `{"schema_version":2,"mode":"override","query_mode":"preserve","query_names":[],"vary_headers":[],"disk_quota_bytes":67108864,"rules":[{"order":1,"action":"cache","ttl_seconds":60,"browser_ttl_seconds":0,"force_cache":null}]}`,
	} {
		var candidate PolicyDocument
		if err := json.Unmarshal([]byte(body), &candidate); err == nil {
			_, err = NormalizePolicyDocument(candidate)
			if err == nil {
				t.Errorf("%s accepted", name)
			}
		}
	}
}
