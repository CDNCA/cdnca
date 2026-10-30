package rangecache

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestCompileJSONIsDeterministicAndIsolatesCacheKeys(t *testing.T) {
	first := validPolicyJSON(1, `[
		{"site_id":"site-b","listen_address":"127.0.0.1","listen_port":18087,"hosts":["B.EXAMPLE.test."],"origin_host":"origin.test","origin_port":18090},
		{"site_id":"site-a","listen_address":"127.0.0.1","listen_port":18086,"hosts":["edge-b.example.test","EDGE-A.example.test."],"origin_host":"127.0.0.1","origin_port":18090}
	]`)
	second := validPolicyJSON(1, `[
		{"site_id":"site-a","listen_address":"127.0.0.1","listen_port":18086,"hosts":["edge-a.example.test","edge-b.example.test"],"origin_host":"127.0.0.1","origin_port":18090},
		{"site_id":"site-b","listen_address":"127.0.0.1","listen_port":18087,"hosts":["b.example.test"],"origin_host":"origin.test","origin_port":18090}
	]`)

	left, err := CompileJSON(first, RuntimePaths{StateRoot: "/var/lib/cdnca-range", LuaRoot: "/opt/cdnca-range"})
	if err != nil {
		t.Fatal(err)
	}
	right, err := CompileJSON(second, RuntimePaths{StateRoot: "/var/lib/cdnca-range", LuaRoot: "/opt/cdnca-range"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(left.CanonicalPolicy, right.CanonicalPolicy) || !bytes.Equal(left.Nginx, right.Nginx) || left.Digest != right.Digest {
		t.Fatal("equivalent policies did not compile byte-for-byte identically")
	}

	config := string(left.Nginx)
	for _, required := range []string{
		"slice 65536;",
		"proxy_cache_key \"v=1|range=$range_cache_effective_range|scheme=$scheme|host=$host|port=$server_port|request=$request_uri\";",
		"proxy_set_header Range $range_cache_effective_range;",
		"proxy_set_header If-Range \"\";",
		"proxy_set_header Accept-Encoding \"\";",
		"max_ranges 16;",
		"proxy_cache_valid 200 206 60s;",
		"proxy_cache_lock on;",
		"map $upstream_http_vary $range_cache_vary { default 1; \"\" 0; }",
		"map $http_range $range_cache_effective_range { volatile; default $slice_range; ~, $http_range; }",
		"proxy_no_cache $range_cache_encoded $range_cache_unknown_length $range_cache_vary;",
		"require(\"guard\").access({ max_range_bytes = 1024, max_if_range_bytes = 1024, max_ranges = 16, max_range_span_bytes = 67108864 })",
		"require(\"guard\").header_filter",
		"require(\"guard\").body_filter",
	} {
		if !strings.Contains(config, required) {
			t.Fatalf("generated config is missing %q", required)
		}
	}
	if strings.Index(config, "site_id=site-a") > strings.Index(config, "site_id=site-b") {
		t.Fatal("sites were not sorted deterministically")
	}
}

func TestCompileJSONRejectsAmbiguousAndUnboundedInput(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
	}{
		{"empty", nil},
		{"unknown schema", []byte(`{"schema_version":"cdnca.edge.range-cache/v2","policy_version":1}`)},
		{"unknown field", bytes.Replace(validPolicyJSON(1, `[{"site_id":"a","listen_address":"127.0.0.1","listen_port":1,"hosts":["a.test"],"origin_host":"127.0.0.1","origin_port":2}]`), []byte(`,"sites":`), []byte(`,"extra":true,"sites":`), 1)},
		{"duplicate key", []byte(`{"schema_version":"cdnca.edge.range-cache/v1","policy_version":1,"policy_version":2,"slice_bytes":65536,"cache_max_bytes":1048576,"cache_inactive_seconds":60,"cache_valid_seconds":60,"max_range_header_bytes":1024,"max_if_range_header_bytes":1024,"max_response_header_bytes":8192,"sites":[]}`)},
		{"trailing json", append(validPolicyJSON(1, `[{"site_id":"a","listen_address":"127.0.0.1","listen_port":1,"hosts":["a.test"],"origin_host":"127.0.0.1","origin_port":2}]`), []byte(` {}`)...)},
		{"zero version", validPolicyJSON(0, `[{"site_id":"a","listen_address":"127.0.0.1","listen_port":1,"hosts":["a.test"],"origin_host":"127.0.0.1","origin_port":2}]`)},
		{"unsafe host", validPolicyJSON(1, `[{"site_id":"a","listen_address":"127.0.0.1","listen_port":1,"hosts":["bad;host"],"origin_host":"127.0.0.1","origin_port":2}]`)},
		{"duplicate binding", validPolicyJSON(1, `[{"site_id":"a","listen_address":"127.0.0.1","listen_port":1,"hosts":["a.test"],"origin_host":"127.0.0.1","origin_port":2},{"site_id":"b","listen_address":"127.0.0.1","listen_port":1,"hosts":["A.TEST."],"origin_host":"127.0.0.1","origin_port":2}]`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := CompileJSON(test.raw, RuntimePaths{StateRoot: "/state", LuaRoot: "/lua"})
			if !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("error = %v, want ErrInvalidPolicy", err)
			}
		})
	}

	tooLarge := bytes.Repeat([]byte{'x'}, MaxPolicyBytes+1)
	if _, err := CompileJSON(tooLarge, RuntimePaths{StateRoot: "/state", LuaRoot: "/lua"}); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("oversized policy error = %v", err)
	}
	for _, paths := range []RuntimePaths{
		{StateRoot: "relative", LuaRoot: "/lua"},
		{StateRoot: "/state", LuaRoot: "/lua\ninclude"},
		{StateRoot: "/", LuaRoot: "/lua"},
	} {
		if _, err := CompileJSON(validPolicyJSON(1, `[{"site_id":"a","listen_address":"127.0.0.1","listen_port":1,"hosts":["a.test"],"origin_host":"127.0.0.1","origin_port":2}]`), paths); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatalf("unsafe paths %+v error = %v", paths, err)
		}
	}
}

func validPolicyJSON(version uint64, sites string) []byte {
	return []byte(`{"schema_version":"cdnca.edge.range-cache/v1","policy_version":` + uintString(version) + `,"slice_bytes":65536,"cache_max_bytes":1048576,"cache_inactive_seconds":60,"cache_valid_seconds":60,"max_range_header_bytes":1024,"max_if_range_header_bytes":1024,"max_response_header_bytes":8192,"sites":` + sites + `}`)
}
