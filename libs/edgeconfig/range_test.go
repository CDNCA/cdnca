package edgeconfig

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestDecodeRangeCachePolicyFailsClosedForUnknownFieldsAndVersions(t *testing.T) {
	document := RangeCacheDocument{
		SchemaVersion: RangeCacheSchemaVersion, PolicyVersion: 3,
		TenantID: "11111111-1111-4111-8111-111111111111", SiteID: "22222222-2222-4222-8222-222222222222",
		Domain: "media.example.test", ListenPort: 18081,
		SliceBytes: RangeCacheMinSliceBytes, CacheMaxBytes: 128 << 20,
		CacheInactiveSeconds: 300, CacheValidSeconds: 300,
		MaxRangeHeaderBytes: 1024, MaxIfRangeHeaderBytes: 1024, MaxResponseHeaderBytes: 8192,
	}
	canonical, err := CanonicalRangeCachePolicy(document)
	if err != nil {
		t.Fatalf("CanonicalRangeCachePolicy() error = %v", err)
	}
	unknown := append([]byte(nil), canonical[:len(canonical)-2]...)
	unknown = append(unknown, []byte(",\"unknown\":true}\n")...)
	if _, err := DecodeRangeCachePolicy(unknown); !errors.Is(err, ErrInvalidRangeCachePolicy) {
		t.Fatalf("unknown field error = %v", err)
	}
	document.SchemaVersion = "cdnca.edge.range-cache/v2"
	unsupported, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeRangeCachePolicy(unsupported); !errors.Is(err, ErrInvalidRangeCachePolicy) {
		t.Fatalf("unknown schema error = %v", err)
	}
}

func rangeCacheTestSpec(version uint64) Spec {
	return Spec{
		ConfigVersionID: "cfg-range-v1", TenantID: "11111111-1111-4111-8111-111111111111",
		StateRoot: "/var/lib/cdnca-edge", HealthPort: 18080,
		Sites: []Site{{
			ID: "22222222-2222-4222-8222-222222222222", Domain: "media.example.test",
			ListenPort: 18081, Protocol: ProtocolHTTP, Origins: []Origin{{Host: "192.0.2.10", Port: 8080, Weight: 1}},
			Balance: BalanceRoundRobin, FailoverTries: 1, ConnectTimeout: 250 * time.Millisecond,
			ReadTimeout: 2 * time.Second, WebSocket: true, Range: true,
			ACL:   ACLPolicy{DefaultAction: ACLAllow},
			Cache: CachePolicy{Mode: CacheFollowOrigin, ZoneSizeBytes: 1 << 20, MaxSizeBytes: 64 << 20, DefaultTTL: 5 * time.Minute},
			RangeCache: &RangeCachePolicy{
				SchemaVersion: RangeCacheSchemaVersion, PolicyVersion: version,
				SliceBytes: RangeCacheMinSliceBytes, CacheMaxBytes: 128 << 20,
				CacheInactiveSeconds: 300, CacheValidSeconds: 300,
				MaxRangeHeaderBytes: 1024, MaxIfRangeHeaderBytes: 1024, MaxResponseHeaderBytes: 8192,
			},
		}},
	}
}
