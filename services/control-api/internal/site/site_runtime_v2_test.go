package site

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// Production API required by this RED:
//
//	normalizeSiteRuntimeV2Config(raw []byte) ([]byte, error)
//	siteRuntimeV2MutationDigest(siteID uuid.UUID, expectedRevision int64, canonical []byte) ([32]byte, error)
//
// normalizeSiteRuntimeV2Config must reject unsafe input rather than silently
// sorting it. The returned bytes are the RFC 8785 canonical representation.
func TestSiteRuntimeV2NormalizesCompleteOrderedModel(t *testing.T) {
	raw := siteRuntimeV2ConfigFixture(t)
	canonical, err := normalizeSiteRuntimeV2Config(raw)
	if err != nil {
		t.Fatalf("normalizeSiteRuntimeV2Config() error = %v", err)
	}
	var sourceDocument, canonicalDocument any
	if err := json.Unmarshal(raw, &sourceDocument); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(canonical, &canonicalDocument); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(canonicalDocument, sourceDocument) {
		t.Fatalf("normalization changed a canonical field or array:\nsource=%#v\nresult=%#v", sourceDocument, canonicalDocument)
	}

	var document struct {
		Domains   []string `json:"domains"`
		Listeners []struct {
			ID        string   `json:"id"`
			Position  int      `json:"position"`
			Protocols []string `json:"protocols"`
		} `json:"listeners"`
		OriginPools []struct {
			ID        string `json:"id"`
			Position  int    `json:"position"`
			Kind      string `json:"kind"`
			Algorithm string `json:"algorithm"`
			Origins   []struct {
				ID       string `json:"id"`
				Position int    `json:"position"`
			} `json:"origins"`
			Retry struct {
				Methods            []string `json:"methods"`
				BodylessOnly       bool     `json:"bodyless_only"`
				ResponseNotStarted bool     `json:"response_not_started"`
				MaxAttempts        int      `json:"max_attempts"`
				ConnectTimeoutMS   int      `json:"connect_timeout_ms"`
				ReadTimeoutMS      int      `json:"read_timeout_ms"`
				TotalBudgetMS      int      `json:"total_budget_ms"`
			} `json:"retry"`
		} `json:"origin_pools"`
		DefaultPoolID string `json:"default_pool_id"`
		L2            struct {
			Enabled              bool   `json:"enabled"`
			DirectFallbackPoolID string `json:"direct_fallback_pool_id"`
			ProbeIntervalMS      int    `json:"probe_interval_ms"`
			FailureThreshold     int    `json:"failure_threshold"`
			RecoveryThreshold    int    `json:"recovery_threshold"`
			SingleHalfOpenProbe  bool   `json:"single_half_open_probe"`
			MaxHops              int    `json:"max_hops"`
		} `json:"l2"`
	}
	if err := json.Unmarshal(canonical, &document); err != nil {
		t.Fatalf("decode canonical config: %v", err)
	}
	algorithms := make([]string, len(document.OriginPools))
	for index, pool := range document.OriginPools {
		algorithms[index] = pool.Algorithm
		wantOriginCount := 1
		if index == 0 {
			wantOriginCount = 2
		}
		if pool.Position != index || len(pool.Origins) != wantOriginCount {
			t.Fatalf("pool order was not preserved: %+v", pool)
		}
		for originIndex, origin := range pool.Origins {
			if origin.Position != originIndex {
				t.Fatalf("origin order was not preserved: %+v", pool.Origins)
			}
		}
		if !slices.Equal(pool.Retry.Methods, []string{"GET", "HEAD"}) || !pool.Retry.BodylessOnly ||
			!pool.Retry.ResponseNotStarted || pool.Retry.MaxAttempts != 3 ||
			pool.Retry.ConnectTimeoutMS != 3000 || pool.Retry.ReadTimeoutMS != 30000 ||
			pool.Retry.TotalBudgetMS != 60000 {
			t.Fatalf("retry safety contract was not preserved: %+v", pool.Retry)
		}
	}
	wantAlgorithms := []string{"round_robin", "ip_hash", "url_hash", "least_conn", "random"}
	if !slices.Equal(algorithms, wantAlgorithms) {
		t.Fatalf("algorithms = %v, want %v", algorithms, wantAlgorithms)
	}
	if !slices.Equal(document.Domains, []string{"cdn.example.test", "static.example.test"}) {
		t.Fatalf("domains = %v", document.Domains)
	}
	if len(document.Listeners) != 2 || document.Listeners[0].ID != "public-80" ||
		document.Listeners[1].ID != "public-443" || document.Listeners[0].Position != 0 ||
		document.Listeners[1].Position != 1 ||
		!slices.Equal(document.Listeners[1].Protocols, []string{"http1", "http2", "http3"}) {
		t.Fatalf("listeners lost identity/order/protocols: %+v", document.Listeners)
	}
	if document.DefaultPoolID != "l2" || document.OriginPools[3].Kind != "l2" ||
		document.OriginPools[0].Kind != "origin" || !document.L2.Enabled ||
		document.L2.DirectFallbackPoolID != "primary" ||
		document.L2.ProbeIntervalMS != 10000 || document.L2.FailureThreshold != 3 ||
		document.L2.RecoveryThreshold != 3 || !document.L2.SingleHalfOpenProbe || document.L2.MaxHops != 1 {
		t.Fatalf("L2 contract = %+v", document.L2)
	}

	var reordered any
	if err := json.Unmarshal(raw, &reordered); err != nil {
		t.Fatal(err)
	}
	noncanonical, err := json.MarshalIndent(reordered, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	second, err := normalizeSiteRuntimeV2Config(noncanonical)
	if err != nil || !bytes.Equal(second, canonical) {
		t.Fatalf("equivalent JSON did not converge: equal=%t err=%v", bytes.Equal(second, canonical), err)
	}
}

func TestSiteRuntimeV2RejectsUnsafeRetryL2AndCollectionVariants(t *testing.T) {
	tests := map[string]func(map[string]any){
		"POST retry": func(value map[string]any) {
			firstPool(value)["retry"].(map[string]any)["methods"] = []any{"POST"}
		},
		"request body replay": func(value map[string]any) {
			firstPool(value)["retry"].(map[string]any)["bodyless_only"] = false
		},
		"response started replay": func(value map[string]any) {
			firstPool(value)["retry"].(map[string]any)["response_not_started"] = false
		},
		"unbounded total budget": func(value map[string]any) {
			firstPool(value)["retry"].(map[string]any)["total_budget_ms"] = float64(120001)
		},
		"duplicate listener identity": func(value map[string]any) {
			listeners := value["listeners"].([]any)
			listeners = append(listeners, cloneJSONObject(t, listeners[0]))
			value["listeners"] = listeners
		},
		"listener position gap": func(value map[string]any) {
			value["listeners"].([]any)[1].(map[string]any)["position"] = float64(2)
		},
		"listener reorder": func(value map[string]any) {
			listeners := value["listeners"].([]any)
			listeners[0], listeners[1] = listeners[1], listeners[0]
		},
		"pool reorder": func(value map[string]any) {
			pools := value["origin_pools"].([]any)
			pools[0], pools[1] = pools[1], pools[0]
		},
		"duplicate origin position": func(value map[string]any) {
			origins := firstPool(value)["origins"].([]any)
			duplicate := cloneJSONObject(t, origins[0])
			duplicate["id"] = "origin-duplicate"
			firstPool(value)["origins"] = append(origins, duplicate)
		},
		"multi-origin reorder": func(value map[string]any) {
			origins := firstPool(value)["origins"].([]any)
			origins[0], origins[1] = origins[1], origins[0]
		},
		"duplicate pool identity": func(value map[string]any) {
			pools := value["origin_pools"].([]any)
			duplicate := cloneJSONObject(t, pools[0])
			duplicate["position"] = float64(len(pools))
			value["origin_pools"] = append(pools, duplicate)
		},
		"retry outcome mutation": func(value map[string]any) {
			firstPool(value)["retry"].(map[string]any)["retry_on"] = []any{"connect_error"}
		},
		"L2 self fallback": func(value map[string]any) {
			value["l2"].(map[string]any)["direct_fallback_pool_id"] = "l2"
		},
		"L2 multi hop": func(value map[string]any) {
			value["l2"].(map[string]any)["max_hops"] = float64(2)
		},
		"L2 multi probe": func(value map[string]any) {
			value["l2"].(map[string]any)["single_half_open_probe"] = false
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			var value map[string]any
			if err := json.Unmarshal(siteRuntimeV2ConfigFixture(t), &value); err != nil {
				t.Fatal(err)
			}
			mutate(value)
			raw, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := normalizeSiteRuntimeV2Config(raw); err == nil {
				t.Fatal("unsafe runtime config accepted")
			}
		})
	}
}

func TestSiteRuntimeV2MutationDigestBindsSiteRevisionCanonicalBytesAndOrder(t *testing.T) {
	canonical, err := normalizeSiteRuntimeV2Config(siteRuntimeV2ConfigFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	siteID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7103")
	want, err := siteRuntimeV2MutationDigest(siteID, 7, canonical)
	if err != nil || want == ([sha256.Size]byte{}) {
		t.Fatalf("digest = %x, err=%v", want, err)
	}
	for name, changed := range map[string]func() (uuid.UUID, int64, []byte){
		"site":     func() (uuid.UUID, int64, []byte) { return uuid.New(), 7, canonical },
		"revision": func() (uuid.UUID, int64, []byte) { return siteID, 8, canonical },
		"domains": runtimeV2DigestChange(t, siteID, canonical, func(value map[string]any) {
			value["domains"].([]any)[0] = "changed.example.test"
		}),
		"listener order": runtimeV2DigestChange(t, siteID, canonical, func(value map[string]any) {
			listeners := value["listeners"].([]any)
			listeners[0], listeners[1] = listeners[1], listeners[0]
		}),
		"listener identity": runtimeV2DigestChange(t, siteID, canonical, func(value map[string]any) {
			secondListener(value)["id"] = "changed-443"
		}),
		"listener position": runtimeV2DigestChange(t, siteID, canonical, func(value map[string]any) {
			secondListener(value)["position"] = float64(2)
		}),
		"listener address": runtimeV2DigestChange(t, siteID, canonical, func(value map[string]any) {
			secondListener(value)["address_family"] = "ipv6"
		}),
		"listener port": runtimeV2DigestChange(t, siteID, canonical, func(value map[string]any) {
			secondListener(value)["port"] = float64(8443)
		}),
		"listener protocols": runtimeV2DigestChange(t, siteID, canonical, func(value map[string]any) {
			secondListener(value)["protocols"] = []any{"http1", "http2"}
		}),
		"listener TLS": runtimeV2DigestChange(t, siteID, canonical, func(value map[string]any) {
			secondListener(value)["tls"].(map[string]any)["certificate_version_id"] = "018f47a2-5b9c-7d31-8a60-104c9c0b7199"
		}),
		"pool order": runtimeV2DigestChange(t, siteID, canonical, func(value map[string]any) {
			pools := value["origin_pools"].([]any)
			pools[0], pools[1] = pools[1], pools[0]
		}),
		"pool identity":  runtimeV2DigestChange(t, siteID, canonical, func(value map[string]any) { firstPool(value)["id"] = "changed" }),
		"pool position":  runtimeV2DigestChange(t, siteID, canonical, func(value map[string]any) { firstPool(value)["position"] = float64(9) }),
		"pool kind":      runtimeV2DigestChange(t, siteID, canonical, func(value map[string]any) { firstPool(value)["kind"] = "l2" }),
		"pool algorithm": runtimeV2DigestChange(t, siteID, canonical, func(value map[string]any) { firstPool(value)["algorithm"] = "random" }),
		"origin order": runtimeV2DigestChange(t, siteID, canonical, func(value map[string]any) {
			origins := firstPool(value)["origins"].([]any)
			origins[0], origins[1] = origins[1], origins[0]
		}),
		"origin identity": runtimeV2DigestChange(t, siteID, canonical, func(value map[string]any) { firstOrigin(value)["id"] = "changed" }),
		"origin position": runtimeV2DigestChange(t, siteID, canonical, func(value map[string]any) { firstOrigin(value)["position"] = float64(9) }),
		"origin tier":     runtimeV2DigestChange(t, siteID, canonical, func(value map[string]any) { firstOrigin(value)["tier"] = "l2" }),
		"origin scheme":   runtimeV2DigestChange(t, siteID, canonical, func(value map[string]any) { firstOrigin(value)["scheme"] = "http" }),
		"origin host":     runtimeV2DigestChange(t, siteID, canonical, func(value map[string]any) { firstOrigin(value)["host"] = "192.0.2.99" }),
		"origin port":     runtimeV2DigestChange(t, siteID, canonical, func(value map[string]any) { firstOrigin(value)["port"] = float64(8443) }),
		"origin weight":   runtimeV2DigestChange(t, siteID, canonical, func(value map[string]any) { firstOrigin(value)["weight"] = float64(99) }),
		"origin SNI":      runtimeV2DigestChange(t, siteID, canonical, func(value map[string]any) { firstOrigin(value)["sni"] = "changed.example.test" }),
		"origin trust": runtimeV2DigestChange(t, siteID, canonical, func(value map[string]any) {
			firstOrigin(value)["trust_ref"] = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}),
		"origin node":           runtimeV2DigestChange(t, siteID, canonical, func(value map[string]any) { l2Origin(value)["node_id"] = "018f47a2-5b9c-7d31-8a60-104c9c0b7199" }),
		"retry methods":         runtimeV2DigestChange(t, siteID, canonical, func(value map[string]any) { retryPolicy(value)["methods"] = []any{"GET"} }),
		"retry bodyless":        runtimeV2DigestChange(t, siteID, canonical, func(value map[string]any) { retryPolicy(value)["bodyless_only"] = false }),
		"retry response":        runtimeV2DigestChange(t, siteID, canonical, func(value map[string]any) { retryPolicy(value)["response_not_started"] = false }),
		"retry outcomes":        runtimeV2DigestChange(t, siteID, canonical, func(value map[string]any) { retryPolicy(value)["retry_on"] = []any{"connect_error"} }),
		"retry attempts":        runtimeV2DigestChange(t, siteID, canonical, func(value map[string]any) { retryPolicy(value)["max_attempts"] = float64(4) }),
		"retry connect timeout": runtimeV2DigestChange(t, siteID, canonical, func(value map[string]any) { retryPolicy(value)["connect_timeout_ms"] = float64(4000) }),
		"retry read timeout":    runtimeV2DigestChange(t, siteID, canonical, func(value map[string]any) { retryPolicy(value)["read_timeout_ms"] = float64(40000) }),
		"retry total budget":    runtimeV2DigestChange(t, siteID, canonical, func(value map[string]any) { retryPolicy(value)["total_budget_ms"] = float64(70000) }),
		"default pool":          runtimeV2DigestChange(t, siteID, canonical, func(value map[string]any) { value["default_pool_id"] = "primary" }),
		"websocket":             runtimeV2DigestChange(t, siteID, canonical, func(value map[string]any) { value["websocket"] = false }),
		"range":                 runtimeV2DigestChange(t, siteID, canonical, func(value map[string]any) { value["range"] = false }),
		"L2 enabled":            runtimeV2DigestChange(t, siteID, canonical, func(value map[string]any) { l2Policy(value)["enabled"] = false }),
		"L2 fallback":           runtimeV2DigestChange(t, siteID, canonical, func(value map[string]any) { l2Policy(value)["direct_fallback_pool_id"] = "random" }),
		"L2 probe interval":     runtimeV2DigestChange(t, siteID, canonical, func(value map[string]any) { l2Policy(value)["probe_interval_ms"] = float64(11000) }),
		"L2 failure threshold":  runtimeV2DigestChange(t, siteID, canonical, func(value map[string]any) { l2Policy(value)["failure_threshold"] = float64(4) }),
		"L2 recovery threshold": runtimeV2DigestChange(t, siteID, canonical, func(value map[string]any) { l2Policy(value)["recovery_threshold"] = float64(4) }),
		"L2 half open":          runtimeV2DigestChange(t, siteID, canonical, func(value map[string]any) { l2Policy(value)["single_half_open_probe"] = false }),
		"L2 max hops":           runtimeV2DigestChange(t, siteID, canonical, func(value map[string]any) { l2Policy(value)["max_hops"] = float64(2) }),
	} {
		t.Run(name, func(t *testing.T) {
			changedSite, changedRevision, changedCanonical := changed()
			got, err := siteRuntimeV2MutationDigest(changedSite, changedRevision, changedCanonical)
			if err != nil {
				t.Fatal(err)
			}
			if got == want {
				t.Fatalf("mutation identity %q was not digest-bound", name)
			}
		})
	}
}

func firstPool(value map[string]any) map[string]any {
	return value["origin_pools"].([]any)[0].(map[string]any)
}

func secondListener(value map[string]any) map[string]any {
	return value["listeners"].([]any)[1].(map[string]any)
}

func firstOrigin(value map[string]any) map[string]any {
	return firstPool(value)["origins"].([]any)[0].(map[string]any)
}

func l2Origin(value map[string]any) map[string]any {
	return value["origin_pools"].([]any)[3].(map[string]any)["origins"].([]any)[0].(map[string]any)
}

func retryPolicy(value map[string]any) map[string]any {
	return firstPool(value)["retry"].(map[string]any)
}

func l2Policy(value map[string]any) map[string]any {
	return value["l2"].(map[string]any)
}

func runtimeV2DigestChange(
	t *testing.T,
	siteID uuid.UUID,
	canonical []byte,
	mutate func(map[string]any),
) func() (uuid.UUID, int64, []byte) {
	t.Helper()
	return func() (uuid.UUID, int64, []byte) {
		var value map[string]any
		if err := json.Unmarshal(canonical, &value); err != nil {
			t.Fatal(err)
		}
		mutate(value)
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return siteID, 7, raw
	}
}

func cloneJSONObject(t *testing.T, value any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func siteRuntimeV2ConfigFixture(t *testing.T) []byte {
	t.Helper()
	const retry = `"retry":{"methods":["GET","HEAD"],"bodyless_only":true,"response_not_started":true,"retry_on":["connect_error","connect_timeout","read_timeout","http_502","http_503","http_504"],"max_attempts":3,"connect_timeout_ms":3000,"read_timeout_ms":30000,"total_budget_ms":60000}`
	pools := []string{
		`{"id":"primary","position":0,"kind":"origin","algorithm":"round_robin","origins":[{"id":"origin-a","position":0,"tier":"origin","scheme":"https","host":"192.0.2.10","port":443,"weight":100,"sni":"origin.example.test","trust_ref":"sha256:8b5e6f57d8f47ec690b6e1e0ef2fd5d7fa6ef74d8d17eb9e9fc2f0901e21a61d"},{"id":"origin-a2","position":1,"tier":"origin","scheme":"https","host":"192.0.2.20","port":8443,"weight":90,"sni":"origin-2.example.test","trust_ref":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],` + retry + `}`,
		`{"id":"hash-client","position":1,"kind":"origin","algorithm":"ip_hash","origins":[{"id":"origin-b","position":0,"tier":"origin","scheme":"http","host":"192.0.2.11","port":8080,"weight":80}],` + retry + `}`,
		`{"id":"hash-url","position":2,"kind":"origin","algorithm":"url_hash","origins":[{"id":"origin-c","position":0,"tier":"origin","scheme":"http","host":"origin-c.example.test","port":8080,"weight":70}],` + retry + `}`,
		`{"id":"l2","position":3,"kind":"l2","algorithm":"least_conn","origins":[{"id":"l2-a","position":0,"tier":"l2","scheme":"http","host":"2001:db8::10","port":8080,"weight":100,"node_id":"018f47a2-5b9c-7d31-8a60-104c9c0b7105"}],` + retry + `}`,
		`{"id":"random","position":4,"kind":"origin","algorithm":"random","origins":[{"id":"origin-d","position":0,"tier":"origin","scheme":"http","host":"192.0.2.12","port":8080,"weight":60}],` + retry + `}`,
	}
	raw := `{"domains":["cdn.example.test","static.example.test"],"listeners":[{"id":"public-80","position":0,"address_family":"ipv4","port":80,"protocols":["http1"]},{"id":"public-443","position":1,"address_family":"dual_stack","port":443,"protocols":["http1","http2","http3"],"tls":{"certificate_version_id":"018f47a2-5b9c-7d31-8a60-104c9c0b7104"}}],"origin_pools":[` + strings.Join(pools, ",") + `],"default_pool_id":"l2","websocket":true,"range":true,"l2":{"enabled":true,"direct_fallback_pool_id":"primary","probe_interval_ms":10000,"failure_threshold":3,"recovery_threshold":3,"single_half_open_probe":true,"max_hops":1}}`
	return []byte(raw)
}
