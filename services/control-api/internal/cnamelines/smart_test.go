package cnamelines

import (
	"maps"
	"slices"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocation"
)

// Smart scheduling off: WithSmart returns the static plan untouched (same
// sets, no equal-weight line), so the digest and weights of every line are
// byte-for-byte those of the code before migration 609.
func TestWithSmartOffKeepsStaticPlan(t *testing.T) {
	endpoints := []Endpoint{
		{Address: "192.0.2.1", Carrier: "电信"}, {Address: "192.0.2.2", Carrier: "联通"},
		{Address: "198.51.100.1", Region: "日本"}, {Address: "203.0.113.1", Carrier: "BGP"},
	}
	weights := map[cnameallocation.WeightKey]uint32{{Carrier: "电信", Address: "192.0.2.1"}: 40}
	before := Plan(endpoints)
	// Golden digest of the telecom line as written before 609 (cdnca.cname-line/v1 ttl=600 192.0.2.1=40).
	const golden = "telecom"
	wantDigest := before[golden].Digest(600, LineWeights(endpoints, golden, weights))

	plan, equal := WithSmart(Plan(endpoints), nil, []string{"telecom", "unicom", "overseas"})
	if len(equal) != 0 || !maps.EqualFunc(plan, before, func(a, b Set) bool {
		return slices.Equal(a.A, b.A) && slices.Equal(a.AAAA, b.AAAA)
	}) {
		t.Fatalf("plan changed without smart selections: %+v", plan)
	}
	if got := plan[golden].Digest(600, LineWeights(endpoints, golden, weights)); got != wantDigest {
		t.Fatalf("digest drifted: %s != %s", got, wantDigest)
	}
	for scope := range plan {
		if isProvinceScope(scope) {
			t.Fatalf("province line planned while off: %s", scope)
		}
	}
}

func TestWithSmartOverlaysAndRetiresProvinceLines(t *testing.T) {
	smart := map[string]Set{
		"telecom":    {A: []string{"192.0.2.9"}, AAAA: []string{}},
		"广东:telecom": {A: []string{"192.0.2.9"}, AAAA: []string{}},
	}
	plan, equal := WithSmart(Plan([]Endpoint{{Address: "192.0.2.1", Carrier: "电信"}}), smart,
		[]string{"telecom", "浙江:mobile"})
	if !slices.Equal(plan["telecom"].A, []string{"192.0.2.9"}) || !equal["telecom"] || !equal["广东:telecom"] {
		t.Fatalf("smart overlay = %+v %v", plan, equal)
	}
	if retired, ok := plan["浙江:mobile"]; !ok || !retired.Empty() || !equal["浙江:mobile"] {
		t.Fatalf("stale province line must be retired: %+v", plan["浙江:mobile"])
	}
	if equal["unicom"] || !plan["unicom"].Empty() {
		t.Fatalf("unselected carrier lines keep the static plan: %+v", plan["unicom"])
	}
}

func TestProvinceLineSupportFollowsS2(t *testing.T) {
	if line, ok := lineFor("广东:mobile"); !ok || line != "广东移动" {
		t.Fatalf("lineFor = %q,%v", line, ok)
	}
	if !lineSupported("aliyun", "广东:telecom") || !lineSupported("dnspod_cn", "广东:telecom") ||
		lineSupported("cloudflare", "广东:telecom") || lineSupported("aliyun", "广东:overseas") ||
		lineSupported("aliyun", "香港:telecom") || !lineSupported("aliyun", "telecom") {
		t.Fatal("province support must follow dnsproviderremote")
	}
	if line, ok := lineFor("telecom"); !ok || line != "电信" {
		t.Fatalf("carrier line = %q", line)
	}
}
