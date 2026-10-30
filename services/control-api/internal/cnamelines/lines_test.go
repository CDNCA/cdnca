package cnamelines

import (
	"maps"
	"slices"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocation"
)

func TestEndpointScope(t *testing.T) {
	for _, item := range []struct{ region, carrier, want string }{
		{"", "电信", "telecom"},
		{"广东", "中国联通", "unicom"},
		{"cn", "CMCC", "mobile"},
		{"香港", "", "overseas"},
		{"us", "telecom", "overseas"}, // outside the mainland wins over the carrier
		{"", "BGP", ""},
		{"广东", "电信/联通", ""}, // ambiguous carriers stay on the default line only
		{"", "", ""},
	} {
		if got := EndpointScope(item.region, item.carrier); got != item.want {
			t.Errorf("EndpointScope(%q,%q)=%q, want %q", item.region, item.carrier, got, item.want)
		}
	}
}

func TestPlanGroupsEndpointsByLine(t *testing.T) {
	sets := Plan([]Endpoint{
		{Address: "192.0.2.2", Carrier: "电信"}, {Address: "192.0.2.1", Carrier: "telecom"},
		{Address: "2001:db8::1", Carrier: "电信"}, {Address: "192.0.2.1", Carrier: "电信"},
		{Address: "198.51.100.1", Region: "日本"}, {Address: "203.0.113.1", Carrier: "BGP"},
	})
	if len(sets) != len(Scopes) {
		t.Fatalf("every scope must be planned: %v", sets)
	}
	if !slices.Equal(sets["telecom"].A, []string{"192.0.2.1", "192.0.2.2"}) ||
		!slices.Equal(sets["telecom"].AAAA, []string{"2001:db8::1"}) {
		t.Fatalf("telecom = %+v", sets["telecom"])
	}
	if !slices.Equal(sets["overseas"].A, []string{"198.51.100.1"}) || !sets["unicom"].Empty() || !sets["mobile"].Empty() {
		t.Fatalf("sets = %+v", sets)
	}

	// NET-02：同一 IP 挂在多条运营商线路上，每条线路各写一份，不被合并。
	shared := Plan([]Endpoint{
		{Address: "192.0.2.9", Carrier: "电信"}, {Address: "192.0.2.9", Carrier: "联通"},
		{Address: "192.0.2.9", Carrier: "移动"}, {Address: "192.0.2.9"},
	})
	for _, scope := range []string{"telecom", "unicom", "mobile"} {
		if !slices.Equal(shared[scope].A, []string{"192.0.2.9"}) {
			t.Fatalf("%s = %+v", scope, shared[scope])
		}
	}
	if !shared["overseas"].Empty() {
		t.Fatalf("overseas = %+v", shared["overseas"])
	}
	telecom := sets["telecom"]
	if telecom.Digest(300, nil) == telecom.Digest(600, nil) ||
		telecom.Digest(300, nil) == telecom.Digest(300, map[string]uint32{"192.0.2.1": 10}) {
		t.Fatal("digest must bind TTL and weights")
	}
}

func TestSupportedLines(t *testing.T) {
	if !Supported("aliyun", "overseas") || !Supported("huawei", "overseas") || !Supported("huawei", "telecom") ||
		Supported("cloudflare", "telecom") || !Supported("dns_com", "mobile") || !Supported("dnspod_cn", "mobile") {
		t.Fatal("line support must follow dnsproviderremote.SupportedLines")
	}
}

// NET-02（fp-net2）：同一 IP 在电信/联通线路的权重各自写入，不互相覆盖。
func TestLineWeightsKeepEachCarrier(t *testing.T) {
	endpoints := []Endpoint{
		{Address: "192.0.2.9", Carrier: "电信"}, {Address: "192.0.2.9", Carrier: "联通"},
		{Address: "192.0.2.9"}, {Address: "192.0.2.8", Carrier: "中国电信"}, {Address: "192.0.2.8", Carrier: "电信"},
	}
	weights := map[cnameallocation.WeightKey]uint32{
		{Carrier: "电信", Address: "192.0.2.9"}: 70, {Carrier: "联通", Address: "192.0.2.9"}: 20, {Address: "192.0.2.9"}: 50,
		{Carrier: "中国电信", Address: "192.0.2.8"}: 10, {Carrier: "电信", Address: "192.0.2.8"}: 40,
	}
	// 同一线路两种写法的运营商指向同一地址时取运营商最小者（"中国电信" < "电信"）。
	if got := LineWeights(endpoints, "telecom", weights); !maps.Equal(got, map[string]uint32{"192.0.2.9": 70, "192.0.2.8": 10}) {
		t.Fatalf("telecom = %v", got)
	}
	if got := LineWeights(endpoints, "unicom", weights); !maps.Equal(got, map[string]uint32{"192.0.2.9": 20}) {
		t.Fatalf("unicom = %v", got)
	}
	if got := LineWeights(endpoints, "mobile", weights); len(got) != 0 {
		t.Fatalf("mobile = %v", got)
	}
}
