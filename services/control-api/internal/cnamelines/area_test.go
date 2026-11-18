package cnamelines

import (
	"maps"
	"slices"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocation"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
)

func TestAreaScope(t *testing.T) {
	for _, item := range []struct{ provider, area, want string }{
		{"aliyun", "east_asia", "east_asia"},
		{"dnspod_cn", "central_asia", "central_asia"},
		{"huawei", "east_asia", "asia"}, // no Asian sub-areas: 亚洲
		{"dns_la", "south_asia", "asia"},
		{"dns_com", "west_asia", "asia"},
		{"huawei", "europe", "europe"},
		{"dns_la", "africa", "africa"},
		{"jdcloud", "europe", "overseas"}, // no area lines: 境外
		{"custom_http", "southeast_asia", "overseas"},
		{"cloudflare", "europe", ""}, // no lines: default only
		{"aliyun", "global", ""},     // global: default line only
		{"aliyun", "", ""},
		{"aliyun", "antarctica", ""},
		// Continents and regions.
		{"aliyun", "asia", "asia"},
		{"aliyun", "northern_europe", "northern_europe"},
		{"dnspod_cn", "central_america", "central_america"},
		{"aliyun", "middle_africa", "middle_africa"},
		{"dnspod_cn", "polynesia", "polynesia"},
		{"aliyun", "oceania", "oceania"},
		{"huawei", "western_europe", "europe"}, // no regions: the continent
		{"huawei", "caribbean", "north_america"},
		{"huawei", "micronesia", "oceania"},
		{"dns_la", "australia_new_zealand", "oceania"},
		{"dns_la", "southern_africa", "africa"},
		{"dns_com", "eastern_europe", "europe"},
		{"dns_com", "oceania", "oceania"},
		{"jdcloud", "melanesia", "overseas"},
		{"plugin", "northern_america", "overseas"},
		{"cloudflare", "oceania", ""},
	} {
		if got := AreaScope(item.provider, item.area); got != item.want {
			t.Errorf("AreaScope(%s, %s) = %q, want %q", item.provider, item.area, got, item.want)
		}
	}
	// Every scope an area resolves to is a line the provider writes.
	for _, provider := range []string{"aliyun", "huawei", "dnspod_cn", "dns_com", "dns_la", "jdcloud", "custom_http", "plugin"} {
		for _, area := range append(dnsproviderremote.AreaCodes(), "global") {
			scope := AreaScope(provider, area)
			if scope == "" {
				if area != "global" {
					t.Fatalf("%s %s resolves to the default line", provider, area)
				}
				continue
			}
			line, _ := dnsproviderremote.AreaLine(provider, area)
			if got, ok := DNSLine(scope); !ok || got != line || !Supported(provider, scope) {
				t.Fatalf("%s %s: scope %q line %q, want %q", provider, area, scope, got, line)
			}
		}
	}
}

func TestPlanAreaEndpoints(t *testing.T) {
	endpoints := []Endpoint{
		{Address: "192.0.2.1", Area: "east_asia"}, {Address: "192.0.2.2", Area: "south_asia"},
		{Address: "192.0.2.3", Area: "europe"}, {Address: "192.0.2.4", Area: "global"},
		{Address: "198.51.100.1", Region: "日本"}, {Address: "192.0.2.5", Area: "east_asia", Carrier: "电信"},
	}
	huawei := Plan("huawei", endpoints)
	if !slices.Equal(huawei["asia"].A, []string{"192.0.2.1", "192.0.2.2", "192.0.2.5"}) ||
		!slices.Equal(huawei["europe"].A, []string{"192.0.2.3"}) ||
		!slices.Equal(huawei["overseas"].A, []string{"198.51.100.1"}) || !huawei["telecom"].Empty() {
		t.Fatalf("huawei = %+v", huawei)
	}
	// Every line the provider writes for an area is planned (empty retires it).
	for _, scope := range []string{"asia", "europe", "north_america", "south_america", "africa", "oceania"} {
		if _, ok := huawei[scope]; !ok {
			t.Fatalf("huawei plan lacks %s", scope)
		}
	}
	if _, ok := huawei["east_asia"]; ok {
		t.Fatal("huawei has no 东亚 line")
	}
	aliyun := Plan("aliyun", endpoints)
	if !slices.Equal(aliyun["east_asia"].A, []string{"192.0.2.1", "192.0.2.5"}) ||
		!slices.Equal(aliyun["south_asia"].A, []string{"192.0.2.2"}) || !aliyun["asia"].Empty() {
		t.Fatalf("aliyun = %+v", aliyun)
	}
	jd := Plan("jdcloud", endpoints)
	if !slices.Equal(jd["overseas"].A, []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.5", "198.51.100.1"}) ||
		len(jd) != len(Scopes) {
		t.Fatalf("jdcloud = %+v", jd)
	}
	for _, set := range Plan("cloudflare", endpoints) {
		if !set.Empty() && slices.Contains(set.A, "192.0.2.1") {
			t.Fatalf("cloudflare wrote an area line: %+v", set)
		}
	}
	weights := map[cnameallocation.WeightKey]uint32{{Address: "192.0.2.1"}: 30, {Carrier: "电信", Address: "192.0.2.5"}: 60}
	if got := LineWeights("huawei", endpoints, "asia", weights); !maps.Equal(got, map[string]uint32{"192.0.2.1": 30, "192.0.2.5": 60}) {
		t.Fatalf("asia weights = %v", got)
	}
}

// Regions a provider has no line for share their continent's
// record set; the line_scope values the worker can write are the carrier /
// overseas scopes plus every geoarea code except global (migration 680).
func TestPlanAreaRegionsMergeAndScopeSet(t *testing.T) {
	endpoints := []Endpoint{
		{Address: "192.0.2.1", Area: "oceania"}, {Address: "192.0.2.2", Area: "micronesia"},
		{Address: "192.0.2.3", Area: "australia_new_zealand"}, {Address: "192.0.2.4", Area: "northern_europe"},
		{Address: "192.0.2.5", Area: "western_europe"}, {Address: "2001:db8::1", Area: "caribbean"},
	}
	for _, provider := range []string{"huawei", "dns_la", "dns_com"} {
		plan := Plan(provider, endpoints)
		if !slices.Equal(plan["oceania"].A, []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}) ||
			!slices.Equal(plan["europe"].A, []string{"192.0.2.4", "192.0.2.5"}) ||
			!slices.Equal(plan["north_america"].AAAA, []string{"2001:db8::1"}) {
			t.Fatalf("%s = %+v", provider, plan)
		}
		if _, ok := plan["micronesia"]; ok {
			t.Fatalf("%s plans a 密克罗尼西亚 line it does not have", provider)
		}
	}
	aliyun := Plan("aliyun", endpoints)
	if !slices.Equal(aliyun["micronesia"].A, []string{"192.0.2.2"}) || !slices.Equal(aliyun["oceania"].A, []string{"192.0.2.1"}) ||
		!slices.Equal(aliyun["caribbean"].AAAA, []string{"2001:db8::1"}) {
		t.Fatalf("aliyun = %+v", aliyun)
	}
	written := map[string]bool{}
	for _, provider := range []string{"aliyun", "huawei", "dnspod_cn", "dns_com", "dns_la", "jdcloud", "custom_http", "plugin", "cloudflare"} {
		for scope := range Plan(provider, nil) {
			written[scope] = true
		}
	}
	want := []string{"telecom", "unicom", "mobile", "overseas",
		"asia", "east_asia", "southeast_asia", "south_asia", "west_asia", "central_asia",
		"europe", "northern_europe", "western_europe", "southern_europe", "eastern_europe",
		"africa", "northern_africa", "western_africa", "eastern_africa", "middle_africa", "southern_africa",
		"north_america", "northern_america", "central_america", "caribbean", "south_america",
		"oceania", "australia_new_zealand", "melanesia", "micronesia", "polynesia"}
	if got := slices.Sorted(maps.Keys(written)); !slices.Equal(got, slices.Sorted(slices.Values(want))) {
		t.Fatalf("area/carrier scopes = %v", got)
	}
}
