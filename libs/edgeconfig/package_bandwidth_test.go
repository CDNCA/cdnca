package edgeconfig

import (
	"strings"
	"testing"
)

func TestPackageBandwidthDirectiveSplitsBudget(t *testing.T) {
	limit := PackageConnectionLimit{SubscriptionID: "11111111-1111-4111-8111-111111111111", Connections: -1, BandwidthBPS: 8_000_000}
	directive, err := PackageBandwidthDirective(limit)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"set_by_lua_block $cdnca_package_rate {", `ngx.shared["cdnca_package_bandwidth"]`,
		`"11111111-1111-4111-8111-111111111111"`, "dict:incr(key, 1, 0, 3600)", "math.floor(1000000 / math.max(active, 1))",
		"limit_rate $cdnca_package_rate;",
	} {
		if !strings.Contains(directive, want) {
			t.Errorf("directive missing %q:\n%s", want, directive)
		}
	}
	if log := PackageBandwidthLogLua(limit); !strings.Contains(log, "dict:incr(key, -1)") {
		t.Fatalf("log hook = %q", log)
	}
	if http := PackageBandwidthHTTP([]PackageConnectionLimit{limit}); http != "  lua_shared_dict cdnca_package_bandwidth 1m;\n" {
		t.Fatalf("http = %q", http)
	}
	unlimited := PackageConnectionLimit{SubscriptionID: limit.SubscriptionID, Connections: 10}
	if directive, _ := PackageBandwidthDirective(unlimited); directive != "" || PackageBandwidthLogLua(unlimited) != "" ||
		PackageBandwidthHTTP([]PackageConnectionLimit{unlimited}) != "" {
		t.Fatal("a limit without bandwidth renders bandwidth directives")
	}
	for _, invalid := range []int64{-1, MaxPackageBandwidthBPS + 1} {
		if _, err := PackageBandwidthDirective(PackageConnectionLimit{SubscriptionID: limit.SubscriptionID, BandwidthBPS: invalid}); err == nil {
			t.Fatalf("accepted bandwidth %d", invalid)
		}
	}
}
