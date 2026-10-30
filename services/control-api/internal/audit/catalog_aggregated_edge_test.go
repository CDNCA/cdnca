package audit

import (
	"strings"
	"testing"
)

// 聚合边缘里的“供给”改名“第三方 CDN 接入 / 接入点”；
// 节点市场的“供给”不变，所以只查 aggregated_edge.* 条目。
func TestAggregatedEdgeAuditTextsUseAccessPoint(t *testing.T) {
	seen := 0
	for _, entry := range Entries() {
		if !strings.HasPrefix(entry.Action, "aggregated_edge.") {
			continue
		}
		seen++
		if strings.Contains(entry.TemplateZH, "供给") {
			t.Errorf("%s: zh still says 供给: %s", entry.Action, entry.TemplateZH)
		}
		if strings.Contains(strings.ToLower(entry.TemplateEN), "supply") {
			t.Errorf("%s: en still says supply: %s", entry.Action, entry.TemplateEN)
		}
	}
	if seen == 0 {
		t.Fatal("no aggregated_edge.* audit entries found")
	}
	for action, want := range map[string]string{
		"aggregated_edge.supply.create":   "新增第三方 CDN 接入点 {resource}",
		"aggregated_edge.switch.failover": "站点 {resource} 的线路因不健康切换到备用接入点{changes}",
	} {
		entry, ok := Lookup(action)
		if !ok || entry.TemplateZH != want {
			t.Errorf("%s: got %q, want %q", action, entry.TemplateZH, want)
		}
	}
}
