package marketsupply

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

// u4g: codes resolve to the local catalogue names; unknown codes are left
// out for the caller to show as is; duplicates once, in request order.
func TestPluginNamesOf(t *testing.T) {
	got := pluginNamesOf([]string{"ja4", "rule_pack:system/bot", "module.unknown", "ja4", "rule_pack:dev/x/y", "pack.crs"},
		map[string]string{"system/bot": "爬虫规则包"})
	want := []SupplyPlugin{
		{Code: "ja4", NameZH: "JA4 指纹", NameEN: "JA4 fingerprints"},
		{Code: "rule_pack:system/bot", NameZH: "爬虫规则包", NameEN: "爬虫规则包"},
		{Code: "pack.crs", NameZH: "OWASP CRS 档位", NameEN: "OWASP CRS levels"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
	if got := pluginNamesOf(nil, nil); got == nil || len(got) != 0 {
		t.Fatalf("empty: %#v", got)
	}
}

// Over the bound (or empty) nothing is read: no pool needed.
func TestPluginNamesBound(t *testing.T) {
	s := &SupplyGroups{}
	codes := strings.Split(strings.Repeat("ja4,", maxPluginNames+1), ",")[:maxPluginNames+1]
	if got, err := s.PluginNames(context.Background(), codes); err != nil || len(got) != 0 {
		t.Fatalf("over bound: %+v %v", got, err)
	}
	if got, err := s.PluginNames(context.Background(), []string{"ja4"}); err != nil || len(got) != 1 || got[0].NameZH != "JA4 指纹" {
		t.Fatalf("catalogue only: %+v %v", got, err)
	}
}
