package spec

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestAllocationMinAndStrictDecode(t *testing.T) {
	a := Allocation{HTTPPorts: 2, StreamPorts: 5, WebSocket: true, HTTP3: true}
	b := Allocation{HTTPPorts: 3, StreamPorts: 0, WebSocket: true}
	if got, want := a.Min(b), (Allocation{HTTPPorts: 2, WebSocket: true}); got != want {
		t.Fatalf("Min = %+v, want %+v", got, want)
	}
	if (Allocation{HTTPPorts: MaxPorts + 1}).Validate() == nil || (Allocation{StreamPorts: -1}).Validate() == nil {
		t.Fatal("out of range ports accepted")
	}
	// The three metered keys moved to limits in 1.0.35; a signed document
	// still carrying them must fail instead of silently losing its caps.
	for _, key := range []string{"domains", "bandwidth_bps", "monthly_traffic_bytes"} {
		var got Allocation
		if err := DecodeStrict([]byte(`{"http_ports":1,"`+key+`":5}`), &got); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", key, err)
		}
	}
	var c Compliance
	if err := DecodeStrict([]byte(`{"require_icp":true}{}`), &c); !errors.Is(err, ErrInvalid) {
		t.Fatalf("trailing value: %v", err)
	}
}

func TestMetricVocabulary(t *testing.T) {
	want := []Metric{"domains", "bandwidth_peak_bps", "monthly_traffic_bytes", "concurrent_connections",
		"concurrent_requests", "new_connections_per_second", "qps", "node_cpu_percent", "node_memory_percent"}
	if got := Metrics(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Metrics() = %v", got)
	}
	defaults := map[Metric]Action{
		MetricDomains: ActionRejectNew, MetricBandwidthPeakBPS: ActionThrottle, MetricMonthlyTrafficBytes: ActionPause,
		MetricConcurrentConnections: ActionThrottle, MetricConcurrentRequests: ActionThrottle, MetricNewConnectionsPerSecond: ActionThrottle, MetricQPS: ActionThrottle,
		MetricNodeCPUPercent: ActionRemoveNode, MetricNodeMemoryPercent: ActionRemoveNode,
	}
	for m, a := range defaults {
		if m.DefaultAction() != a {
			t.Errorf("%s default = %s, want %s", m, m.DefaultAction(), a)
		}
	}
	realtime := map[Metric]bool{MetricBandwidthPeakBPS: true, MetricConcurrentConnections: true,
		MetricConcurrentRequests: true, MetricNewConnectionsPerSecond: true, MetricQPS: true}
	for _, m := range Metrics() {
		if m.Realtime() != realtime[m] {
			t.Errorf("%s realtime = %v", m, m.Realtime())
		}
	}
	if Metric("iops").Known() || Metric("iops").DefaultAction() != "" {
		t.Fatal("unknown metric reported as known")
	}
}

func TestLimitValidateBoundaries(t *testing.T) {
	ok := []Limit{
		{Metric: MetricDomains, Cap: 1, Action: ActionRejectNew},
		{Metric: MetricDomains, Cap: MetricDomains.MaxCap(), Action: ActionRejectNew},
		{Metric: MetricBandwidthPeakBPS, Cap: MaxBandwidthBPS, Action: ActionStop, SustainBuckets: MaxSustainBuckets},
		{Metric: MetricMonthlyTrafficBytes, Cap: 1, Action: ActionThrottle, ThrottleBPS: 1},
		{Metric: MetricMonthlyTrafficBytes, Cap: 1, Action: ActionPause},
		{Metric: MetricQPS, Cap: 1, Action: ActionPause, SustainBuckets: 1},
		{Metric: MetricNodeCPUPercent, Cap: 100, Action: ActionRemoveNode},
		{Metric: MetricNodeMemoryPercent, Cap: 1, Action: ActionRemoveNode},
	}
	for _, l := range ok {
		if err := l.Validate(); err != nil {
			t.Errorf("%+v: %v", l, err)
		}
	}
	bad := map[string]Limit{
		"unknown metric":      {Metric: "iops", Cap: 1, Action: ActionThrottle},
		"zero cap":            {Metric: MetricDomains, Cap: 0, Action: ActionRejectNew},
		"negative cap":        {Metric: MetricQPS, Cap: -1, Action: ActionThrottle, SustainBuckets: 2},
		"cap above max":       {Metric: MetricBandwidthPeakBPS, Cap: MaxBandwidthBPS + 1, Action: ActionThrottle, SustainBuckets: 2},
		"cpu above 100":       {Metric: MetricNodeCPUPercent, Cap: 101, Action: ActionRemoveNode},
		"domains throttle":    {Metric: MetricDomains, Cap: 1, Action: ActionThrottle},
		"node pause":          {Metric: MetricNodeCPUPercent, Cap: 50, Action: ActionPause},
		"qps remove_node":     {Metric: MetricQPS, Cap: 1, Action: ActionRemoveNode, SustainBuckets: 2},
		"empty action":        {Metric: MetricQPS, Cap: 1, SustainBuckets: 2},
		"traffic throttle 0":  {Metric: MetricMonthlyTrafficBytes, Cap: 1, Action: ActionThrottle},
		"throttle_bps pause":  {Metric: MetricMonthlyTrafficBytes, Cap: 1, Action: ActionPause, ThrottleBPS: 5},
		"throttle_bps on bw":  {Metric: MetricBandwidthPeakBPS, Cap: 1, Action: ActionThrottle, ThrottleBPS: 5, SustainBuckets: 2},
		"throttle_bps huge":   {Metric: MetricMonthlyTrafficBytes, Cap: 1, Action: ActionThrottle, ThrottleBPS: MaxBandwidthBPS + 1},
		"realtime no sustain": {Metric: MetricQPS, Cap: 1, Action: ActionThrottle},
		"sustain too long":    {Metric: MetricQPS, Cap: 1, Action: ActionThrottle, SustainBuckets: MaxSustainBuckets + 1},
		"sustain on traffic":  {Metric: MetricMonthlyTrafficBytes, Cap: 1, Action: ActionPause, SustainBuckets: 2},
	}
	for name, l := range bad {
		if err := l.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
}

func TestLimitSetNormalizeAndCanonicalOrder(t *testing.T) {
	in := LimitSet{
		{Metric: MetricQPS, Cap: 100},
		{Metric: MetricMonthlyTrafficBytes, Cap: 1 << 40},
		{Metric: MetricDomains, Cap: 5},
	}
	got, err := in.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	want := LimitSet{
		{Metric: MetricDomains, Cap: 5, Action: ActionRejectNew},
		{Metric: MetricMonthlyTrafficBytes, Cap: 1 << 40, Action: ActionPause},
		{Metric: MetricQPS, Cap: 100, Action: ActionThrottle, SustainBuckets: DefaultSustainBuckets},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Normalize = %+v", got)
	}
	if in[0].Metric != MetricQPS || in[0].Action != "" {
		t.Fatal("Normalize mutated its input")
	}
	if err := in.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatal("non-canonical set validated")
	}
	if _, err := (LimitSet{{Metric: MetricQPS, Cap: 1}, {Metric: MetricQPS, Cap: 2}}).Normalize(); !errors.Is(err, ErrInvalid) {
		t.Fatal("duplicate metric accepted")
	}
	if empty, err := (LimitSet{}).Normalize(); err != nil || len(empty) != 0 {
		t.Fatalf("empty set: %+v, %v", empty, err)
	}
	if v, ok := want.Cap(MetricQPS); !ok || v != 100 {
		t.Fatal("Cap(qps)")
	}
	if _, ok := want.Cap(MetricBandwidthPeakBPS); ok {
		t.Fatal("unselected metric must be unlimited")
	}
}

func TestLimitSetJSON(t *testing.T) {
	if b, _ := json.Marshal(LimitSet(nil)); string(b) != "[]" {
		t.Fatalf("nil set = %s", b)
	}
	if b, _ := json.Marshal(struct {
		L LimitSet `json:"l"`
	}{}); string(b) != `{"l":[]}` {
		t.Fatalf("nil field = %s", b)
	}
	set := LimitSet{{Metric: MetricMonthlyTrafficBytes, Cap: 9, Action: ActionThrottle, ThrottleBPS: 3}}
	raw, _ := json.Marshal(set)
	if string(raw) != `[{"metric":"monthly_traffic_bytes","cap":9,"action":"throttle","throttle_bps":3}]` {
		t.Fatalf("encoding = %s", raw)
	}
	var back LimitSet
	if err := json.Unmarshal(raw, &back); err != nil || !reflect.DeepEqual(back, set) {
		t.Fatalf("round trip %+v, %v", back, err)
	}
	if err := DecodeStrict([]byte(`[{"metric":"qps","cap":1,"action":"throttle","sustain_buckets":2,"burst":3}]`), &back); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown limit field: %v", err)
	}
}

func TestLimitSetMinAlongPath(t *testing.T) {
	seller := LimitSet{
		{Metric: MetricDomains, Cap: 100, Action: ActionRejectNew},
		{Metric: MetricBandwidthPeakBPS, Cap: 1_000, Action: ActionThrottle, SustainBuckets: 2},
		{Metric: MetricQPS, Cap: 50, Action: ActionThrottle, SustainBuckets: 2},
	}
	reseller := LimitSet{
		{Metric: MetricDomains, Cap: 10, Action: ActionRejectNew},
		{Metric: MetricBandwidthPeakBPS, Cap: 5_000, Action: ActionStop, SustainBuckets: 3},
		{Metric: MetricMonthlyTrafficBytes, Cap: 7, Action: ActionPause},
		{Metric: MetricQPS, Cap: 50, Action: ActionPause, SustainBuckets: 4},
	}
	want := LimitSet{
		{Metric: MetricDomains, Cap: 10, Action: ActionRejectNew},                               // smaller cap wins
		{Metric: MetricBandwidthPeakBPS, Cap: 1_000, Action: ActionThrottle, SustainBuckets: 2}, // with its own action
		{Metric: MetricMonthlyTrafficBytes, Cap: 7, Action: ActionPause},                        // one hop caps it
		{Metric: MetricQPS, Cap: 50, Action: ActionPause, SustainBuckets: 4},                    // tie: stricter action
	}
	for _, got := range []LimitSet{seller.Min(reseller), reseller.Min(seller)} {
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("Min = %+v", got)
		}
		if err := got.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	if got := (LimitSet{}).Min(nil); got == nil || len(got) != 0 {
		t.Fatal("two unlimited hops must stay unlimited")
	}
	if got := LimitSet(nil).Min(seller); !reflect.DeepEqual(got, seller) {
		t.Fatal("unlimited hop must not loosen the other")
	}
}

func TestLoadFloor(t *testing.T) {
	floor := DefaultLoadFloor
	if floor != (LoadThresholds{CPUPercent: 80, MemoryPercent: 70}) {
		t.Fatalf("platform floor = %+v", floor)
	}
	set, _ := LimitSet{{Metric: MetricQPS, Cap: 9}, {Metric: MetricNodeCPUPercent, Cap: 60}}.Normalize()
	if err := set.CheckLoadFloor(floor); err != nil {
		t.Fatal(err)
	}
	loose := LimitSet{{Metric: MetricNodeMemoryPercent, Cap: 71, Action: ActionRemoveNode}}
	err := loose.CheckLoadFloor(floor)
	var fe *FloorError
	if !errors.As(err, &fe) || fe.Metric != MetricNodeMemoryPercent || fe.Floor != 70 || !errors.Is(err, ErrInvalid) {
		t.Fatalf("looser than floor: %v", err)
	}
	limits, effective := set.SplitLoad(floor)
	if len(limits) != 1 || limits[0].Metric != MetricQPS || effective != (LoadThresholds{CPUPercent: 60, MemoryPercent: 70}) {
		t.Fatalf("SplitLoad = %+v, %+v", limits, effective)
	}
	// A floor tightened after listing overrides the stored seller value.
	if _, effective := set.SplitLoad(LoadThresholds{CPUPercent: 50, MemoryPercent: 40}); effective != (LoadThresholds{CPUPercent: 50, MemoryPercent: 40}) {
		t.Fatalf("tightened floor: %+v", effective)
	}
	if (LoadThresholds{CPUPercent: 0, MemoryPercent: 70}).Validate() == nil || (LoadThresholds{CPUPercent: 80, MemoryPercent: 101}).Validate() == nil {
		t.Fatal("out of range thresholds accepted")
	}
}

func TestPrepaidAction(t *testing.T) {
	if PrepaidPause.Validate() != nil || PrepaidStop.Validate() != nil || PrepaidAction("throttle").Validate() == nil || PrepaidAction("").Validate() == nil {
		t.Fatal("prepaid action vocabulary")
	}
}

func TestTags(t *testing.T) {
	got, err := (Tags{}).Normalize()
	if err != nil || got.CCProtection != CCNone || got.Tenancy != TenancyShared {
		t.Fatalf("defaults: %+v, %v", got, err)
	}
	full := Tags{CCProtection: CCAdvanced, DDoSProtectionGbps: MaxDDoSProtectionGbps, ComplaintResistant: true,
		Tenancy: TenancyDedicated, MobileReachable: true, RegionBlock: true, LineClass: strings.Repeat("线", MaxLineClassRunes),
		Plugins: []string{"module.autodefense", "pack.cc.advanced"}}
	if err := full.Validate(); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(full)
	var back Tags
	if err := json.Unmarshal(raw, &back); err != nil || !reflect.DeepEqual(back, full) {
		t.Fatalf("round trip %+v, %v", back, err)
	}
	bad := map[string]func(*Tags){
		"cc":               func(x *Tags) { x.CCProtection = "max" },
		"tenancy":          func(x *Tags) { x.Tenancy = "" },
		"ddos neg":         func(x *Tags) { x.DDoSProtectionGbps = -1 },
		"ddos huge":        func(x *Tags) { x.DDoSProtectionGbps = MaxDDoSProtectionGbps + 1 },
		"line long":        func(x *Tags) { x.LineClass = strings.Repeat("a", MaxLineClassRunes+1) },
		"line ctrl":        func(x *Tags) { x.LineClass = "BGP\n" },
		"line binary":      func(x *Tags) { x.LineClass = "\xff" },
		"plugin theme":     func(x *Tags) { x.Plugins = []string{"theme.dark"} },
		"plugin bad":       func(x *Tags) { x.Plugins = []string{"Module.X"} },
		"rule pack bare":   func(x *Tags) { x.Plugins = []string{"rule_pack:p1"} },
		"rule pack scheme": func(x *Tags) { x.Plugins = []string{"rule_pack:team/p1"} },
		"plugin order":     func(x *Tags) { x.Plugins = []string{"pack.crs", "module.autodefense"} },
		"plugin dup":       func(x *Tags) { x.Plugins = []string{"pack.crs", "pack.crs"} },
		"plugin many": func(x *Tags) {
			x.Plugins = nil
			for i := 0; i <= MaxPlugins; i++ {
				x.Plugins = append(x.Plugins, fmt.Sprintf("pack.p%03d", i))
			}
		},
	}
	for name, mutate := range bad {
		x := full
		mutate(&x)
		if err := x.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
	sorted, err := (Tags{Plugins: []string{"pack.crs", "module.autodefense"}}).Normalize()
	if err != nil || !reflect.DeepEqual(sorted.Plugins, []string{"module.autodefense", "pack.crs"}) {
		t.Fatalf("normalize sorts plugins: %+v, %v", sorted, err)
	}
	if _, err := (Tags{Plugins: []string{"pack.crs", "pack.crs"}}).Normalize(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("normalize keeps duplicates invalid: %v", err)
	}
	if err := DecodeStrict([]byte(`{"cc_protection":"none","tenancy":"shared","anycast":true}`), &back); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown tag: %v", err)
	}
}

// 卖家自定义特性标签，最多 10 个、每个 ≤16 字符，
// Normalize 去首尾空格、去空、去重（保留首次出现顺序），控制字符拒绝。
func TestTagsCustom(t *testing.T) {
	got, err := (Tags{Custom: []string{" 高防 ", "高防", "", "  ", "原生 IP"}}).Normalize()
	if err != nil || !reflect.DeepEqual(got.Custom, []string{"高防", "原生 IP"}) {
		t.Fatalf("normalize custom: %+v, %v", got.Custom, err)
	}
	if got, err := (Tags{Custom: []string{" ", ""}}).Normalize(); err != nil || got.Custom != nil {
		t.Fatalf("blank custom drops to nil: %+v, %v", got.Custom, err)
	}
	ten := make([]string, MaxCustomTags)
	for i := range ten {
		ten[i] = fmt.Sprintf("标签%d", i)
	}
	ok := Tags{CCProtection: CCNone, Tenancy: TenancyShared, Custom: append([]string{strings.Repeat("长", MaxCustomTagRunes)}, ten[1:]...)}
	if err := ok.Validate(); err != nil {
		t.Fatalf("10 tags of 16 runes: %v", err)
	}
	raw, _ := json.Marshal(ok)
	var back Tags
	if err := DecodeStrict(raw, &back); err != nil || !reflect.DeepEqual(back, ok) {
		t.Fatalf("round trip %+v, %v", back, err)
	}
	if raw, _ := json.Marshal(Tags{CCProtection: CCNone, Tenancy: TenancyShared}); strings.Contains(string(raw), "custom") {
		t.Fatalf("empty custom is omitted: %s", raw)
	}
	for name, custom := range map[string][]string{
		"too many":  append(slices.Clone(ten), "多一个"),
		"too long":  {strings.Repeat("长", MaxCustomTagRunes+1)},
		"control":   {"高\u0007防"},
		"newline":   {"高防\n"},
		"binary":    {"\xff"},
		"duplicate": {"高防", "高防"},
		"untrimmed": {" 高防"},
		"empty":     {""},
	} {
		x := Tags{CCProtection: CCNone, Tenancy: TenancyShared, Custom: custom}
		if err := x.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
	// Normalize trims and dedupes first, then still refuses what stays invalid.
	if _, err := (Tags{Custom: append(slices.Clone(ten), "多一个")}).Normalize(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("normalize keeps 11 tags invalid: %v", err)
	}
	if _, err := (Tags{Custom: []string{"高\u0007防"}}).Normalize(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("normalize keeps control characters invalid: %v", err)
	}
	// Grants carry no custom tags: controllers decode grants strictly.
	g := Tags{CCProtection: CCBasic, Tenancy: TenancyShared, Plugins: []string{"pack.crs"}, Custom: []string{"高防"}}.ForGrant()
	if g.Custom != nil || g.CCProtection != CCBasic || !reflect.DeepEqual(g.Plugins, []string{"pack.crs"}) {
		t.Fatalf("for grant: %+v", g)
	}
}

// A supply may include a rule pack the
// seller bought and every node has, as rule_pack:<pack id>.
func TestValidPluginAcceptsRulePacks(t *testing.T) {
	for _, code := range []string{"rule_pack:system/crs-strict", "rule_pack:dev/io.cdnca.examples/bad-bots",
		"rule_pack:user/0f8e7d6c-5b4a-4321-8fed-cba987654321/my-pack"} {
		if !ValidPlugin(code) || !IsRulePackPlugin(code) {
			t.Errorf("%s: want a valid rule pack plugin", code)
		}
	}
	for _, code := range []string{"rule_pack:", "rule_pack:p1", "rule_pack:System/x", "rule_pack:user/not-a-uuid/x",
		"rule_pack:dev/x/" + strings.Repeat("a", 65), "rule_packs:system/x"} {
		if ValidPlugin(code) {
			t.Errorf("%s: want invalid", code)
		}
	}
	if IsRulePackPlugin("pack.crs") || !ValidPlugin("pack.crs") {
		t.Fatal("feature codes are unchanged")
	}
	tags := Tags{Plugins: []string{"module.autodefense", "rule_pack:system/crs-strict"}}
	if _, err := tags.Normalize(); err != nil {
		t.Fatal(err)
	}
}
