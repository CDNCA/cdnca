package edgeconfig

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	_ "time/tzdata" // the control plane embeds it too
)

type userAgentCase struct {
	Note    string  `json:"note"`
	UA      string  `json:"ua"`
	Browser string  `json:"browser"`
	Version *[3]int `json:"version"`
	Device  string  `json:"device"`
}

func loadUserAgentCases(t *testing.T) []userAgentCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/user_agents.json")
	if err != nil {
		t.Fatal(err)
	}
	var table struct {
		Cases []userAgentCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &table); err != nil || len(table.Cases) == 0 {
		t.Fatalf("user agent table: %v", err)
	}
	return table.Cases
}

func TestParseUserAgentTable(t *testing.T) {
	seen := map[string]bool{}
	for _, test := range loadUserAgentCases(t) {
		got := ParseUserAgent(test.UA)
		var version *[3]int
		if got.HasVersion {
			version = &got.Version
		}
		if got.Browser != test.Browser || got.Device != test.Device || !reflect.DeepEqual(version, test.Version) {
			t.Errorf("%s: got %s %v %s, want %s %v %s", test.Note, got.Browser, version, got.Device, test.Browser, test.Version, test.Device)
		}
		seen[got.Browser] = true
		seen["device:"+got.Device] = true
	}
	for _, name := range WAFBrowserNames {
		if !seen[name] {
			t.Errorf("no table case for browser %s", name)
		}
	}
	for _, kind := range WAFDeviceKinds {
		if !seen["device:"+kind] {
			t.Errorf("no table case for device %s", kind)
		}
	}
}

// Only the first 512 bytes are parsed.
func TestParseUserAgentTruncates(t *testing.T) {
	padding := strings.Repeat("x", MaxParsedUserAgentBytes-len("Firefox/1"))
	if got := ParseUserAgent(padding + "Firefox/120.0"); got.Browser != WAFBrowserFirefox || !got.HasVersion || got.Version != [3]int{1, 0, 0} {
		t.Fatalf("token cut at the limit: %+v", got)
	}
	if got := ParseUserAgent(strings.Repeat("x", MaxParsedUserAgentBytes) + "Firefox/120.0"); got.Browser != WAFBrowserUnknown {
		t.Fatalf("token past the limit parsed: %+v", got)
	}
}

func TestBrowserOrderIsFixed(t *testing.T) {
	want := []string{"wechat_browser", "qq_browser", "uc_browser", "baidu_browser", "sogou_browser", "360_browser",
		"microsoft_edge", "opera", "samsung_browser", "firefox", "google_chrome", "safari", "unknown"}
	if !reflect.DeepEqual(WAFBrowserNames, want) {
		t.Fatalf("browser names %v", WAFBrowserNames)
	}
	if !reflect.DeepEqual(WAFDeviceKinds, []string{"bot", "desktop", "mobile", "tablet"}) {
		t.Fatalf("device kinds %v", WAFDeviceKinds)
	}
}

func TestParseBrowserVersion(t *testing.T) {
	for raw, want := range map[string][3]int{"100": {100, 0, 0}, "119.0.6045": {119, 0, 6045}, "17.4": {17, 4, 0}, "0": {0, 0, 0}, "99999.99999.99999": {99999, 99999, 99999}} {
		if got, err := ParseBrowserVersion(raw); err != nil || got != want {
			t.Errorf("%q: %v %v", raw, got, err)
		}
	}
	for _, raw := range []string{"", "a", "1.", ".1", "1.2.3.4", "123456", "1..2", " 1", "1 ", "+1", "1.2.3a"} {
		if _, err := ParseBrowserVersion(raw); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%q accepted", raw)
		}
	}
}

func TestBrowserVersionMatches(t *testing.T) {
	chrome99 := ParseUserAgent("Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/99.0.4844.51 Safari/537.36")
	chrome120 := ParseUserAgent("Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/120.0.6099.43 Safari/537.36")
	edge99 := ParseUserAgent("Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/99.0.4844.51 Safari/537.36 Edg/99.0.1150.30")
	firefox99 := ParseUserAgent("Mozilla/5.0 (X11; Linux x86_64; rv:99.0) Gecko/20100101 Firefox/99.0")
	noVersion := ParseUserAgent("Mozilla/5.0 Chrome/abc")
	below100 := WAFBrowserVersion{Name: WAFBrowserChrome, Op: WAFVersionLT, Version: [3]int{100, 0, 0}}
	for _, test := range []struct {
		ua   UserAgentInfo
		want bool
	}{{chrome99, true}, {chrome120, false}, {edge99, false}, {firefox99, false}, {noVersion, false}} {
		if got := below100.Matches(test.ua); got != test.want {
			t.Errorf("%+v: %v", test.ua, got)
		}
	}
	if !(WAFBrowserVersion{Name: WAFBrowserChrome, Op: WAFVersionGTE, Version: [3]int{120, 0, 0}}).Matches(chrome120) ||
		!(WAFBrowserVersion{Name: WAFBrowserChrome, Op: WAFVersionEQ, Version: [3]int{99, 0, 4844}}).Matches(chrome99) ||
		(WAFBrowserVersion{Name: WAFBrowserChrome, Op: WAFVersionEQ, Version: [3]int{99, 0, 0}}).Matches(chrome99) {
		t.Fatal("gte / eq")
	}
	browsers := WAFBrowserMatch{Names: []string{WAFBrowserChrome, WAFBrowserEdge}}
	if !browsers.Matches(chrome99) || !browsers.Matches(edge99) || browsers.Matches(firefox99) {
		t.Fatal("browser in")
	}
	notBrowsers := WAFBrowserMatch{Names: []string{WAFBrowserChrome}, Negate: true}
	if notBrowsers.Matches(chrome99) || !notBrowsers.Matches(firefox99) || !notBrowsers.Matches(ParseUserAgent("curl/8")) {
		t.Fatal("browser not in (unknown counts as not)")
	}
	devices := WAFDeviceMatch{Kinds: []string{WAFDeviceBot}, Negate: true}
	if devices.Matches(ParseUserAgent("")) || !devices.Matches(chrome99) {
		t.Fatal("device not in")
	}
}

func TestNormalizeWAFMatchClientConditions(t *testing.T) {
	match, err := normalizeWAFMatch(WAFMatch{
		Browser:        &WAFBrowserMatch{Names: []string{WAFBrowserChrome, WAFBrowserEdge}},
		BrowserVersion: &WAFBrowserVersion{Name: WAFBrowserChrome, Op: WAFVersionLT, Version: [3]int{100, 0, 0}},
		Device:         &WAFDeviceMatch{Kinds: []string{WAFDeviceMobile, WAFDeviceTablet}, Negate: true},
	})
	if err != nil || match.Browser == nil || match.BrowserVersion == nil || match.Device == nil {
		t.Fatalf("%+v %v", match, err)
	}
	for name, bad := range map[string]WAFMatch{
		"browser empty":         {Browser: &WAFBrowserMatch{Names: []string{}}},
		"browser unknown name":  {Browser: &WAFBrowserMatch{Names: []string{"vivo_browser"}}},
		"browser unsorted":      {Browser: &WAFBrowserMatch{Names: []string{WAFBrowserEdge, WAFBrowserChrome}}},
		"browser duplicate":     {Browser: &WAFBrowserMatch{Names: []string{WAFBrowserChrome, WAFBrowserChrome}}},
		"version op":            {BrowserVersion: &WAFBrowserVersion{Name: WAFBrowserChrome, Op: "gt", Version: [3]int{1, 0, 0}}},
		"version unknown":       {BrowserVersion: &WAFBrowserVersion{Name: WAFBrowserUnknown, Op: WAFVersionLT, Version: [3]int{1, 0, 0}}},
		"version 360 (never)":   {BrowserVersion: &WAFBrowserVersion{Name: WAFBrowser360, Op: WAFVersionLT, Version: [3]int{1, 0, 0}}},
		"version too large":     {BrowserVersion: &WAFBrowserVersion{Name: WAFBrowserChrome, Op: WAFVersionLT, Version: [3]int{100000, 0, 0}}},
		"version negative":      {BrowserVersion: &WAFBrowserVersion{Name: WAFBrowserChrome, Op: WAFVersionLT, Version: [3]int{1, -1, 0}}},
		"device empty":          {Device: &WAFDeviceMatch{}},
		"device unknown kind":   {Device: &WAFDeviceMatch{Kinds: []string{"tv"}}},
		"device unsorted":       {Device: &WAFDeviceMatch{Kinds: []string{WAFDeviceTablet, WAFDeviceMobile}}},
		"time without anything": {Time: &WAFTimeMatch{}},
	} {
		if _, err := normalizeWAFMatch(bad); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestClientConditionSpecs(t *testing.T) {
	if RuleOpBrowserIn != "browser_in" || RuleOpBrowserVersion != "browser_version" || RuleOpDeviceIn != "device_in" || RuleOpTimeWindow != "time_window" {
		t.Fatal("rule plan op names")
	}
	if got := (WAFBrowserMatch{Names: []string{WAFBrowserChrome}}).Spec(); got != `{"names":["google_chrome"]}` {
		t.Fatal(got)
	}
	if got := (WAFBrowserVersion{Name: WAFBrowserChrome, Op: WAFVersionLT, Version: [3]int{100, 0, 0}}).Spec(); got != `{"name":"google_chrome","op":"lt","version":[100,0,0]}` {
		t.Fatal(got)
	}
	if got := (WAFDeviceMatch{Kinds: []string{WAFDeviceBot}, Negate: true}).Spec(); got != `{"kinds":["bot"],"negate":true}` {
		t.Fatal(got)
	}
	if got := (WAFTimeMatch{Ranges: [][2]int64{{1, 2}}}).Spec(); got != `{"ranges":[[1,2]]}` {
		t.Fatal(got)
	}
}
