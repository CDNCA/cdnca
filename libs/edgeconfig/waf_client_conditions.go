package edgeconfig

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Client conditions (C6; CAPABILITY_NAME_WAF v6,
// WAFClientConditionsAPIVersion): the browser, browser version and device
// type a request's User-Agent claims, and the request time (waf_time_window.go).
// The node parses the User-Agent with cdnca_ua.lua; ParseUserAgent is the
// reference both are tested against (testdata/user_agents.json), and the
// control plane's parse-user-agent endpoint uses it. A User-Agent is client
// supplied: these conditions route and filter, they never authenticate.

// Browser names, in detection order (a browser whose UA also carries Chrome/
// is detected before Chrome, Chrome before Safari). Changing the list or the
// tokens changes node behaviour and needs a new WAF version.
const (
	WAFBrowserWeChat  = "wechat_browser"
	WAFBrowserQQ      = "qq_browser"
	WAFBrowserUC      = "uc_browser"
	WAFBrowserBaidu   = "baidu_browser"
	WAFBrowserSogou   = "sogou_browser"
	WAFBrowser360     = "360_browser" // mostly indistinguishable from Chrome; never has a version
	WAFBrowserEdge    = "microsoft_edge"
	WAFBrowserOpera   = "opera"
	WAFBrowserSamsung = "samsung_browser"
	WAFBrowserFirefox = "firefox"
	WAFBrowserChrome  = "google_chrome"
	WAFBrowserSafari  = "safari"
	WAFBrowserUnknown = "unknown" // none of the above
)

// Device kinds (sorted).
const (
	WAFDeviceBot     = "bot" // claims to be a crawler or script client, or no User-Agent
	WAFDeviceDesktop = "desktop"
	WAFDeviceMobile  = "mobile"
	WAFDeviceTablet  = "tablet"
)

// Browser version operators (WAFBrowserVersion.Op; the policy operators
// version_eq / version_gte / version_lt).
const (
	WAFVersionEQ  = "eq"
	WAFVersionGTE = "gte"
	WAFVersionLT  = "lt"
)

// Rule plan operations of the client conditions; the value is the
// condition's Spec (its canonical JSON). They sit after ja4_not_in and
// before ip_intel in a rule's condition order.
const (
	RuleOpBrowserIn      = "browser_in"
	RuleOpBrowserVersion = "browser_version"
	RuleOpDeviceIn       = "device_in"
	RuleOpTimeWindow     = "time_window"
)

// MaxParsedUserAgentBytes: only this prefix of the User-Agent is parsed.
const MaxParsedUserAgentBytes = 512

// MaxBrowserVersionPart bounds each of major, minor and patch (5 digits).
const MaxBrowserVersionPart = 99999

type uaBrowserRule struct {
	name    string
	tokens  []string // any one present (plain, case-sensitive find)
	require string   // also required when set
	version []string // the first present one is followed by the version
}

var uaBrowserRules = []uaBrowserRule{
	{name: WAFBrowserWeChat, tokens: []string{"MicroMessenger/"}, version: []string{"MicroMessenger/"}},
	{name: WAFBrowserQQ, tokens: []string{"MQQBrowser/", "QQBrowser/"}, version: []string{"MQQBrowser/", "QQBrowser/"}},
	{name: WAFBrowserUC, tokens: []string{"UCBrowser/", "UCWEB"}, version: []string{"UCBrowser/"}},
	{name: WAFBrowserBaidu, tokens: []string{"baiduboxapp/", "BIDUBrowser", "baidubrowser/"}, version: []string{"baiduboxapp/", "BIDUBrowser/", "baidubrowser/"}},
	{name: WAFBrowserSogou, tokens: []string{"SogouMobileBrowser/", "SE 2.X MetaSr"}, version: []string{"SogouMobileBrowser/"}},
	{name: WAFBrowser360, tokens: []string{"QihooBrowser", "360SE", "360EE"}},
	{name: WAFBrowserEdge, tokens: []string{"Edg/", "EdgA/", "EdgiOS/", "Edge/"}, version: []string{"Edg/", "EdgA/", "EdgiOS/", "Edge/"}},
	{name: WAFBrowserOpera, tokens: []string{"OPR/", "OPiOS/", "Opera/"}, version: []string{"OPR/", "OPiOS/", "Opera/"}},
	{name: WAFBrowserSamsung, tokens: []string{"SamsungBrowser/"}, version: []string{"SamsungBrowser/"}},
	{name: WAFBrowserFirefox, tokens: []string{"Firefox/", "FxiOS/"}, version: []string{"Firefox/", "FxiOS/"}},
	{name: WAFBrowserChrome, tokens: []string{"Chrome/", "CriOS/"}, version: []string{"Chrome/", "CriOS/"}},
	{name: WAFBrowserSafari, tokens: []string{"Safari/"}, require: "Version/", version: []string{"Version/"}},
}

// WAFBrowserNames are the browser names in detection order, unknown last.
var WAFBrowserNames = func() []string {
	names := make([]string, 0, len(uaBrowserRules)+1)
	for _, rule := range uaBrowserRules {
		names = append(names, rule.name)
	}
	return append(names, WAFBrowserUnknown)
}()

// WAFDeviceKinds are the device kinds (sorted).
var WAFDeviceKinds = []string{WAFDeviceBot, WAFDeviceDesktop, WAFDeviceMobile, WAFDeviceTablet}

// uaBotTokens are found in the ASCII lower-cased User-Agent.
var uaBotTokens = []string{"bot", "spider", "crawl", "slurp", "curl/", "wget/", "python-requests", "python-urllib",
	"go-http-client", "okhttp", "headless"}

// UserAgentInfo is what the browser and device conditions see. Version is
// [major, minor, patch] (missing parts 0) when HasVersion.
type UserAgentInfo struct {
	Browser    string
	Version    [3]int
	HasVersion bool
	Device     string
}

// VersionString is "major.minor.patch", "" without a version.
func (info UserAgentInfo) VersionString() string {
	if !info.HasVersion {
		return ""
	}
	return strconv.Itoa(info.Version[0]) + "." + strconv.Itoa(info.Version[1]) + "." + strconv.Itoa(info.Version[2])
}

// ParseUserAgent detects the browser, its version and the device kind from
// the first MaxParsedUserAgentBytes of ua:
//
//   - browser: the first rule of the fixed order with one of its tokens
//     present (Safari also needs Version/); none: unknown.
//   - version: after the first present version token, 1-5 digits (major),
//     then up to two ".<1-5 digits>" (minor, patch; missing parts 0). No
//     digits, or a major of more than 5 digits: no version; a longer minor
//     or patch ends the version there.
//   - device: bot (ASCII lower-cased UA has a bot token, or UA empty),
//     tablet (iPad; Android without Mobile; Tablet), mobile (Mobile, iPhone,
//     Android, HarmonyOS, Windows Phone), else desktop.
func ParseUserAgent(ua string) UserAgentInfo {
	if len(ua) > MaxParsedUserAgentBytes {
		ua = ua[:MaxParsedUserAgentBytes]
	}
	info := UserAgentInfo{Browser: WAFBrowserUnknown, Device: userAgentDevice(ua)}
	for _, rule := range uaBrowserRules {
		if !containsAny(ua, rule.tokens) || rule.require != "" && !strings.Contains(ua, rule.require) {
			continue
		}
		info.Browser = rule.name
		for _, token := range rule.version {
			if index := strings.Index(ua, token); index >= 0 {
				info.Version, info.HasVersion = parseUserAgentVersion(ua[index+len(token):])
				break
			}
		}
		break
	}
	return info
}

func containsAny(value string, tokens []string) bool {
	return slices.ContainsFunc(tokens, func(token string) bool { return strings.Contains(value, token) })
}

func userAgentDevice(ua string) string {
	lower := asciiLower(ua)
	switch {
	case ua == "" || containsAny(lower, uaBotTokens):
		return WAFDeviceBot
	case strings.Contains(ua, "iPad") || strings.Contains(ua, "Android") && !strings.Contains(ua, "Mobile") ||
		strings.Contains(ua, "Tablet"):
		return WAFDeviceTablet
	case containsAny(ua, []string{"Mobile", "iPhone", "Android", "HarmonyOS", "Windows Phone"}):
		return WAFDeviceMobile
	default:
		return WAFDeviceDesktop
	}
}

// parseUserAgentVersion reads the version at the start of rest.
func parseUserAgentVersion(rest string) ([3]int, bool) {
	var version [3]int
	for part := 0; part < 3; part++ {
		if part > 0 {
			if !strings.HasPrefix(rest, ".") {
				break
			}
			rest = rest[1:]
		}
		digits := 0
		for digits < len(rest) && rest[digits] >= '0' && rest[digits] <= '9' {
			digits++
		}
		if digits == 0 || digits > 5 {
			if part == 0 {
				return [3]int{}, false
			}
			break
		}
		version[part], _ = strconv.Atoi(rest[:digits])
		rest = rest[digits:]
	}
	return version, true
}

var browserVersionPattern = regexp.MustCompile(`^[0-9]{1,5}(\.[0-9]{1,5}){0,2}$`)

// ParseBrowserVersion parses a condition's version value ("100",
// "119.0.6045"; missing parts 0).
func ParseBrowserVersion(value string) ([3]int, error) {
	if !browserVersionPattern.MatchString(value) {
		return [3]int{}, ErrInvalidConfig
	}
	var version [3]int
	for index, part := range strings.Split(value, ".") {
		version[index], _ = strconv.Atoi(part)
	}
	return version, nil
}

// WAFBrowserMatch: the detected browser is (Negate: is not) one of Names
// (sorted, unique; unknown may be listed).
type WAFBrowserMatch struct {
	Names  []string `json:"names"`
	Negate bool     `json:"negate,omitempty"`
}

// WAFBrowserVersion: the detected browser is Name and its version compares
// to Version by Op. Another browser, or no version, does not match.
type WAFBrowserVersion struct {
	Name    string `json:"name"`
	Op      string `json:"op"`
	Version [3]int `json:"version"`
}

// WAFDeviceMatch: the device kind is (Negate: is not) one of Kinds (sorted,
// unique).
type WAFDeviceMatch struct {
	Kinds  []string `json:"kinds"`
	Negate bool     `json:"negate,omitempty"`
}

// Spec is the rule plan value (RuleOpBrowserIn).
func (match WAFBrowserMatch) Spec() string { return conditionSpec(match) }

// Spec is the rule plan value (RuleOpBrowserVersion).
func (match WAFBrowserVersion) Spec() string { return conditionSpec(match) }

// Spec is the rule plan value (RuleOpDeviceIn).
func (match WAFDeviceMatch) Spec() string { return conditionSpec(match) }

// Matches is the condition's reference semantics.
func (match WAFBrowserMatch) Matches(info UserAgentInfo) bool {
	return slices.Contains(match.Names, info.Browser) != match.Negate
}

// Matches is the condition's reference semantics.
func (match WAFDeviceMatch) Matches(info UserAgentInfo) bool {
	return slices.Contains(match.Kinds, info.Device) != match.Negate
}

// Matches is the condition's reference semantics.
func (match WAFBrowserVersion) Matches(info UserAgentInfo) bool {
	if info.Browser != match.Name || !info.HasVersion {
		return false
	}
	compare := slices.Compare(info.Version[:], match.Version[:])
	switch match.Op {
	case WAFVersionEQ:
		return compare == 0
	case WAFVersionGTE:
		return compare >= 0
	case WAFVersionLT:
		return compare < 0
	}
	return false
}

// WAFBrowserHasVersion reports whether a browser_version condition may name
// browser: every detected browser except 360 and unknown can carry one.
func WAFBrowserHasVersion(name string) bool {
	return name != WAFBrowser360 && name != WAFBrowserUnknown && slices.Contains(WAFBrowserNames, name)
}

func sortedUniqueIn(values, allowed []string) bool {
	if len(values) == 0 || len(values) > len(allowed) {
		return false
	}
	for index, value := range values {
		if !slices.Contains(allowed, value) || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}

func normalizeWAFBrowserMatch(value *WAFBrowserMatch) (*WAFBrowserMatch, error) {
	if value == nil {
		return nil, nil
	}
	if !sortedUniqueIn(value.Names, WAFBrowserNames) {
		return nil, ErrInvalidConfig
	}
	return &WAFBrowserMatch{Names: slices.Clone(value.Names), Negate: value.Negate}, nil
}

func normalizeWAFBrowserVersion(value *WAFBrowserVersion) (*WAFBrowserVersion, error) {
	if value == nil {
		return nil, nil
	}
	if !WAFBrowserHasVersion(value.Name) || value.Op != WAFVersionEQ && value.Op != WAFVersionGTE && value.Op != WAFVersionLT {
		return nil, ErrInvalidConfig
	}
	for _, part := range value.Version {
		if part < 0 || part > MaxBrowserVersionPart {
			return nil, ErrInvalidConfig
		}
	}
	copied := *value
	return &copied, nil
}

func normalizeWAFDeviceMatch(value *WAFDeviceMatch) (*WAFDeviceMatch, error) {
	if value == nil {
		return nil, nil
	}
	if !sortedUniqueIn(value.Kinds, WAFDeviceKinds) {
		return nil, ErrInvalidConfig
	}
	return &WAFDeviceMatch{Kinds: slices.Clone(value.Kinds), Negate: value.Negate}, nil
}
