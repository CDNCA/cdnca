package rulecatalog

// Code generated from the competitor capture;
// names, types, parameters and legacy ids are kept verbatim. DO NOT EDIT by hand:
// the license-service seed migration is checked against this list.

// CompetitorSeed returns the competitor's 11 CC rule groups, 3 matchers and
// 17 filters as revision-1 catalog items sorted by system_key.
func CompetitorSeed() []Item {
	items := []Item{
		{SystemKey: "cc_matcher:5", Kind: KindCCMatcher, LegacyID: "5", Name: "匹配内置资源", Description: "内置匹配器", Sort: 1, Revision: 1,
			Body: ItemBody{CCMatcher: &CCMatcherBody{Conditions: []CCMatcherCondition{{Field: "uri", Operator: "contain", Key: "", Values: []string{"/_guard/click.js", "/_guard/slide.js", "/_guard/captcha.png", "/_guard/verify-captcha", "/_guard/encrypt.js", "favicon.ico"}}}}}},
		{SystemKey: "cc_matcher:4", Kind: KindCCMatcher, LegacyID: "4", Name: "匹配静态资源", Description: "内置匹配器", Sort: 2, Revision: 1,
			Body: ItemBody{CCMatcher: &CCMatcherBody{Conditions: []CCMatcherCondition{{Field: "req_uri", Operator: "contain", Key: "", Values: []string{".js", ".css", ".png", ".jpg", ".jpeg", ".gif"}}}}}},
		{SystemKey: "cc_matcher:3", Kind: KindCCMatcher, LegacyID: "3", Name: "匹配所有资源", Description: "内置匹配器", Sort: 3, Revision: 1,
			Body: ItemBody{CCMatcher: &CCMatcherBody{Conditions: []CCMatcherCondition{}}}},
		{SystemKey: "cc_filter:10004", Kind: KindCCFilter, LegacyID: "10004", Name: "滑动过滤(简单)60-5", Description: "内置过滤器", Sort: 1, Revision: 1,
			Body: ItemBody{CCFilter: &CCFilterBody{Type: "easy_slide_filter", WithinSecond: 60, MaxReq: 5, MaxReqPerURI: 0, Extra: map[string]string{}}}},
		{SystemKey: "cc_filter:10003", Kind: KindCCFilter, LegacyID: "10003", Name: "点击过滤(简单)60-5", Description: "内置过滤器", Sort: 2, Revision: 1,
			Body: ItemBody{CCFilter: &CCFilterBody{Type: "easy_click_filter", WithinSecond: 60, MaxReq: 5, MaxReqPerURI: 0, Extra: map[string]string{}}}},
		{SystemKey: "cc_filter:10002", Kind: KindCCFilter, LegacyID: "10002", Name: "旋转图片60-5", Description: "内置过滤器", Sort: 3, Revision: 1,
			Body: ItemBody{CCFilter: &CCFilterBody{Type: "rotate_filter", WithinSecond: 60, MaxReq: 5, MaxReqPerURI: 0, Extra: map[string]string{}}}},
		{SystemKey: "cc_filter:10001", Kind: KindCCFilter, LegacyID: "10001", Name: "5秒盾60-5", Description: "内置过滤器", Sort: 4, Revision: 1,
			Body: ItemBody{CCFilter: &CCFilterBody{Type: "delay_jump_filter", WithinSecond: 60, MaxReq: 5, MaxReqPerURI: 0, Extra: map[string]string{}}}},
		{SystemKey: "cc_filter:10000", Kind: KindCCFilter, LegacyID: "10000", Name: "点击过滤60-5", Description: "内置过滤器", Sort: 5, Revision: 1,
			Body: ItemBody{CCFilter: &CCFilterBody{Type: "click_filter", WithinSecond: 60, MaxReq: 5, MaxReqPerURI: 0, Extra: map[string]string{}}}},
		{SystemKey: "cc_filter:12", Kind: KindCCFilter, LegacyID: "12", Name: "临时白名单专用2", Description: "内置过滤器", Sort: 6, Revision: 1,
			Body: ItemBody{CCFilter: &CCFilterBody{Type: "req_rate", WithinSecond: 5, MaxReq: 200, MaxReqPerURI: 50, Extra: map[string]string{}}}},
		{SystemKey: "cc_filter:11", Kind: KindCCFilter, LegacyID: "11", Name: "临时白名单专用1", Description: "内置过滤器", Sort: 7, Revision: 1,
			Body: ItemBody{CCFilter: &CCFilterBody{Type: "req_rate", WithinSecond: 5, MaxReq: 300, MaxReqPerURI: 50, Extra: map[string]string{}}}},
		{SystemKey: "cc_filter:10", Kind: KindCCFilter, LegacyID: "10", Name: "请求速率5-200-50", Description: "内置过滤器", Sort: 8, Revision: 1,
			Body: ItemBody{CCFilter: &CCFilterBody{Type: "req_rate", WithinSecond: 5, MaxReq: 200, MaxReqPerURI: 50, Extra: map[string]string{}}}},
		{SystemKey: "cc_filter:9", Kind: KindCCFilter, LegacyID: "9", Name: "请求速率5-300-50", Description: "内置过滤器", Sort: 9, Revision: 1,
			Body: ItemBody{CCFilter: &CCFilterBody{Type: "req_rate", WithinSecond: 5, MaxReq: 300, MaxReqPerURI: 50, Extra: map[string]string{}}}},
		{SystemKey: "cc_filter:8", Kind: KindCCFilter, LegacyID: "8", Name: "浏览器识别60-5", Description: "内置过滤器", Sort: 10, Revision: 1,
			Body: ItemBody{CCFilter: &CCFilterBody{Type: "browser_verify_auto", WithinSecond: 60, MaxReq: 5, MaxReqPerURI: 0, Extra: map[string]string{}}}},
		{SystemKey: "cc_filter:7", Kind: KindCCFilter, LegacyID: "7", Name: "请求速率5-100-10", Description: "内置过滤器", Sort: 11, Revision: 1,
			Body: ItemBody{CCFilter: &CCFilterBody{Type: "req_rate", WithinSecond: 5, MaxReq: 100, MaxReqPerURI: 10, Extra: map[string]string{}}}},
		{SystemKey: "cc_filter:6", Kind: KindCCFilter, LegacyID: "6", Name: "请求速率5-30-20", Description: "内置过滤器", Sort: 12, Revision: 1,
			Body: ItemBody{CCFilter: &CCFilterBody{Type: "req_rate", WithinSecond: 5, MaxReq: 30, MaxReqPerURI: 20, Extra: map[string]string{}}}},
		{SystemKey: "cc_filter:5", Kind: KindCCFilter, LegacyID: "5", Name: "请求速率5-20-10", Description: "内置过滤器", Sort: 13, Revision: 1,
			Body: ItemBody{CCFilter: &CCFilterBody{Type: "req_rate", WithinSecond: 5, MaxReq: 20, MaxReqPerURI: 10, Extra: map[string]string{}}}},
		{SystemKey: "cc_filter:4", Kind: KindCCFilter, LegacyID: "4", Name: "内置请求保护60-20-15", Description: "内置过滤器", Sort: 14, Revision: 1,
			Body: ItemBody{CCFilter: &CCFilterBody{Type: "req_rate", WithinSecond: 60, MaxReq: 20, MaxReqPerURI: 15, Extra: map[string]string{}}}},
		{SystemKey: "cc_filter:3", Kind: KindCCFilter, LegacyID: "3", Name: "验证码60-5", Description: "内置过滤器", Sort: 15, Revision: 1,
			Body: ItemBody{CCFilter: &CCFilterBody{Type: "captcha_filter", WithinSecond: 60, MaxReq: 5, MaxReqPerURI: 0, Extra: map[string]string{}}}},
		{SystemKey: "cc_filter:2", Kind: KindCCFilter, LegacyID: "2", Name: "滑动过滤60-5", Description: "内置过滤器", Sort: 16, Revision: 1,
			Body: ItemBody{CCFilter: &CCFilterBody{Type: "slide_filter", WithinSecond: 60, MaxReq: 5, MaxReqPerURI: 0, Extra: map[string]string{}}}},
		{SystemKey: "cc_filter:1", Kind: KindCCFilter, LegacyID: "1", Name: "302跳转60-5", Description: "内置过滤器", Sort: 17, Revision: 1,
			Body: ItemBody{CCFilter: &CCFilterBody{Type: "302_challenge", WithinSecond: 60, MaxReq: 5, MaxReqPerURI: 0, Extra: map[string]string{}}}},
		{SystemKey: "cc_rule:10002", Kind: KindCCRuleGroup, LegacyID: "10002", Name: "关闭", Description: "内置规则", Sort: 1, Hidden: false, Revision: 1,
			Body: ItemBody{CCRuleGroup: &CCRuleGroupBody{Entries: []CCRuleGroupEntry{}}}},
		{SystemKey: "cc_rule:6", Kind: KindCCRuleGroup, LegacyID: "6", Name: "宽松", Description: "内置规则", Sort: 2, Hidden: false, Revision: 1,
			Body: ItemBody{CCRuleGroup: &CCRuleGroupBody{Entries: []CCRuleGroupEntry{{MatcherKey: "cc_matcher:3", Filter1Key: "cc_filter:9", Filter2Key: "", Action: "block", Mode: "break", Enabled: true}}}}},
		{SystemKey: "cc_rule:1", Kind: KindCCRuleGroup, LegacyID: "1", Name: "JS验证", Description: "内置规则", Sort: 3, Hidden: false, Revision: 1,
			Body: ItemBody{CCRuleGroup: &CCRuleGroupBody{Entries: []CCRuleGroupEntry{{MatcherKey: "cc_matcher:3", Filter1Key: "cc_filter:8", Filter2Key: "", Action: "block", Mode: "break", Enabled: true}}}}},
		{SystemKey: "cc_rule:10001", Kind: KindCCRuleGroup, LegacyID: "10001", Name: "5秒盾", Description: "内置规则", Sort: 4, Hidden: false, Revision: 1,
			Body: ItemBody{CCRuleGroup: &CCRuleGroupBody{Entries: []CCRuleGroupEntry{{MatcherKey: "cc_matcher:3", Filter1Key: "cc_filter:10001", Filter2Key: "", Action: "block", Mode: "break", Enabled: true}}}}},
		{SystemKey: "cc_rule:10000", Kind: KindCCRuleGroup, LegacyID: "10000", Name: "点击验证", Description: "内置规则", Sort: 5, Hidden: false, Revision: 1,
			Body: ItemBody{CCRuleGroup: &CCRuleGroupBody{Entries: []CCRuleGroupEntry{{MatcherKey: "cc_matcher:3", Filter1Key: "cc_filter:10000", Filter2Key: "", Action: "block", Mode: "break", Enabled: true}}}}},
		{SystemKey: "cc_rule:2", Kind: KindCCRuleGroup, LegacyID: "2", Name: "滑块验证", Description: "内置规则", Sort: 6, Hidden: false, Revision: 1,
			Body: ItemBody{CCRuleGroup: &CCRuleGroupBody{Entries: []CCRuleGroupEntry{{MatcherKey: "cc_matcher:3", Filter1Key: "cc_filter:2", Filter2Key: "", Action: "block", Mode: "break", Enabled: true}}}}},
		{SystemKey: "cc_rule:4", Kind: KindCCRuleGroup, LegacyID: "4", Name: "验证码", Description: "内置规则", Sort: 7, Hidden: false, Revision: 1,
			Body: ItemBody{CCRuleGroup: &CCRuleGroupBody{Entries: []CCRuleGroupEntry{{MatcherKey: "cc_matcher:3", Filter1Key: "cc_filter:3", Filter2Key: "", Action: "block", Mode: "break", Enabled: true}}}}},
		{SystemKey: "cc_rule:10003", Kind: KindCCRuleGroup, LegacyID: "10003", Name: "旋转图片", Description: "内置规则", Sort: 8, Hidden: false, Revision: 1,
			Body: ItemBody{CCRuleGroup: &CCRuleGroupBody{Entries: []CCRuleGroupEntry{{MatcherKey: "cc_matcher:3", Filter1Key: "cc_filter:10002", Filter2Key: "", Action: "block", Mode: "break", Enabled: true}}}}},
		{SystemKey: "cc_rule:10004", Kind: KindCCRuleGroup, LegacyID: "10004", Name: "点击验证(简单)", Description: "内置规则", Sort: 9, Hidden: false, Revision: 1,
			Body: ItemBody{CCRuleGroup: &CCRuleGroupBody{Entries: []CCRuleGroupEntry{{MatcherKey: "cc_matcher:3", Filter1Key: "cc_filter:10003", Filter2Key: "", Action: "block", Mode: "break", Enabled: true}}}}},
		{SystemKey: "cc_rule:10005", Kind: KindCCRuleGroup, LegacyID: "10005", Name: "滑块验证(简单)", Description: "内置规则", Sort: 10, Hidden: false, Revision: 1,
			Body: ItemBody{CCRuleGroup: &CCRuleGroupBody{Entries: []CCRuleGroupEntry{{MatcherKey: "cc_matcher:3", Filter1Key: "cc_filter:10004", Filter2Key: "", Action: "block", Mode: "break", Enabled: true}}}}},
		{SystemKey: "cc_rule:3", Kind: KindCCRuleGroup, LegacyID: "3", Name: "临时白名单", Description: "内置规则", Sort: 100, Hidden: true, Revision: 1,
			Body: ItemBody{CCRuleGroup: &CCRuleGroupBody{Entries: []CCRuleGroupEntry{{MatcherKey: "cc_matcher:3", Filter1Key: "cc_filter:11", Filter2Key: "", Action: "block", Mode: "break", Enabled: true}}}}},
	}
	sortItems(items)
	return items
}

// CompetitorFilterParams returns revision 2 of the competitor's 17 filters
// (license-service migration 065): revision 1 plus the enforcement parameters
// the node needs, so no value is assumed by the compiler. Times follow the
// competitor documentation (CCcanshupeizhi: blacklist 360 s, whitelist
// 21600 s); verification pages live 120 s; the pass cookie is bound to the
// client /24 (IPv4) or /64 (IPv6) and signed with a key rotated daily.
// Proof-of-work difficulty: 5秒盾 18 bits (plus the 5 s wait), 浏览器识别
// 16 bits, interactive pages 12 bits (the person also solves the widget).
func CompetitorFilterParams() []Item {
	verify := func(bits, delay int) *CCFilterParams {
		return &CCFilterParams{BanSeconds: 360, PassSeconds: 21600, PowBits: bits, DelaySeconds: delay,
			ChallengeSeconds: 120, BindIPv4Prefix: 24, BindIPv6Prefix: 64, KeyRotateSeconds: 86400}
	}
	params := map[string]*CCFilterParams{
		"browser_verify_auto": verify(16, 0), "delay_jump_filter": verify(18, 5), "click_filter": verify(12, 0),
		"easy_click_filter": verify(12, 0), "slide_filter": verify(12, 0), "easy_slide_filter": verify(12, 0),
		"captcha_filter": verify(12, 0), "rotate_filter": verify(12, 0), "302_challenge": verify(0, 0),
		"req_rate": {BanSeconds: 360},
	}
	items := make([]Item, 0, 17)
	for _, item := range CompetitorSeed() {
		if item.Kind != KindCCFilter {
			continue
		}
		body := *item.Body.CCFilter
		body.Params = params[body.Type]
		item.Body = ItemBody{CCFilter: &body}
		item.Revision = 2
		items = append(items, item)
	}
	return items
}

// CurrentSeed is the catalog the license-service migrations deliver today:
// competitor rule groups and matchers (revision 1), filters with parameters
// (revision 2), the "频率超限才挑战" templates, the self-developed WAF sets and
// the OWASP CRS WAF sets.
func CurrentSeed() []Item {
	filters := map[string]Item{}
	for _, item := range CompetitorFilterParams() {
		filters[item.SystemKey] = item
	}
	items := make([]Item, 0, 64)
	for _, item := range CompetitorSeed() {
		if filter, ok := filters[item.SystemKey]; ok {
			item = filter
		}
		items = append(items, item)
	}
	items = append(items, TriggeredChallengeSeed()...)
	items = append(items, BuiltinWAFSeed()...)
	items = append(items, CRSWAFSeed()...)
	sortItems(items)
	return items
}
