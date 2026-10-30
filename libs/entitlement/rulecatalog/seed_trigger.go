package rulecatalog

// TriggeredChallengeSeed returns the "频率超限才挑战" system templates
// (license-service migration 119): competitor two-filter entries, filter1 a
// request rate and filter2 a verification filter. A client is challenged only
// after more than 100 requests within 5 s; failing the page more than the
// verification filter's max_req times blacklists it (action block). The rate
// filter has no per-URI budget: the challenge trigger counts every request of
// the client (securitypolicy.ExpandCCRuleGroup).
func TriggeredChallengeSeed() []Item {
	group := func(key, name string, sort int, verify string) Item {
		return Item{SystemKey: key, Kind: KindCCRuleGroup, Name: name, Description: "内置规则：请求频率超限后才验证", Sort: sort,
			Revision: 1, Body: ItemBody{CCRuleGroup: &CCRuleGroupBody{Entries: []CCRuleGroupEntry{{MatcherKey: "cc_matcher:3",
				Filter1Key: "cc_filter:rate_trigger_5_100", Filter2Key: verify, Action: "block", Mode: "break", Enabled: true}}}}}
	}
	items := []Item{
		{SystemKey: "cc_filter:rate_trigger_5_100", Kind: KindCCFilter, Name: "请求速率5-100", Description: "内置过滤器：超限转验证的触发阈值",
			Sort: 18, Revision: 1, Body: ItemBody{CCFilter: &CCFilterBody{Type: "req_rate", WithinSecond: 5, MaxReq: 100,
				Extra: map[string]string{}, Params: &CCFilterParams{BanSeconds: 360}}}},
		group("cc_rule:rate_then_js", "超限转JS验证", 11, "cc_filter:8"),
		group("cc_rule:rate_then_slider", "超限转滑块验证", 12, "cc_filter:2"),
		group("cc_rule:rate_then_five_second", "超限转5秒盾", 13, "cc_filter:10001"),
	}
	sortItems(items)
	return items
}
