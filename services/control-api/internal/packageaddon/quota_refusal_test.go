package packageaddon

import (
	"errors"
	"fmt"
	"testing"
)

// 额度拒绝写明是哪项资源（含网站数 sites：订阅当前权益的 site_limit，-1 不限）、上限、变更前已用与本次新增；
// 仍是 ErrQuotaExceeded，现有 errors.Is 判断与错误码映射不变。
func TestSiteQuotaRefusalNamesTheResource(t *testing.T) {
	limits := RuntimeLimits{Sites: 2, Domains: 1, RootDomains: 2, HTTPPorts: 1}
	for name, check := range map[string]struct {
		before, after SiteUsageCounts
		want          *QuotaExceededError
	}{
		"domains":              {SiteUsageCounts{Domains: 1, RootDomains: 1}, SiteUsageCounts{Domains: 2, RootDomains: 1}, &QuotaExceededError{Resource: QuotaResourceDomains, Limit: 1, Used: 1, Requested: 1}},
		"root_domains":         {SiteUsageCounts{Domains: 1, RootDomains: 2}, SiteUsageCounts{Domains: 1, RootDomains: 4}, &QuotaExceededError{Resource: QuotaResourceRootDomains, Limit: 2, Used: 2, Requested: 2}},
		"http_ports":           {SiteUsageCounts{HTTPPorts: 1}, SiteUsageCounts{HTTPPorts: 2}, &QuotaExceededError{Resource: QuotaResourceHTTPPorts, Limit: 1, Used: 1, Requested: 1}},
		"sites":                {SiteUsageCounts{Sites: 2}, SiteUsageCounts{Sites: 3}, &QuotaExceededError{Resource: QuotaResourceSites, Limit: 2, Used: 2, Requested: 1}},
		"edit at limit":        {SiteUsageCounts{Sites: 2, Domains: 1}, SiteUsageCounts{Sites: 2, Domains: 1}, nil},
		"over quota unchanged": {SiteUsageCounts{Sites: 4}, SiteUsageCounts{Sites: 4}, nil},
		"within":               {SiteUsageCounts{Domains: 0}, SiteUsageCounts{Domains: 1}, nil},
		"shrinking":            {SiteUsageCounts{Domains: 3}, SiteUsageCounts{Domains: 2}, nil},
	} {
		err := siteQuotaRefusal(check.before, check.after, limits)
		if check.want == nil {
			if err != nil {
				t.Fatalf("%s: admitted change refused: %v", name, err)
			}
			continue
		}
		var refusal *QuotaExceededError
		if !errors.As(err, &refusal) || *refusal != *check.want {
			t.Fatalf("%s: refusal=%+v err=%v", name, refusal, err)
		}
		if !errors.Is(fmt.Errorf("wrap: %w", err), ErrQuotaExceeded) {
			t.Fatalf("%s: refusal is not ErrQuotaExceeded", name)
		}
	}
	if err := siteQuotaRefusal(SiteUsageCounts{Sites: 50}, SiteUsageCounts{Sites: 51, Domains: 99}, RuntimeLimits{Sites: -1, Domains: -1, RootDomains: -1, HTTPPorts: -1}); err != nil {
		t.Fatalf("unlimited refused: %v", err)
	}
}
