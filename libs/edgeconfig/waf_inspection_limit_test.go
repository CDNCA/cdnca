package edgeconfig

import ()

// FX12: 检查上限类判定（请求头超过 100 个、CRS TX:MSC_* 检查上限）默认只记录不拦截；
// 站点托管 WAF 把 inspection_limit_action 设为 block 时才回 403。

const (
	headerOverflowBlockPrelude = "        local raw_headers, header_error = ngx.req.get_headers(100, true)\n" +
		"        if header_error == \"truncated\" then\n          return ngx.exit(403)\n        end\n"
	headerOverflowLogPrelude = "        local raw_headers, header_error = ngx.req.get_headers(100, true)\n" +
		"        if header_error == \"truncated\" then\n" +
		"          ngx.log(ngx.WARN, \"cdnca waf: more than 100 request headers, header conditions do not match\")\n" +
		"          raw_headers = {}\n        end\n"
)

func headerRuleSite(action string) Site {
	site := managedWAFTestSite()
	site.WAF = WAFPolicy{Rules: []WAFRule{{Match: WAFMatch{Header: &WAFHeaderMatch{Name: "X-Probe", Kind: WAFHeaderExists}},
		Action: WAFDeny, Control: WAFStop}}}
	if action == "none" {
		site.ManagedWAF = nil
	} else {
		site.ManagedWAF.InspectionLimitAction = action
	}
	return site
}
