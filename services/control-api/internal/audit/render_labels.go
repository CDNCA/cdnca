package audit

import (
	"regexp"
	"strings"
)

// fieldLabels names change/payload keys for people. Unknown keys show as-is;
// add a label here when a new field appears in a change summary.
var fieldLabels = map[string][2]string{
	"enabled":              {"启用状态", "enabled"},
	"customer_limit":       {"客户数上限", "customer limit"},
	"wholesale_price_list": {"批发价表", "wholesale price list"},
	"low_balance_minor":    {"预付余额提醒线", "low balance alert"},
	"parent_scope_id":      {"所属代理商", "reseller"},
	"status":               {"状态", "status"},
	"state":                {"状态", "state"},
	"name":                 {"名称", "name"},
	"display_name":         {"显示名称", "display name"},
	"domain":               {"域名", "domain"},
	"domains":              {"域名列表", "domains"},
	"apex":                 {"主域名", "apex domain"},
	"method":               {"验证方式", "method"},
	"origin":               {"回源地址", "origin"},
	"origins":              {"回源地址", "origins"},
	"origin_protocol":      {"回源协议", "origin protocol"},
	"origin_host":          {"回源 Host", "origin host"},
	"cc_enabled":           {"CC 防护", "CC protection"},
	"cc_mode":              {"CC 防护模式", "CC mode"},
	"waf_enabled":          {"WAF 防护", "WAF protection"},
	"waf_mode":             {"WAF 模式", "WAF mode"},
	"https_enabled":        {"HTTPS", "HTTPS"},
	"force_https":          {"强制 HTTPS", "force HTTPS"},
	"hsts":                 {"HSTS", "HSTS"},
	"http2":                {"HTTP/2", "HTTP/2"},
	"http3":                {"HTTP/3", "HTTP/3"},
	"cache_rules":          {"缓存规则", "cache rules"},
	"package_id":           {"套餐", "package"},
	"plan":                 {"套餐", "plan"},
	"price":                {"价格", "price"},
	"amount":               {"金额", "amount"},
	"currency":             {"币种", "currency"},
	"balance":              {"余额", "balance"},
	"quota":                {"额度", "quota"},
	"traffic_limit":        {"流量上限", "traffic limit"},
	"bandwidth_limit":      {"带宽上限", "bandwidth limit"},
	"expires_at":           {"到期时间", "expires at"},
	"email":                {"邮箱", "email"},
	"phone":                {"手机号", "phone"},
	"username":             {"用户名", "username"},
	"role":                 {"角色", "role"},
	"roles":                {"角色", "roles"},
	"permissions":          {"权限", "permissions"},
	"login_method":         {"登录方式", "sign-in method"},
	"decision":             {"审核结果", "decision"},
	"retention_days":       {"保留天数", "retention days"},
	"ip":                   {"IP", "IP"},
	"ips":                  {"IP 列表", "IPs"},
	"port":                 {"端口", "port"},
	"ports":                {"端口", "ports"},
	"region":               {"区域", "region"},
	"line_group":           {"线路分组", "line group"},
	"node_group":           {"节点分组", "node group"},
	"weight":               {"权重", "weight"},
	"rule":                 {"规则", "rule"},
	"rules":                {"规则", "rules"},
	"action":               {"动作", "action"},
	"threshold":            {"阈值", "threshold"},
	"window_seconds":       {"统计窗口（秒）", "window (s)"},
	"block_seconds":        {"封禁时长（秒）", "block (s)"},
	"certificate_type":     {"证书类型", "certificate type"},
	"dns_provider_id":      {"DNS 服务商", "DNS provider"},
	"auto_renew":           {"自动续费", "auto renew"},
	"description":          {"描述", "description"},
	"remark":               {"备注", "remark"},
	"capture_headers":      {"记录请求头", "capture headers"},
	"capture_body":         {"记录请求体", "capture body"},
	"admin_state":          {"管理状态", "admin state"},
	"monitoring_enabled":   {"监控", "monitoring"},
}

func fieldLabel(field string, locale Locale) string {
	if pair, ok := fieldLabels[field]; ok {
		if locale == LocaleEN {
			return pair[1]
		}
		return pair[0]
	}
	return field
}

// reasonLabels explain common reason codes. Unknown codes show as-is.
var reasonLabels = map[string][2]string{
	"permission_denied":      {"没有权限", "no permission"},
	"forbidden":              {"没有权限", "forbidden"},
	"invalid_credentials":    {"用户名或密码错误", "wrong username or password"},
	"invalid_password":       {"密码错误", "wrong password"},
	"user_disabled":          {"账号已停用", "account disabled"},
	"account_locked":         {"账号已锁定", "account locked"},
	"mfa_required":           {"需要二次验证", "two-factor required"},
	"mfa_invalid":            {"二次验证码错误", "wrong two-factor code"},
	"captcha_invalid":        {"验证码错误", "wrong captcha"},
	"rate_limited":           {"操作太频繁", "too many requests"},
	"quota_exceeded":         {"超出额度", "quota exceeded"},
	"insufficient_balance":   {"余额不足", "insufficient balance"},
	"entitlement_denied":     {"授权不允许", "license does not allow it"},
	"capability_missing":     {"节点版本不支持", "nodes lack the capability"},
	"conflict":               {"与现有数据冲突", "conflict"},
	"not_found":              {"对象不存在", "not found"},
	"invalid_input":          {"输入不正确", "invalid input"},
	"accepted":               {"已受理", "accepted"},
	"ip_not_allowed":         {"来源 IP 不在白名单", "source IP not allowed"},
	"session_expired":        {"会话已过期", "session expired"},
	"signature_invalid":      {"签名校验失败", "invalid signature"},
	"provider_unavailable":   {"第三方服务不可用", "provider unavailable"},
	"domain_blocked":         {"域名在黑名单中", "domain is blocklisted"},
	"domain_claimed":         {"域名已被他人认领", "domain claimed by another owner"},
	"ownership_not_verified": {"域名所有权未验证", "domain ownership not verified"},
	// Codes the web console reports as api_<status>_<code> (frontendReporter.ts).
	"observability_logs_invalid_request": {"日志查询条件无效，请检查 IP 地址和时间范围", "invalid log filters; check the IP address and time range"},
	"observability_logs_cursor_expired":  {"查询位置已失效，请从第一页重新查询", "page position expired; search from the first page"},
	"observability_logs_unavailable":     {"日志服务暂不可用", "log service unavailable"},
	"authentication_required":            {"登录已失效，请重新登录", "sign-in required"},
}

// apiReasonPattern matches frontend API error reports: api_<HTTP status>_<error code>.
var apiReasonPattern = regexp.MustCompile(`^api_([1-5][0-9]{2})_([a-z0-9_.]+)$`)

func reasonLabel(code string, locale Locale) string {
	code = strings.TrimSpace(code)
	if code == "" {
		return ""
	}
	if pair, ok := reasonLabels[code]; ok {
		if locale == LocaleEN {
			return pair[1]
		}
		return pair[0]
	}
	// Namespaced codes ("api_key.client_ip_not_allowed") match their last part.
	if index := strings.LastIndex(code, "."); index >= 0 {
		if pair, ok := reasonLabels[code[index+1:]]; ok {
			if locale == LocaleEN {
				return pair[1]
			}
			return pair[0]
		}
	}
	// UPLAN-07: never show a bare api_400_* code; name the known error, else a
	// generic sentence with the HTTP status. reason_code keeps the raw code.
	if match := apiReasonPattern.FindStringSubmatch(code); match != nil {
		if label := reasonLabel(match[2], locale); label != match[2] {
			return label
		}
		if locale == LocaleEN {
			return "request failed (HTTP " + match[1] + ")"
		}
		return "请求未能完成（HTTP " + match[1] + "）"
	}
	return code
}
