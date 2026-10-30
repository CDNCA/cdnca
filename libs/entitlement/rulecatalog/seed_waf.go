package rulecatalog

import "strconv"

// BuiltinWAFSeed returns the self-developed WAF system rule sets
// (license-service migration 052), one per common detection class
// (SQL 注入 / XSS / 命令与代码注入 / 危险文件上传 / 文件包含 / 模板注入 / 反序列化,
// split into ten classes).
//
// These are keyword/regex SIGNATURES over URL-decoded, lower-cased request
// arguments (plus the request URI for path classes). They are NOT semantic
// (libinjection-style) detection. Every rule ships with action "log" so that
// enabling a set cannot block traffic until operators review false positives
// and publish a revision with "block". As of this revision no node compiler
// consumes catalog WAF sets yet.
//
// These are the default ("自研检测") rule sets. The node adds its semantic
// SQL injection / XSS detectors to waf_set:sqli and waf_set:xss
// (securitypolicy.ExpandWAFRuleSets). The optional OWASP CRS sets are
// separate items (CRSWAFSeed); a site may run either, both or neither.
func BuiltinWAFSeed() []Item {
	set := func(key, name, description string, sort int, rules ...WAFRule) Item {
		return Item{SystemKey: "waf_set:" + key, Kind: KindWAFRuleSet, LegacyID: "", Name: name, Description: description,
			Sort: sort, Revision: 1, Body: ItemBody{WAFRuleSet: &WAFRuleSetBody{Rules: rules}}}
	}
	rule := func(id, name string, matchers ...WAFMatcher) WAFRule {
		return WAFRule{ID: id, Name: name, Enabled: true, Action: "log", MatcherGroups: []WAFMatcherGroup{{ID: id + ".g1", Matchers: matchers}}}
	}
	args := func(pattern string) WAFMatcher {
		return WAFMatcher{Field: "args", Operator: "regex", Transform: "urldecode", Value: pattern}
	}
	uri := func(pattern string) WAFMatcher {
		return WAFMatcher{Field: "req_uri", Operator: "regex", Transform: "urldecode", Value: pattern}
	}
	path := func(pattern string) WAFMatcher {
		return WAFMatcher{Field: "uri", Operator: "regex", Transform: "urldecode", Value: pattern}
	}
	userAgent := func(pattern string) WAFMatcher {
		return WAFMatcher{Field: "user_agent", Operator: "regex", Transform: "none", Value: pattern}
	}
	body := func(pattern string) WAFMatcher {
		return WAFMatcher{Field: "body", Operator: "regex", Transform: "urldecode", Value: pattern}
	}
	upload := func(pattern string) WAFMatcher {
		return WAFMatcher{Field: "upload_extension", Operator: "regex", Transform: "none", Value: pattern}
	}
	// group: one more matcher group (OR) of a rule.
	group := func(rule WAFRule, matchers ...WAFMatcher) WAFRule {
		rule.MatcherGroups = append(rule.MatcherGroups, WAFMatcherGroup{
			ID: rule.ID + ".g" + strconv.Itoa(len(rule.MatcherGroups)+1), Matchers: matchers})
		return rule
	}
	items := []Item{
		set("sqli", "SQL注入", "内置 WAF 签名：UNION/堆叠查询、时间盲注、布尔恒真等常见 SQL 注入特征（签名匹配，非语义检测）", 1,
			rule("sqli.union", "UNION/SELECT 联合查询", args(`(?i)\bunion\b[\s\S]{0,40}\bselect\b`)),
			rule("sqli.time", "时间盲注函数", args(`(?i)\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(`)),
			rule("sqli.tautology", "布尔恒真与注释截断", args(`(?i)['"]\s*(or|and)\s+['"]?\d+['"]?\s*=\s*['"]?\d+|['"]\s*(--|#|/\*)`))),
		set("xss", "XSS", "内置 WAF 签名：script 标签、事件处理器、javascript: 伪协议（签名匹配，非语义检测）", 2,
			rule("xss.tag", "script/iframe/svg 标签", args(`(?i)<\s*(script|iframe|svg|object|embed)\b`)),
			rule("xss.event", "HTML 事件处理器", args(`(?i)\bon(error|load|click|mouseover|focus)\s*=`)),
			rule("xss.scheme", "javascript: 伪协议", args(`(?i)javascript\s*:`))),
		set("file_upload", "文件上传", "内置 WAF 签名：URI 或参数中出现可执行脚本扩展名（签名匹配；不解析 multipart 文件内容）", 3,
			rule("upload.ext", "可执行脚本扩展名", uri(`(?i)\.(php[0-9]?|phtml|jsp|jspx|asp|aspx|cer|asa)(\?|$)`)),
			rule("upload.arg", "参数中的可执行扩展名", args(`(?i)filename\s*=\s*["']?[^"'\s]+\.(php[0-9]?|phtml|jsp|jspx|asp|aspx)\b`))),
		set("file_include", "文件包含", "内置 WAF 签名：目录穿越、敏感系统文件、php:// 等包装协议（签名匹配，非语义检测）", 4,
			rule("lfi.traversal", "目录穿越", uri(`(\.\./|\.\.\\){2,}`)),
			rule("lfi.sensitive", "敏感系统文件", args(`(?i)(/etc/passwd|/etc/shadow|win\.ini|boot\.ini)`)),
			rule("rfi.wrapper", "包装协议", args(`(?i)\b(php|file|zip|phar|data|expect)://`))),
		set("cmd_injection", "命令注入", "内置 WAF 签名：命令分隔符后接常见系统命令、反引号与 $() 替换（签名匹配，非语义检测）", 5,
			rule("cmd.chain", "分隔符拼接系统命令", args(`(?i)[;&|]\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|powershell)\b`)),
			rule("cmd.subst", "命令替换", args("(\\$\\([^)]{1,64}\\)|`[^`]{1,64}`)"))),
		set("java_code_injection", "Java代码注入", "内置 WAF 签名：Runtime.exec/ProcessBuilder、JNDI 远程查找（签名匹配，非语义检测）", 6,
			rule("java.exec", "Runtime/ProcessBuilder 调用", args(`(?i)(java\.lang\.runtime|getruntime\(\)|processbuilder)`)),
			rule("java.jndi", "JNDI 查找", args(`(?i)\$\{\s*jndi\s*:\s*(ldap|rmi|dns|iiop)`))),
		set("java_deserialization", "Java反序列化", "内置 WAF 签名：Java 序列化流魔数（Base64 rO0AB / 十六进制 aced0005）（签名匹配，不反序列化）", 7,
			rule("java.serial", "Java 序列化魔数", args(`(rO0AB|(?i)aced0005)`))),
		set("php_code_injection", "PHP代码注入", "内置 WAF 签名：eval/assert/system 等危险函数调用（签名匹配，非语义检测）", 8,
			rule("php.func", "危险函数调用", args(`(?i)\b(eval|assert|system|exec|shell_exec|passthru|popen|proc_open|create_function|call_user_func)\s*\(`))),
		set("php_deserialization", "PHP反序列化", "内置 WAF 签名：PHP 序列化对象格式 O:<len>:\"Class\"（签名匹配，不反序列化）", 9,
			rule("php.serial", "PHP 序列化对象", args(`(?i)\b[oc]:\d+:"[a-z_\\][\w\\]*":\d+:\{`))),
		set("ssti", "SSTI模板注入", "内置 WAF 签名：{{7*7}}/${...}/#{...} 表达式与 __class__ 反射链（签名匹配，非语义检测）", 10,
			rule("ssti.expr", "模板表达式求值", args(`(\{\{[\s\S]{0,64}\}\}|\$\{[\s\S]{0,64}\}|#\{[\s\S]{0,64}\})`)),
			rule("ssti.reflect", "Python 反射链", args(`(?i)__(class|mro|subclasses|globals|builtins)__`))),
		// ge-waf S2: web shells, sensitive paths and bots.
		// Unlike a bot list of bare substrings (such as "java" or "php"
		// anywhere in the User-Agent), tool names are matched as whole tokens
		// at the start of a product token, so browsers and apps that merely
		// mention them are not hit.
		set("webshell", "WebShell", "内置 WAF 签名：一句话木马调用（eval/assert/system 接收请求参数）、常见 WebShell 文件名与上传的服务端脚本（签名匹配，非语义检测）", 11,
			group(rule("webshell.oneliner", "一句话木马", args(`(?i)\b(eval|assert|system|passthru|shell_exec|popen|proc_open|preg_replace)\s*\(\s*(@?\$_(post|get|request|cookie|server)|base64_decode|gzinflate|str_rot13)`)),
				body(`(?i)<\?(php|=)?[\s\S]{0,200}\b(eval|assert|system|passthru|shell_exec)\s*\(\s*@?\$_(post|get|request|cookie)`)),
			rule("webshell.files", "常见 WebShell 文件名", path(`(?i)/(c99|r57|wso|b374k|shell|cmd|spy|phpspy|webshell|alfa|indoxploit|adminer)[0-9_-]*\.(php[0-9]?|phtml|asp|aspx|jsp|jspx)$`)),
			rule("webshell.upload", "上传服务端脚本", upload(`^(php[0-9]?|phtml|phar|jsp|jspx|asp|aspx|ashx|asmx|cer|asa|cgi|pl)$`))),
		set("sensitive_paths", "敏感目录", "内置 WAF 签名：版本库与开发目录（.git/.svn/.hg/.env/.DS_Store）、备份与转储文件、服务器状态页（签名匹配）", 12,
			rule("dirs.vcs", "版本库与开发目录", path(`(?i)/\.(git|svn|hg|bzr|cvs|idea|vscode|env|ds_store|htpasswd|htaccess|npmrc|dockerenv)(/|$)`)),
			rule("dirs.backup", "备份与转储文件", path(`(?i)\.(bak|backup|old|orig|swp|swo|sql|sql\.gz|tar|tar\.gz|tgz|zip|rar|7z|dump)$|~$`)),
			rule("dirs.status", "服务器状态与调试页", path(`(?i)^/(server-status|server-info|phpinfo\.php|actuator(/|$)|web-inf/|meta-inf/|wp-config\.php)`))),
		set("bot_tools", "恶意爬虫与扫描器", "内置 WAF 签名：漏洞扫描器与恶意爬虫的 User-Agent（sqlmap/nikto/nmap/masscan/zgrab/dirbuster 等，签名匹配，可被伪造）", 13,
			rule("bot.scanner", "漏洞扫描器", userAgent(`(?i)\b(sqlmap|nikto|nmap|masscan|zgrab|zmeu|dirbuster|gobuster|wpscan|acunetix|netsparker|nessus|openvas|nuclei|xray|awvs|appscan|w3af|whatweb|jaeles|fimap|havij|pangolin)\b`)),
			rule("bot.crawler", "批量采集框架", userAgent(`(?i)^(python-requests|python-urllib|aiohttp|scrapy|go-http-client|java/|okhttp|apache-httpclient|libwww-perl|mechanize|httpclient|node-fetch|axios|guzzlehttp|ruby|php/)`))),
		set("download_tools", "下载工具与空 UA", "内置 WAF 签名：命令行下载工具（curl/wget/aria2 等）与空 User-Agent（签名匹配，可被伪造）", 14,
			rule("download.tools", "命令行下载工具", userAgent(`(?i)^(curl|wget|aria2|axel|httrack|offline explorer|teleport|webzip|webcopier|lwp-download|powershell)\b`)),
			rule("download.empty_ua", "空 User-Agent", WAFMatcher{Field: "user_agent", Operator: "not_regex", Transform: "none", Value: `\S`})),
	}
	sortItems(items)
	return items
}

// CRSWAFSeed returns the OWASP CRS WAF system rule sets (license-service
// migration 064), run by libmodsecurity in the optional node engine
// extension. They sit next to the self-developed sets (BuiltinWAFSeed) under
// their own keys (waf_set:crs_*): each of the ten classes is a CRS rule group
// (docs/security/waf-engine-selection.md has the mapping), with the CRS
// production defaults paranoia 1 / anomaly threshold 5 (one critical match)
// and action block; java deserialization defaults to paranoia 2 because CRS's
// magic-byte rules (944200/944210/944240) are PL2.
//   - waf_set:crs_settings (hidden) holds the request inspection defaults of
//     libmodsecurity's modsecurity.conf-recommended (body limits, 1000
//     arguments, JSON depth 512); its PCRE match limit of 1000 aborts CRS's
//     own regression payloads (942521 performance tests), so the catalog
//     default is 100000.
//   - waf_set:crs_rules (hidden) is the CRS rule text (CRSRulesBundle) with
//     the CRS LICENSE and our NOTICE (revision 2, license migration 082):
//     delivered with the signed catalog, never shipped in node packages.
func CRSWAFSeed() []Item {
	set := func(key, name, description string, sort, paranoia int, files []string, include, exclude []int) Item {
		return Item{SystemKey: "waf_set:crs_" + key, Kind: KindWAFRuleSet, Name: "CRS·" + name, Description: description,
			Sort: 10 + sort, Revision: 1, Body: ItemBody{WAFRuleSet: &WAFRuleSetBody{Engine: &WAFEngineSet{Engine: WAFEngineCRS,
				Files: files, IncludeIDs: include, ExcludeIDs: exclude, Action: "block", Paranoia: paranoia, Threshold: 5}}}}
	}
	none := []int{}
	javaDeserialization := []int{944120, 944200, 944210, 944240}
	upload := []int{920400, 920410, 932180, 933110, 933111, 933220, 944140}
	items := []Item{
		set("sqli", "SQL注入", "OWASP CRS REQUEST-942：libinjection 词法指纹 + 正则，覆盖联合查询、布尔/时间盲注、堆叠查询、注释与编码绕过", 1, 1,
			[]string{"REQUEST-942"}, none, none),
		set("xss", "XSS", "OWASP CRS REQUEST-941：libinjection XSS 检测 + HTML/事件/伪协议/AngularJS 模板注入规则", 2, 1,
			[]string{"REQUEST-941"}, none, none),
		set("file_upload", "文件上传", "OWASP CRS：上传大小限制(920400/920410)、multipart 攻击(922)、受限文件名(932180)、PHP/JSP 脚本与会话文件上传(933110/933111/933220/944140)", 3, 1,
			[]string{"REQUEST-922"}, upload, none),
		set("file_include", "文件包含", "OWASP CRS REQUEST-930 本地文件包含（目录穿越、敏感系统文件）+ REQUEST-931 远程文件包含", 4, 1,
			[]string{"REQUEST-930", "REQUEST-931"}, none, none),
		set("cmd_injection", "命令注入", "OWASP CRS REQUEST-932：Unix/Windows shell、PowerShell 命令注入与逃逸（932180 归文件上传）", 5, 1,
			[]string{"REQUEST-932"}, none, []int{932180}),
		set("java_code_injection", "Java代码注入", "OWASP CRS REQUEST-944：Java 类/方法、进程创建、Log4Shell JNDI 查找（反序列化与上传规则另列）", 6, 1,
			[]string{"REQUEST-944"}, none, append(append([]int(nil), javaDeserialization...), 944140)),
		set("java_deserialization", "Java反序列化", "OWASP CRS 944120/944200/944210/944240：序列化魔数（含 Base64）与危险类", 7, 2,
			[]string{}, javaDeserialization, none),
		set("php_code_injection", "PHP代码注入", "OWASP CRS REQUEST-933：PHP 函数、变量、包装协议、配置指令注入（反序列化与上传规则另列）", 8, 1,
			[]string{"REQUEST-933"}, none, []int{933110, 933111, 933170, 933220}),
		set("php_deserialization", "PHP反序列化", "OWASP CRS 933170：PHP 序列化对象注入", 9, 1,
			[]string{}, []int{933170}, none),
		set("ssti", "SSTI模板注入", "OWASP CRS 934200/934180：服务端模板注入表达式", 10, 1,
			[]string{}, []int{934180, 934200}, none),
		// The rest of
		// REQUEST-934 was in no set; 严格防护 and above only (标准防护 unchanged)
		set("generic", "通用代码注入与SSRF", "OWASP CRS REQUEST-934：Node.js 注入与 DoS、JavaScript 原型污染、Ruby/Perl 注入、PHP data 协议、云元数据/内网地址 SSRF、ORM 查询运算符注入（934180/934200 归 SSTI）", 11, 1,
			[]string{"REQUEST-934"}, none, []int{934180, 934200}),
		{SystemKey: "waf_set:crs_settings", Kind: KindWAFRuleSet, Name: "WAF 引擎参数", Hidden: true, Sort: 100, Revision: 1,
			Description: "请求检查上限：请求体含文件 13107200 字节、不含文件 131072 字节（超限拒绝），最多 1000 个参数，JSON 最深 512 层（libmodsecurity 推荐配置）；单个正则匹配上限 100000 步（超过即拒绝，防正则回溯攻击）",
			Body: ItemBody{WAFRuleSet: &WAFRuleSetBody{Settings: &WAFEngineSettings{Engine: WAFEngineCRS,
				RequestBodyLimit: 13107200, RequestBodyNoFilesLimit: 131072, RequestBodyLimitAction: "reject",
				ArgumentsLimit: 1000, JSONDepthLimit: 512, PCREMatchLimit: 100000}}}},
		{SystemKey: "waf_set:crs_rules", Kind: KindWAFRuleSet, Name: "OWASP CRS 规则文本", Hidden: true, Sort: 101, Revision: 2,
			Description: "OWASP CRS " + CRSRulesBundle().Version + " 请求侧规则文件与数据文件（Apache-2.0，随附 LICENSE 与 NOTICE），随签名目录下发，节点安装包不内置",
			Body: ItemBody{WAFRuleSet: &WAFRuleSetBody{Bundle: CRSRulesBundle()}}},
	}
	sortItems(items)
	return items
}
