import i18n from './index'

const zhCN = {
  challenge: {
    log_only: '只记录不拉黑',
    failure_window_seconds: '统计周期(秒)', failure_window_secondsHelp: '在该时间内统计未通过验证的次数',
    max_failures: '验证失败次数', max_failuresHelp: '统计周期内超过该次数未通过验证即拉黑',
    ban_seconds: '拉黑时长(秒)', ban_secondsHelp: '拉黑客户端 IP 的时长（返回 403）',
    pass_seconds: '白名单有效期(秒)', pass_secondsHelp: '验证通过后通行 Cookie 的有效期',
    pow_bits: 'PoW 难度(位)', pow_bitsHelp: '浏览器需算出前导零位数达到该值的 SHA-256；每加 1 位计算量翻倍',
    delay_seconds: '等待秒数', delay_secondsHelp: '5秒盾最少等待时间',
    challenge_seconds: '验证页有效期(秒)', challenge_secondsHelp: '一次验证页面（一次性 token）的有效期',
    bind_ipv4_prefix: '绑定 IPv4 前缀', bind_ipv4_prefixHelp: '通行 Cookie 只在同一网段有效；32 表示单个 IP',
    bind_ipv6_prefix: '绑定 IPv6 前缀', bind_ipv6_prefixHelp: '通行 Cookie 只在同一网段有效；128 表示单个 IP',
    key_rotate_seconds: '密钥轮换周期(秒)', key_rotate_secondsHelp: '不能小于白名单有效期；只接受当前与上一周期的密钥',
    trigger_window_seconds: '时间窗口(秒)', trigger_max_requests: '超过次数',
    triggerHelp: '同一客户端在时间窗口内请求超过该次数才弹验证；两项都留空表示每个未通过验证的请求都验证',
    triggerPair: '时间窗口和超过次数要同时填写，或同时留空', triggerEmpty: '留空：每次',
  },
  waf: {
    request_body_limit: '请求体上限(含文件)', request_body_no_files_limit: '请求体上限(不含文件)',
    request_body_limit_action: '超过上限', bodyActions: { reject: '拒绝(413)', partial: '只检查前面部分' },
    inspection_limit_action: '触发检查上限', limitActions: { log: '仅记录', block: '拦截(403)' },
    inspection_limit_actionHelp: '正则匹配超过上限、请求头超过 100 个等无法完整检查的请求：仅记录时放行（请求头条件按不命中处理），拦截时返回 403',
    arguments_limit: '最多参数个数', json_depth_limit: 'JSON 最大层数', pcre_match_limit: '正则匹配上限',
    profile: 'CRS 档位', profileHelp: '档位决定启用哪些 CRS 规则集、防护等级（Paranoia）、异常分阈值与拦截/仅记录；换档位需要节点重新加载',
    noProfiles: '主控尚未从授权端同步到 CRS 档位包（档位包随核心自动下载，请检查授权同步）',
    exclusions: '排除规则 ID', exclusionsHelp: '这些 CRS 规则对绑定本规则库的网站整站不生效（每个请求即时生效，不重载节点）；只能填当前档位允许排除的规则',
    ruleIdsInvalid: '填写 9 开头的 6 位规则 ID，用逗号分隔', notExported: '当前档位不允许排除：{{ids}}',
  },
  import: {
    select: '选择要导入的系统规则', button: '从系统规则导入', pendingHint: '已选 {{count}} 项还未加入规则，请点「从系统规则导入」，否则保存时不会包含。', placeholder: { waf: '选择 WAF 规则集（自研检测 / OWASP CRS，可同时选）', cc: '选择 CC 规则组（可多选，按选择顺序合并，最多 8 个）' },
    groups: { self: '自研检测（默认）', crs: 'OWASP CRS（需节点引擎扩展，按需下载）' },
  },
}

const enUS = {
  challenge: {
    log_only: 'Record only (no ban)',
    failure_window_seconds: 'Window (s)', failure_window_secondsHelp: 'Unpassed verifications are counted over this time',
    max_failures: 'Max failures', max_failuresHelp: 'More unpassed verifications than this within the window bans the client',
    ban_seconds: 'Ban (s)', ban_secondsHelp: 'How long the client IP is banned (403)',
    pass_seconds: 'Pass lifetime (s)', pass_secondsHelp: 'Lifetime of the pass cookie after a solved challenge',
    pow_bits: 'PoW bits', pow_bitsHelp: 'Leading zero bits of SHA-256 the browser must find; each bit doubles the work',
    delay_seconds: 'Wait (s)', delay_secondsHelp: 'Minimum wait of the 5-second shield',
    challenge_seconds: 'Page lifetime (s)', challenge_secondsHelp: 'Lifetime of one challenge page (one-time token)',
    bind_ipv4_prefix: 'IPv4 bind prefix', bind_ipv4_prefixHelp: 'The pass is valid only from the same network; 32 = one address',
    bind_ipv6_prefix: 'IPv6 bind prefix', bind_ipv6_prefixHelp: 'The pass is valid only from the same network; 128 = one address',
    key_rotate_seconds: 'Key rotation (s)', key_rotate_secondsHelp: 'At least the pass lifetime; current and previous keys are accepted',
    trigger_window_seconds: 'Window (s)', trigger_max_requests: 'More than (requests)',
    triggerHelp: 'Challenge a client only after more requests than this within the window; leave both empty to challenge every unpassed request',
    triggerPair: 'Set both the window and the request count, or leave both empty', triggerEmpty: 'Empty: always',
  },
  waf: {
    request_body_limit: 'Body limit (with files)', request_body_no_files_limit: 'Body limit (without files)',
    request_body_limit_action: 'Over the limit', bodyActions: { reject: 'Reject (413)', partial: 'Inspect the first bytes only' },
    inspection_limit_action: 'Inspection limit hit', limitActions: { log: 'Record only', block: 'Block (403)' },
    inspection_limit_actionHelp: 'Requests that cannot be fully inspected (regex match limit, more than 100 request headers): record only lets them through (header conditions do not match); block returns 403',
    arguments_limit: 'Max arguments', json_depth_limit: 'Max JSON depth', pcre_match_limit: 'Regex match limit',
    profile: 'CRS profile', profileHelp: 'The profile decides which CRS rule sets run, the paranoia level, the anomaly threshold and block / record only; switching profiles reloads the nodes',
    noProfiles: 'No CRS profile pack has been synced from the license service yet (they download automatically; check the license sync)',
    exclusions: 'Excluded rule IDs', exclusionsHelp: 'These CRS rules do not run for the sites bound to this library (per request, no node reload); only rules the profile lets a site exclude',
    ruleIdsInvalid: 'Six-digit rule IDs starting with 9, comma separated', notExported: 'The profile does not let a site exclude: {{ids}}',
  },
  import: {
    select: 'System rules to import', button: 'Import from system rules', pendingHint: '{{count}} selected item(s) are not in the rules yet. Click "Import from system rules", or they will not be saved.', placeholder: { waf: 'Choose WAF rule sets (self-developed / OWASP CRS, both allowed)', cc: 'Choose CC rule groups (several allowed, merged in the order chosen, up to 8)' },
    groups: { self: 'Self-developed detection (default)', crs: 'OWASP CRS (node engine extension, downloaded on demand)' },
  },
}

function pseudo(value: unknown): unknown {
  if (typeof value === 'string') return `[!! ${value} !!]`
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, pseudo(item)]))
  return value
}

i18n.addResourceBundle('zh-CN', 'managedRules', zhCN, true, true)
i18n.addResourceBundle('en-US', 'managedRules', enUS, true, true)
i18n.addResourceBundle('qps-ploc', 'managedRules', pseudo(enUS), true, true)
i18n.addResourceBundle('qps-Ploc', 'managedRules', pseudo(enUS), true, true)

export { enUS as managedRulesEnUS, zhCN as managedRulesZhCN }
