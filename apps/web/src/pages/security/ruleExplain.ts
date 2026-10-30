// Plain-language "when does it trigger, what happens" text for system rule
// catalog items. Every number is read from the item (filter params, CRS engine
// values); mirrors edge/openresty/ccv2/engine.lua, securitypolicy.ExpandCCRuleGroup
// and the managed WAF (OWASP CRS on libmodsecurity, libs/edgeconfig/waf_managed.go).

export type ExplainParams = {
  ban_seconds: number
  pass_seconds?: number
  pow_bits?: number
  delay_seconds?: number
  bind_ipv4_prefix?: number
  bind_ipv6_prefix?: number
}
export type ExplainFilter = { type: string; within_second: number; max_req: number; max_req_per_uri: number; params?: ExplainParams }
export type ExplainEntry = { matcher_key: string; filter1_key: string; filter2_key?: string; action: string; enabled: boolean }
export type ExplainEngine = { action: string; paranoia: number; threshold: number }
export type ExplainSettings = { request_body_limit: number; request_body_no_files_limit: number; request_body_limit_action: string }
export type ExplainBody = {
  cc_filter?: ExplainFilter
  cc_matcher?: { conditions: { field: string; operator: string; values: string[] }[] }
  cc_rule_group?: { entries: ExplainEntry[] }
  waf_rule_set?: { rules?: { action: string }[]; engine?: ExplainEngine; settings?: ExplainSettings }
}

const pages: Record<string, string> = {
  browser_verify_auto: '浏览器自动完成的 JS 验证（用户无感）',
  delay_jump_filter: '等待页，等待结束后浏览器自动提交',
  click_filter: '“点击指定图形”验证',
  easy_click_filter: '“点击按钮继续”验证',
  slide_filter: '“拖动滑块到指定位置”验证',
  easy_slide_filter: '“把滑块拖到最右侧”验证',
  captcha_filter: '图片字符验证码',
  rotate_filter: '“旋转图片到正确方向”验证',
  '302_challenge': '302 跳转并检查浏览器是否带回 Cookie',
}

const wafSets: Record<string, string> = {
  'waf_set:sqli': 'SQL 注入（OWASP CRS REQUEST-942）：libinjection 词法指纹与正则，检查参数、Cookie、请求头、表单/JSON/XML 请求体，自动多重解码',
  'waf_set:xss': 'XSS（CRS REQUEST-941）：libinjection XSS 检测，script/事件属性/javascript: 伪协议/AngularJS 模板注入等',
  'waf_set:cmd_injection': '命令注入（CRS REQUEST-932）：Unix/Windows shell、PowerShell 命令及引号、反斜杠、通配符逃逸',
  'waf_set:file_include': '文件包含（CRS REQUEST-930/931）：目录穿越、敏感系统文件、远程 URL 包含',
  'waf_set:file_upload': '文件上传（CRS 920400/920410/922/932180/933110/933111/933220/944140）：上传大小、multipart 攻击、PHP/JSP 脚本与会话文件上传',
  'waf_set:java_code_injection': 'Java 代码注入（CRS REQUEST-944）：Java 类/方法、进程创建、Log4Shell JNDI 查找',
  'waf_set:java_deserialization': 'Java 反序列化（CRS 944120/944200/944210/944240）：序列化流魔数（含 Base64）与利用链类名',
  'waf_set:php_code_injection': 'PHP 代码注入（CRS REQUEST-933）：PHP 函数、变量、包装协议、配置指令注入',
  'waf_set:php_deserialization': 'PHP 反序列化（CRS 933170）：PHP 序列化对象注入',
  'waf_set:ssti': '模板注入（CRS 934200/934180）：服务端模板表达式',
}

function duration(seconds: number): string {
  return seconds % 3600 === 0 ? `${seconds / 3600} 小时` : `${seconds} 秒`
}

// A rule group entry with filter2 (超频转验证, securitypolicy.ExpandCCRuleGroup): filter1 is a plain
// request rate that only triggers filter2's challenge; the challenge's failures ban. Any other pair is
// refused by the backend, so it is not explained.
function explainPair(rate: ExplainFilter, challenge: ExplainFilter, action: string, passLimit?: ExplainFilter): string {
  if (rate.type !== 'req_rate' || challenge.type === 'req_rate' || rate.max_req_per_uri !== 0 || rate.max_req < 1) {
    return '过滤器组合无法说明（过滤器1须为请求频率、过滤器2须为验证），规则组无法发布到节点。'
  }
  return `同一 IP 在 ${rate.within_second} 秒内请求超过 ${rate.max_req} 次后才开始验证（未超过时不验证、直接放行）：` +
    explainFilter(challenge, action, passLimit)
}

export function explainFilter(filter: ExplainFilter, action = 'block', passLimit?: ExplainFilter): string {
  const params = filter.params
  if (!params) return '缺少执行参数，规则组无法发布到节点。'
  const after = action === 'log' ? '只记录日志，不拦截' : `该 IP 被拉黑 ${duration(params.ban_seconds)}（返回 403）`
  if (filter.type === 'req_rate') {
    const perUri = filter.max_req_per_uri ? `，或同一个网址超过 ${filter.max_req_per_uri} 次` : ''
    return `同一 IP 在 ${filter.within_second} 秒内请求超过 ${filter.max_req} 次${perUri}时，${after}。`
  }
  const page = filter.type === 'delay_jump_filter' ? `${params.delay_seconds ?? 0} 秒${pages[filter.type]}` : pages[filter.type] ?? filter.type
  const pow = params.pow_bits ? `浏览器先完成 ${params.pow_bits} 位 SHA-256 工作量证明，` : ''
  const bind = params.bind_ipv4_prefix ? `（Cookie 绑定 IPv4 /${params.bind_ipv4_prefix}、IPv6 /${params.bind_ipv6_prefix} 网段和浏览器）` : ''
  const limit = passLimit ? `；同一 IP ${passLimit.within_second} 秒超过 ${passLimit.max_req} 次${passLimit.max_req_per_uri ? `或同一网址超过 ${passLimit.max_req_per_uri} 次` : ''}会要求重新验证` : ''
  return `没有验证通过的访客会先看到${page}，${pow}通过后 ${duration(params.pass_seconds ?? 0)}内放行${bind}${limit}；` +
    `${filter.within_second} 秒内超过 ${filter.max_req || 1} 次没通过验证时，${after}。`
}

export function explainMatcher(body: NonNullable<ExplainBody['cc_matcher']>): string {
  if (body.conditions.length === 0) return '所有请求'
  return body.conditions.map((condition) => `网址包含 ${condition.values.join('、')}`).join('，且')
}

export function explainRule(systemKey: string, body: ExplainBody, lookup: (key: string) => ExplainBody | undefined, description = ''): string {
  if (body.cc_filter) return explainFilter(body.cc_filter)
  if (body.cc_matcher) return `匹配：${explainMatcher(body.cc_matcher)}。`
  if (body.cc_rule_group) {
    const entries = body.cc_rule_group.entries.filter((entry) => entry.enabled)
    if (entries.length === 0) return '不做任何 CC 防护，所有请求直接放行。'
    const passLimit = lookup('cc_filter:11')?.cc_filter
    return entries.map((entry) => {
      const matcher = lookup(entry.matcher_key)?.cc_matcher
      const filter = lookup(entry.filter1_key)?.cc_filter
      const scope = matcher && matcher.conditions.length ? `对${explainMatcher(matcher)}的请求：` : ''
      if (entry.filter2_key) {
        const second = lookup(entry.filter2_key)?.cc_filter
        return scope + (filter && second ? explainPair(filter, second, entry.action, passLimit) : `${entry.filter1_key} → ${entry.filter2_key}`)
      }
      return scope + (filter ? explainFilter(filter, entry.action, filter.type === 'req_rate' ? undefined : passLimit) : entry.filter1_key)
    }).join(' ')
  }
  const waf = body.waf_rule_set
  if (waf?.settings) {
    const over = waf.settings.request_body_limit_action === 'partial' ? '只检查前面部分' : '拒绝请求（413）'
    return `WAF 请求体检查上限：含文件 ${waf.settings.request_body_limit} 字节、不含文件 ${waf.settings.request_body_no_files_limit} 字节，超过时${over}。`
  }
  if (waf?.engine) {
    const mode = waf.engine.action === 'log' ? '只记录不拦截' : '拦截（返回 403）'
    return `${wafSets[systemKey] ?? description}。Paranoia ${waf.engine.paranoia}，命中规则分数之和达到 ${waf.engine.threshold} 时${mode}；站点可单独调整动作、等级、阈值和排除规则。`
  }
  if (waf?.rules) {
    const mode = waf.rules.every((rule) => rule.action === 'log') ? '只记录不拦截。' : '命中即拦截（返回 403）。'
    return `${description}。${mode}`
  }
  return description
}
