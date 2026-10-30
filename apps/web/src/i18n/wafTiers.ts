import i18n from './index'

// WAF 防护档位：仅记录 / 标准防护 / 严格防护 / 极严格防护，严格递增。
// 档位名、攻击类型、规则数与“比上一档新增”都来自服务端按 CRS 规则统计的 tier（rulepack.CRSTier），这里只放文案。
const zhCN = {
  tiers: {
    'system/crs-pl1-log': '仅记录', 'system/crs-pl1': '标准防护', 'system/crs-pl2': '严格防护', 'system/crs-pl3': '极严格防护',
  },
  sets: {
    'waf_set:crs_sqli': 'SQL注入', 'waf_set:crs_xss': 'XSS', 'waf_set:crs_file_upload': '文件上传',
    'waf_set:crs_file_include': '文件包含', 'waf_set:crs_cmd_injection': '命令注入',
    'waf_set:crs_java_code_injection': 'Java代码注入', 'waf_set:crs_java_deserialization': 'Java反序列化',
    'waf_set:crs_php_code_injection': 'PHP代码注入', 'waf_set:crs_php_deserialization': 'PHP反序列化',
    'waf_set:crs_ssti': 'SSTI模板注入', 'waf_set:crs_generic': '通用代码注入与SSRF',
  },
  action: { log: '只记录不拦截', block: '拦截' },
  summary: '{{action}} · 防护等级 {{paranoia}} · {{count}} 类攻击',
  classes: '包含的攻击类型',
  rules: '{{count}} 条规则',
  added: '比「{{previous}}」新增',
  addedNone: '这是最基础的一档',
  addedSet: '新增攻击类型「{{name}}」（{{rules}} 条规则）',
  addedParanoia: '「{{name}}」启用防护等级 {{from}}→{{to}} 的规则（+{{rules}} 条）',
  addedBlock: '命中后拦截（「{{previous}}」只记录，{{rules}} 条规则相同）',
  falsePositive: '极严格防护会明显增加误报，请先用「仅记录」观察，再按站点关闭误报的规则或规则组。',
  strictHint: '严格防护误报多于标准防护，建议先观察再启用。',
  setSwitches: '规则组开关',
  setSwitchesHint: '关闭某个攻击类型后，该类全部规则对使用此规则库的站点不生效（每个请求即时生效，不重载节点）。',
  setOn: '{{name}}：开启', setOff: '{{name}}：关闭',
  tierUnavailable: '主控尚未同步 CRS 规则文本，暂时无法列出各档的攻击类型',
}

const enUS: typeof zhCN = {
  tiers: {
    'system/crs-pl1-log': 'Record only', 'system/crs-pl1': 'Standard', 'system/crs-pl2': 'Strict', 'system/crs-pl3': 'Very strict',
  },
  sets: {
    'waf_set:crs_sqli': 'SQL injection', 'waf_set:crs_xss': 'XSS', 'waf_set:crs_file_upload': 'File upload',
    'waf_set:crs_file_include': 'File inclusion', 'waf_set:crs_cmd_injection': 'Command injection',
    'waf_set:crs_java_code_injection': 'Java code injection', 'waf_set:crs_java_deserialization': 'Java deserialization',
    'waf_set:crs_php_code_injection': 'PHP code injection', 'waf_set:crs_php_deserialization': 'PHP deserialization',
    'waf_set:crs_ssti': 'Server-side template injection (SSTI)', 'waf_set:crs_generic': 'Generic code injection and SSRF',
  },
  action: { log: 'records without blocking', block: 'blocks' },
  summary: '{{action}} · paranoia level {{paranoia}} · {{count}} attack types',
  classes: 'Attack types covered',
  rules: '{{count}} rules',
  added: 'Added over "{{previous}}"',
  addedNone: 'This is the base tier',
  addedSet: 'New attack type "{{name}}" ({{rules}} rules)',
  addedParanoia: '"{{name}}" runs paranoia level {{from}}→{{to}} rules (+{{rules}})',
  addedBlock: 'Blocks on a match ("{{previous}}" only records the same {{rules}} rules)',
  falsePositive: 'Very strict raises false positives noticeably: watch with "Record only" first, then turn off the rules or rule groups that misfire for a site.',
  strictHint: 'Strict has more false positives than Standard; watch before enabling it.',
  setSwitches: 'Rule groups',
  setSwitchesHint: 'A rule group turned off does not run for the sites using this library (per request, no node reload).',
  setOn: '{{name}}: on', setOff: '{{name}}: off',
  tierUnavailable: 'The CRS rule text has not been synced to this control plane yet; the attack types of each tier cannot be listed',
}

function pseudo(value: unknown): unknown {
  return typeof value === 'string'
    ? `［${value}］`
    : Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudo(child)]))
}

export const wafTiersMessages = { 'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudo(zhCN), 'qps-Ploc': pseudo(zhCN) }

for (const [locale, messages] of Object.entries(wafTiersMessages)) i18n.addResourceBundle(locale, 'wafTiers', messages, true, true)
