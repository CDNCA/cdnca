import i18n from './index'

const zhCN = {
  systemRules: {
    title: '系统规则', notice: '系统规则由系统统一下发，规则内容不能修改，可按需启用或停用。',
    adminNotice: '系统规则由系统统一下发，可设置是否对用户显示以及仅对指定用户显示。',
    empty: '暂未同步到系统规则', count: '系统规则 {{count}} 条',
    loadFailed: '系统规则暂时读取失败，下面只显示你自己的规则；这不代表没有系统规则。可重试。',
    enforcementPending: '节点按“效果说明”执行：验证类规则会真的弹出对应验证页，通过后放行，多次不通过会临时拉黑；频率类规则按统计周期和次数严格计数。',
    wafSignatureNotice: 'SQL 注入与 XSS 规则能识别经过编码变形的攻击。内置规则启用后默认只记录：命中时只记日志、不拦截。管理员在“拦截事件明细”里确认没有误拦正常访问后，可在“系统设置 > 默认配置 > 网站 > 安全设置”的“内置模块防护”里把对应模块改为“防护”（拦截），或在网站的 WAF 规则里把动作改为“拦截”。',
    columns: {
      id: 'ID', name: '名称', type: '类型', summary: '规则内容', effect: '效果说明（什么情况下触发、触发后会怎样）', status: '状态', enabled: '启用', visible: '对用户显示', showTo: '仅对以下用户显示',
      matcher: '匹配器', filter1: '过滤器1', filter2: '过滤器2', action: '动作', mode: '模式', revision: '版本',
    },
    values: {
      active: '正常', withdrawn: '已下线', system: '系统', systemRule: '系统规则', withdrawnHint: '授权中心已停止下发，已在用的保持最后版本，不能再新启用',
      block: '拉黑', allow: '放行', log: '记录', break: '停止匹配', continue: '继续下一条规则', matchAll: '匹配所有请求',
      allTenants: '所有用户', rules: '{{count}} 条规则', entries: '{{count}} 条规则',
    },
    filterTypes: {
      req_rate: '请求频率', browser_verify_auto: '无感验证(JS)', delay_jump_filter: '5 秒盾', click_filter: '点击验证',
      easy_click_filter: '点击验证（简单）', slide_filter: '滑动验证', easy_slide_filter: '滑动验证（简单）', captcha_filter: '验证码',
      rotate_filter: '旋转图片', '302_challenge': '302 跳转',
    },
    filterSummary: '{{type}} · {{window}} 秒内 {{max}} 次{{perUri}}', perUri: '，单 URL {{value}} 次', sortLabel: '排序 {{sort}}',
    showToPlaceholder: '留空表示所有用户；输入用户名称搜索', showToEmpty: '没有匹配的用户', showToListFailed: '用户列表读取失败，可粘贴用户作用域 ID',
    expand: '展开系统规则', collapse: '收起系统规则', searchLabel: '搜索系统规则', searchPlaceholder: '按名称或 ID 搜索', noMatch: '没有匹配的系统规则', saved: '已保存', failed: '保存失败',
    errors: { security_system_rule_withdrawn: '该系统规则已下线，不能再启用', security_system_rule_not_found: '系统规则不存在或不可见' },
  },
}

type Messages = typeof zhCN

const enUS: Messages = {
  systemRules: {
    title: 'System rules', notice: 'System rules are delivered by the system. Their content cannot be edited; you can enable or disable them.',
    adminNotice: 'System rules are delivered by the system. Choose whether users see them, or show them only to selected users.',
    empty: 'No system rules synchronized yet', count: '{{count}} system rules',
    loadFailed: 'System rules could not be read right now; only your own rules are shown below. This does not mean there are none. Retry.',
    enforcementPending: 'Nodes enforce each rule as described: verification rules show the matching challenge page, passed visitors are let through, repeated failures are temporarily blocked; rate rules count exactly per window.',
    wafSignatureNotice: 'The SQL injection and XSS rules also catch encoded variants of attacks. Once enabled, built-in rules only log by default: a match is logged, not blocked. After checking in "Blocked event details" that no normal traffic is caught, an administrator can set the module to "Protect" (block) under System settings > Default configuration > Site > Security settings > Built-in module protection, or change the action to "Block" in the site\'s WAF rules.',
    columns: {
      id: 'ID', name: 'Name', type: 'Type', summary: 'Rule', effect: 'What it does', status: 'Status', enabled: 'Enabled', visible: 'Shown to tenants', showTo: 'Only shown to',
      matcher: 'Matcher', filter1: 'Filter 1', filter2: 'Filter 2', action: 'Action', mode: 'Mode', revision: 'Revision',
    },
    values: {
      active: 'Active', withdrawn: 'Withdrawn', system: 'System', systemRule: 'System rule', withdrawnHint: 'No longer delivered; existing use keeps the last revision and it cannot be newly enabled',
      block: 'Block', allow: 'Allow', log: 'Log', break: 'Stop matching', continue: 'Continue', matchAll: 'Matches every request',
      allTenants: 'All tenants', rules: '{{count}} rules', entries: '{{count}} rules',
    },
    filterTypes: {
      req_rate: 'Request rate', browser_verify_auto: 'Browser check (JS)', delay_jump_filter: '5-second shield', click_filter: 'Click',
      easy_click_filter: 'Click (simple)', slide_filter: 'Slider', easy_slide_filter: 'Slider (simple)', captcha_filter: 'Captcha',
      rotate_filter: 'Rotate image', '302_challenge': '302 redirect',
    },
    filterSummary: '{{type}} · {{max}} in {{window}}s{{perUri}}', perUri: ', {{value}} per URL', sortLabel: 'Sort {{sort}}',
    showToPlaceholder: 'Empty means all tenants; type a tenant name to search', showToEmpty: 'No matching tenants', showToListFailed: 'Tenant list unavailable; paste a tenant scope ID',
    expand: 'Show system rules', collapse: 'Hide system rules', searchLabel: 'Search system rules', searchPlaceholder: 'Search by name or ID', noMatch: 'No matching system rules', saved: 'Saved', failed: 'Save failed',
    errors: { security_system_rule_withdrawn: 'This system rule was withdrawn and cannot be enabled', security_system_rule_not_found: 'System rule not found' },
  },
}

for (const [locale, messages] of Object.entries({ 'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': zhCN, 'qps-Ploc': zhCN })) {
  i18n.addResourceBundle(locale, 'securityPolicies', messages, true, true)
}
