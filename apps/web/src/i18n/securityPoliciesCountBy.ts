import i18n from './index'

// CC rules counting by client network / host / URI / TLS fingerprint
// (统计对象, CC API v4, node agent 1.0.35), several system rule groups at
// once (#16) and reordering rules (FX26).
const zhCN = {
  countBy: {
    label: '统计对象',
    help: '按什么累计请求次数，可选一个或两个组合。默认按客户端 IP。',
    placeholder: '默认：客户端 IP',
    keys: {
      client_ip: '客户端 IP', client_cidr: '客户端网段', host: '域名（Host）', uri: 'URI（含参数）', uri_path: 'URI（不含参数）', ja4: 'TLS 指纹（JA4）',
      user_agent: '浏览器 UA（User-Agent）', referer: '请求来源（Referer）', header: '指定请求头', cookie: 'Cookie', query: '查询参数',
    },
    phrases: {
      client_ip: '客户端 IP', client_cidr: '/{{v4}} 网段（IPv6 /{{v6}}）', host: '域名', uri: 'URI', uri_path: 'URI（不含参数）', ja4: 'TLS 指纹（JA4）',
      user_agent: 'UA', referer: 'Referer', header: '请求头 {{name}}', cookie: 'Cookie {{name}}', query: '参数 {{name}}',
    },
    ipv4Prefix: 'IPv4 前缀', ipv6Prefix: 'IPv6 前缀',
    names: { header: '请求头名称', cookie: 'Cookie 名称', query: '参数名称' },
    namePlaceholders: { header: '如 X-Api-Key', cookie: '如 session_id', query: '如 token' },
    nameInvalid: '名称只能包含字母、数字和 - _ . : 等字符',
    v7Help: '按 UA、Referer、请求头、Cookie 或参数计数需要节点支持 CC v7（CC_MATCH_KEYS），节点版本过低会拒绝发布；请求里没有该值时不计入这条规则。',
    ja4Help: '按 TLS 指纹计数需要节点 1.0.35 且已启用 JA4 模块；没有 TLS 指纹的请求（明文 HTTP、HTTP/3）不计入这条规则。',
    nodeHelp: '选择 IP 以外的统计对象需要节点 agent 1.0.35 及以上，旧节点会拒绝发布。',
    target: '封禁整个统计对象',
    targetHelp: '超限后封禁整个统计对象（例如这个网段、这个 TLS 指纹），而不只是触发的客户端。',
    preview: '同一 {{keys}}，{{window}} 秒超过 {{requests}} 次 → {{action}}',
    previewJoin: ' + 同一 ',
    actions: {
      temporary_ban: '封禁 {{seconds}} 秒', temporary_ban_bucket: '封禁该统计对象 {{seconds}} 秒', reject_429: '返回 429', log: '仅记录',
      challenge: '验证码', rate: '限速',
      challengeTypes: {
        js: 'JS 挑战', five_second: '5 秒盾', click: '点击验证', simple_click: '点击验证（简单）', slider: '滑块验证',
        simple_slider: '滑块验证（简单）', captcha: '验证码', rotate_image: '旋转图片', redirect: '302 跳转验证',
      },
    },
    problems: {
      tooMany: '最多选 2 个统计对象', ipAndCidr: '客户端 IP 和客户端网段不能同时选', uriAndPath: '两种 URI 不能同时选',
      statistics: '含“不同 UA 数 / 404 次数”条件的规则只能按客户端 IP 统计',
      challengeTrigger: '验证码规则按其他统计对象计数时需要设置触发阈值（时间窗口与请求数）',
      target: '只有“临时封禁”规则在选择了统计对象后才能封禁整个统计对象',
    },
  },
  ruleOrder: {
    drag: '拖动调整规则顺序', moveUp: '上移规则 {{index}}', moveDown: '下移规则 {{index}}',
  },
  catalogMerge: {
    duplicates: '已去重 {{count}} 条与先选规则库相同的规则',
    conflicts: '以下规则与先选规则库匹配条件相同但动作不同，先选的规则库优先：{{rules}}',
    tooMany: '最多同时选 {{count}} 个规则库',
  },
  countByPublish: {
    refusal: '部分节点版本过低，不支持按网段/域名/URI/TLS 指纹计数。已记录本次发布，节点升级后会自动发布；也可以把统计对象改回按 IP。',
    refusalNodes: '需要升级的节点：{{nodes}}',
    waiting: '等待节点升级后自动发布（策略版本 v{{version}}，节点：{{nodes}}）',
    waitingRulePacks: '等待节点装好规则包后自动下发（策略版本 v{{version}}，节点：{{nodes}}）',
  },
}

type Messages = typeof zhCN

const enUS: Messages = {
  countBy: {
    label: 'Count by',
    help: 'What requests are counted per: one key or two combined. The default is the client IP.',
    placeholder: 'Default: client IP',
    keys: {
      client_ip: 'Client IP', client_cidr: 'Client network', host: 'Host', uri: 'URI (with query)', uri_path: 'URI (without query)', ja4: 'TLS fingerprint (JA4)',
      user_agent: 'Browser UA (User-Agent)', referer: 'Request source (Referer)', header: 'A request header', cookie: 'Cookie', query: 'Query argument',
    },
    phrases: {
      client_ip: 'client IP', client_cidr: '/{{v4}} network (IPv6 /{{v6}})', host: 'host', uri: 'URI', uri_path: 'URI (without query)', ja4: 'TLS fingerprint (JA4)',
      user_agent: 'UA', referer: 'Referer', header: 'header {{name}}', cookie: 'cookie {{name}}', query: 'argument {{name}}',
    },
    ipv4Prefix: 'IPv4 prefix', ipv6Prefix: 'IPv6 prefix',
    names: { header: 'Header name', cookie: 'Cookie name', query: 'Argument name' },
    namePlaceholders: { header: 'such as X-Api-Key', cookie: 'such as session_id', query: 'such as token' },
    nameInvalid: 'Names may contain letters, digits and - _ . : only',
    v7Help: 'Counting by UA, Referer, a header, cookie or argument needs nodes with CC v7 (CC_MATCH_KEYS); older nodes refuse the release. Requests without the value are not counted by this rule.',
    ja4Help: 'Counting by TLS fingerprint needs node 1.0.35 with the JA4 module; requests without one (plain HTTP, HTTP/3) are not counted by this rule.',
    nodeHelp: 'Counting by anything other than the client IP needs node agent 1.0.35 or later; older nodes refuse the release.',
    target: 'Ban the whole counted key',
    targetHelp: 'Over the limit, ban everything counted together (this network, this TLS fingerprint), not only the client that tripped it.',
    preview: 'Same {{keys}}: more than {{requests}} requests in {{window}} s → {{action}}',
    previewJoin: ' + ',
    actions: {
      temporary_ban: 'ban {{seconds}} s', temporary_ban_bucket: 'ban the counted key {{seconds}} s', reject_429: 'answer 429', log: 'record only',
      challenge: 'challenge', rate: 'rate limit',
      challengeTypes: {
        js: 'JS challenge', five_second: '5-second shield', click: 'click challenge', simple_click: 'simple click challenge', slider: 'slider challenge',
        simple_slider: 'simple slider challenge', captcha: 'CAPTCHA', rotate_image: 'rotate-image challenge', redirect: '302 redirect challenge',
      },
    },
    problems: {
      tooMany: 'Choose at most 2 keys', ipAndCidr: 'Client IP and client network cannot be combined', uriAndPath: 'The two URI keys cannot be combined',
      statistics: 'Rules with a distinct-UA or 404-count condition count per client IP only',
      challengeTrigger: 'A challenge counting by another key needs a trigger (window and requests)',
      target: 'Only a temporary ban with a counting key can ban the whole key',
    },
  },
  ruleOrder: {
    drag: 'Drag to reorder rules', moveUp: 'Move rule {{index}} up', moveDown: 'Move rule {{index}} down',
  },
  catalogMerge: {
    duplicates: 'Dropped {{count}} rules an earlier rule group already has',
    conflicts: 'These rules match like an earlier group\'s but act differently; the earlier group runs first: {{rules}}',
    tooMany: 'Choose at most {{count}} rule groups',
  },
  countByPublish: {
    refusal: 'Some nodes are too old to count by network, host, URI or TLS fingerprint. The release is recorded and is published automatically once they are upgraded; or count by IP instead.',
    refusalNodes: 'Nodes to upgrade: {{nodes}}',
    waiting: 'Waiting for node upgrades to publish automatically (policy v{{version}}, nodes: {{nodes}})',
    waitingRulePacks: 'Waiting for the nodes to install the rule packs to deliver automatically (policy v{{version}}, nodes: {{nodes}})',
  },
}

function pseudo(value: unknown): unknown {
  if (typeof value === 'string') return `［${value}］`
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudo(child)]))
}

export const countByMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', Messages> = {
  'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudo(zhCN) as Messages, 'qps-Ploc': pseudo(zhCN) as Messages,
}

for (const [locale, messages] of Object.entries(countByMessages)) {
  i18n.addResourceBundle(locale, 'securityPolicies', messages, true, true)
}
