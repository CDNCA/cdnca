import i18n from './index'

// 四层防护规则（guard_rules）的界面文案。
const zhCN = {
  title: '防护规则',
  hint: '按顺序判定每个新连接（UDP 为新会话），第一条全部条件都满足的规则生效；放行只结束规则判定，区域屏蔽与单 IP 新建速率照常生效。所有节点需升级到支持四层防护规则的版本，否则发布会被拒绝并列出节点。',
  empty: '还没有防护规则',
  add: '添加规则',
  tooMany: '最多 {{count}} 条规则',
  rule: '规则 {{index}}',
  moveUp: '上移规则 {{index}}',
  moveDown: '下移规则 {{index}}',
  remove: '删除规则 {{index}}',
  removeConfirm: '确认删除规则 {{index}}？',
  confirm: '确认',
  cancel: '取消',
  action: '动作',
  actions: { drop: '断开', ban: '断开并拉黑', allow: '放行' },
  conditions: '条件（全部满足才命中，至少填一项）',
  firstPacket: '首包',
  firstPacketHelp: '客户端发出的第一段数据（TCP 最多等 2.5 秒、取前 512 字节；UDP 为第一个数据报）。客户端不先发数据的协议（SSH、MySQL、SMTP 等）等满后按未命中放行，但首个连接会多等 2.5 秒。',
  firstPacketNone: '不按首包',
  matches: { prefix_hex: '前缀（十六进制）', contains: '包含文本', regex: '正则' },
  firstPacketValue: '匹配内容',
  firstPacketPlaceholder: { prefix_hex: '例如 16030100', contains: '例如 GET /admin', regex: '例如 ^SSH-2\\.0-' },
  serverNames: 'SNI（TLS 透传）',
  serverNamesHelp: '按 TLS 握手中的域名匹配，支持 *.example.com。',
  clientIP: '客户端 IP',
  clientIPPlaceholder: '每行一个 IP 段，如 203.0.113.0/24',
  negate: '取反（不在其中时命中）',
  tags: '运营商 / IDC',
  tagsPlaceholder: '选择运营商或 IDC',
  countries: '国家',
  countriesPlaceholder: '两位国家代码，如 US, SG',
  otherGeo: '另有 {{count}} 个通过接口设置的地理条件（ASN/省/市），保存时保留',
  geoHelp: '运营商、IDC、国家按节点 IP 情报库查表；节点尚未加载已验签的库时发布会被拒绝，库到达后自动发布。',
  tagNames: {
    'carrier_cn_telecom': '中国电信', 'carrier_cn_unicom': '中国联通', 'carrier_cn_mobile': '中国移动', 'carrier_cn_cernet': '教育网',
    'carrier_cn_cstnet': '科技网', 'carrier_cn_drpeng': '鹏博士', 'carrier_cn_cbn': '广电', 'idc_cn': '国内 IDC', 'idc_global': '境外 IDC',
  },
  banSeconds: '拉黑时长（秒）',
  threshold: '命中次数',
  thresholdHelp: '1 为首次命中即拉黑；大于 1 时在计数窗口内命中这么多次才拉黑，此前每次只断开。',
  window: '计数窗口（秒）',
  banHelp: '拉黑期间该 IP 对本转发的新连接一律拒绝；只属于本转发的端口还会在节点内核层（nftables）拦截。',
  problems: {
    noCondition: '请至少填写一个条件',
    sniNeedsPassthrough: 'SNI 条件只能用于 TLS 透传转发',
    sniTooMany: 'SNI 最多 32 个',
    hexInvalid: '前缀须为偶数位十六进制，最多 256 字节',
    patternTooLong: '匹配内容最多 256 字节',
    cidrInvalid: '请输入有效的 IP 段（每条最多 1024 个）',
    countryInvalid: '国家代码须为两位字母',
    banSecondsRange: '拉黑时长须为 1 到 86400 秒',
    thresholdRange: '命中次数须为 1 到 10000',
    windowRange: '计数窗口须为 1 到 3600 秒',
  },
}

const enUS: typeof zhCN = {
  title: 'Guard rules',
  hint: 'Each new connection (UDP: new session) is checked against the rules in order; the first rule whose conditions all hold decides. Allow only ends rule evaluation: region blocking and the per-IP new connection rate still apply. Every node must run a version with L4 guard rules, otherwise publication is refused and the nodes are listed.',
  empty: 'No guard rules yet',
  add: 'Add rule',
  tooMany: 'At most {{count}} rules',
  rule: 'Rule {{index}}',
  moveUp: 'Move rule {{index}} up',
  moveDown: 'Move rule {{index}} down',
  remove: 'Delete rule {{index}}',
  removeConfirm: 'Delete rule {{index}}?',
  confirm: 'Confirm',
  cancel: 'Cancel',
  action: 'Action',
  actions: { drop: 'Disconnect', ban: 'Disconnect and ban', allow: 'Allow' },
  conditions: 'Conditions (all must hold; at least one)',
  firstPacket: 'First packet',
  firstPacketHelp: 'The first data the client sends (TCP: waits up to 2.5 seconds, first 512 bytes; UDP: the first datagram). Protocols where the server speaks first (SSH, MySQL, SMTP) are forwarded as not matching after the wait, which delays their first connection by 2.5 seconds.',
  firstPacketNone: 'Any first packet',
  matches: { prefix_hex: 'Prefix (hex)', contains: 'Contains text', regex: 'Regular expression' },
  firstPacketValue: 'Pattern',
  firstPacketPlaceholder: { prefix_hex: 'e.g. 16030100', contains: 'e.g. GET /admin', regex: 'e.g. ^SSH-2\\.0-' },
  serverNames: 'SNI (TLS passthrough)',
  serverNamesHelp: 'Matches the TLS handshake server name; *.example.com wildcards are supported.',
  clientIP: 'Client IP',
  clientIPPlaceholder: 'One network per line, e.g. 203.0.113.0/24',
  negate: 'Negate (match when not in it)',
  tags: 'Carrier / IDC',
  tagsPlaceholder: 'Choose carriers or IDC',
  countries: 'Countries',
  countriesPlaceholder: 'Two-letter codes, e.g. US, SG',
  otherGeo: '{{count}} more geo conditions set through the API (ASN / province / city) are kept on save',
  geoHelp: 'Carrier, IDC and country are looked up in the node IP intelligence library; publication is refused until the nodes have loaded a verified library and resumes automatically when it arrives.',
  tagNames: {
    'carrier_cn_telecom': 'China Telecom', 'carrier_cn_unicom': 'China Unicom', 'carrier_cn_mobile': 'China Mobile', 'carrier_cn_cernet': 'CERNET',
    'carrier_cn_cstnet': 'CSTNET', 'carrier_cn_drpeng': 'Dr. Peng', 'carrier_cn_cbn': 'China Broadnet', 'idc_cn': 'China IDC', 'idc_global': 'Global IDC',
  },
  banSeconds: 'Ban duration (seconds)',
  threshold: 'Hits',
  thresholdHelp: '1 bans at the first hit; above 1 the client is banned after this many hits within the window and only disconnected before.',
  window: 'Window (seconds)',
  banHelp: 'While banned, new connections of the IP to this forward are refused; on ports only this forward uses they are also dropped in the node kernel (nftables).',
  problems: {
    noCondition: 'Fill in at least one condition',
    sniNeedsPassthrough: 'SNI conditions need TLS passthrough',
    sniTooMany: 'At most 32 server names',
    hexInvalid: 'The prefix must be an even number of hex digits, at most 256 bytes',
    patternTooLong: 'The pattern is at most 256 bytes',
    cidrInvalid: 'Enter valid networks (at most 1024 per rule)',
    countryInvalid: 'Country codes have two letters',
    banSecondsRange: 'The ban lasts 1 to 86400 seconds',
    thresholdRange: 'Hits must be 1 to 10000',
    windowRange: 'The window is 1 to 3600 seconds',
  },
}

function pseudoTree(value: unknown): unknown {
  if (typeof value === 'string') return `［${value.replace(/\s/g, '~')}］`
  if (!value || typeof value !== 'object') return value
  return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, pseudoTree(child)]))
}

const pseudoCN = pseudoTree(zhCN) as typeof zhCN
for (const [locale, messages] of Object.entries({ 'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudoCN, 'qps-Ploc': pseudoCN })) {
  i18n.addResourceBundle(locale, 'streamGuard', messages, true, true)
}

export { enUS, zhCN }
