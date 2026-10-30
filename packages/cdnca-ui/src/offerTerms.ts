// Node market offer wording shared by the controller (apps/web 节点市场 → 卖节点)
// and the seller site (apps/seller-portal 节点与套餐), fix-sellersite: the two
// sides edit the same offer through the same market rules, so they say the same
// thing. Keys mirror market-service offers.go (OfferTerms / OfferLimits) and the
// metric / action names of libs/marketproto/spec.

export type OfferCopyLocale = 'zh-CN' | 'en-US'

export function offerCopyLocale(language?: string): OfferCopyLocale {
  return language?.toLowerCase().startsWith('en') ? 'en-US' : 'zh-CN'
}

const zhCN = {
  // Same text as the controller listing form (apps/web i18n nodeMarket listing.*).
  // Prices are entered in yuan (fix-offerform, user 10-27); the market API stays in minor units (分).
  dailyMinor: '日价（元 / 天）', perGBMinor: '每 GB 单价（元）', perMbpsMonthMinor: '单价（元 / Mbps / 月）', perMbpsDayMinor: '单价（元 / Mbps / 天）',
  depositMinor: '押金（元）', minDays: '最短天数', maxDays: '最长天数', prepaid: '预付用完处置',
  prepaidHelp: '订阅方预付余额用完时对该订阅全部供给的处置；充值到账后自动恢复。',
  limits: '限额', limitsHelp: '不勾选的项目不限。实时类（带宽、并发连接、新建连接、QPS）上限是整个供给的总量，按在线节点平分到每个节点；节点承受力按单节点判，超过即把该节点从本供给摘除。',
  metrics: {
    domains: '域名数', bandwidth_peak_bps: '峰值带宽', monthly_traffic_bytes: '月流量', concurrent_connections: '并发连接',
    new_connections_per_second: '新建连接', qps: 'QPS', node_cpu_percent: '节点 CPU', node_memory_percent: '节点内存',
  },
  actions: { throttle: '限速', pause: '暂停调度', stop: '停止服务', reject_new: '拒绝新增', remove_node: '摘除该节点' },
  resaleAllowed: '允许转售', siteAutoPause: '同站点自动暂停',
  // What a change does to sold subscriptions (offers.go UpdateOfferTerms / UpdateOfferLimits, renewal.go).
  revisionNotice: '保存会生成新的报价修订：新订单按新条款；已售订阅保持购买时的快照，日包到期时按各自的续费价格条件决定跟随新条款还是关闭（涨价或收紧限额视为涨价）；按量计费的订阅终身保持原价。订阅方会收到条款变更通知。',
  changed: '报价已在别处（主控或卖家站）修改，请刷新后重新打开再保存',
  nodesOnController: '节点的增减在主控 → 节点市场 → 卖节点 中设置；报价包含的节点和节点插件由主控按本机节点证明，卖家站只能查看。',
  delistNotice: '下架只停止新购买，已售订阅照常服务与续费。',
  republishNotice: '沿用同一报价，平台会按当前规则重新检查上架资格（入驻、佣金预付、欠费等）；需要审核时先进入待审核。',
}

const enUS: typeof zhCN = {
  dailyMinor: 'Daily price (CNY / day)', perGBMinor: 'Price per GB (CNY)', perMbpsMonthMinor: 'Price (CNY / Mbps / month)', perMbpsDayMinor: 'Price (CNY / Mbps / day)',
  depositMinor: 'Deposit (CNY)', minDays: 'Minimum days', maxDays: 'Maximum days', prepaid: 'When prepaid runs out',
  prepaidHelp: 'What happens to all of a subscription\'s supply when its prepaid balance runs out; it resumes once topped up.',
  limits: 'Limits', limitsHelp: 'Unchecked items are unlimited. Realtime caps (bandwidth, concurrent and new connections, QPS) are the whole supply\'s total, split over the online nodes; node load is judged per node and removes that node from this supply when exceeded.',
  metrics: {
    domains: 'Domains', bandwidth_peak_bps: 'Peak bandwidth', monthly_traffic_bytes: 'Monthly traffic', concurrent_connections: 'Concurrent connections',
    new_connections_per_second: 'New connections', qps: 'QPS', node_cpu_percent: 'Node CPU', node_memory_percent: 'Node memory',
  },
  actions: { throttle: 'Throttle', pause: 'Pause scheduling', stop: 'Stop service', reject_new: 'Reject new', remove_node: 'Remove the node' },
  resaleAllowed: 'Allow resale', siteAutoPause: 'Same-site automatic pause',
  revisionNotice: 'Saving creates a new offer revision: new orders get the new terms; sold subscriptions keep their purchase snapshot, and day bundles follow the new terms at renewal only as their renewal price condition allows (a higher price or a stricter limit counts as an increase); metered subscriptions keep their price for life. Subscribers are notified.',
  changed: 'The offer was changed elsewhere (controller or seller site). Refresh and reopen before saving',
  nodesOnController: 'Nodes are added and removed on the controller under Node market → Sell. The nodes and node plugins behind an offer are proven by the controller from its own nodes; the seller site only shows them.',
  delistNotice: 'Delisting only stops new purchases; sold subscriptions keep serving and renewing.',
  republishNotice: 'The same offer is listed again after the current listing checks (onboarding, commission prepayment, arrears); with review on it goes to review first.',
}

export type OfferCopy = typeof zhCN

export const offerCopy: Record<OfferCopyLocale, OfferCopy> = { 'zh-CN': zhCN, 'en-US': enUS }

// Money in offers: the market API counts minor units (分, integers); people
// enter and read yuan (元, at most 2 decimals). yuanToMinor refuses anything it
// would have to round (more than 2 decimals, negative, not a number) so a value
// is never changed silently; the form shows the refusal instead.
export function yuanToMinor(yuan: number | string | null | undefined): number | null {
  if (yuan === null || yuan === undefined) return null
  const text = typeof yuan === 'number' ? (Number.isFinite(yuan) ? String(yuan) : '') : yuan.trim()
  const match = /^(\d+)(?:\.(\d{1,2}))?$/.exec(text)
  if (!match) return null
  const minor = Number(match[1]) * 100 + Number((match[2] ?? '').padEnd(2, '0'))
  return Number.isSafeInteger(minor) ? minor : null
}

export function minorToYuan(minor: number): number {
  return Math.round(minor) / 100
}

/** "1.00", "0.05": a minor amount shown in yuan with 2 decimals. */
export function formatYuan(minor: number): string {
  const sign = minor < 0 ? '-' : ''
  const abs = Math.abs(Math.round(minor))
  return `${sign}${Math.floor(abs / 100)}.${String(abs % 100).padStart(2, '0')}`
}
