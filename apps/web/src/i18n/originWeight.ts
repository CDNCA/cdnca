import i18n from './index'

// 源站权重的占比说明。占比 = 本源站权重 ÷ 同一级已启用源站
// 权重之和（pages/originWeightShare.ts）；各负载方式的说法按 cdnca_origin.lua /
// l4runtime v2_compiler.go 的实际行为写。
const zhCN = {
  share: '约 {{share}}%',
  shareLeastConn: '权重占比 {{share}}%',
  disabled: '已停用，不分流量',
  down: '不分流量',
  help: '权重 1–100。各源站按权重占比分配流量；权重合计不必等于 100，未分配部分按同样比例分摊。',
  tipLabel: '权重与流量占比说明',
  draftShare: '该源站约占 {{share}}%',
  draftShareLeastConn: '该源站权重占比 {{share}}%',
  draftDisabled: '已停用，不分流量',
  backup: '备用源不参与源站列表的占比：所有主源站都不可用时才启用第 1 个备用源，它也不可用再用下一个；启用中的备用源承接全部流量。',
  method: {
    round_robin: '当前负载方式“轮询”：按权重轮流转发，实际占比即权重占比。',
    random: '当前负载方式“随机”：按权重随机选择，请求量大时接近权重占比。',
    ip_hash: '当前负载方式“IP 哈希”：同一访客（IPv4 同一 /24 网段）固定落到一个源站，整体比例近似权重占比。',
    url_hash: '当前负载方式“URL 哈希”：同一 URL 固定落到一个源站，整体比例近似权重占比。',
    hash: '当前负载方式“自定义哈希”：相同键固定落到一个源站，整体比例近似权重占比；键为空时按轮询。',
    least_conn: '当前负载方式“最少连接”：选当前连接数与权重之比最小的源站，权重越大承担越多连接；实际流量占比随各源站处理快慢变化。',
    sticky: '当前负载方式“会话保持”：首次访问按权重选源站，之后同一访客固定在该源站，整体比例近似权重占比。',
  },
  stream: {
    rr: '轮询：按权重轮流转发，实际占比即权重占比；下线的源站不分流量。',
    ip_hash: '定源：同一客户端 IP 固定到一个源站，整体比例近似权重占比；下线的源站不分流量。',
  },
}

type Messages = typeof zhCN

const enUS: Messages = {
  share: '≈{{share}}%',
  shareLeastConn: 'weight share {{share}}%',
  disabled: 'Disabled, gets no traffic',
  down: 'gets no traffic',
  help: 'Weight 1–100. Origins share traffic in proportion to their weights; the weights need not add up to 100, the rest is split in the same proportion.',
  tipLabel: 'About weights and traffic share',
  draftShare: 'This origin gets about {{share}}%',
  draftShareLeastConn: 'This origin\'s weight share is {{share}}%',
  draftDisabled: 'Disabled, gets no traffic',
  backup: 'Backup origins are not part of the origin list share: the first backup is used only when every primary origin is unavailable, the next only when that one is too; the backup in use takes all traffic.',
  method: {
    round_robin: 'Load balancing "Round robin": requests take turns by weight, so the share is the weight share.',
    random: 'Load balancing "Random": a random pick by weight; with enough requests it approaches the weight share.',
    ip_hash: 'Load balancing "IP hash": one visitor (for IPv4 one /24) always reaches one origin; overall the split approximates the weight share.',
    url_hash: 'Load balancing "URL hash": one URL always reaches one origin; overall the split approximates the weight share.',
    hash: 'Load balancing "Custom hash": one key always reaches one origin; overall the split approximates the weight share. An empty key is round robin.',
    least_conn: 'Load balancing "Least connections": picks the origin with the lowest connections-to-weight ratio, so a higher weight takes more connections; the traffic share varies with how fast each origin responds.',
    sticky: 'Load balancing "Session affinity": the first request picks an origin by weight and the visitor then stays on it; overall the split approximates the weight share.',
  },
  stream: {
    rr: 'Round robin: connections take turns by weight, so the share is the weight share; offline origins get no traffic.',
    ip_hash: 'Fixed origin: one client IP always reaches one origin; overall the split approximates the weight share. Offline origins get no traffic.',
  },
}

type Tree = { [key: string]: string | Tree }

function pseudoTree(value: Tree): Tree {
  return Object.fromEntries(Object.entries(value).map(([key, child]) => [
    key, typeof child === 'string' ? `［${child}］` : pseudoTree(child),
  ]))
}

const pseudo = (value: Messages) => pseudoTree(value) as Messages

export const originWeightMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', Messages> = {
  'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudo(zhCN), 'qps-Ploc': pseudo(zhCN),
}

for (const [locale, messages] of Object.entries(originWeightMessages)) {
  i18n.addResourceBundle(locale, 'originWeight', messages, true, true)
}
