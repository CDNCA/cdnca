import i18n from './index'

// IP 情报库标签（libs/entitlement/ipintel 冻结的标签表）与客户端 IP 信息显示，
// 快速屏蔽卡片和访问/拦截日志共用（G3-d）。
const zhCN = {
  // Keys are the tag names with ":" as "." (ipIntelTagKey); i18next reads ":" as a namespace.
  tags: {
    carrier: { 'cn-telecom': '中国电信', 'cn-unicom': '中国联通', 'cn-mobile': '中国移动', 'cn-cernet': '教育网',
      'cn-cstnet': '科技网', 'cn-drpeng': '鹏博士', 'cn-cbn': '中国广电' },
    idc: { cn: '国内 IDC', global: '境外 IDC' },
  },
  asn: 'AS{{asn}}',
  unknown: '未知',
  columns: { carrier: '运营商', region: '地区', asn: 'ASN', idc: 'IDC' },
  detail: { title: '客户端 IP 信息', revision: 'IP 情报库 r{{revision}}', unavailable: '主控尚无 IP 情报库，无法显示运营商与地区' },
} as const

type Widen<T> = T extends string ? string : { [Key in keyof T]: Widen<T[Key]> }
type Messages = Widen<typeof zhCN>

const enUS: Messages = {
  tags: {
    carrier: { 'cn-telecom': 'China Telecom', 'cn-unicom': 'China Unicom', 'cn-mobile': 'China Mobile', 'cn-cernet': 'CERNET',
      'cn-cstnet': 'CSTNET', 'cn-drpeng': 'Dr. Peng', 'cn-cbn': 'China Broadnet' },
    idc: { cn: 'China IDC', global: 'Global IDC' },
  },
  asn: 'AS{{asn}}',
  unknown: 'Unknown',
  columns: { carrier: 'Carrier', region: 'Region', asn: 'ASN', idc: 'IDC' },
  detail: { title: 'Client IP information', revision: 'IP intelligence r{{revision}}',
    unavailable: 'The control plane has no IP intelligence library yet; carrier and region are not shown' },
}

function pseudo(value: unknown): unknown {
  // Brackets only, so {{interpolation}} keeps working.
  return typeof value === 'string'
    ? `［${value}］`
    : Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudo(child)]))
}

/** The translation key of an IP intelligence tag name (carrier:cn-telecom -> tags.carrier.cn-telecom). */
export function ipIntelTagKey(tag: string): string {
  return `tags.${tag.replace(':', '.')}`
}

export const ipIntelMessages = { 'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudo(zhCN), 'qps-Ploc': pseudo(zhCN) }

for (const [locale, messages] of Object.entries(ipIntelMessages)) i18n.addResourceBundle(locale, 'ipIntel', messages, true, true)
