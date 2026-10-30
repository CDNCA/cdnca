import i18n from './index'

const zhCN = {
  label: 'IP 允许列表',
  placeholder: '每行填写一个规范网络 CIDR；留空表示不限制来源 IP',
  help: '仅支持规范 IPv4/IPv6 网络，不能包含主机位、重复或重叠网段，最多 32 个。',
  unrestricted: '不限制来源 IP',
  validation: {
    api_key_ip_allowlist_invalid_cidr: '请输入规范网络 CIDR（不允许主机位、地址区或非规范写法）',
    api_key_ip_allowlist_unsupported_prefix: 'CIDR 前缀长度超出地址范围',
    api_key_ip_allowlist_duplicate: 'IP 允许列表不能包含重复网段',
    api_key_ip_allowlist_overlap: 'IP 允许列表不能包含重叠网段',
    api_key_ip_allowlist_too_many: 'IP 允许列表最多 32 个网段',
  },
} as const

const enUS = {
  label: 'IP allowlist',
  placeholder: 'Enter one canonical network CIDR per line; leave empty for unrestricted source IPs',
  help: 'Canonical IPv4/IPv6 networks only; host bits, duplicates, overlaps, and more than 32 entries are rejected.',
  unrestricted: 'Unrestricted source IPs',
  validation: {
    api_key_ip_allowlist_invalid_cidr: 'Enter canonical network CIDRs without host bits, address zones, or non-canonical spelling',
    api_key_ip_allowlist_unsupported_prefix: 'The CIDR prefix length is outside the address range',
    api_key_ip_allowlist_duplicate: 'The IP allowlist cannot contain duplicate networks',
    api_key_ip_allowlist_overlap: 'The IP allowlist cannot contain overlapping networks',
    api_key_ip_allowlist_too_many: 'The IP allowlist can contain at most 32 networks',
  },
} as const

type MessageTree = { [key: string]: string | MessageTree }
function pseudoText(value: string): string {
  const expanded = value.split(/({{[^}]+}})/g).map((part) => part.startsWith('{{') ? part : [...part].map((char) => /\s/u.test(char) ? char : `${char}~`).join('')).join('')
  return `［${expanded}］`
}
function pseudoTree(value: unknown): unknown {
  return typeof value === 'string' ? pseudoText(value) : Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudoTree(child)]))
}

const pseudoCN = pseudoTree(zhCN) as MessageTree
export const apiKeyAllowlistMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', MessageTree> = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudoCN,
  'qps-Ploc': pseudoCN,
}
for (const [locale, messages] of Object.entries(apiKeyAllowlistMessages)) {
  i18n.addResourceBundle(locale, 'apiKeyAllowlist', messages, true, true)
}
