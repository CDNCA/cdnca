import i18n from './index'

const zhCN = {
  title: 'API 访问配置',
  description: '管理账号 API 密钥、调用开关和允许访问的客户端 IP。',
  status: 'API 密钥状态',
  statusHelp: '关闭后将撤销当前 API 密钥，外部程序无法继续调用接口。',
  enabled: '已开启',
  disabled: '未开启',
  unknown: '状态未知',
  loading: '加载中',
  enableHint: '开启后自动生成一对密钥（全部权限、永不过期）。',
  noScopes: '当前账号没有可授予 API 的权限，无法开启。',
  multipleHint: '你有多个密钥，请在高级密钥管理里操作。',
  allowlist: 'IP 白名单',
  allowlistHelp: '限制允许调用 API 的客户端 IP；多个 IP 或网段用竖线、逗号或换行分隔，留空不限制。',
  allowlistDisabled: '开启 API 后可配置 IP 白名单。',
  allowlistPlaceholder: '如 192.0.2.10 | 198.51.100.0/24，留空不限制',
  allowlistSaveHint: '失焦或回车即保存；单个 IP 按 /32（IPv6 按 /128）保存。',
  keyInfo: '密钥信息',
  keyInfoHelp: 'api_secret 只在开启或重置密钥时显示一次，请妥善保存。',
  keyInfoDisabled: 'API 未开启，暂无可用密钥。',
  apiKey: 'api_key',
  apiSecret: 'api_secret',
  secretHidden: '已隐藏，仅在开启或重置时显示一次',
  copy: '复制',
  copyKey: '复制 api_key',
  copySecret: '复制 api_secret',
  reset: '重置密钥',
  resetConfirm: '确认重置密钥？',
  resetDescription: '旧密钥立即失效，权限同步为当前账号的全部权限，新的 api_secret 只显示一次。',
  defaultKeyName: '默认密钥',
  issuedTitle: 'API 密钥已生成',
  issuedWarning: 'api_secret 只显示这一次，请立即保存。关闭后无法再次查看，遗失只能重置。',
  usage: '调用接口时在请求头携带：Authorization: CdncaKey <api_key>.<api_secret>',
  activeCount: '{{count}} 个有效密钥',
  activeCountMore: '至少 {{count}} 个有效密钥',
  advancedTitle: '高级密钥管理',
  advancedDescription: '管理多个密钥、最小权限、有效期、轮换和撤销。',
  disableConfirm: '确认关闭 API？',
  disableDescription: '当前有效密钥将立即撤销，外部程序无法继续调用。',
} as const

const enUS = {
  title: 'API access configuration',
  description: 'Manage account API keys, access status, and allowed client IP addresses.',
  status: 'API key status',
  statusHelp: 'Disabling access immediately revokes the current key and stops external API calls.',
  enabled: 'Enabled',
  disabled: 'Disabled',
  unknown: 'Status unknown',
  loading: 'Loading',
  enableHint: 'Turning this on generates a key pair with all permissions and no expiry.',
  noScopes: 'This account has no permissions that can be granted to an API key.',
  multipleHint: 'You have multiple keys. Manage them in advanced key management.',
  allowlist: 'IP allowlist',
  allowlistHelp: 'Restrict API clients by IP; separate IPs or networks with pipes, commas, or line breaks. Leave empty for no restriction.',
  allowlistDisabled: 'Enable API access before configuring an IP allowlist.',
  allowlistPlaceholder: 'For example 192.0.2.10 | 198.51.100.0/24; empty means unrestricted',
  allowlistSaveHint: 'Saved on blur or Enter. A single IP is saved as /32 (IPv6 as /128).',
  keyInfo: 'Key information',
  keyInfoHelp: 'api_secret appears only once, when access is enabled or the key is reset. Store it securely.',
  keyInfoDisabled: 'API access is disabled and no key is available.',
  apiKey: 'api_key',
  apiSecret: 'api_secret',
  secretHidden: 'Hidden; shown only once when enabled or reset',
  copy: 'Copy',
  copyKey: 'Copy api_key',
  copySecret: 'Copy api_secret',
  reset: 'Reset key',
  resetConfirm: 'Reset this key?',
  resetDescription: 'The old key stops working immediately, its permissions are refreshed to everything your account can grant, and the new api_secret is shown only once.',
  defaultKeyName: 'Default key',
  issuedTitle: 'API key generated',
  issuedWarning: 'api_secret is shown only this once. Save it now; after closing it cannot be viewed again, only reset.',
  usage: 'Send it in the request header: Authorization: CdncaKey <api_key>.<api_secret>',
  activeCount: '{{count}} active keys',
  activeCountMore: 'At least {{count}} active keys',
  advancedTitle: 'Advanced key management',
  advancedDescription: 'Manage multiple keys, least-privilege scopes, expiry, rotation, and revocation.',
  disableConfirm: 'Disable API access?',
  disableDescription: 'The active key is revoked immediately and external API calls stop.',
} as const

type MessageTree = { [key: string]: string | MessageTree }

function pseudoText(value: string): string {
  const expanded = value.split(/({{[^}]+}})/g).map((part) => part.startsWith('{{')
    ? part
    : [...part].map((character) => /\s/u.test(character) ? character : `${character}~`).join('')).join('')
  return `［${expanded}］`
}

function pseudoTree(value: unknown): unknown {
  return typeof value === 'string'
    ? pseudoText(value)
    : Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudoTree(child)]))
}

const pseudo = pseudoTree(zhCN) as MessageTree
export const apiKeyCompatibilityMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', MessageTree> = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudo,
  'qps-Ploc': pseudo,
}

for (const [locale, messages] of Object.entries(apiKeyCompatibilityMessages)) {
  i18n.addResourceBundle(locale, 'apiKeys', { compatibility: messages }, true, true)
}
