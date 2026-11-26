import i18n from './index'

const zhCN = {
  title: 'API 访问配置',
  status: 'API 密钥状态',
  statusHelp: '关闭后将撤销当前 API 密钥，外部程序无法继续调用接口。',
  enabled: '已开启',
  disabled: '未开启',
  unknown: '状态未知',
  loading: '加载中',
  noScopes: '当前账号没有可授予 API 的权限，无法开启。',
  createCompatible: '创建兼容密钥',
  compatibleConfirm: '创建兼容密钥？',
  compatibleDescription: '兼容密钥拥有当前账号可授予的全部 {{count}} 项权限，且永不过期，用于旧接入。',
  multipleHint: '你有多个密钥，请在高级密钥管理里操作。',
  allowlist: 'IP 白名单',
  allowlistPlaceholder: '如 192.0.2.10 | 198.51.100.0/24，留空不限制',
  allowlistSaveHint: '失焦或回车即保存；单个 IP 按 /32（IPv6 按 /128）保存。',
  keyInfo: '密钥信息',
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
  disableConfirm: '确认关闭 API？',
  disableDescription: '当前有效密钥将立即撤销，外部程序无法继续调用。',
  impersonationReadOnly: '代登录期间仅可查看密钥，创建、修改、轮换或撤销请由用户本人登录后操作。',
  expired: '已到期',
  allowlistSaving: '正在保存…',
  allowlistSaved: '已保存',
  allowlistUnsaved: '有未保存的修改，失焦或回车保存。',
  allowlistConflict: '白名单已被其他操作修改，你的修改尚未保存。',
  allowlistServerValue: '当前已保存',
  allowlistDraftValue: '你的修改',
  allowlistUseServer: '采用新版',
  allowlistKeepDraft: '继续编辑',
  allowlistOrphaned: '你正在编辑的密钥已被撤销、到期或替换，未保存的白名单修改没有提交。',
  allowlistDismiss: '知道了',
  expiredHelp: '密钥已于 {{time}} 到期，外部程序已无法调用。开启 API 会生成一把新的默认密钥；旧密钥可在高级密钥管理中查看或撤销。',
  expiringSoon: '密钥将于 {{time}} 到期，到期后外部程序无法调用。如需继续使用，请在高级密钥管理中调整到期时间或创建新密钥。',
} as const

const enUS = {
  title: 'API access configuration',
  status: 'API key status',
  statusHelp: 'Disabling access immediately revokes the current key and stops external API calls.',
  enabled: 'Enabled',
  disabled: 'Disabled',
  unknown: 'Status unknown',
  loading: 'Loading',
  noScopes: 'This account has no permissions that can be granted to an API key.',
  createCompatible: 'Create compatibility key',
  compatibleConfirm: 'Create a compatibility key?',
  compatibleDescription: 'A compatibility key has all {{count}} permissions this account can grant and never expires; it is for existing integrations.',
  multipleHint: 'You have multiple keys. Manage them in advanced key management.',
  allowlist: 'IP allowlist',
  allowlistPlaceholder: 'For example 192.0.2.10 | 198.51.100.0/24; empty means unrestricted',
  allowlistSaveHint: 'Saved on blur or Enter. A single IP is saved as /32 (IPv6 as /128).',
  keyInfo: 'Key information',
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
  disableConfirm: 'Disable API access?',
  disableDescription: 'The active key is revoked immediately and external API calls stop.',
  impersonationReadOnly: 'While signed in on behalf of this user you can only view keys. The user must create, change, rotate or revoke keys from their own account.',
  expired: 'Expired',
  allowlistSaving: 'Saving…',
  allowlistSaved: 'Saved',
  allowlistUnsaved: 'Unsaved changes. Leave the field or press Enter to save.',
  allowlistConflict: 'The allowlist was changed by another operation. Your edit has not been saved.',
  allowlistServerValue: 'Currently saved',
  allowlistDraftValue: 'Your edit',
  allowlistUseServer: 'Use the new version',
  allowlistKeepDraft: 'Keep editing',
  allowlistOrphaned: 'The key you were editing was revoked, expired or replaced. Your unsaved allowlist edit was not submitted.',
  allowlistDismiss: 'Dismiss',
  expiredHelp: 'The key expired at {{time}} and external programs can no longer call the API. Turning API access on generates a new default key; the old key stays in advanced key management to view or revoke.',
  expiringSoon: 'The key expires at {{time}}. After that external programs cannot call the API. To keep using it, change its expiry or create a new key in advanced key management.',
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
