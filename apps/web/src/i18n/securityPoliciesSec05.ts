import i18n from './index'

type Messages = { [key: string]: string | Messages }

const zhCN = {
  editor: {
    aclImport: '批量导入',
    aclImportHint: '每行一条：allow 或 block + CIDR，可追加 expires=UTC时间 和 # 注释。导入时忽略下方手工规则。',
    aclImportPlaceholder: 'allow 192.0.2.42 # 运维出口\nblock 192.0.2.0/24 expires=2030-01-02T03:04:05Z # 临时拦截',
    comment: '注释',
    expiresAt: '有效期至（UTC）',
    expiresPlaceholder: '例如 2030-01-02T03:04:05Z',
  },
  errors: { acl_import_invalid: '批量导入包含无效行，请按行修正。' },
  import: {
    lineError: '第 {{line}} 行：{{reason}}',
    invalid_action: '动作必须是 allow 或 block',
    invalid_cidr: 'CIDR 或 IP 地址无效',
    invalid_expiry: '有效期必须是 UTC 秒精度时间',
    invalid_comment: '注释为空、过长或包含控制字符',
    invalid_syntax: '格式无效',
    duplicate_cidr: 'CIDR 重复',
    too_many_entries: '规则数量超过 100 条',
    invalid_size: '导入内容为空、过大或编码无效',
    empty_import: '没有可导入的规则',
  },
} as const

const enUS = {
  editor: {
    aclImport: 'Bulk import',
    aclImportHint: 'One entry per line: allow or block plus CIDR, optionally expires=UTC-time and # comment. Imported entries replace the manual rules below.',
    aclImportPlaceholder: 'allow 192.0.2.42 # operations egress\nblock 192.0.2.0/24 expires=2030-01-02T03:04:05Z # temporary block',
    comment: 'Comment',
    expiresAt: 'Expires at (UTC)',
    expiresPlaceholder: 'e.g. 2030-01-02T03:04:05Z',
  },
  errors: { acl_import_invalid: 'The bulk import contains invalid lines. Correct each reported line.' },
  import: {
    lineError: 'Line {{line}}: {{reason}}',
    invalid_action: 'Action must be allow or block',
    invalid_cidr: 'CIDR or IP address is invalid',
    invalid_expiry: 'Expiration must be a UTC timestamp with second precision',
    invalid_comment: 'Comment is empty, too long, or contains control characters',
    invalid_syntax: 'Syntax is invalid',
    duplicate_cidr: 'CIDR is duplicated',
    too_many_entries: 'The import exceeds 100 rules',
    invalid_size: 'Import is empty, too large, or has invalid encoding',
    empty_import: 'No importable rules were found',
  },
} as const

function pseudo(value: unknown): unknown {
  if (typeof value === 'string') return `［${value}］`
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, item]) => [key, pseudo(item)]))
}

const bundles: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', Messages> = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudo(zhCN) as Messages,
  'qps-Ploc': pseudo(zhCN) as Messages,
}

for (const [locale, messages] of Object.entries(bundles)) {
  i18n.addResourceBundle(locale, 'securityPolicies', messages, true, true)
}

export { bundles as securityPoliciesSec05Messages }
