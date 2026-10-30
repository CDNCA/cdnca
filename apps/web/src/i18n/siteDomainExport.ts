import i18n from './index'

type MessageTree = { [key: string]: string | MessageTree }

const zhCN = {
  progress: '正在生成网站域名导出文件',
  success: '网站域名导出已开始',
  target: { title: '选择导出的租户', label: '目标租户', placeholder: '搜索用户名、邮箱、用户ID或粘贴作用域 UUID', empty: '没有匹配的用户' },
  errors: {
    unsupportedFilters: '当前筛选包含导出合同不支持的条件，请清除后重试。',
    platformTargetRequired: '请先选择要导出的租户。',
    forbidden: '当前账号没有网站域名导出权限。',
    failed: '网站域名导出失败，请稍后重试。',
  },
} satisfies MessageTree

const enUS: typeof zhCN = {
  progress: 'Generating the site-domain export',
  success: 'The site-domain export has started',
  target: { title: 'Choose the tenant to export', label: 'Target tenant', placeholder: 'Search username, email, user ID or paste a scope UUID', empty: 'No matching users' },
  errors: {
    unsupportedFilters: 'The active filters are not supported by the export contract. Clear them and try again.',
    platformTargetRequired: 'Select the tenant to export first.',
    forbidden: 'Your account cannot export site domains.',
    failed: 'The site-domain export failed. Try again later.',
  },
}

function pseudoText(value: string): string {
  return `［${[...value].map((character) => /\s/u.test(character) ? character : `${character}~`).join('')}］`
}

function pseudoTree(tree: MessageTree): MessageTree {
  return Object.fromEntries(Object.entries(tree).map(([key, value]) => [
    key,
    typeof value === 'string' ? pseudoText(value) : pseudoTree(value),
  ]))
}

const pseudoCN = pseudoTree(zhCN)
export const siteDomainExportMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', MessageTree> = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudoCN,
  'qps-Ploc': pseudoCN,
}

for (const [locale, messages] of Object.entries(siteDomainExportMessages)) {
  i18n.addResourceBundle(locale, 'siteDomainExport', messages, true, true)
}
