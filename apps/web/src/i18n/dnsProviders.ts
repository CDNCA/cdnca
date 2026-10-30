import i18n from './index'
import { enUS, zhCN } from './resources'

const zhProviderMessages = {
  ...zhCN.dnsProviders,
  errors: {
    ...zhCN.dnsProviders.errors,
    notFoundTitle: 'DNS 配置不存在',
    notFoundDescription: 'DNS 配置不存在或已不属于当前作用域。',
  },
} as const

const enProviderMessages = {
  ...enUS.dnsProviders,
  errors: {
    ...enUS.dnsProviders.errors,
    notFoundTitle: 'DNS configuration not found',
    notFoundDescription: 'The DNS configuration does not exist or is outside the current scope.',
  },
} as const

type MessageTree = { [key: string]: string | MessageTree }

function pseudoText(value: string): string {
  return `［${value.split(/({{[^}]+}})/g).map((part) => (
    part.startsWith('{{')
      ? part
      : [...part].map((character) => /\s|\d/u.test(character) ? character : `${character}~`).join('')
  )).join('')}］`
}

function pseudoTree(value: unknown): MessageTree {
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [
    key,
    typeof child === 'string' ? pseudoText(child) : pseudoTree(child),
  ]))
}

const pseudoProviderMessages = pseudoTree(zhProviderMessages)

export const dnsProvidersMessages: Record<
  'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc',
  MessageTree
> = {
  'zh-CN': zhProviderMessages,
  'en-US': enProviderMessages,
  'qps-ploc': pseudoProviderMessages,
  'qps-Ploc': pseudoProviderMessages,
}

for (const [locale, messages] of Object.entries(dnsProvidersMessages)) {
  i18n.addResourceBundle(locale, 'dnsProviders', messages, true, true)
}
