import i18n from './index'
import { enUS, zhCN } from './resources'

export type PluginWebhooksMessageTree = { [key: string]: string | PluginWebhooksMessageTree }
type MessageShape<T> = { [K in keyof T]: T[K] extends string ? string : MessageShape<T[K]> }

const zhPluginWebhooks = zhCN.pluginWebhooks
const enPluginWebhooks = enUS.pluginWebhooks satisfies MessageShape<typeof zhPluginWebhooks>

function pseudoText(value: string): string {
  const expanded = value
    .split(/({{[^}]+}})/g)
    .map((part) => part.startsWith('{{') && part.endsWith('}}')
      ? part
      : [...part].map((character) => (/\s/u.test(character) ? character : `${character}~`)).join(''))
    .join('')
  return `［${expanded}］`
}

function pseudoTree(tree: PluginWebhooksMessageTree): PluginWebhooksMessageTree {
  return Object.fromEntries(Object.entries(tree).map(([key, value]) => [
    key,
    typeof value === 'string' ? pseudoText(value) : pseudoTree(value),
  ]))
}

const pseudoPluginWebhooks = pseudoTree(zhPluginWebhooks)

export const pluginWebhooksMessages: Record<
  'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc',
  PluginWebhooksMessageTree
> = {
  'zh-CN': zhPluginWebhooks,
  'en-US': enPluginWebhooks,
  'qps-ploc': pseudoPluginWebhooks,
  'qps-Ploc': pseudoPluginWebhooks,
}

for (const [locale, messages] of Object.entries(pluginWebhooksMessages)) {
  i18n.addResourceBundle(locale, 'pluginWebhooks', messages, true, true)
}
