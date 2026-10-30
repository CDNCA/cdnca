import i18n from './index'

// ui_page plugin pages (PA-19): mounted in a sandboxed iframe.
const zhCN = {
  tab: '扩展',
  tabHint: '以下页面由已启用的插件提供，运行在插件开发者自己的网站上，看不到你的登录凭据。',
  pageHint: '本页面由插件「{{plugin}}」提供，运行在 {{origin}}。',
  notFound: '插件页面不存在或插件已停用',
  loadFailed: '插件页面加载失败：{{code}}',
}

type MessageShape<T> = { [K in keyof T]: T[K] extends string ? string : MessageShape<T[K]> }
type Messages = MessageShape<typeof zhCN>

const enUS: Messages = {
  tab: 'Extensions',
  tabHint: 'These pages come from enabled plugins. They run on the plugin developer\'s own site and cannot see your sign-in credentials.',
  pageHint: 'This page is provided by plugin "{{plugin}}" and runs on {{origin}}.',
  notFound: 'The plugin page does not exist or the plugin is disabled',
  loadFailed: 'Failed to load plugin pages: {{code}}',
}

function pseudoTree(value: unknown): unknown {
  if (typeof value === 'string') return `［${value} · ${value}］`
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudoTree(child)]))
}

const pseudo = pseudoTree(zhCN) as Messages

export const pluginUIMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', Messages> = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudo,
  'qps-Ploc': pseudo,
}

for (const [locale, messages] of Object.entries(pluginUIMessages)) {
  i18n.addResourceBundle(locale, 'pluginUI', messages, true, true)
}
