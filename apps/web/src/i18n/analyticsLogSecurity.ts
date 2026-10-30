import i18n from './index'

export type AnalyticsLogSecurityMessages = { [key: string]: string | AnalyticsLogSecurityMessages }

const zhCN = {
  redacted: '已脱敏',
  responseBody: '响应体',
} as const

const enUS = {
  redacted: 'Redacted',
  responseBody: 'Response body',
} as const

function pseudoText(value: string): string {
  return `［${[...value].map((character) => /\s|\d/u.test(character) ? character : `${character}~`).join('')}］`
}

function pseudoTree(value: unknown): unknown {
  return typeof value === 'string'
    ? pseudoText(value)
    : Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudoTree(child)]))
}

const pseudo = pseudoTree(zhCN) as AnalyticsLogSecurityMessages

export const analyticsLogSecurityMessages: Record<
  'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc',
  AnalyticsLogSecurityMessages
> = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudo,
  'qps-Ploc': pseudo,
}

for (const [locale, messages] of Object.entries(analyticsLogSecurityMessages)) {
  i18n.addResourceBundle(locale, 'analyticsLogSecurity', messages, true, true)
}
