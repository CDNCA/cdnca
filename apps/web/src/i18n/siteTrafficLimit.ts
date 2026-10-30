import i18n from './index'

// 网站流量上限（ge-analytics）。
const zhCN = {
  title: '网站流量上限',
  hint: '与套餐无关的本站上限：超过任一上限后，所有节点对本站请求返回 509 和下方提示页，直到进入下一周期或上限调高。',
  enabled: '启用',
  daily: '每日上限 (GB)',
  monthly: '每月上限 (GB)',
  total: '总上限 (GB)',
  capPlaceholder: '不限',
  timeZone: '周期时区',
  notice: '超限提示页 (HTML)',
  noticePlaceholder: '留空使用默认提示页',
  noticeTooLarge: '提示页不能超过 64 KB',
  needCap: '启用时至少设置一个上限',
  status: {
    within: '未超限', daily: '已超出每日上限', monthly: '已超出每月上限', total: '已超出总上限',
    evaluated: '最近统计：{{time}}', totalSince: '总上限自 {{time}} 起累计',
  },
  save: '保存', saving: '保存中…', saved: '已保存，正在下发到节点。', loadFailed: '流量上限加载失败', retry: '重试',
  errors: {
    validation_error: '设置无效，请检查上限与时区', version_conflict: '网站已被修改，请刷新后重试',
    site_locked: '网站已被平台锁定', idempotency_conflict: '请求重复，请刷新后重试', unknown: '保存失败（{{code}}）',
  },
} as const

type Widen<T> = T extends string ? string : { [Key in keyof T]: Widen<T[Key]> }

const enUS: Widen<typeof zhCN> = {
  title: 'Website traffic limit',
  hint: "This website's own caps, independent of its package: once any cap is reached, every node answers its requests with 509 and the page below until the next period starts or the cap is raised.",
  enabled: 'Enabled',
  daily: 'Daily cap (GB)',
  monthly: 'Monthly cap (GB)',
  total: 'Total cap (GB)',
  capPlaceholder: 'Unlimited',
  timeZone: 'Period time zone',
  notice: 'Notice page (HTML)',
  noticePlaceholder: 'Leave empty for the default page',
  noticeTooLarge: 'The notice page must be at most 64 KB',
  needCap: 'Set at least one cap to enable the limit',
  status: {
    within: 'Within limits', daily: 'Daily cap exceeded', monthly: 'Monthly cap exceeded', total: 'Total cap exceeded',
    evaluated: 'Last measured: {{time}}', totalSince: 'Total cap counts since {{time}}',
  },
  save: 'Save', saving: 'Saving…', saved: 'Saved. Deploying to the nodes.', loadFailed: 'Failed to load the traffic limit', retry: 'Retry',
  errors: {
    validation_error: 'Invalid setting; check the caps and time zone', version_conflict: 'The website changed; refresh and retry',
    site_locked: 'The website is locked by the platform', idempotency_conflict: 'Duplicate request; refresh and retry', unknown: 'Save failed ({{code}})',
  },
}

type Messages = { [key: string]: string | Messages }

// Pseudo-locale like every other namespace: {{name}} placeholders stay intact.
function pseudoText(value: string): string {
  const expanded = value.split(/({{[^}]+}})/g).map((part) => part.startsWith('{{') ? part
    : [...part].map((character) => /\s/u.test(character) ? character : `${character}~`).join('')).join('')
  return `［${expanded}］`
}

function pseudo(value: Messages): Messages {
  return Object.fromEntries(Object.entries(value).map(([key, child]) => [
    key,
    typeof child === 'string' ? pseudoText(child) : pseudo(child),
  ]))
}

const pseudoCN = pseudo(zhCN)

export const siteTrafficLimitMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', Messages> = {
  'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudoCN, 'qps-Ploc': pseudoCN,
}

for (const [locale, messages] of Object.entries(siteTrafficLimitMessages)) {
  i18n.addResourceBundle(locale, 'siteTrafficLimit', messages, true, true)
}
