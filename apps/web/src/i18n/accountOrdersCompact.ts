import i18n from './index'

// the narrow 消费记录 table (type and time, amount, row details).
const messages = {
  'zh-CN': { compact: { record: '类型与时间', amount: '金额', details: '详情', detailsNamed: '详情：{{type}} {{time}}', detailTitle: '消费记录详情', close: '关闭' } },
  'en-US': { compact: { record: 'Type and time', amount: 'Amount', details: 'Details', detailsNamed: 'Details: {{type}} {{time}}', detailTitle: 'Statement entry', close: 'Close' } },
  'qps-ploc': { compact: { record: '[!! Ţÿþê åñð ţïmê !!]', amount: '[!! Åmöüñţ !!]', details: '[!! Ðêţåïls !!]', detailsNamed: '[!! Ðêţåïls: {{type}} {{time}} !!]', detailTitle: '[!! Šţåţêmêñţ êñţrÿ !!]', close: '[!! Çlöšê !!]' } },
} as const

for (const [locale, bundle] of Object.entries({ ...messages, 'qps-Ploc': messages['qps-ploc'] })) {
  i18n.addResourceBundle(locale, 'accountOrders', bundle, true, true)
}
