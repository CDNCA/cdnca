import i18n from './index'

const zhCN = { actions: { moreRow: '更多', manage: '管理' } }
const enUS = { actions: { moreRow: 'More', manage: 'Manage' } }
const pseudo = (value: string) => `［¡¡ ${value.replace(/[A-Za-z\u4e00-\u9fff]/g, '$&$&')} !!］`
const qps = { actions: { moreRow: pseudo('更多'), manage: pseudo('管理') } }

for (const [locale, messages] of Object.entries({ 'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': qps, 'qps-Ploc': qps })) {
  const isProductionPseudoLocale = import.meta.env.PROD && /^qps(?:-|$)/i.test(locale)
  if (!isProductionPseudoLocale) i18n.addResourceBundle(locale, 'nodes', messages, true, true)
}
