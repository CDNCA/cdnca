import i18n from './index'

// MARKET-03 buyer side: links to the agreements the operator published, read in a dialog.
const zhCN = {
  kinds: { privacy: '隐私政策', seller_terms: '服务协议' },
  version: '版本 {{version}}',
  close: '关闭',
  consent: '购买即表示同意',
  quoted: '《{{name}}》',
  footerLabel: '市场协议',
}
const enUS = {
  kinds: { privacy: 'Privacy Policy', seller_terms: 'Terms of Service' },
  version: 'Version {{version}}',
  close: 'Close',
  consent: 'By purchasing you agree to the ',
  quoted: '{{name}}',
  footerLabel: 'Marketplace agreements',
}
const pseudo = (value: string) => `［¡¡ ${value.replace(/[A-Za-z一-鿿]/g, '$&$&')} !!］`
const qps = {
  kinds: { privacy: pseudo(zhCN.kinds.privacy), seller_terms: pseudo(zhCN.kinds.seller_terms) },
  version: pseudo('版本') + ' {{version}}',
  close: pseudo(zhCN.close),
  consent: pseudo(zhCN.consent),
  quoted: '《{{name}}》',
  footerLabel: pseudo(zhCN.footerLabel),
}

for (const [locale, messages] of Object.entries({ 'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': qps, 'qps-Ploc': qps })) {
  const isProductionPseudoLocale = import.meta.env.PROD && /^qps(?:-|$)/i.test(locale)
  if (!isProductionPseudoLocale) i18n.addResourceBundle(locale, 'marketAgreements', messages, true, true)
}
