import i18n from './index'

const zhCN = {
  title: '登录地区发生变化',
  body: '检测到当前访问 IP 与登录时不在同一国家或省份。为保护账号安全，请重新输入登录密码后继续。',
  password: '登录密码',
  confirm: '验证并继续',
  wrongPassword: '密码错误，请重新输入。',
  logout: '退出登录',
}
const enUS: typeof zhCN = {
  title: 'Sign-in region changed',
  body: 'Your current IP is in a different country or province than when you signed in. Enter your password to continue.',
  password: 'Password',
  confirm: 'Verify and continue',
  wrongPassword: 'The password is incorrect. Try again.',
  logout: 'Sign out',
}
function pseudo(value: unknown): unknown {
  if (typeof value === 'string') return `［${value.split(/(\{\{[^{}]+\}\})/g).map(part => part.startsWith('{{') ? part : part.replace(/[A-Za-z\u4e00-\u9fff]/g, '$&~')).join('')}］`
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudo(child)]))
}
for (const [locale, messages] of Object.entries({ 'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudo(zhCN), 'qps-Ploc': pseudo(zhCN) })) {
  i18n.addResourceBundle(locale, 'sessionRegion', messages, true, true)
}
