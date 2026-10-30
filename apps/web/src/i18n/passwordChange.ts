import i18n from './index'

const zhCN = {
  title: '请先修改密码',
  body: '管理员要求你在本次登录时修改密码。修改完成后需要用新密码重新登录。',
  current: '当前密码',
  next: '新密码',
  confirm: '再次输入新密码',
  mismatch: '两次输入的新密码不一致。',
  submit: '修改密码',
  logout: '退出登录',
  wrongPassword: '当前密码错误，请重新输入。',
  invalid: '新密码须为 8–1024 位，至少包含大写字母、小写字母、数字、符号中的两种，且不能与当前密码相同。',
}
const enUS: typeof zhCN = {
  title: 'Change your password first',
  body: 'An administrator requires you to change your password at this sign-in. Afterwards, sign in again with the new password.',
  current: 'Current password',
  next: 'New password',
  confirm: 'Repeat the new password',
  mismatch: 'The new passwords do not match.',
  submit: 'Change password',
  logout: 'Sign out',
  wrongPassword: 'The current password is incorrect. Try again.',
  invalid: 'The new password needs 8–1024 characters with at least two of upper case, lower case, digits and symbols and must differ from the current one.',
}
function pseudo(value: unknown): unknown {
  if (typeof value === 'string') return `［${value.split(/(\{\{[^{}]+\}\})/g).map(part => part.startsWith('{{') ? part : part.replace(/[A-Za-z\u4e00-\u9fff]/g, '$&~')).join('')}］`
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudo(child)]))
}
for (const [locale, messages] of Object.entries({ 'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudo(zhCN), 'qps-Ploc': pseudo(zhCN) })) {
  i18n.addResourceBundle(locale, 'passwordChange', messages, true, true)
}
