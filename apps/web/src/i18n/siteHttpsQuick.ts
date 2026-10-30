import i18n from './index'

// site-parity3a：网站列表 HTTPS 列「未开启」点击快捷开启（走站点 HTTPS 现有流程：先有绑定证书才能开）。
const zhCN = {
  open: '点击开启 HTTPS',
  title: '开启 HTTPS',
  site: '网站',
  checking: '正在检查证书绑定…',
  bound: '已绑定证书，开启后 HTTPS 入口立即可用（监听端口 {{ports}}）。',
  unbound: '这个网站还没有绑定证书，HTTPS 需要先有证书才能开启。',
  applyCertificate: '申请证书',
  chooseCertificate: '选择证书',
  confirm: '开启',
  cancel: '取消',
  success: '已开启 HTTPS',
  failed: '开启失败：{{message}}',
  loadFailed: '读取证书绑定失败，请重试',
  retry: '重试',
}
const enUS: typeof zhCN = {
  open: 'Turn on HTTPS',
  title: 'Turn on HTTPS',
  site: 'Site',
  checking: 'Checking the certificate binding…',
  bound: 'A certificate is bound; HTTPS works as soon as it is on (ports {{ports}}).',
  unbound: 'No certificate is bound to this site yet. HTTPS needs one first.',
  applyCertificate: 'Request certificate',
  chooseCertificate: 'Choose certificate',
  confirm: 'Turn on',
  cancel: 'Cancel',
  success: 'HTTPS is on',
  failed: 'Could not turn it on: {{message}}',
  loadFailed: 'Could not read the certificate binding. Try again.',
  retry: 'Retry',
}

type Messages = typeof zhCN
function pseudoText(value: string): string {
  const expanded = value.split(/({{[^}]+}})/g).map((part) => part.startsWith('{{') ? part : [...part].map((char) => /\s/u.test(char) ? char : `${char}~`).join('')).join('')
  return `［${expanded}］`
}
const pseudoCN = Object.fromEntries(Object.entries(zhCN).map(([key, value]) => [key, pseudoText(value)])) as Messages
export const siteHttpsQuickMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', Messages> = {
  'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudoCN, 'qps-Ploc': pseudoCN,
}
for (const [locale, messages] of Object.entries(siteHttpsQuickMessages)) i18n.addResourceBundle(locale, 'siteHttpsQuick', messages, true, true)
