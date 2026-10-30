import i18n from './index'

// site-parity4: 网站管理各标签页的本页摘要；fix-siteinstant: 改动即生效的轻提示。
const zhCN = {
  summary: {
    label: '本页摘要',
    jump: '跳到{{name}}',
    on: '已开启',
    off: '已关闭',
    none: '未设置',
    count: '{{count}} 条',
    cache: { unsaved: '策略有未保存修改' },
    waf: { modulesOn: '{{on}}/{{total}} 开启' },
    advanced: { uploadValue: '{{mb}} MB' },
    https: {
      bound: '已绑定', unbound: '未绑定',
      protocolSection: 'TLS 与加密套件', versionsSection: 'HTTP 协议与客户端证书',
      offWarning: '保存后本站 HTTPS 入口立即停用：HTTPS 访问失败，强制 HTTPS 跳转一并失效。',
    },
    basic: { cnameFailed: '生成失败', origins: '主 {{primary}} · 备 {{backup}}' },
    origin: {
      protocol: '回源协议',
      host: '回源 Host',
      timeout: '超时（读取/连接）',
      timeoutValue: '{{read}} 秒 / {{connect}} 秒',
      keepalive: '连接复用',
      auth: '回源鉴权',
    },
  },
  // fix-siteinstant：改动即生效的轻提示。
  instant: {
    success: '操作成功',
    failed: '操作失败，已恢复为服务端的值',
    conflict: '配置已被其他人修改，已刷新为最新值，请重新操作',
    invalid: '内容有误，未保存',
  },
}

const enUS: Messages = {
  summary: {
    label: 'Summary',
    jump: 'Go to {{name}}',
    on: 'On',
    off: 'Off',
    none: 'Not set',
    count: '{{count}}',
    cache: { unsaved: 'Unsaved policy changes' },
    waf: { modulesOn: '{{on}} of {{total}} on' },
    advanced: { uploadValue: '{{mb}} MB' },
    https: {
      bound: 'Bound', unbound: 'Not bound',
      protocolSection: 'TLS and cipher suites', versionsSection: 'HTTP versions and client certificates',
      offWarning: 'Saving turns HTTPS off for this site right away: HTTPS requests fail and the forced HTTPS redirect stops.',
    },
    basic: { cnameFailed: 'Failed', origins: '{{primary}} primary · {{backup}} backup' },
    origin: {
      protocol: 'Origin protocol',
      host: 'Origin Host',
      timeout: 'Timeout (read/connect)',
      timeoutValue: '{{read}}s / {{connect}}s',
      keepalive: 'Connection reuse',
      auth: 'Origin auth',
    },
  },
  instant: {
    success: 'Saved',
    failed: 'Not saved; the server value is restored',
    conflict: 'Someone else changed this; the latest values are loaded. Try again.',
    invalid: 'Check the value; nothing was saved',
  },
}

type Messages = { [key: string]: string | Messages }

function pseudoText(value: string): string {
  // keep {{placeholders}} intact
  return `［${value.split(/(\{\{[^}]+\}\})/u).map((part) => part.startsWith('{{') ? part : [...part].map((character) => /\s/u.test(character) ? character : `${character}~`).join('')).join('')}］`
}

function pseudo(value: Messages): Messages {
  return Object.fromEntries(Object.entries(value).map(([key, child]) => [
    key,
    typeof child === 'string' ? pseudoText(child) : pseudo(child),
  ]))
}

const pseudoCN = pseudo(zhCN)

export const siteEditV4Messages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', Messages> = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudoCN,
  'qps-Ploc': pseudoCN,
}

for (const [locale, messages] of Object.entries(siteEditV4Messages)) {
  i18n.addResourceBundle(locale, 'siteEditV4', messages, true, true)
}
