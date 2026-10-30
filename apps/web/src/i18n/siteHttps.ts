import i18n from './index'

type Messages = { [key: string]: string | Messages }

const zhCN = {
  title: 'HTTPS证书',
  access: {
    label: 'HTTPS访问',
    help: '关闭后，HTTPS 入口将不可用；开启后可配置证书和监听端口。',
    disabled: 'HTTPS 未开启，证书、协议和相关增强功能暂不生效。',
    certificateRequired: '还没有绑定证书：请先在下方选择证书（选中即绑定），再开启 HTTPS 和强制跳转。',
  },
  ports: {
    label: 'HTTPS监听端口',
    help: '多个端口使用空格、英文逗号或换行分隔。',
    placeholder: '例如：443 8443',
  },
  tls: {
    label: 'TLS协议',
  },
  force: {
    label: '强制HTTPS',
    help: '开启后 HTTP 访问 301 跳转到 HTTPS（证书验证路径 /.well-known/acme-challenge/ 除外）。新建网站默认跟随系统设置。',
    port: '跳转端口',
    firstPort: '第一个监听端口',
  },
  certificate: {
    label: '证书',
    placeholder: '请选择覆盖当前网站域名的证书',
    help: '这里只显示已激活的证书版本；控制面会校验证书是否覆盖网站全部域名。',
    noAssets: '暂无可用证书，请先申请或上传并激活证书。',
    unavailable: '当前账号无权读取证书资产，仍可保存 HTTPS 开关、端口和 TLS 协议。',
    scopeMissing: '网站响应缺少租户作用域，平台管理员暂时不能读取或绑定该网站的证书。请刷新后重试。',
    manage: '证书管理',
    binding: '正在绑定证书…',
    unbinding: '正在解绑证书…',
    unbindConfirmTitle: '解绑证书？',
    unbindConfirm: '本站已开启 HTTPS，解绑后 HTTPS 入口没有证书可用，强制 HTTPS 与 HSTS 随之失效。',
    unbindOk: '解绑',
    unbindCancel: '取消',
    current: '当前绑定',
    none: '不绑定证书',
  },
  feedback: {
    conflict: '证书绑定已被其他操作修改，已刷新最新状态，请重新选择。',
    outcomeUnknown: '证书操作结果未知，使用同一请求重试或刷新核对。',
    refreshed: '已刷新证书绑定状态。',
  },
  actions: {
    retry: '重试',
    retrySameRequest: '使用同一请求重试',
    refresh: '刷新核对',
  },
  errors: {
    load: '证书资产加载失败，请稍后重试。',
    invalidResponse: '证书服务返回了无效数据，请刷新后重试。',
    permission: '当前账号缺少证书资产权限。',
    request: '证书操作失败，请稍后重试。',
  },
} satisfies Messages

const enUS = {
  title: 'HTTPS certificate',
  access: {
    label: 'HTTPS access',
    help: 'Disabling HTTPS removes the HTTPS ingress. Enable it to configure certificates and listen ports.',
    disabled: 'HTTPS is disabled. Certificates, protocols, and related enhancements are inactive.',
    certificateRequired: 'No certificate is bound. Choose a certificate below (it is bound at once) before turning on HTTPS or forced HTTPS.',
  },
  ports: {
    label: 'HTTPS listen ports',
    help: 'Separate multiple ports with spaces, commas, or new lines.',
    placeholder: 'For example: 443 8443',
  },
  tls: { label: 'TLS protocols' },
  force: {
    label: 'Force HTTPS',
    help: 'Redirect HTTP requests to HTTPS (301), except certificate validation under /.well-known/acme-challenge/. New sites follow the system default.',
    port: 'Redirect port',
    firstPort: 'First listen port',
  },
  certificate: {
    label: 'Certificate',
    placeholder: 'Select a certificate that covers every site domain',
    help: 'Only active certificate versions are shown. The control plane verifies coverage for every site domain.',
    noAssets: 'No active certificate is available. Request or upload and activate one first.',
    unavailable: 'This account cannot read certificate assets. HTTPS access, ports, and TLS protocols can still be saved.',
    scopeMissing: 'The site response does not include its tenant scope, so a platform operator cannot read or bind its certificate. Refresh and try again.',
    manage: 'Manage certificates',
    binding: 'Binding the certificate…',
    unbinding: 'Unbinding the certificate…',
    unbindConfirmTitle: 'Unbind the certificate?',
    unbindConfirm: 'HTTPS is on for this site. Without a certificate the HTTPS listener stops working, and forced HTTPS and HSTS stop with it.',
    unbindOk: 'Unbind',
    unbindCancel: 'Cancel',
    current: 'Current binding',
    none: 'No certificate',
  },
  feedback: {
    conflict: 'Another operation changed this certificate binding. The latest state has been loaded; select again.',
    outcomeUnknown: 'The certificate outcome is unknown. Retry the same request or refresh to reconcile it.',
    refreshed: 'The certificate binding has been refreshed.',
  },
  actions: { retry: 'Retry', retrySameRequest: 'Retry same request', refresh: 'Refresh and reconcile' },
  errors: {
    load: 'Failed to load certificate assets. Try again later.',
    invalidResponse: 'The certificate service returned invalid data. Refresh and try again.',
    permission: 'This account lacks certificate asset permission.',
    request: 'The certificate operation failed. Try again later.',
  },
} satisfies Messages

function pseudoText(value: string): string {
  return `［${value
    .split(/({{[^}]+}})/g)
    .map((part) => part.startsWith('{{') ? part : [...part].map((character) => /\s|\d/u.test(character) ? character : `${character}~`).join(''))
    .join('')}］`
}

function pseudo(value: Messages): Messages {
  return Object.fromEntries(Object.entries(value).map(([key, child]) => [
    key,
    typeof child === 'string' ? pseudoText(child) : pseudo(child),
  ]))
}

const pseudoCN = pseudo(zhCN)

export const siteHttpsMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', Messages> = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudoCN,
  'qps-Ploc': pseudoCN,
}

for (const [locale, messages] of Object.entries(siteHttpsMessages)) {
  i18n.addResourceBundle(locale, 'siteHttps', messages, true, true)
}
