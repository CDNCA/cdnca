import i18n from './index'

const zhCN = {
  title: '后台访问白名单',
  intro: '开启后，平台管理员只能从下列 IP 或网段登录和使用管理后台；租户用户和 API 密钥不受影响。',
  enabled: '启用白名单',
  allowlist: '允许的 IP 或网段',
  allowlistPlaceholder: '每行一个，如 203.0.113.5 或 10.0.0.0/8',
  currentIP: '你当前的 IP：{{ip}}',
  currentUnknown: '无法识别你当前的 IP，开启前请确认反向代理已正确传递来源地址。',
  addCurrent: '加入当前 IP',
  save: '保存',
  saved: '已保存',
  confirmTitle: '确认保存后台访问白名单？',
  confirmContent: '保存后不在白名单的 IP（包括你当前的 IP：{{ip}}）将无法访问后台。',
  confirmUnknownIP: '无法识别',
  confirmOk: '确认保存',
  confirmCancel: '取消',
  recoveryTitle: '被锁在外面怎么办',
  recovery: '本机回环地址（127.0.0.1、::1）始终允许，可通过 SSH 隧道访问控制台。也可以在控制端主机上以 root 运行：',
  recoveryCommand: 'DATABASE_URL=… control-api admin-access-allowlist disable',
  recoveryAfter: '该命令关闭白名单（保留列表）并记录审计日志。',
  errors: {
    admin_access_self_lockout: '保存后你当前的 IP 将无法访问后台，请先把当前 IP 加入白名单。',
    validation_error: '白名单格式无效，或开启时列表为空。',
    version_conflict: '白名单已被他人修改，请刷新后重试。',
    admin_access_denied: '当前 IP 不在后台访问白名单内。',
  },
}
const enUS: typeof zhCN = {
  title: 'Administration access allowlist',
  intro: 'When on, platform administrators can sign in to and use the console only from these IP addresses or ranges. Tenant users and API keys are not affected.',
  enabled: 'Enable allowlist',
  allowlist: 'Allowed IP addresses or ranges',
  allowlistPlaceholder: 'One per line, e.g. 203.0.113.5 or 10.0.0.0/8',
  currentIP: 'Your current IP: {{ip}}',
  currentUnknown: 'Your current IP could not be determined. Check that the reverse proxy forwards the client address before turning this on.',
  addCurrent: 'Add current IP',
  save: 'Save',
  saved: 'Saved',
  confirmTitle: 'Save the administration access allowlist?',
  confirmContent: 'After saving, IPs not on the allowlist (including your current IP: {{ip}}) can no longer reach the console.',
  confirmUnknownIP: 'unknown',
  confirmOk: 'Save',
  confirmCancel: 'Cancel',
  recoveryTitle: 'If you are locked out',
  recovery: 'Loopback (127.0.0.1, ::1) is always allowed, so the console stays reachable through an SSH tunnel. Or run as root on the control host:',
  recoveryCommand: 'DATABASE_URL=… control-api admin-access-allowlist disable',
  recoveryAfter: 'The command turns the allowlist off (the list is kept) and writes an audit event.',
  errors: {
    admin_access_self_lockout: 'Saving would block your current IP. Add your current IP first.',
    validation_error: 'The allowlist is invalid, or empty while enabled.',
    version_conflict: 'Someone else changed the allowlist. Refresh and try again.',
    admin_access_denied: 'Your current IP is not in the administration access allowlist.',
  },
}
function pseudo(value: unknown): unknown {
  if (typeof value === 'string') return `［${value.split(/(\{\{[^{}]+\}\})/g).map(part => part.startsWith('{{') ? part : part.replace(/[A-Za-z\u4e00-\u9fff]/g, '$&~')).join('')}］`
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudo(child)]))
}
export const adminAccessMessages = { 'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudo(zhCN), 'qps-Ploc': pseudo(zhCN) }
for (const [locale, messages] of Object.entries(adminAccessMessages)) {
  i18n.addResourceBundle(locale, 'adminAccess', messages, true, true)
}
