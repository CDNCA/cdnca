import i18n from './index'

const zhCN = {
  title: '第三方服务商插件',
  intro: '第三方 DNS、短信、备案查询、支付插件安装或升级后，主控会用沙箱参数跑一遍契约测试；测试通过的插件才能启用，启用后才能被选为 DNS 服务商、短信通道、备案查询来源或收款通道。',
  columns: { plugin: '插件', kinds: '类型', contract: '契约测试', enabled: '启用', actions: '操作' },
  kinds: { dns: 'DNS', sms: '短信', icp: '备案查询', payment: '支付', mail: '邮件' },
  contract: {
    pending: '待测试', passed: '已通过', failed: '未通过', checkedAt: '测试时间 {{time}}',
    cases: '{{passed}}/{{total}} 项通过', withdrawn: '授权已失效',
  },
  status: { enabled: '已启用', disabled: '未启用', usable: '可用', highRisk: '高风险' },
  actions: { run: '重新测试', enable: '启用', disable: '停用', details: '查看用例', refresh: '刷新' },
  detail: { title: '契约测试用例 · {{id}}', passed: '通过', failed: '失败', code: '原因' },
  hints: { enableNeedsContract: '契约测试通过后才能启用', empty: '还没有已授权的第三方服务商插件', noTenant: '找不到该插件安装所属租户，无法完成二次验证' },
  confirm: {
    title: '启用支付插件 · {{id}}', intro: '支付插件属于高风险权限，需要确认风险并通过 MFA 二次验证。',
    risk: '我已阅读以上风险提示，确认启用该支付插件', method: '验证方式', totp: '身份验证器', recovery: '恢复码',
    code: '验证码', submit: '验证并启用', cancel: '取消', needRisk: '请先确认风险提示', needCode: '请输入验证码',
  },
  messages: { ran: '契约测试已完成', enabled: '已启用', disabled: '已停用' },
  errors: {
    loadFailed: '读取服务商插件失败', actionFailed: '操作失败',
    codes: {
      plugin_provider_contract_not_passed: '契约测试未通过，不能启用', plugin_provider_not_active: '插件授权已失效',
      plugin_provider_changed: '插件刚刚升级，请刷新后重试', plugin_provider_unavailable: '服务暂不可用，请稍后重试',
      permission_denied: '没有权限',
      plugin_provider_risk_not_acknowledged: '启用支付插件前需要确认风险提示',
      plugin_provider_step_up_required: '二次验证未通过，请重新输入验证码',
    },
  },
}

type Messages = typeof zhCN

const enUS: Messages = {
  title: 'Third-party provider plugins',
  intro: 'When a third-party DNS, SMS, ICP lookup or payment plugin is installed or upgraded, the control plane runs its contract test against the plugin sandbox. Only a plugin that passed can be enabled, and only an enabled plugin can be chosen as a DNS provider, SMS channel, ICP lookup source or payment channel.',
  columns: { plugin: 'Plugin', kinds: 'Kinds', contract: 'Contract test', enabled: 'Enabled', actions: 'Actions' },
  kinds: { dns: 'DNS', sms: 'SMS', icp: 'ICP lookup', payment: 'Payment', mail: 'Email' },
  contract: {
    pending: 'Pending', passed: 'Passed', failed: 'Failed', checkedAt: 'Tested {{time}}',
    cases: '{{passed}}/{{total}} cases passed', withdrawn: 'No longer authorized',
  },
  status: { enabled: 'Enabled', disabled: 'Disabled', usable: 'Usable', highRisk: 'High risk' },
  actions: { run: 'Run again', enable: 'Enable', disable: 'Disable', details: 'Cases', refresh: 'Refresh' },
  detail: { title: 'Contract cases · {{id}}', passed: 'Passed', failed: 'Failed', code: 'Reason' },
  hints: { enableNeedsContract: 'The contract test must pass before enabling', empty: 'No authorized third-party provider plugin yet', noTenant: 'The tenant of this plugin installation is unknown; step-up verification is not possible' },
  confirm: {
    title: 'Enable payment plugin · {{id}}', intro: 'A payment plugin is a high-risk permission: acknowledge the risk and pass an MFA step-up.',
    risk: 'I have read the risk notice above and want to enable this payment plugin', method: 'Method', totp: 'Authenticator app', recovery: 'Recovery code',
    code: 'Code', submit: 'Verify and enable', cancel: 'Cancel', needRisk: 'Acknowledge the risk notice first', needCode: 'Enter the code',
  },
  messages: { ran: 'Contract test finished', enabled: 'Enabled', disabled: 'Disabled' },
  errors: {
    loadFailed: 'Could not load provider plugins', actionFailed: 'The action failed',
    codes: {
      plugin_provider_contract_not_passed: 'The contract test has not passed; the plugin cannot be enabled',
      plugin_provider_not_active: 'The plugin is no longer authorized',
      plugin_provider_changed: 'The plugin was just upgraded; refresh and try again',
      plugin_provider_unavailable: 'Temporarily unavailable; try again later', permission_denied: 'Permission denied',
      plugin_provider_risk_not_acknowledged: 'Acknowledge the risk notice before enabling a payment plugin',
      plugin_provider_step_up_required: 'Step-up verification failed; enter a new code',
    },
  },
}

function pseudoTree(value: unknown): unknown {
  if (typeof value === 'string') return `［${value} · ${value}］`
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudoTree(child)]))
}

const pseudo = pseudoTree(zhCN) as Messages

export const pluginProvidersMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', Messages> = {
  'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudo, 'qps-Ploc': pseudo,
}

for (const [locale, messages] of Object.entries(pluginProvidersMessages)) {
  i18n.addResourceBundle(locale, 'pluginProviders', messages, true, true)
}
