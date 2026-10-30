import i18n from './index'

const zhCN = {
  title: '批量添加监听端口',
  open: '批量添加监听端口',
  description: '选择同协议的现有规则作为完整配置模板。每个端口会创建独立规则和发布意图，保存成功不代表节点已生效。',
  ports: '监听端口清单',
  portsPlaceholder: '例如：88、99/udp、443/tcp',
  portsHelp: '使用逗号、中文逗号、空格或换行分隔；未写协议时默认为 TCP。',
  tcpTemplate: 'TCP 配置模板',
  udpTemplate: 'UDP 配置模板',
  templatePlaceholder: '选择同协议现有规则',
  templateOption: '{{name}}（端口 {{port}}，修订 {{revision}}）',
  noTemplate: '当前列表没有可复用的完整正式合同模板，请先通过完整表单创建对应协议规则。',
  preview: '创建预览',
  columns: { protocol: '协议', port: '监听端口', template: '配置模板', revision: '模板修订', result: '解析结果' },
  valid: '可创建',
  create: '创建 {{count}} 条规则',
  creating: '正在创建第 {{current}}/{{total}} 条规则',
  cancel: '取消',
  completed: '已创建 {{count}} 条规则；发布意图仍需另行确认。',
  retryExact: '按原请求重试',
  abandon: '放弃并刷新',
  validation: {
    empty: '请输入至少一个监听端口',
    invalid_entry: '端口项只能使用“端口”或“端口/tcp|udp”格式',
    port_range: '监听端口必须是 1 到 65535 的整数',
    duplicate: '同一协议的监听端口不能重复',
    conflict: '监听端口已被当前规则占用',
    template: '每种协议都必须选择一条完整配置模板',
  },
  partial: {
    description: '已完成其余规则，{{count}} 条规则创建失败。刷新事实后仅重试失败规则，已成功规则不会再次提交。',
    retry: '重试 {{count}} 条失败规则',
  },
  unknown: {
    title: '创建结果尚未确认',
    description: '批量操作已暂停。请使用冻结的请求内容和幂等键重试当前端口，或放弃并刷新列表核对事实。',
  },
  errors: {
    stream_port_conflict: '监听端口已被现有资源占用',
    stream_name_conflict: '按模板生成的规则名称已存在',
    stream_shared_port_proxy_protocol: '这个端口有多个使用方（转发或网站），不能开启 PROXY 协议（入站或出站）',
    idempotency_conflict: '幂等键已绑定到不同请求',
    permission_denied: '当前账号无权创建四层转发规则',
    validation_error: '批量规则未通过服务端校验',
    request_failed: '批量创建失败，请检查当前事实后重试',
  },
}

const enUS: typeof zhCN = {
  title: 'Add listener ports in bulk',
  open: 'Add listener ports in bulk',
  description: 'Reuse an existing rule of the same protocol as the complete configuration template. Each port creates a separate rule and publication intent; saving does not prove node activation.',
  ports: 'Listener port list',
  portsPlaceholder: 'For example: 88, 99/udp, 443/tcp',
  portsHelp: 'Separate entries with commas, spaces, or line breaks. Entries without a protocol default to TCP.',
  tcpTemplate: 'TCP configuration template',
  udpTemplate: 'UDP configuration template',
  templatePlaceholder: 'Select an existing rule with the same protocol',
  templateOption: '{{name}} (port {{port}}, revision {{revision}})',
  noTemplate: 'The current list has no reusable full-contract template. Create a rule for the protocol with the complete form first.',
  preview: 'Creation preview',
  columns: { protocol: 'Protocol', port: 'Listener port', template: 'Configuration template', revision: 'Template revision', result: 'Parse result' },
  valid: 'Ready',
  create: 'Create {{count}} rules',
  creating: 'Creating rule {{current}}/{{total}}',
  cancel: 'Cancel',
  completed: 'Created {{count}} rules. Publication intent delivery still needs separate confirmation.',
  retryExact: 'Retry exact request',
  abandon: 'Abandon and refresh',
  validation: {
    empty: 'Enter at least one listener port',
    invalid_entry: 'Each entry must use the port or port/tcp|udp format',
    port_range: 'Listener ports must be integers from 1 to 65535',
    duplicate: 'A listener port cannot repeat within the same protocol',
    conflict: 'The listener port is already used by a current rule',
    template: 'Select one complete configuration template for every protocol',
  },
  partial: {
    description: 'The remaining rules completed and {{count}} rules failed. Refresh durable facts, then retry only failed rules; successful rules are not submitted again.',
    retry: 'Retry {{count}} failed rules',
  },
  unknown: {
    title: 'Creation result is unconfirmed',
    description: 'The batch is paused. Retry the current port with the frozen body and idempotency key, or abandon and refresh the list to check durable facts.',
  },
  errors: {
    stream_port_conflict: 'The listener port is already used by an existing resource',
    stream_name_conflict: 'The rule name generated from the template already exists',
    stream_shared_port_proxy_protocol: 'PROXY protocol (inbound or outbound) cannot be used on a port shared with other streams or websites',
    idempotency_conflict: 'The idempotency key is bound to a different request',
    permission_denied: 'This account cannot create layer 4 forwarding rules',
    validation_error: 'The batch rule failed server validation',
    request_failed: 'Bulk creation failed. Check current facts before retrying',
  },
}

function pseudo(value: unknown): unknown {
  if (typeof value === 'string') {
    const expanded = value.split(/({{[^}]+}})/g).map((part) => part.startsWith('{{')
      ? part
      : [...part].map((character) => /\s/u.test(character) ? character : `${character}~`).join('')).join('')
    return `［${expanded}］`
  }
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudo(child)]))
}

const pseudoCN = pseudo(zhCN) as typeof zhCN

export const streamQuickCreateMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', typeof zhCN> = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudoCN,
  'qps-Ploc': pseudoCN,
}

for (const [locale, messages] of Object.entries(streamQuickCreateMessages)) {
  i18n.addResourceBundle(locale, 'streamQuickCreate', messages, true, true)
}
