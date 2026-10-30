import i18n from './index'

const zhCN = {
  title: '域名与监听端口',
  description: 'HTTP 始终开启；HTTPS 可独立开关。保存的是控制面期望状态，不代表节点已经生效。',
  fields: {
    domain: '域名',
    httpEnabled: 'HTTP 监听',
    httpPorts: 'HTTP监听端口',
    ipv6Enabled: 'IPv6 监听',
    ipv6Runtime: 'IPv6 运行状态',
    httpsEnabled: 'HTTPS 监听',
    httpsPorts: 'HTTPS监听端口',
  },
  values: { enabled: '已开启' },
  help: {
    domain: '每行填写一个域名，最多 100 个；支持 *.example.com 通配符。',
    http: 'HTTP 必须保持开启。',
    ports: '多个端口使用空格或英文逗号分隔。',
    ipv6: '开关表示期望状态；运行状态由节点成功激活并回报后更新。',
  },
  runtime: { disabled: '未启用', pending: '待生效', active: '已生效', failed: '生效失败' },
  validation: {
    domains: '请输入 1 到 100 个有效且不重复的域名，可使用 *.example.com 通配符。',
    httpsPorts: '启用 HTTPS 时必须填写 1 到 32 个不重复的 1-65535 端口。',
    portConflict: 'HTTP 与 HTTPS 监听端口不能重复。',
  },
}

const enUS: typeof zhCN = {
  title: 'Domains and listener ports',
  description: 'HTTP is always enabled; HTTPS can be toggled independently. Saving changes control-plane desired state and does not prove node activation.',
  fields: {
    domain: 'Domain',
    httpEnabled: 'HTTP listener',
    httpPorts: 'HTTP listener ports',
    ipv6Enabled: 'IPv6 listener',
    ipv6Runtime: 'IPv6 runtime state',
    httpsEnabled: 'HTTPS listener',
    httpsPorts: 'HTTPS listener ports',
  },
  values: { enabled: 'Enabled' },
  help: {
    domain: 'Enter one domain per line, up to 100. Wildcards such as *.example.com are supported.',
    http: 'HTTP must remain enabled.',
    ports: 'Separate multiple ports with spaces or commas.',
    ipv6: 'The switch is desired state. Runtime state changes only after edge activation is reported.',
  },
  runtime: { disabled: 'Disabled', pending: 'Pending', active: 'Active', failed: 'Failed' },
  validation: {
    domains: 'Enter 1 to 100 valid unique domains. Wildcards such as *.example.com are supported.',
    httpsPorts: 'When HTTPS is enabled, enter 1 to 32 unique ports from 1 to 65535.',
    portConflict: 'HTTP and HTTPS listener ports must not overlap.',
  },
}

type MessageTree = { [key: string]: string | MessageTree }

function pseudoText(value: string): string {
  return `［${[...value].map((character) => /\s/u.test(character) ? character : `${character}~`).join('')}］`
}

function pseudoTree(tree: MessageTree): MessageTree {
  return Object.fromEntries(Object.entries(tree).map(([key, value]) => [
    key,
    typeof value === 'string' ? pseudoText(value) : pseudoTree(value),
  ]))
}

const pseudoCN = pseudoTree(zhCN)
export const siteListenerDomainMessages: Record<
  'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc',
  MessageTree
> = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudoCN,
  'qps-Ploc': pseudoCN,
}

for (const [locale, messages] of Object.entries(siteListenerDomainMessages)) {
  i18n.addResourceBundle(locale, 'siteListenerDomains', messages, true, true)
}
