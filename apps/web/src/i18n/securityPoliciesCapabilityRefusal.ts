import i18n from './index'

// A release refused because target nodes lack a capability the rule set
// uses (node_capability_unavailable): name the nodes; there is no weaker
// variant to publish instead.
const zhCN = {
  capabilityRefusal: {
    hint: '目标节点版本不支持这个规则集用到的功能，请先升级节点，或去掉该功能后重新发布。',
  },
}

type Messages = typeof zhCN

const enUS: Messages = {
  capabilityRefusal: {
    hint: 'A target node does not support a feature this rule set uses. Upgrade the node first, or remove the feature and publish again.',
  },
}

function pseudo(value: unknown): unknown {
  if (typeof value === 'string') return `［${value}］`
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudo(child)]))
}

export const capabilityRefusalMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', Messages> = {
  'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudo(zhCN) as Messages, 'qps-Ploc': pseudo(zhCN) as Messages,
}

for (const [locale, messages] of Object.entries(capabilityRefusalMessages)) {
  i18n.addResourceBundle(locale, 'securityPolicies', messages, true, true)
}
