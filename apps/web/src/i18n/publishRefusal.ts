import i18n from './index'
import type { ApiError } from '../api/auth'

// ui-errmsg-1024 N17: a publish / activation refused because target nodes
// lack a rule pack or a capability names the nodes (structured error fields,
// never the server's text). Node IDs and pack digests are internal IDs.
const zhCN = {
  rulePacks: '节点 {{node}} 尚未安装网站引用的规则包（{{packs}}），已拒绝本次发布。请等规则包同步到该节点后重新发布，或联系平台管理员检查节点制品集；也可先把该节点移出线路组。',
  capability: '节点 {{node}} 不支持本次配置用到的功能（{{capability}} v{{version}}），已拒绝本次发布。请升级该节点，或去掉相应功能后重新发布。',
  others: '同样受影响的节点：{{nodes}}',
  rulePacksAutoResume: '节点 {{node}} 尚未安装网站引用的规则包（{{packs}}）。已记录本次生效，节点装好规则包后会自动下发，无需再次发布。',
}

const enUS: typeof zhCN = {
  rulePacks: 'Node {{node}} has not installed the rule packs the sites use ({{packs}}), so the release was refused. Publish again once the packs reach the node, or ask a platform administrator to check the node artifact set; you can also remove the node from the line group first.',
  capability: 'Node {{node}} does not support a feature this configuration uses ({{capability}} v{{version}}), so the release was refused. Upgrade the node, or remove the feature and publish again.',
  others: 'Also affected: {{nodes}}',
  rulePacksAutoResume: 'Node {{node}} has not installed the rule packs the sites use ({{packs}}). The activation is recorded and is delivered automatically once the node has the packs; no need to publish again.',
}

const pseudo = (value: typeof zhCN): typeof zhCN =>
  Object.fromEntries(Object.entries(value).map(([key, text]) => [key, `［${text}］`])) as typeof zhCN

for (const [locale, messages] of Object.entries({ 'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudo(zhCN), 'qps-Ploc': pseudo(zhCN) })) {
  i18n.addResourceBundle(locale, 'publishRefusal', messages, true, true)
}

const withOthers = (text: string, others: string[]) =>
  others.length ? `${text} ${i18n.t('publishRefusal:others', { nodes: others.join('、') })}` : text

/** The refusal of rule_pack_unavailable / node_capability_unavailable with
 * the nodes the server named; undefined for any other error. */
export function publishRefusalText(error: ApiError): string | undefined {
  if (error.code === 'rule_pack_unavailable' && error.rulePacks) {
    const { node_id: node, sha256, other_node_ids: others, auto_resume: autoResume } = error.rulePacks
    const key = autoResume ? 'publishRefusal:rulePacksAutoResume' : 'publishRefusal:rulePacks'
    return withOthers(i18n.t(key, { node, packs: sha256.map((digest) => digest.slice(0, 12)).join('、') }), others)
  }
  if (error.code === 'node_capability_unavailable' && error.capability) {
    const { node_id: node, capability, required_version: version, other_node_ids: others } = error.capability
    return withOthers(i18n.t('publishRefusal:capability', { node, capability: capability.replace(/^CAPABILITY_NAME_/, ''), version }), others)
  }
  return undefined
}
