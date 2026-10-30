import i18n from './index'
import { enUS, zhCN } from './resources'

type SitePublicationsMessages = { [key: string]: string | SitePublicationsMessages }

function cloneTree(tree: SitePublicationsMessages): SitePublicationsMessages {
  return Object.fromEntries(Object.entries(tree).map(([key, value]) => [
    key,
    typeof value === 'string' ? value : cloneTree(value),
  ]))
}

function pseudoText(value: string): string {
  return `［${value.split(/({{[^}]+}})/g).map((part) => (
    part.startsWith('{{')
      ? part
      : [...part].map((character) => /\s|\d/u.test(character) ? character : `${character}~`).join('')
  )).join('')}］`
}

function pseudoTree(tree: SitePublicationsMessages): SitePublicationsMessages {
  return Object.fromEntries(Object.entries(tree).map(([key, value]) => [
    key,
    typeof value === 'string' ? pseudoText(value) : pseudoTree(value),
  ]))
}

const zhSitePublications = cloneTree(zhCN.sitePublications as unknown as SitePublicationsMessages)
const enSitePublications = cloneTree(enUS.sitePublications as unknown as SitePublicationsMessages)

Object.assign(zhSitePublications.actions as SitePublicationsMessages, {
  start: '开始发布', pause: '暂停', resume: '继续',
})
Object.assign(zhSitePublications.notices as SitePublicationsMessages, {
  start: '灰度发布已开始', pause: '灰度发布已暂停', resume: '灰度发布已继续',
})
Object.assign(zhSitePublications.states as SitePublicationsMessages, { paused: '已暂停' })
Object.assign(zhSitePublications.values as SitePublicationsMessages, { yes: '是', no: '否' })
Object.assign(zhSitePublications, {
  rollout: {
    strategy: '灰度策略', canary: '金丝雀分批', canarySize: '首批节点数', batchSize: '后续每批节点数',
    failureThreshold: '单批失败暂停阈值', releasedCohort: '已释放批次', cohort: '批次', released: '已释放',
    autoStart: '创建后立即开始',
  },
  pauseReasons: { operator: '管理员暂停', failure_threshold: '失败达到自动暂停阈值' },
})
Object.assign(enSitePublications.actions as SitePublicationsMessages, {
  start: 'Start', pause: 'Pause', resume: 'Resume',
})
Object.assign(enSitePublications.notices as SitePublicationsMessages, {
  start: 'Progressive rollout started', pause: 'Progressive rollout paused', resume: 'Progressive rollout resumed',
})
Object.assign(enSitePublications.states as SitePublicationsMessages, { paused: 'Paused' })
Object.assign(enSitePublications.values as SitePublicationsMessages, { yes: 'Yes', no: 'No' })
Object.assign(enSitePublications, {
  rollout: {
    strategy: 'Rollout strategy', canary: 'Canary batches', canarySize: 'Canary nodes', batchSize: 'Nodes per batch',
    failureThreshold: 'Per-batch failure threshold', releasedCohort: 'Released cohort', cohort: 'Cohort', released: 'Released',
    autoStart: 'Start after creation',
  },
  pauseReasons: { operator: 'Paused by operator', failure_threshold: 'Failure threshold reached' },
})
const zhLineSwitch = zhSitePublications.lineSwitch as SitePublicationsMessages
const enLineSwitch = enSitePublications.lineSwitch as SitePublicationsMessages
Object.assign(zhLineSwitch.actions as SitePublicationsMessages, {
  retryExact: '按原命令重试',
  abandonRefresh: '放弃并刷新事实',
  retryRead: '重新读取',
})
Object.assign(zhLineSwitch.fields as SitePublicationsMessages, { dnsGate: 'DNS 切换' })
Object.assign(zhLineSwitch, {
  dnsGate: {
    retarget_pending: '等待解析切走旧节点（{{pending}}/{{owners}} 个域名未完成），旧节点端口保持监听',
    propagation_wait: '解析已切换，等待 DNS 缓存过期（预计 {{readyAt}} 后排空旧节点端口）',
    timeout: '在整体期限内 DNS 未切离旧节点，已恢复旧线路；请检查 DNS 解析任务后重试',
  },
})
Object.assign(enLineSwitch.fields as SitePublicationsMessages, { dnsGate: 'DNS cutover' })
Object.assign(enLineSwitch, {
  dnsGate: {
    retarget_pending: 'Waiting for DNS to leave the old nodes ({{pending}} of {{owners}} hostnames pending); old listeners stay open',
    propagation_wait: 'DNS switched; waiting for resolver caches to expire (old listeners drain after {{readyAt}})',
    timeout: 'DNS did not leave the old nodes before the deadline, so the old line was restored. Check the DNS tasks and retry.',
  },
})
Object.assign(zhLineSwitch.errors as SitePublicationsMessages, {
  forbidden: '没有权限执行线路切换',
  readForbidden: '没有权限读取线路切换状态',
  notFound: '线路切换记录不存在',
  conflict: '线路切换状态已变化，请刷新后重试',
  invalid: '线路切换请求无效',
})
Object.assign(zhLineSwitch, {
  unknown: {
    title: '线路切换结果未知',
    description: '服务可能已经接收原命令。请按原命令重试，或放弃并读取服务端最新事实。',
  },
})
Object.assign(enLineSwitch.actions as SitePublicationsMessages, {
  retryExact: 'Retry exact command',
  abandonRefresh: 'Abandon and refresh facts',
  retryRead: 'Read again',
})
Object.assign(enLineSwitch.errors as SitePublicationsMessages, {
  forbidden: 'You do not have permission to switch line groups',
  readForbidden: 'You do not have permission to read the line-group switch state',
  notFound: 'The line-group switch no longer exists',
  conflict: 'The line-group switch state changed. Refresh and retry.',
  invalid: 'The line-group switch request is invalid',
})
Object.assign(enLineSwitch, {
  unknown: {
    title: 'Line-group switch outcome unknown',
    description: 'The service may have accepted the original command. Retry it exactly, or abandon it and read the latest server facts.',
  },
})
// node_capability_unavailable: the whole release is refused; error.capability
// names the nodes to upgrade (same list as SecurityActivationPanel).
Object.assign(zhSitePublications.errors as SitePublicationsMessages, {
  capabilityRefusal: '部分目标节点版本过低，不支持这次配置用到的功能，已拒绝整次发布。请升级这些节点，或去掉相应功能后重新发布。',
  capabilityRefusalNamed: '部分目标节点版本过低，不支持这次配置用到的功能（{{capability}} v{{version}}），已拒绝整次发布。请升级这些节点，或去掉相应功能后重新发布。',
  capabilityNodes: '需要升级的节点：{{nodes}}',
  ipIntelRefusal: '运营商、IDC、ASN 或地区规则需要节点 IP 情报库，部分目标节点尚未加载已验签的情报库或版本过低，已拒绝整次发布。请等待情报库同步到节点（或升级节点）后重新发布，或去掉这些规则。',
  ipIntelNodes: '尚未就绪的节点：{{nodes}}',
  // rule_pack_unavailable: the release is kept (held) and published once the
  // packs reach the nodes (error.rule_packs).
  rulePackRefusal: '部分目标节点还没有收到这次配置用到的规则包（站点挂载的规则包或托管 WAF 的 CRS 档位包）。本次发布已记录，规则包同步到这些节点后会自动发布，无需重复操作。',
  rulePackNodes: '尚未收到规则包的节点：{{nodes}}',
  // rule_pack_out_of_profile: a site's ModSecurity pack is outside its CRS profile.
  rulePackOutOfProfile: '有网站挂载的 ModSecurity 规则包超出了它当前的 CRS 防护档位（规则包只能在档位已有的攻击类别和防护等级内关闭部分规则，不能新增规则、提高等级或改变拦截方式），已拒绝整次发布。请在网站的规则包页停用该包，或把网站的 CRS 档位调整到包含这些规则后重新发布。',
})
Object.assign(enSitePublications.errors as SitePublicationsMessages, {
  capabilityRefusal: 'Some target nodes run an agent too old for a feature this configuration uses, so the whole publication was refused. Upgrade those nodes, or remove the feature and publish again.',
  capabilityRefusalNamed: 'Some target nodes run an agent too old for a feature this configuration uses ({{capability}} v{{version}}), so the whole publication was refused. Upgrade those nodes, or remove the feature and publish again.',
  capabilityNodes: 'Nodes to upgrade: {{nodes}}',
  ipIntelRefusal: 'Carrier, IDC, ASN or region rules need the node IP intelligence library. Some target nodes have not loaded a verified library yet or run an older agent, so the whole publication was refused. Publish again once the library reaches the nodes (or they are upgraded), or remove those rules.',
  ipIntelNodes: 'Nodes not ready: {{nodes}}',
  rulePackRefusal: 'Some target nodes have not received a rule pack this configuration uses (a pack mounted by a site or a managed WAF CRS profile pack). The publication is recorded and goes out automatically once the packs reach those nodes; there is no need to publish again.',
  rulePackNodes: 'Nodes waiting for rule packs: {{nodes}}',
  rulePackOutOfProfile: "A site mounts a ModSecurity rule pack outside its current CRS profile (a pack can only switch off rules within the profile's attack classes and paranoia level; it cannot add rules, raise the level or change how requests are blocked), so the whole publication was refused. Disable the pack on the site's rule pack page, or move the site to a CRS profile that covers those rules, then publish again.",
})
const pseudoSitePublications = pseudoTree(zhSitePublications)

export const sitePublicationsMessages: Record<
  'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc',
  SitePublicationsMessages
> = {
  'zh-CN': zhSitePublications,
  'en-US': enSitePublications,
  'qps-ploc': pseudoSitePublications,
  'qps-Ploc': pseudoSitePublications,
}

for (const [locale, messages] of Object.entries(sitePublicationsMessages)) {
  i18n.addResourceBundle(locale, 'sitePublications', messages, true, true)
}
