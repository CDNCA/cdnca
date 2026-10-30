import i18n from './index'

const zhCN = {
  title: '承载的租户',
  description: '此节点上每个租户配置的当前版本与应用进度。多租户节点上各租户独立部署、独立回滚。',
  empty: '此节点尚未承载任何租户的配置。',
  columns: {
    tenant: '租户', current: '当前版本', previous: '上一版本', deployment: '最近部署', apply: '节点最近应用', updatedAt: '更新时间',
  },
  scopeKinds: { platform: '平台', tenant: '租户' },
  noVersion: '尚无',
  reconciliation: '待对账',
  telemetryExcluded: {
    tag: '遥测已隔离',
    platform_scope: '平台自身的配置没有归属租户，节点授权不为它下发遥测站点；其他租户不受影响。',
    invalid_config_version: '这个租户在本节点上的某个配置版本无法读取，节点授权暂不为它下发遥测站点。节点和其他租户照常工作；请检查并重新发布这个租户的配置。',
    telemetry_site_limit: '节点授权的遥测站点数已到上限，这个租户的站点没有放进去。节点和其他租户照常工作。',
  },
  attempt: '第 {{attempt}} 次',
  deploymentStates: {
    queued: '待下发', delivered: '已送达', agent_queued: '节点排队中', started: '已开始', staged: '已暂存',
    prechecked: '已预检', activated: '已激活', healthy: '健康', failed: '失败', reverting: '回滚中',
    reverted: '已回滚', rollback_failed: '回滚失败', cancelled: '已取消',
  },
  applyStates: {
    healthy: '健康', failed: '失败', reverted: '已回滚', rollback_failed: '回滚失败', superseded: '已被新版本替换',
  },
  rejections: {
    title: '被拒绝的发布',
    description: '这些发布无法与同一节点上的其他租户共存，下发前已被拒绝。',
    empty: '没有被拒绝的发布。',
    columns: { tenant: '租户', reason: '原因', requestId: '请求 ID', occurredAt: '时间' },
  },
  errors: { unavailable: '承载租户暂不可用，请稍后重试', invalidResponse: '承载租户响应无效，请重试' },
  regressions: {
    title: '节点版本低于正在使用的功能',
    message: '{{tenant}} 最近一次健康部署（版本 {{version}}）用到了{{feature}}，但节点当前的 agent（{{agent}}）只声明 {{capability}} v{{declared}}，需要 v{{required}}。通常是节点 agent 回滚到了旧版本。',
    remedy: '处置：把节点 agent 重新升级到 1.0.35 或更高版本；或在这个租户的配置里去掉该功能后重新发布。去掉之前，含该功能的发布会被拒绝。',
    unknownAgent: '未知版本',
    features: {
      cc_proof_of_work: 'CC 工作量证明（PoW）验证页',
      waf_crs_module: 'OWASP CRS 托管 WAF',
      l4_tls_passthrough: '四层 TLS 透传（按 SNI）或与网站共享端口',
      l4_additional_listeners: '四层附加监听端口',
      l4_toa: '四层 TOA 传递客户端 IP',
    },
  },
}

type Messages = typeof zhCN

const enUS: Messages = {
  title: 'Tenants on this node',
  description: 'Current version and apply progress of each tenant configuration on this node. On a shared node each tenant deploys and rolls back on its own.',
  empty: 'This node carries no tenant configuration yet.',
  columns: {
    tenant: 'Tenant', current: 'Current version', previous: 'Previous version', deployment: 'Latest deployment',
    apply: 'Last apply on node', updatedAt: 'Updated',
  },
  scopeKinds: { platform: 'Platform', tenant: 'Tenant' },
  noVersion: 'None yet',
  reconciliation: 'Needs reconciliation',
  telemetryExcluded: {
    tag: 'Telemetry isolated',
    platform_scope: 'The platform\'s own configuration belongs to no tenant, so the node authorization carries no telemetry sites for it. Other tenants are not affected.',
    invalid_config_version: 'A configuration version of this tenant on this node cannot be read, so the node authorization leaves its telemetry out. The node and the other tenants keep working; check and republish this tenant\'s configuration.',
    telemetry_site_limit: 'The node authorization reached its telemetry site limit and this tenant\'s sites did not fit. The node and the other tenants keep working.',
  },
  attempt: 'Attempt {{attempt}}',
  deploymentStates: {
    queued: 'Queued', delivered: 'Delivered', agent_queued: 'Queued on node', started: 'Started', staged: 'Staged',
    prechecked: 'Prechecked', activated: 'Activated', healthy: 'Healthy', failed: 'Failed', reverting: 'Reverting',
    reverted: 'Reverted', rollback_failed: 'Rollback failed', cancelled: 'Cancelled',
  },
  applyStates: {
    healthy: 'Healthy', failed: 'Failed', reverted: 'Reverted', rollback_failed: 'Rollback failed',
    superseded: 'Superseded by a newer version',
  },
  rejections: {
    title: 'Refused publications',
    description: 'These publications could not share the node with another tenant and were refused before delivery.',
    empty: 'No refused publications.',
    columns: { tenant: 'Tenant', reason: 'Reason', requestId: 'Request ID', occurredAt: 'Time' },
  },
  errors: {
    unavailable: 'Tenants on this node are unavailable. Try again later.',
    invalidResponse: 'The tenants response was invalid. Try again.',
  },
  regressions: {
    title: 'Node agent is older than the features in use',
    message: 'The latest healthy deployment of {{tenant}} (version {{version}}) uses {{feature}}, but the node\'s current agent ({{agent}}) declares only {{capability}} v{{declared}}; v{{required}} is required. Usually the node agent was rolled back.',
    remedy: 'To resolve: upgrade the node agent to 1.0.35 or later again, or remove the feature from this tenant\'s configuration and publish it again. Until then publications with the feature are refused.',
    unknownAgent: 'unknown version',
    features: {
      cc_proof_of_work: 'CC verification pages with proof of work',
      waf_crs_module: 'the OWASP CRS managed WAF',
      l4_tls_passthrough: 'L4 TLS passthrough by SNI or ports shared with websites',
      l4_additional_listeners: 'L4 additional listeners',
      l4_toa: 'L4 client address via TOA',
    },
  },
}

function pseudo(value: unknown): unknown {
  if (typeof value === 'string') {
    const tokens: string[] = []
    const protectedValue = value.replace(/\{\{[^{}]+\}\}/g, (token) => {
      tokens.push(token)
      return `§${tokens.length - 1}§`
    })
    return `［¡¡ ${protectedValue.replace(/[A-Za-z\u4e00-\u9fff]/g, '$&$&')} !!］`
      .replace(/§(\d+)§/g, (_match, index: string) => tokens[Number(index)] ?? '')
  }
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudo(child)]))
}

const pseudoCN = pseudo(zhCN) as Messages

export const nodeConfigurationScopesMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', Messages> = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudoCN,
  'qps-Ploc': pseudoCN,
}

for (const [locale, messages] of Object.entries(nodeConfigurationScopesMessages)) {
  i18n.addResourceBundle(locale, 'nodeConfigurationScopes', messages, true, true)
}
