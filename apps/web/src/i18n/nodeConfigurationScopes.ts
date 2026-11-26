import i18n from './index'

const zhCN = {
  title: '承载的租户',
  description: '此节点上每个租户配置的当前版本与应用进度。多租户节点上各租户独立部署、独立回滚。',
  empty: '此节点尚未承载任何租户的配置。',
  columns: {
    tenant: '租户', current: '当前版本', previous: '上一版本', deployment: '最近部署', apply: '节点最近应用', updatedAt: '更新时间',
  },
  scopeKinds: { platform: '平台', tenant: '租户' },
  copy: { tenant: '复制 {{name}} 的租户 ID', current: '复制 {{name}} 的当前配置版本', previous: '复制 {{name}} 的上一配置版本' },
  noVersion: '尚无',
  reconciliation: '待对账',
  reconcile: {
    reason: '部署 {{deployment}}（第 {{attempt}} 次）回滚失败，节点实际运行的配置未经确认，之后的发布都在等待对账。',
    action: '按节点上报状态对账',
    confirmTitle: '按节点上报的状态结束待对账？',
    confirmBody: '节点心跳上报这个租户当前运行的配置是 {{version}}（{{time}}）。主控以此为准结束待对账；失败的部署记录保留，并解除这个节点的对账限制：仍在有效期内的自动发布会继续下发，已超时的请到网站详情点“重新发布”。',
    none: '无（节点已明确退回空配置）',
    unknownTime: '时间未知',
    unconfirmed: '节点状态未确认：{{reason}}。',
    unconfirmedReasons: {
      no_scope_report: '节点没有单独上报这个租户的状态',
      stale_report: '节点在回滚失败之后没有新的上报（或已离线、会话已更换）',
      contradicting_report: '节点上报互相矛盾（仍报告回滚失败，或没有配置却仍在服务）',
      default: '原因 {{code}}',
    },
    unconfirmedAction: '人工确认后对账',
    unconfirmedTitle: '人工确认后对账',
    unconfirmedBody: '节点状态未确认，主控无法以节点上报为准。确认后主控不再假定节点运行该租户的任何配置：失败的部署记录保留，并解除这个节点的对账限制：仍在有效期内的自动发布会继续下发，已超时的请到网站详情点“重新发布”。',
    servingSourceBody: '确认后主控按节点仍在运行原发布（版本 {{version}}）处理：失败的部署记录保留，并解除这个节点的对账限制；旧版本的访问记录可在租户重新发布后补报。',
    checkNodeFirst: '请先在节点上核实。',
    uncheckedHeldNote: '不勾选时，节点保留的原版本访问记录会继续保留，在补充确认前也会挡住后续的访问统计上报。',
    ok: '对账',
    cancel: '取消',
    servingSource: '节点仍在服务原发布（版本 {{version}}）',
    done: '已对账，已解除这个节点的对账限制。已超时的发布不会自动重发，请到网站详情点“重新发布”。',
    doneServing: '已对账。请让租户重新发布一次，积压的访问记录随后补报。',
    failed: '对账失败（{{code}}），请刷新后重试。',
    failedCodes: {
      reconciliation_version_not_source: '对账被拒绝：只能确认这次失败部署自己的版本。请刷新后重试。',
      reconciliation_source_unverifiable: '对账被拒绝：原发布的配置已无法核实。请不勾选「节点仍在服务原发布」，人工确认后对账，再让租户重新发布。',
    },
  },
  supplement: {
    rowState: '已对账 · 未确认版本',
    action: '补充确认',
    title: '补充确认原部署曾在节点运行',
    body: '这个租户已于 {{time}} 人工对账，但没有确认版本。如果核实原部署 {{deployment}} 在回滚失败后曾在本节点运行，可以补充确认一次：旧版本 {{version}} 进入节点的访问统计授权，当前版本不变；租户下一次发布到本节点时，节点放行按旧版本保留的访问记录，按原顺序补报。补充确认只能做一次，不能撤回。',
    option: '原部署在回滚失败后曾在本节点运行（旧版本 {{version}}）',
    checkNodeFirst: '请先在节点上核实。',
    ok: '补充确认',
    done: '已为 {{tenant}} 补充确认。请让租户重新发布一次：发布到本节点时，节点放行保留的访问记录并按原顺序补报。',
    readingBack: '正在读取最新状态。',
    readbackFailed: '补充确认已记录，最新状态暂时读取失败，可在下方重试读取。',
    refresh: '刷新作用域',
    viewPublications: '查看当前发布',
    failedCodes: {
      reconciliation_supplement_not_eligible: '补充确认被拒绝：这个租户最近一次对账已不是「未填版本」的人工确认（可能已经补充确认过）。请刷新后查看。',
      reconciliation_version_not_source: '补充确认被拒绝：只能确认原部署自己的版本。请刷新后查看。',
      reconciliation_source_unverifiable: '补充确认被拒绝：原发布的配置已无法核实，不能再确认这个版本。可以刷新作用域查看最新状态，或查看这个租户当前的发布。',
    },
  },
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
  lastApply: {
    needsReconciliation: '回滚失败，需对账',
    servingAfterRollbackFailure: '回滚失败，仍在服务原发布',
    details: '原始错误与恢复记录',
    error: '原始错误：{{code}}',
    finishedAt: '结束时间：{{time}}',
    recovery: '最近一次恢复记录：节点上报运行 {{version}}（{{time}}）',
    noRecovery: '最近一次恢复记录：尚无',
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
  copy: { tenant: 'Copy tenant ID of {{name}}', current: 'Copy current configuration version of {{name}}', previous: 'Copy previous configuration version of {{name}}' },
  noVersion: 'None yet',
  reconciliation: 'Needs reconciliation',
  reconcile: {
    reason: 'Deployment {{deployment}} (attempt {{attempt}}) failed to roll back, so what the node runs is unconfirmed and later publications wait for reconciliation.',
    action: 'Reconcile with what the node reports',
    confirmTitle: 'End the reconciliation with what the node reports?',
    confirmBody: 'The node\'s heartbeat reports that this tenant runs configuration {{version}} ({{time}}). The control plane takes that as the node\'s state; the failed deployment stays on record and the node\'s reconciliation hold is lifted: an automatic publication still within its deadline continues, an expired one needs Republish on the site.',
    none: 'none (the node explicitly returned to an empty configuration)',
    unknownTime: 'time unknown',
    unconfirmed: 'Node state unconfirmed: {{reason}}.',
    unconfirmedReasons: {
      no_scope_report: 'the node did not report this tenant on its own',
      stale_report: 'the node has not reported since the rollback failed (or is offline, or its session changed)',
      contradicting_report: 'the node\'s report contradicts itself (it still reports the failed rollback, or no configuration while serving)',
      default: 'reason {{code}}',
    },
    unconfirmedAction: 'Confirm manually and reconcile',
    unconfirmedTitle: 'Confirm manually and reconcile',
    unconfirmedBody: 'The node state is unconfirmed, so the control plane cannot rely on the node\'s report. Once confirmed it assumes no configuration of this tenant runs on the node: the failed deployment stays on record and the node\'s reconciliation hold is lifted: an automatic publication still within its deadline continues, an expired one needs Republish on the site.',
    servingSourceBody: 'Once confirmed the control plane treats the node as still running the original release (version {{version}}): the failed deployment stays on record and the node\'s reconciliation hold is lifted; the access records of that version are uploaded after the tenant publishes again.',
    checkNodeFirst: 'Check the node first.',
    uncheckedHeldNote: 'Left unticked, the access records the node keeps of the original version stay held, and until a supplemental confirmation they also hold back later access statistics uploads.',
    ok: 'Reconcile',
    cancel: 'Cancel',
    servingSource: 'The node still serves the original release (version {{version}})',
    done: 'Reconciled. The node\'s reconciliation hold is lifted. An expired publication is not retried automatically; use Republish on the site.',
    doneServing: 'Reconciled. Ask the tenant to publish once more; the queued access records are uploaded after that.',
    failed: 'Reconciliation failed ({{code}}). Refresh and try again.',
    failedCodes: {
      reconciliation_version_not_source: 'Reconciliation refused: only the failed deployment\'s own version can be confirmed. Refresh and try again.',
      reconciliation_source_unverifiable: 'Reconciliation refused: the original release can no longer be verified. Leave "The node still serves the original release" unticked, confirm manually, then ask the tenant to publish again.',
    },
  },
  supplement: {
    rowState: 'Reconciled · no version confirmed',
    action: 'Confirm',
    title: 'Confirm the original deployment ran on the node',
    body: 'This tenant was reconciled manually at {{time}} without a version. If you verified that the original deployment {{deployment}} ran on this node after its rollback failed, confirm it once: the old version {{version}} is authorized for the node\'s access statistics and the current version stays as it is. When the tenant next publishes to this node, the node releases the access records it keeps of the old version and uploads them in their original order. This confirmation can be made only once and cannot be undone.',
    option: 'The original deployment ran on this node after its rollback failed (old version {{version}})',
    checkNodeFirst: 'Check the node first.',
    ok: 'Confirm',
    done: 'Confirmed for {{tenant}}. Ask the tenant to publish once more: when it reaches this node, the node releases the access records it keeps and uploads them in their original order.',
    readingBack: 'Reading the latest state.',
    readbackFailed: 'The confirmation is recorded; the latest state could not be read for now. Retry reading below.',
    refresh: 'Refresh scopes',
    viewPublications: 'View current publications',
    failedCodes: {
      reconciliation_supplement_not_eligible: 'Supplemental confirmation refused: the tenant\'s latest reconciliation is no longer a manual confirmation without a version (it may already be supplemented). Refresh to check.',
      reconciliation_version_not_source: 'Supplemental confirmation refused: only the original deployment\'s own version can be confirmed. Refresh to check.',
      reconciliation_source_unverifiable: 'Supplemental confirmation refused: the original release can no longer be verified, so this version cannot be confirmed. Refresh the scopes to see the latest state, or view the tenant\'s current publications.',
    },
  },
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
  lastApply: {
    needsReconciliation: 'Rollback failed, needs reconciliation',
    servingAfterRollbackFailure: 'Rollback failed, still serving the original release',
    details: 'Original error and recovery record',
    error: 'Original error: {{code}}',
    finishedAt: 'Finished: {{time}}',
    recovery: 'Latest recovery record: the node reported running {{version}} ({{time}})',
    noRecovery: 'Latest recovery record: none yet',
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
