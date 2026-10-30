import i18n from './index'

const zhCN = {
  title: 'JA4 封禁工作流',
  description: '基于权威排行快照创建并跟踪单个 JA4 封禁工作流。',
  actions: {
    create: '创建 JA4 封禁', confirm: '确认创建', cancel: '取消',
    confirmBlock: '确认封禁',
    retryRead: '重试读取', retrySame: '使用同一请求重试', abandon: '放弃并清除',
  },
  states: {
    empty: '本页尚未跟踪 JA4 封禁工作流', loading: '正在加载 JA4 封禁工作流',
    loadError: 'JA4 封禁工作流加载失败', forbidden: '无权管理 JA4 封禁',
    outcomeUnknown: '创建结果待确认', active: '已激活',
  },
  fields: {
    tenantScopeId: '租户作用域 ID', siteId: '站点 ID', ja4: 'JA4 原始值', snapshotAt: '权威快照时间',
    durationSeconds: '封禁时长（秒）', reason: '原因码', stepUp: '二次认证证明', workflowId: '工作流 ID',
    maskedJa4: 'JA4 指纹（脱敏）', ja4Sha256: 'JA4 SHA-256', phase: '工作流阶段', revision: '工作流修订', policyId: '策略 ID',
    policyRevision: '策略修订', bindingId: '绑定 ID', bindingRevision: '绑定修订',
    edgePublicationId: '边缘发布 ID', rolloutId: '灰度任务 ID', edgeState: '边缘状态', attemptCount: '尝试次数',
    snapshot: '快照时间', duration: '封禁时长', lastError: '最后错误码',
  },
  phases: {
    queued: '已排队', policy_ready: '策略已就绪', edge_pending: '边缘下发中',
    active: '已激活', failed: '失败', expired: '已过期',
  },
  edgeStates: {
    none: '尚未下发', pending: '等待边缘确认', active: '边缘已激活',
    failed: '边缘失败', rolled_back: '已回滚',
  },
  receipt: {
    title: '不可变工作流回执',
    disclaimer: '回执仅陈述不可变策略、绑定、发布和灰度状态；只有工作流与边缘状态均为 active 时才表示已激活。',
  },
  confirmation: {
    title: '确认 JA4 封禁',
    description: '确认后将创建可审计的封禁工作流；任务受理不代表边缘节点已经生效。',
  },
  dialog: { title: '创建 JA4 封禁工作流' },
  validation: {
    tenantScope: '请输入规范小写的租户作用域 UUID', site: '请输入规范小写的站点 UUID',
    ja4: '请输入 1 到 128 个允许字符组成的 JA4 值', snapshot: '请输入有效的权威快照时间',
    duration: '封禁时长必须在 60 到 2592000 秒之间', reason: '原因码必须使用小写字母、数字和下划线',
    stepUp: '请提供二次认证证明',
  },
  errors: {
    invalidInput: '提交内容无效，请检查后重试。', permissionDenied: '无权创建 JA4 封禁',
    authenticationRequired: '登录状态已失效，请重新登录。',
    conflict: '该请求与现有工作流冲突，请刷新排行后重新确认。',
    snapshotStale: '排行快照已失效，请刷新后重新选择。',
    dependencyInvalid: '封禁服务返回了无效回执，请稍后重试。',
    idempotencyConflict: '幂等请求与原请求不一致，请核对后重新创建。',
    revisionConflict: '创建前置修订不匹配，请重新确认。', stepUpRequired: '需要重新完成二次认证。',
    unavailable: 'JA4 封禁服务暂不可用，请稍后重试。', requestFailed: 'JA4 封禁请求失败，请重试。',
  },
}

const enUS: typeof zhCN = {
  title: 'JA4 block workflows',
  description: 'Create and track one JA4 block workflow from an authoritative ranking snapshot.',
  actions: {
    create: 'Create JA4 block', confirm: 'Confirm creation', cancel: 'Cancel',
    confirmBlock: 'Confirm block',
    retryRead: 'Retry read', retrySame: 'Retry the same request', abandon: 'Abandon and clear',
  },
  states: {
    empty: 'This page is not tracking a JA4 block workflow', loading: 'Loading JA4 block workflow',
    loadError: 'Failed to load JA4 block workflow', forbidden: 'No permission to manage JA4 blocks',
    outcomeUnknown: 'Creation result pending confirmation', active: 'Active',
  },
  fields: {
    tenantScopeId: 'Tenant scope ID', siteId: 'Site ID', ja4: 'Raw JA4 value', snapshotAt: 'Authoritative snapshot time',
    durationSeconds: 'Block duration (seconds)', reason: 'Reason code', stepUp: 'Step-up proof', workflowId: 'Workflow ID',
    maskedJa4: 'JA4 fingerprint (masked)', ja4Sha256: 'JA4 SHA-256', phase: 'Workflow phase', revision: 'Workflow revision', policyId: 'Policy ID',
    policyRevision: 'Policy revision', bindingId: 'Binding ID', bindingRevision: 'Binding revision',
    edgePublicationId: 'Edge publication ID', rolloutId: 'Rollout ID', edgeState: 'Edge state', attemptCount: 'Attempt count',
    snapshot: 'Snapshot time', duration: 'Block duration', lastError: 'Last error code',
  },
  phases: {
    queued: 'Queued', policy_ready: 'Policy ready', edge_pending: 'Edge publication pending',
    active: 'Active', failed: 'Failed', expired: 'Expired',
  },
  edgeStates: {
    none: 'Not published', pending: 'Waiting for edge confirmation', active: 'Active on edge',
    failed: 'Edge failed', rolled_back: 'Rolled back',
  },
  receipt: {
    title: 'Immutable workflow receipt',
    disclaimer: 'The receipt states only immutable policy, binding, publication, and rollout facts. Activation requires both workflow and edge state to be active.',
  },
  confirmation: {
    title: 'Confirm JA4 block',
    description: 'Confirmation creates an auditable block workflow. Acceptance does not mean edge nodes are active.',
  },
  dialog: { title: 'Create JA4 block workflow' },
  validation: {
    tenantScope: 'Enter a canonical lowercase tenant scope UUID.', site: 'Enter a canonical lowercase site UUID.',
    ja4: 'Enter a JA4 value containing 1 to 128 allowed characters.', snapshot: 'Enter a valid authoritative snapshot time.',
    duration: 'Block duration must be between 60 and 2592000 seconds.', reason: 'Use lowercase letters, numbers, and underscores for the reason code.',
    stepUp: 'Provide a step-up proof.',
  },
  errors: {
    invalidInput: 'The submitted values are invalid. Check them and try again.', permissionDenied: 'No permission to create JA4 blocks',
    authenticationRequired: 'Your session has expired. Sign in again.',
    conflict: 'This request conflicts with an existing workflow. Refresh the ranking and confirm again.',
    snapshotStale: 'The ranking snapshot has expired. Refresh it and select the fingerprint again.',
    dependencyInvalid: 'The block service returned an invalid receipt. Try again later.',
    idempotencyConflict: 'The idempotency request differs from the original request. Verify it before creating again.',
    revisionConflict: 'The create precondition revision does not match. Confirm again.', stepUpRequired: 'Complete step-up authentication again.',
    unavailable: 'The JA4 block service is temporarily unavailable. Try again later.', requestFailed: 'The JA4 block request failed. Try again.',
  },
}

type Messages = typeof zhCN

function pseudo(value: unknown): unknown {
  if (typeof value === 'string') {
    const tokens: string[] = []
    const protectedValue = value.replace(/\{\{[^{}]+\}\}/g, (token) => { tokens.push(token); return `__TOKEN_${tokens.length - 1}__` })
    return `［¡¡ ${protectedValue.replace(/[A-Za-z\u4e00-\u9fff]/g, '$&$&')} !!］`.replace(/__TOKEN_(\d+)__/g, (_match, index: string) => tokens[Number(index)] ?? '')
  }
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudo(child)]))
}

const pseudoCN = pseudo(zhCN) as Messages

export const ja4BlocksMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', Messages> = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudoCN,
  'qps-Ploc': pseudoCN,
}

for (const [locale, messages] of Object.entries(ja4BlocksMessages)) {
  i18n.addResourceBundle(locale, 'ja4Blocks', messages, true, true)
}
