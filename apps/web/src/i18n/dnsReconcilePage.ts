import i18n from './index'

const zhCN = {
  title: 'DNS 对账',
  description: '先生成确定性的 DNS 修复计划，再在传播健康后显式提交删除操作。',
  fields: {
    name: '域名', type: '记录类型', expectedValue: '预期记录值', authoritativeNS: '权威 DNS',
    ttl: 'TTL', line: '线路', weight: '权重', propagationWindow: '传播窗口（秒）', zoneID: 'DNS 区域 ID', providerRevision: '提供商修订',
  },
  actions: {
    generatePlan: '生成对账计划', apply: '执行对账', refreshTask: '刷新任务', retrySameRequest: '使用同一请求重试',
    abandonRefresh: '放弃并刷新', commit: '提交删除', cancelTask: '取消任务', cancel: '取消', keep: '保留任务',
  },
  validation: { required: '请填写域名、预期记录、区域 ID 和有效的数值字段。' },
  dryRun: { loading: '正在生成 DNS 对账计划' },
  plan: {
    title: '修复计划', summary: '发现 {{count}} 项变更', revision: '前置修订', digest: '计划摘要', status: '计划状态', empty: '当前没有需要修改的记录。',
  },
  columns: {
    sequence: '序号', action: '动作', name: '名称', type: '类型', value: '值', line: '线路', weight: '权重', reason: '原因', status: '状态',
    providerRequestID: '提供商请求 ID', providerRecordID: '远端记录 ID', errorCode: '错误码',
  },
  task: {
    title: '对账任务', loading: '正在加载 DNS 对账任务', prompt: '生成计划后可查看持久化任务。', revision: '任务修订 {{revision}}',
    progress: '已完成 {{completed}} / {{total}}', id: '任务 ID', jobAttempt: '任务尝试',
    attempt: '第 {{attempt}} / {{maximum}} 次尝试', providerRevision: '提供商修订', failure: '失败原因：{{code}}',
  },
  values: { empty: '—' },
  diagnosis: {
    title: '{{domain}} 的解析检测结果', domain: '域名', site: '网站ID', cname: '分配的 CNAME', account: 'DNS 账号',
    task: '自动添加记录任务', updatedAt: '最近更新', noAccount: '未配置', noTask: '没有自动添加记录任务',
    taskState: '{{state}}（已尝试 {{attempts}} 次）', taskStates: { pending: '执行中', done: '已完成', failed: '失败' },
    layers: {
      ok: '解析正常：域名已指向分配的 CNAME', account: '问题在 DNS 账号', cname: '问题在网站 CNAME',
      provider: '问题在 DNS 服务商写入', propagation: '问题在解析生效',
    },
    reasons: {
      resolved: '服务商已写入记录且回查一致。', noAccount: '这个网站没有配置用于自动添加记录的 DNS 账号。',
      pending: '自动添加记录任务正在执行，请稍后刷新。', cname_pending: '网站 CNAME 尚未分配，分配后会自动重试。',
      zone_not_hosted: '所选 DNS 账号下没有托管这个域名。', dns_record_unconfirmed: '服务商没有回查到刚写入的记录，可能仍在生效。',
      dns_record_conflict: '该域名已有其他记录，系统没有覆盖。', apex_domain: '根域名不能设置 CNAME。', wildcard_domain: '泛域名不会自动添加。',
      dns_provider_unavailable: 'DNS 服务商暂时不可用。', unknown: '添加失败（{{code}}）。',
    },
    next: {
      configureDnsApi: '下一步：在 网站管理 > DNS API 配置托管该域名的账号，再回到解析检测同步解析。',
      sync: '下一步：回到解析检测，选中该域名点“同步解析”重试。', wait: '下一步：等待任务完成后回到解析检测查看。', none: '无需处理。',
    },
    back: '返回解析检测',
  },
  advanced: {
    title: '高级修复', open: '打开高级修复（生成对账计划）',
    description: '只读诊断不会修改任何记录。需要按指定记录值重写解析时，再打开高级修复生成计划，确认后才会执行。',
  },
  operationResults: { title: '远端操作结果', empty: '尚无远端操作结果。' },
  operationStatuses: {
    planned: '已计划', deferred_until_commit: '等待提交', running: '执行中', succeeded: '成功', transient_failed: '暂时失败',
    permanent_failed: '永久失败', revision_conflict: '修订冲突', cancelled: '已取消', skipped: '已跳过',
  },
  observations: {
    title: '解析观察', role: '解析角色', resolver: '解析器', values: '观察值', minimumTTL: '最小 TTL',
    roles: { authoritative: '权威 DNS', public_recursive: '公共递归 DNS' }, lkg: '最近有效状态已保留',
  },
  compensation: { title: '补偿计划' },
  propagation: {
    title: '传播状态', empty: '暂时没有传播检查记录。', attempt: '检查次数', status: '状态', healthy: '连续健康次数',
    states: { healthy: '健康', pending: '等待中', failed: '失败' },
  },
  operations: { create: '创建', update: '更新', delete: '删除' },
  statuses: {
    dry_run: '计划已生成', applying: '执行中', propagating: '传播中', ready_to_commit: '可提交', committed: '已提交',
    failed: '执行失败', cancelled: '已取消', timed_out: '已超时', commit_failed: '提交失败',
  },
  confirmations: {
    apply: '确认按当前前置修订执行 DNS 对账？', commit: '确认提交并删除计划中的旧记录？',
    cancel: '确认取消此 DNS 对账任务？',
  },
  unknown: {
    title: '写入结果待确认', description: '连接在确认结果前中断。只能使用原操作、原请求体、原修订和原幂等键重试，或放弃并刷新任务。',
  },
  errors: {
    forbiddenTitle: '无权查看 DNS 对账', forbiddenDescription: '当前租户身份缺少 DNS 读取权限。', forbidden: '当前身份无权执行 DNS 对账。',
    notFound: '未找到 DNS 对账资源。', notFoundTitle: 'DNS 对账任务不存在', notFoundDescription: '任务可能已被删除，或不属于当前租户。',
    conflict: 'DNS 对账状态或修订发生冲突，请刷新后重试。', rateLimited: '操作过于频繁，请稍后重试。',
    unavailable: 'DNS 对账服务暂不可用，请稍后重试。', invalidRequest: 'DNS 对账请求无效，请检查字段后重试。',
    requestFailed: 'DNS 对账请求失败，请稍后重试。',
  },
} as const

const enUS = {
  title: 'DNS reconciliation',
  description: 'Build a deterministic DNS repair plan, then explicitly commit deletions after propagation is healthy.',
  fields: {
    name: 'Domain', type: 'Record type', expectedValue: 'Expected record value', authoritativeNS: 'Authoritative DNS',
    ttl: 'TTL', line: 'Line', weight: 'Weight', propagationWindow: 'Propagation window (seconds)', zoneID: 'DNS zone ID', providerRevision: 'Provider revision',
  },
  actions: {
    generatePlan: 'Generate reconciliation plan', apply: 'Apply reconciliation', refreshTask: 'Refresh task', retrySameRequest: 'Retry same request',
    abandonRefresh: 'Abandon and refresh', commit: 'Commit deletes', cancelTask: 'Cancel task', cancel: 'Cancel', keep: 'Keep task',
  },
  validation: { required: 'Enter a domain, expected record, zone ID, and valid numeric fields.' },
  dryRun: { loading: 'Generating DNS reconciliation plan' },
  plan: {
    title: 'Repair plan', summary: '{{count}} changes found', revision: 'Precondition revision', digest: 'Plan digest', status: 'Plan status', empty: 'No records require changes.',
  },
  columns: {
    sequence: 'Sequence', action: 'Action', name: 'Name', type: 'Type', value: 'Value', line: 'Line', weight: 'Weight', reason: 'Reason', status: 'Status',
    providerRequestID: 'Provider request ID', providerRecordID: 'Remote record ID', errorCode: 'Error code',
  },
  task: {
    title: 'Reconciliation task', loading: 'Loading DNS reconciliation task', prompt: 'The durable task appears after a plan is applied.', revision: 'Task revision {{revision}}',
    progress: '{{completed}} / {{total}} complete', id: 'Task ID', jobAttempt: 'Job attempt',
    attempt: 'Attempt {{attempt}} / {{maximum}}', providerRevision: 'Provider revision', failure: 'Failure reason: {{code}}',
  },
  values: { empty: '—' },
  diagnosis: {
    title: 'Resolution check of {{domain}}', domain: 'Domain', site: 'Site ID', cname: 'Assigned CNAME', account: 'DNS account',
    task: 'Automatic record task', updatedAt: 'Last updated', noAccount: 'Not configured', noTask: 'No automatic record task',
    taskState: '{{state}} ({{attempts}} attempts)', taskStates: { pending: 'Running', done: 'Done', failed: 'Failed' },
    layers: {
      ok: 'Resolved: the domain points at the assigned CNAME', account: 'The DNS account is the problem', cname: 'The site CNAME is the problem',
      provider: 'Writing at the DNS provider is the problem', propagation: 'The record has not taken effect',
    },
    reasons: {
      resolved: 'The provider has the record and it reads back the same.', noAccount: 'This site has no DNS account for automatic records.',
      pending: 'The automatic record task is running; refresh later.', cname_pending: 'The site CNAME is not assigned yet; it retries once assigned.',
      zone_not_hosted: 'The chosen DNS account does not host this domain.', dns_record_unconfirmed: 'The provider did not read back the record yet; it may still be taking effect.',
      dns_record_conflict: 'The domain already has another record, which was not overwritten.', apex_domain: 'An apex domain cannot be a CNAME.', wildcard_domain: 'Wildcard domains are not added automatically.',
      dns_provider_unavailable: 'The DNS provider is unavailable for now.', unknown: 'Adding failed ({{code}}).',
    },
    next: {
      configureDnsApi: 'Next: under Sites > DNS API add the account that hosts this domain, then sync it from Resolution check.',
      sync: 'Next: go back to Resolution check, select the domain and click Sync to retry.', wait: 'Next: wait for the task, then check Resolution check again.', none: 'Nothing to do.',
    },
    back: 'Back to Resolution check',
  },
  advanced: {
    title: 'Advanced repair', open: 'Open advanced repair (generate a plan)',
    description: 'This diagnosis changes nothing. To rewrite records to given values, open advanced repair to generate a plan; it runs only after you confirm.',
  },
  operationResults: { title: 'Remote operation results', empty: 'No remote operation results yet.' },
  operationStatuses: {
    planned: 'Planned', deferred_until_commit: 'Waiting for commit', running: 'Running', succeeded: 'Succeeded', transient_failed: 'Temporary failure',
    permanent_failed: 'Permanent failure', revision_conflict: 'Revision conflict', cancelled: 'Cancelled', skipped: 'Skipped',
  },
  observations: {
    title: 'DNS observations', role: 'Resolver role', resolver: 'Resolver', values: 'Observed values', minimumTTL: 'Minimum TTL',
    roles: { authoritative: 'Authoritative DNS', public_recursive: 'Public recursive DNS' }, lkg: 'Last known good state retained',
  },
  compensation: { title: 'Compensation plan' },
  propagation: {
    title: 'Propagation status', empty: 'No propagation checks yet.', attempt: 'Attempt', status: 'Status', healthy: 'Consecutive healthy',
    states: { healthy: 'Healthy', pending: 'Pending', failed: 'Failed' },
  },
  operations: { create: 'Create', update: 'Update', delete: 'Delete' },
  statuses: {
    dry_run: 'Plan generated', applying: 'Applying', propagating: 'Propagating', ready_to_commit: 'Ready to commit', committed: 'Committed',
    failed: 'Failed', cancelled: 'Cancelled', timed_out: 'Timed out', commit_failed: 'Commit failed',
  },
  confirmations: {
    apply: 'Apply DNS reconciliation using the current precondition revision?', commit: 'Commit and delete the superseded records in this plan?',
    cancel: 'Cancel this DNS reconciliation task?',
  },
  unknown: {
    title: 'Write outcome unknown', description: 'The connection ended before the outcome was confirmed. Retry only with the original operation, body, revision, and idempotency key, or abandon and refresh the task.',
  },
  errors: {
    forbiddenTitle: 'DNS reconciliation unavailable', forbiddenDescription: 'The current tenant identity lacks DNS read permission.', forbidden: 'The current identity cannot execute DNS reconciliation.',
    notFound: 'The DNS reconciliation resource was not found.', notFoundTitle: 'DNS reconciliation task not found', notFoundDescription: 'The task may have been removed or belongs to another tenant.',
    conflict: 'The DNS reconciliation state or revision conflicts. Refresh and try again.', rateLimited: 'Too many operations. Try again later.',
    unavailable: 'The DNS reconciliation service is temporarily unavailable. Try again.', invalidRequest: 'The DNS reconciliation request is invalid. Check the fields and try again.',
    requestFailed: 'The DNS reconciliation request failed. Try again later.',
  },
}

type MessageShape = { [key: string]: string | MessageShape }
function pseudo(value: unknown): unknown {
  if (typeof value === 'string') return `［${value.replace(/[A-Za-z\u4e00-\u9fff]/g, '$&~')}］`
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudo(child)]))
}

const pseudoCN = pseudo(zhCN) as MessageShape
export const dnsReconcilePageMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', MessageShape> = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudoCN,
  'qps-Ploc': pseudoCN,
}

for (const [locale, messages] of Object.entries(dnsReconcilePageMessages)) {
  i18n.addResourceBundle(locale, 'dnsReconcilePage', messages, true, true)
}
