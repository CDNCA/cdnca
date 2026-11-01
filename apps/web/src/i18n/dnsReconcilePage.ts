import i18n from './index'

// 页面按「检查现状 → 确认方案 → 修改并等待生效 → 完成」四步组织；
// 文案只用用户能懂的话，内部术语（前置修订、计划摘要、厂商请求 ID 等）只出现在「技术详情」里。
const zhCN = {
  title: '修复域名解析',
  description: '检查域名是否正确指向本平台。发现问题时生成修复方案，你确认后自动修改，等各地解析生效后再删除旧记录。',
  steps: { diagnose: '检查现状', plan: '确认方案', apply: '修改并等待生效', finish: '完成', label: '修复进度', compact: '第 {{current}} / {{total}} 步：{{title}}' },
  picker: {
    title: '选择要检查的域名', label: '域名', placeholder: '输入域名或网站 ID 搜索',
    help: '选好后会自动带出它应指向的 CNAME、DNS 账号和 DNS 区域，不需要手动填写。',
    currentSite: '当前网站', otherSites: '其他网站', site: '网站 {{id}}', empty: '没有找到匹配的域名', loading: '正在加载网站',
    error: '网站列表加载失败，请重试。',
  },
  check: { action: '检查并生成修复方案', loading: '正在读取当前解析并生成修复方案', changeDomain: '换一个域名' },
  units: { seconds: '秒' },
  advanced: { title: '高级设置', summary: '默认值已按网站和 DNS 账号自动填好，一般不需要修改。' },
  fields: {
    type: { label: '记录类型', help: '网站接入用 CNAME；只有直接指向 IP 时才选 A 或 AAAA。' },
    expectedValue: { label: '应指向的值', help: '默认是网站分配的 CNAME。多个值用英文逗号分隔。' },
    ttl: { label: 'TTL', help: '解析结果被缓存的时长，1–604800 秒，默认 300 秒。' },
    line: { label: '解析线路', help: '只在 DNS 服务商支持分线路时填写，如“境外”；留空表示默认线路。' },
    weight: { label: '权重', help: '同一线路有多条记录时的流量比例，0–100；0 表示不设置。' },
    propagationWindow: { label: '最长等待生效', help: '超过这个时间各地仍未生效就停止并提示，1–604800 秒，默认 900 秒（15 分钟）。' },
    authoritativeNS: { label: '权威 DNS 服务器', help: '用来检查记录是否生效的权威服务器，多个用英文逗号分隔；留空用系统默认。' },
    zoneID: { label: 'DNS 区域', help: '托管这个域名的 DNS 区域，已按域名自动匹配。' },
    zoneIDManual: { label: 'DNS 区域 ID', help: '没能读取区域列表，请填写 网站管理 > DNS API 中该域名所在区域的 ID。' },
    providerRevision: { label: '区域版本', help: '用来避免和其他人的修改冲突，选好区域后自动带出。' },
  },
  fieldErrors: {
    summary: '有 {{count}} 项设置需要修改，已在下方标出。',
    name: '请先选择域名。',
    expectedValue: '请至少填写一个值，多个值用英文逗号分隔。',
    ttl: '请输入 1–604800 之间的整数（秒）。',
    line: '线路名称不能有首尾空格或控制字符，且不超过 64 字节。',
    weight: '请输入 0–100 之间的整数。',
    propagationWindow: '请输入 1–604800 之间的整数（秒）。',
    zoneID: '请选择托管这个域名的 DNS 区域。',
    providerRevision: '请输入大于 0 的整数。',
  },
  plan: {
    title: '将要做的修改', none: '解析已经正确，不需要修改。',
    summary: '共 {{count}} 项：', summaryParts: { create: '新增 {{count}}', update: '修改 {{count}}', delete: '删除 {{count}}' }, summarySeparator: '，',
    groups: { create: '新增记录', update: '修改记录', delete: '删除记录' },
    deleteNote: '旧记录会在新记录各地生效、你再次确认之后才删除。',
    ttl: 'TTL：{{ttl}} 秒', change: '{{label}}：{{from}} → {{to}}', line: '线路', weight: '权重', defaultLine: '默认',
    recheck: '重新检查', readOnly: '你只有查看权限，需要有 DNS 管理权限的成员执行修复。',
  },
  progress: {
    applying: '正在向 DNS 服务商写入记录', propagating: '记录已写入，正在等待各地解析生效',
    done: '已完成 {{completed}} / {{total}} 项', wait: '通常几分钟内生效，最长等待 {{minutes}} 分钟，页面会自动刷新。',
    resolvers: '各地解析情况', healthy: '已生效', pending: '未生效', noCheck: '还没有检查结果，稍后会自动刷新。',
    failed: '修复没有完成：{{reason}}', failedHint: '可以取消本次修复，检查高级设置或 DNS 账号后重新检查。',
  },
  finish: {
    readyTitle: '新记录已在各地生效', readyDescription: '确认后会删除方案里的旧记录，修复就完成了。',
    committedTitle: '修复完成', committedDescription: '解析已更新，旧记录已删除。',
    cancelledTitle: '修复已取消', cancelledDescription: '旧记录没有删除。需要时可以重新检查。',
    commitFailedTitle: '删除旧记录失败：{{reason}}', commitFailedDescription: '新记录仍然有效。可以取消本次修复后重新检查。',
  },
  failureReasons: {
    timed_out: '等待生效超时', provider: 'DNS 服务商返回错误', unknown: '原因未知',
  },
  actions: {
    apply: '开始修复', refreshTask: '刷新', retrySameRequest: '用原请求再试一次', abandonRefresh: '放弃并刷新',
    commit: '确认生效并删除旧记录', cancelTask: '取消修复', cancel: '取消', keep: '继续修复', back: '返回解析检测',
  },
  confirmations: {
    apply: '确认开始修复？会按上面的方案修改 DNS 服务商上的记录。', commit: '确认删除旧记录？删除后不会自动恢复。',
    cancel: '确认取消修复？旧记录不会被删除。',
  },
  technical: {
    title: '技术详情', planRevision: '区域版本', digest: '方案编号', planStatus: '方案状态', taskID: '任务 ID',
    taskRevision: '任务版本', attempt: '第 {{attempt}} / {{maximum}} 次尝试', jobAttempt: '执行次数',
    providerRevision: '服务商当前版本', failure: '错误码：{{code}}', plan: '修复方案',
  },
  values: { empty: '—' },
  diagnosis: {
    title: '{{domain}} 的当前情况', domain: '域名', site: '网站 ID', cname: '应指向（CNAME）', account: 'DNS 账号', zone: 'DNS 区域',
    zoneLoading: '正在匹配', zoneMissing: '未找到托管这个域名的区域',
    task: '自动添加记录', updatedAt: '最近更新', noAccount: '未配置', noTask: '没有自动添加记录',
    taskState: '{{state}}（已尝试 {{attempts}} 次）', taskStates: { pending: '执行中', done: '已完成', failed: '失败' },
    layers: {
      ok: '解析正常：域名已指向分配的 CNAME', account: '问题在 DNS 账号', cname: '问题在网站 CNAME',
      provider: '问题在 DNS 服务商写入', propagation: '问题在解析生效',
    },
    reasons: {
      resolved: '服务商已写入记录且回查一致。', noAccount: '这个网站没有配置用于自动添加记录的 DNS 账号。',
      pending: '自动添加记录正在执行，请稍后再检查。', cname_pending: '网站 CNAME 尚未分配，分配后会自动重试。',
      zone_not_hosted: '所选 DNS 账号下没有托管这个域名。', dns_record_unconfirmed: '服务商没有回查到刚写入的记录，可能仍在生效。',
      dns_record_conflict: '该域名已有其他记录，系统没有覆盖。', apex_domain: '根域名不能设置 CNAME。', wildcard_domain: '泛域名不会自动添加。',
      dns_provider_unavailable: 'DNS 服务商暂时不可用。', unknown: '添加失败（{{code}}）。',
    },
    next: {
      configureDnsApi: '先在 网站管理 > DNS API 添加托管这个域名的账号，再回来检查。',
      sync: '点“检查并生成修复方案”，看清要改哪些记录后再决定是否修复。',
      wait: '自动添加记录还在进行，可以稍后再检查。', none: '解析正常。也可以再检查一次，确认没有多余的旧记录。',
    },
  },
  operationResults: { title: '服务商操作结果', empty: '还没有服务商操作结果。' },
  operationStatuses: {
    planned: '待执行', deferred_until_commit: '等待确认后执行', running: '执行中', succeeded: '成功', transient_failed: '暂时失败',
    permanent_failed: '失败', revision_conflict: '与其他修改冲突', cancelled: '已取消', skipped: '已跳过',
  },
  columns: {
    sequence: '序号', action: '动作', name: '名称', type: '类型', value: '值', line: '线路', weight: '权重', reason: '原因', status: '状态',
    providerRequestID: '服务商请求 ID', providerRecordID: '服务商记录 ID', errorCode: '错误码',
  },
  observations: {
    title: '解析检查', role: '解析点类型', resolver: '解析服务器', values: '查到的值', minimumTTL: '最小 TTL',
    roles: { authoritative: '权威 DNS', public_recursive: '公共 DNS' }, lkg: '已保留最近一次正常的解析状态',
  },
  compensation: { title: '撤销方案' },
  propagation: {
    title: '生效检查记录', empty: '还没有生效检查记录。', attempt: '检查次数', status: '状态', healthy: '连续生效次数',
    states: { healthy: '已生效', pending: '等待中', failed: '失败' },
  },
  operations: { create: '新增', update: '修改', delete: '删除' },
  statuses: {
    dry_run: '方案已生成', applying: '正在写入', propagating: '等待生效', ready_to_commit: '待确认', committed: '已完成',
    failed: '失败', cancelled: '已取消', timed_out: '超时', commit_failed: '删除旧记录失败',
  },
  unknown: {
    title: '暂时无法确认是否已执行', description: '连接在返回结果前中断。可以用原请求再试一次（不会重复执行），或放弃并刷新查看实际状态。',
  },
  errors: {
    forbiddenTitle: '无权查看域名解析修复', forbiddenDescription: '当前账号没有 DNS 查看权限。', forbidden: '当前账号无权执行这个操作。',
    notFound: '没有找到这次修复。', notFoundTitle: '修复任务不存在', notFoundDescription: '任务可能已被删除，或不属于当前账号。',
    conflict: '域名解析刚被其他操作修改过，请刷新后重新检查。', rateLimited: '操作过于频繁，请稍后重试。',
    unavailable: '修复服务暂时不可用，请稍后重试。', invalidRequest: '请求被拒绝，请检查高级设置里的值后重试。',
    requestFailed: '请求失败，请稍后重试。',
  },
} as const
const enUS = {
  title: 'Fix domain DNS',
  description: 'Check whether a domain points at this platform. If not, build a fix, apply it after you confirm, and remove old records once the change is live everywhere.',
  steps: { diagnose: 'Check', plan: 'Review fix', apply: 'Apply and wait', finish: 'Finish', label: 'Fix progress', compact: 'Step {{current}} of {{total}}: {{title}}' },
  picker: {
    title: 'Choose a domain to check', label: 'Domain', placeholder: 'Search by domain or site ID',
    help: 'Its CNAME, DNS account and DNS zone are filled in for you.',
    currentSite: 'This site', otherSites: 'Other sites', site: 'Site {{id}}', empty: 'No matching domains', loading: 'Loading sites',
    error: 'Sites could not be loaded. Try again.',
  },
  check: { action: 'Check and build a fix', loading: 'Reading current DNS and building a fix', changeDomain: 'Choose another domain' },
  units: { seconds: 's' },
  advanced: { title: 'Advanced settings', summary: 'Filled in from the site and DNS account. You rarely need to change these.' },
  fields: {
    type: { label: 'Record type', help: 'Sites use CNAME. Pick A or AAAA only to point straight at an IP.' },
    expectedValue: { label: 'Should point to', help: 'Defaults to the CNAME assigned to the site. Separate several values with commas.' },
    ttl: { label: 'TTL', help: 'How long resolvers cache the answer, 1–604800 seconds. Default 300.' },
    line: { label: 'Resolution line', help: 'Only when your DNS provider supports lines, such as "Overseas". Leave empty for the default line.' },
    weight: { label: 'Weight', help: 'Traffic share when a line has several records, 0–100. 0 means not set.' },
    propagationWindow: { label: 'Maximum wait', help: 'Stop and report if the change is not live everywhere by then, 1–604800 seconds. Default 900 (15 minutes).' },
    authoritativeNS: { label: 'Authoritative DNS servers', help: 'Servers used to confirm the change is live, separated by commas. Leave empty for the system default.' },
    zoneID: { label: 'DNS zone', help: 'The zone hosting this domain, matched from the domain name.' },
    zoneIDManual: { label: 'DNS zone ID', help: 'Zones could not be loaded. Enter the zone ID shown under Sites > DNS API.' },
    providerRevision: { label: 'Zone version', help: 'Prevents overwriting someone else\'s change. Filled in from the zone.' },
  },
  fieldErrors: {
    summary: '{{count}} settings need changes. They are marked below.',
    name: 'Choose a domain first.',
    expectedValue: 'Enter at least one value. Separate several values with commas.',
    ttl: 'Enter a whole number from 1 to 604800 (seconds).',
    line: 'The line name cannot have leading or trailing spaces or control characters, and must be 64 bytes or less.',
    weight: 'Enter a whole number from 0 to 100.',
    propagationWindow: 'Enter a whole number from 1 to 604800 (seconds).',
    zoneID: 'Choose the DNS zone that hosts this domain.',
    providerRevision: 'Enter a whole number greater than 0.',
  },
  plan: {
    title: 'Changes to make', none: 'DNS is already correct. Nothing to change.',
    summary: 'Changes ({{count}}): ', summaryParts: { create: '{{count}} to add', update: '{{count}} to change', delete: '{{count}} to delete' }, summarySeparator: ', ',
    groups: { create: 'Records to add', update: 'Records to change', delete: 'Records to delete' },
    deleteNote: 'Old records are deleted only after the new ones are live everywhere and you confirm again.',
    ttl: 'TTL: {{ttl}} s', change: '{{label}}: {{from}} → {{to}}', line: 'Line', weight: 'Weight', defaultLine: 'Default',
    recheck: 'Check again', readOnly: 'You can view only. A member with DNS manage permission must apply the fix.',
  },
  progress: {
    applying: 'Writing records at the DNS provider', propagating: 'Records written. Waiting for the change to go live everywhere',
    done: '{{completed}} / {{total}} done', wait: 'This usually takes a few minutes, up to {{minutes}} minutes. The page refreshes on its own.',
    resolvers: 'Resolver status', healthy: 'Live', pending: 'Not live yet', noCheck: 'No check results yet. The page refreshes on its own.',
    failed: 'The fix did not finish: {{reason}}', failedHint: 'Cancel this fix, review the advanced settings or DNS account, then check again.',
  },
  finish: {
    readyTitle: 'The new records are live everywhere', readyDescription: 'Confirm to delete the old records in the fix and finish.',
    committedTitle: 'Fix complete', committedDescription: 'DNS is updated and the old records are deleted.',
    cancelledTitle: 'Fix cancelled', cancelledDescription: 'Old records were not deleted. You can check again at any time.',
    commitFailedTitle: 'Old records could not be deleted: {{reason}}', commitFailedDescription: 'The new records still work. Cancel this fix and check again.',
  },
  failureReasons: {
    timed_out: 'waiting for the change timed out', provider: 'the DNS provider returned an error', unknown: 'unknown reason',
  },
  actions: {
    apply: 'Start fix', refreshTask: 'Refresh', retrySameRequest: 'Retry the same request', abandonRefresh: 'Give up and refresh',
    commit: 'Confirm and delete old records', cancelTask: 'Cancel fix', cancel: 'Cancel', keep: 'Keep fixing', back: 'Back to Resolution check',
  },
  confirmations: {
    apply: 'Start the fix? Records at your DNS provider change as listed above.', commit: 'Delete the old records? They are not restored automatically.',
    cancel: 'Cancel the fix? Old records are not deleted.',
  },
  technical: {
    title: 'Technical details', planRevision: 'Zone version', digest: 'Fix ID', planStatus: 'Fix status', taskID: 'Task ID',
    taskRevision: 'Task version', attempt: 'Attempt {{attempt}} / {{maximum}}', jobAttempt: 'Attempts',
    providerRevision: 'Provider version', failure: 'Error code: {{code}}', plan: 'Fix',
  },
  values: { empty: '—' },
  diagnosis: {
    title: 'Current state of {{domain}}', domain: 'Domain', site: 'Site ID', cname: 'Should point to (CNAME)', account: 'DNS account', zone: 'DNS zone',
    zoneLoading: 'Matching', zoneMissing: 'No zone hosts this domain',
    task: 'Automatic record', updatedAt: 'Last updated', noAccount: 'Not configured', noTask: 'No automatic record',
    taskState: '{{state}} ({{attempts}} attempts)', taskStates: { pending: 'Running', done: 'Done', failed: 'Failed' },
    layers: {
      ok: 'Resolved: the domain points at the assigned CNAME', account: 'The DNS account is the problem', cname: 'The site CNAME is the problem',
      provider: 'Writing at the DNS provider is the problem', propagation: 'The record has not taken effect',
    },
    reasons: {
      resolved: 'The provider has the record and it reads back the same.', noAccount: 'This site has no DNS account for automatic records.',
      pending: 'The automatic record is still being added; check again later.', cname_pending: 'The site CNAME is not assigned yet; it retries once assigned.',
      zone_not_hosted: 'The chosen DNS account does not host this domain.', dns_record_unconfirmed: 'The provider did not read back the record yet; it may still be taking effect.',
      dns_record_conflict: 'The domain already has another record, which was not overwritten.', apex_domain: 'An apex domain cannot be a CNAME.', wildcard_domain: 'Wildcard domains are not added automatically.',
      dns_provider_unavailable: 'The DNS provider is unavailable for now.', unknown: 'Adding failed ({{code}}).',
    },
    next: {
      configureDnsApi: 'First add the account that hosts this domain under Sites > DNS API, then check again.',
      sync: 'Click "Check and build a fix" to see which records would change before you decide.',
      wait: 'The automatic record is still in progress. Check again later.', none: 'DNS is fine. You can check again to make sure no old records remain.',
    },
  },
  operationResults: { title: 'Provider results', empty: 'No provider results yet.' },
  operationStatuses: {
    planned: 'Pending', deferred_until_commit: 'Runs after you confirm', running: 'Running', succeeded: 'Succeeded', transient_failed: 'Temporary failure',
    permanent_failed: 'Failed', revision_conflict: 'Conflicts with another change', cancelled: 'Cancelled', skipped: 'Skipped',
  },
  columns: {
    sequence: 'No.', action: 'Action', name: 'Name', type: 'Type', value: 'Value', line: 'Line', weight: 'Weight', reason: 'Reason', status: 'Status',
    providerRequestID: 'Provider request ID', providerRecordID: 'Provider record ID', errorCode: 'Error code',
  },
  observations: {
    title: 'DNS checks', role: 'Resolver type', resolver: 'Resolver', values: 'Values found', minimumTTL: 'Minimum TTL',
    roles: { authoritative: 'Authoritative DNS', public_recursive: 'Public DNS' }, lkg: 'The last working DNS state is kept',
  },
  compensation: { title: 'Undo plan' },
  propagation: {
    title: 'Live checks', empty: 'No live checks yet.', attempt: 'Check', status: 'Status', healthy: 'Live in a row',
    states: { healthy: 'Live', pending: 'Waiting', failed: 'Failed' },
  },
  operations: { create: 'Add', update: 'Change', delete: 'Delete' },
  statuses: {
    dry_run: 'Fix ready', applying: 'Writing', propagating: 'Waiting to go live', ready_to_commit: 'Waiting for you', committed: 'Complete',
    failed: 'Failed', cancelled: 'Cancelled', timed_out: 'Timed out', commit_failed: 'Deleting old records failed',
  },
  unknown: {
    title: 'Not sure whether it ran', description: 'The connection ended before a result came back. Retry the same request (it will not run twice), or give up and refresh to see what happened.',
  },
  errors: {
    forbiddenTitle: 'You cannot view DNS fixes', forbiddenDescription: 'Your account lacks DNS view permission.', forbidden: 'Your account cannot do this.',
    notFound: 'This fix was not found.', notFoundTitle: 'Fix not found', notFoundDescription: 'It may have been removed or belongs to another account.',
    conflict: 'DNS was just changed by something else. Refresh and check again.', rateLimited: 'Too many requests. Try again later.',
    unavailable: 'The fix service is unavailable for now. Try again later.', invalidRequest: 'The request was rejected. Review the advanced settings and try again.',
    requestFailed: 'The request failed. Try again later.',
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
