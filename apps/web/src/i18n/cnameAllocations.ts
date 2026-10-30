import i18n from './index'

const zhCN = {
  title: 'CNAME 分配权威',
  description: { tenant: '查看当前租户的 CNAME 分配、权威详情与站点诊断。', platform: '查看所选租户的 CNAME 分配、权威详情与站点诊断。' },
  scope: { label: '租户作用域 ID', query: '查询', prompt: '请输入租户作用域后查询。', invalid: '请输入规范的小写 UUID。' },
  actions: { refresh: '刷新', retry: '重试', previous: '上一页', next: '下一页', detail: '查看详情', diagnose: '诊断' },
  diagnosis: { title: '站点诊断', site: '站点 ID', domain: '域名', hostname: '主机名', ready: '可用', blocked: '不可用', result: '诊断结果', invalid: '请输入规范的站点 ID 与小写域名。' },
  columns: { id: '分配 ID', mode: '模式', owner: '所有者 ID', domain: '域名', hostname: '主机名', state: '状态', generation: '代次', revision: '当前版本', updated: '更新时间', actions: '操作', provider: 'DNS 提供商 ID', zone: 'DNS 区域 ID', job: '任务 ID', explicit: '显式主机名', lkg: '最近可用版本' },
  modes: { site: '站点', package: '套餐' },
  states: { pending: '处理中', failed: '失败', done: '已完成' },
  values: { yes: '是', no: '否', none: '无' },
  pagination: { page: '第 {{page}} 页' },
  data: { loading: '正在加载 CNAME 分配记录', empty: '暂无 CNAME 分配记录', detailLoading: '正在加载 CNAME 分配详情', diagnosisLoading: '正在诊断 CNAME 分配权威' },
  reasons: { ready: '分配权威已就绪', mode_unconfigured: '站点尚未配置分配模式', package_binding_missing: '站点缺少套餐绑定', mode_invalid: '分配模式无效', current_binding_missing: '当前绑定缺失', lkg_available: '存在最近可用分配', lkg_missing: '没有最近可用分配', default_zone_missing: '默认 DNS 区域缺失', zone_not_found: 'DNS 区域不存在', provider_mismatch: 'CNAME 域名所在的 DNS 服务商已停用', owner_allocation_missing: '所有者分配缺失', owner_allocation_pending: '所有者分配仍在处理', owner_allocation_failed: '所有者分配失败', owner_allocation_invalid: '所有者分配状态无效', current_binding_drift: '当前绑定发生漂移', allocation_zone_drift: '分配 DNS 区域发生漂移', allocation_hostname_drift: '分配主机名发生漂移', hostname_claim_conflict: '主机名声明冲突', unknown: '未识别的诊断原因' },
  failure: { title: 'CNAME 分配失败：{{reasons}}', unknown: 'CNAME 分配失败，暂时无法获取失败原因', hints: { default_zone_missing: '未配置默认 CNAME 区，请到 节点管理 → DNS配置 → CNAME域名 配置。', zone_not_found: '站点使用的 CNAME 域名没有对应的 DNS 区域，请到 节点管理 → DNS配置 → CNAME域名 添加。', provider_mismatch: 'CNAME 域名所在的 DNS 服务商已停用，请到 节点管理 → DNS配置 检查。', package_binding_missing: '站点未绑定套餐，请先为站点绑定套餐。', mode_unconfigured: '站点尚未配置 CNAME 分配模式。' } },
  errors: { forbiddenTitle: '无权查看 CNAME 分配权威', forbiddenDescription: '当前身份缺少所需的 DNS 读取或平台管理权限。', requestFailed: 'CNAME 分配记录加载失败，请重试', invalidResponse: 'CNAME 分配服务返回了无效数据', notFound: '未找到当前作用域内的 CNAME 分配权威', requestTimeout: 'CNAME 分配查询超时，请重试', unavailable: 'CNAME 分配服务暂不可用，请稍后重试', network: '网络连接失败，请重试', validation: 'CNAME 分配查询参数无效' },
}

const enUS: typeof zhCN = {
  title: 'CNAME allocation authority',
  description: { tenant: 'View CNAME allocations, authority detail, and site diagnosis for the current tenant.', platform: 'View CNAME allocations, authority detail, and site diagnosis for the selected tenant.' },
  scope: { label: 'Tenant scope ID', query: 'Query', prompt: 'Enter a tenant scope to query.', invalid: 'Enter a canonical lowercase UUID.' },
  actions: { refresh: 'Refresh', retry: 'Retry', previous: 'Previous page', next: 'Next page', detail: 'View detail', diagnose: 'Diagnose' },
  diagnosis: { title: 'Site diagnosis', site: 'Site ID', domain: 'Domain', hostname: 'Hostname', ready: 'Ready', blocked: 'Blocked', result: 'Diagnosis result', invalid: 'Enter a canonical site ID and lowercase domain names.' },
  columns: { id: 'Allocation ID', mode: 'Mode', owner: 'Owner ID', domain: 'Domain', hostname: 'Hostname', state: 'State', generation: 'Generation', revision: 'Current revision', updated: 'Updated at', actions: 'Actions', provider: 'DNS provider ID', zone: 'DNS zone ID', job: 'Job ID', explicit: 'Explicit hostname', lkg: 'Last-known-good revision' },
  modes: { site: 'Site', package: 'Package' },
  states: { pending: 'Pending', failed: 'Failed', done: 'Done' },
  values: { yes: 'Yes', no: 'No', none: 'None' },
  pagination: { page: 'Page {{page}}' },
  data: { loading: 'Loading CNAME allocations', empty: 'No CNAME allocations', detailLoading: 'Loading CNAME allocation detail', diagnosisLoading: 'Diagnosing CNAME allocation authority' },
  reasons: { ready: 'Allocation authority is ready', mode_unconfigured: 'Allocation mode is not configured', package_binding_missing: 'Package binding is missing', mode_invalid: 'Allocation mode is invalid', current_binding_missing: 'Current binding is missing', lkg_available: 'A last-known-good allocation is available', lkg_missing: 'No last-known-good allocation is available', default_zone_missing: 'Default DNS zone is missing', zone_not_found: 'DNS zone was not found', provider_mismatch: 'The DNS provider of the CNAME domain is disabled', owner_allocation_missing: 'Owner allocation is missing', owner_allocation_pending: 'Owner allocation is pending', owner_allocation_failed: 'Owner allocation failed', owner_allocation_invalid: 'Owner allocation state is invalid', current_binding_drift: 'Current binding has drifted', allocation_zone_drift: 'Allocation DNS zone has drifted', allocation_hostname_drift: 'Allocation hostname has drifted', hostname_claim_conflict: 'Hostname claim conflicts with another allocation', unknown: 'Unrecognized diagnosis reason' },
  failure: { title: 'CNAME allocation failed: {{reasons}}', unknown: 'CNAME allocation failed; the reason is not available yet', hints: { default_zone_missing: 'No default CNAME zone is configured. Configure one under Nodes → DNS configuration → CNAME domains.', zone_not_found: 'The CNAME domain used by this site has no DNS zone. Add it under Nodes → DNS configuration → CNAME domains.', provider_mismatch: 'The DNS provider of the CNAME domain is disabled. Check it under Nodes → DNS configuration.', package_binding_missing: 'The site has no package binding. Bind a package first.', mode_unconfigured: 'The site has no CNAME allocation mode configured.' } },
  errors: { forbiddenTitle: 'No permission to view CNAME allocation authority', forbiddenDescription: 'The current identity lacks the required DNS read or platform administration permission.', requestFailed: 'Could not load CNAME allocations. Try again.', invalidResponse: 'The CNAME allocation service returned invalid data.', notFound: 'No CNAME allocation authority was found in this scope.', requestTimeout: 'The CNAME allocation query timed out. Try again.', unavailable: 'The CNAME allocation service is temporarily unavailable. Try again later.', network: 'The network request failed. Try again.', validation: 'The CNAME allocation query is invalid.' },
}

type Messages = typeof zhCN

function pseudoText(value: string): string {
  const tokens: string[] = []
  const protectedValue = value.replace(/\{\{[^{}]+\}\}/g, (token) => {
    tokens.push(token)
    return `__TOKEN_${tokens.length - 1}__`
  })
  return `［¡¡ ${protectedValue.replace(/[A-Za-z\u4e00-\u9fff]/g, '$&$&')} !!］`
    .replace(/__TOKEN_(\d+)__/g, (_match, index: string) => tokens[Number(index)] ?? '')
}

function pseudoTree(value: unknown): unknown {
  return typeof value === 'string' ? pseudoText(value) : Object.fromEntries(
    Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudoTree(child)]),
  )
}

const pseudoCN = pseudoTree(zhCN) as Messages

export const cnameAllocationsMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', Messages> = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudoCN,
  'qps-Ploc': pseudoCN,
}

for (const [locale, messages] of Object.entries(cnameAllocationsMessages)) {
  i18n.addResourceBundle(locale, 'cnameAllocations', messages, true, true)
}
