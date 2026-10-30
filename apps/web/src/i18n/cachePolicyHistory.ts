import i18n from './index'

export type CachePolicyHistoryMessageTree = {
  [key: string]: string | CachePolicyHistoryMessageTree
}

type MessageShape<T> = {
  [K in keyof T]: T[K] extends string ? string : MessageShape<T[K]>
}

const zhCN = {
  title: '缓存策略修订历史',
  subtitle: '按站点查看已发布的缓存策略修订和不可变详情。',
  filters: {
    siteId: '站点 ID',
    sitePlaceholder: '输入站点 UUID',
    invalidSite: '请输入有效的站点 UUID。',
  },
  actions: {
    search: '查询修订',
    refresh: '刷新',
    retry: '重试',
    previous: '上一页',
    next: '下一页',
    view: '查看详情',
    close: '关闭详情',
  },
  states: {
    selectSite: '输入站点 ID 后查询修订历史。',
    loading: '缓存策略修订加载中',
    empty: '当前站点暂无缓存策略修订。',
    loadFailed: '缓存策略修订加载失败。',
    forbiddenTitle: '无权查看缓存策略历史',
    forbiddenDescription: '当前租户身份缺少站点查看权限。',
    notFoundTitle: '未找到缓存策略历史',
    notFoundDescription: '站点不存在、不可见或尚未建立缓存策略。',
    detailLoading: '缓存策略修订详情加载中',
    detailFailed: '缓存策略修订详情加载失败。',
    detailNotFound: '该缓存策略修订不存在或不可见。',
  },
  table: {
    revision: '修订',
    mode: '缓存模式',
    createdAt: '发布时间',
    createdBy: '发布用户',
    requestId: '请求 ID',
    action: '操作',
    page: '第 {{page}} 页',
  },
  detail: {
    title: '修订 {{revision}} 详情',
    siteId: '站点 ID',
    revision: '修订',
    mode: '缓存模式',
    queryMode: '查询参数模式',
    ruleCount: '规则数量',
    diskQuota: '磁盘配额',
    createdAt: '发布时间',
    createdBy: '发布用户',
    requestId: '请求 ID',
  },
  modes: {
    disabled: '停用缓存',
    follow_origin: '遵循源站',
    override: '自定义规则',
  },
  queryModes: {
    preserve: '保留全部参数',
    ignore: '忽略全部参数',
    include: '仅保留指定参数',
    exclude: '排除指定参数',
  },
  errors: {
    network_error: '无法连接缓存策略服务，请稍后重试。',
    invalid_response: '缓存策略服务响应无效，请稍后重试。',
    permission_denied: '当前身份无权查看缓存策略修订。',
    not_found: '未找到站点或缓存策略修订。',
    invalid_request: '缓存策略历史查询无效，请检查站点 ID。',
    service_unavailable: '缓存策略服务暂不可用，请稍后重试。',
    request_failed: '缓存策略历史查询失败，请稍后重试。',
  },
} as const

const enUS = {
  title: 'Cache policy revision history',
  subtitle: 'Inspect published cache policy revisions and immutable details by site.',
  filters: {
    siteId: 'Site ID',
    sitePlaceholder: 'Enter a site UUID',
    invalidSite: 'Enter a valid site UUID.',
  },
  actions: {
    search: 'Search revisions',
    refresh: 'Refresh',
    retry: 'Retry',
    previous: 'Previous',
    next: 'Next',
    view: 'View details',
    close: 'Close details',
  },
  states: {
    selectSite: 'Enter a site ID to load revision history.',
    loading: 'Loading cache policy revisions',
    empty: 'This site has no cache policy revisions.',
    loadFailed: 'Failed to load cache policy revisions.',
    forbiddenTitle: 'Cache policy history unavailable',
    forbiddenDescription: 'The current tenant identity lacks site read permission.',
    notFoundTitle: 'Cache policy history not found',
    notFoundDescription: 'The site does not exist, is not visible, or has no cache policy.',
    detailLoading: 'Loading cache policy revision details',
    detailFailed: 'Failed to load cache policy revision details.',
    detailNotFound: 'This cache policy revision does not exist or is not visible.',
  },
  table: {
    revision: 'Revision',
    mode: 'Cache mode',
    createdAt: 'Published at',
    createdBy: 'Published by',
    requestId: 'Request ID',
    action: 'Action',
    page: 'Page {{page}}',
  },
  detail: {
    title: 'Revision {{revision}} details',
    siteId: 'Site ID',
    revision: 'Revision',
    mode: 'Cache mode',
    queryMode: 'Query parameter mode',
    ruleCount: 'Rule count',
    diskQuota: 'Disk quota',
    createdAt: 'Published at',
    createdBy: 'Published by',
    requestId: 'Request ID',
  },
  modes: {
    disabled: 'Caching disabled',
    follow_origin: 'Follow origin',
    override: 'Custom rules',
  },
  queryModes: {
    preserve: 'Preserve all parameters',
    ignore: 'Ignore all parameters',
    include: 'Preserve selected parameters',
    exclude: 'Exclude selected parameters',
  },
  errors: {
    network_error: 'Unable to reach the cache policy service. Try again later.',
    invalid_response: 'The cache policy service returned an invalid response. Try again later.',
    permission_denied: 'The current identity cannot view cache policy revisions.',
    not_found: 'The site or cache policy revision was not found.',
    invalid_request: 'The cache policy history request is invalid. Check the site ID.',
    service_unavailable: 'The cache policy service is temporarily unavailable. Try again later.',
    request_failed: 'The cache policy history request failed. Try again later.',
  },
} satisfies MessageShape<typeof zhCN>

function pseudoText(value: string): string {
  const expanded = value
    .split(/({{[^}]+}})/g)
    .map((part) => part.startsWith('{{') && part.endsWith('}}')
      ? part
      : [...part].map((character) => (/\s/u.test(character) ? character : `${character}~`)).join(''))
    .join('')
  return `［${expanded}］`
}

function pseudoTree(tree: CachePolicyHistoryMessageTree): CachePolicyHistoryMessageTree {
  return Object.fromEntries(Object.entries(tree).map(([key, value]) => [
    key,
    typeof value === 'string' ? pseudoText(value) : pseudoTree(value),
  ]))
}

const pseudoCN = pseudoTree(zhCN)

export const cachePolicyHistoryMessages = {
  'zh-CN': zhCN,
  'en-US': enUS,

} as unknown as Record<
  'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc',
  CachePolicyHistoryMessageTree
>

if (import.meta.env.MODE === 'test') {
  cachePolicyHistoryMessages['qps-ploc'] = pseudoCN
  cachePolicyHistoryMessages['qps-Ploc'] = pseudoCN
}

for (const [locale, messages] of Object.entries(cachePolicyHistoryMessages)) {
  i18n.addResourceBundle(locale, 'cachePolicyHistory', messages, true, true)
}
