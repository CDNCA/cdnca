// 接口目录数据：tools/openapi-catalog 从 api/openapi/v1/{control,sites,dns-acme}.yaml 生成
// （Go 单测防漂移），不手写：
//   generated/api-catalog.json            索引（方法、路径、摘要、认证、operationId、分组）
//   generated/api-operations/<分组>.json   每个 operation 的详情（说明、权限、参数、请求体与响应字段、状态码）
// 索引约 300 KB，只在 /developers/api* 页按需加载；分组详情只在对应分组页加载。
// 预渲染与测试同步读（setCatalog / setGroupDetails），浏览器端动态 import 后再水合。
export interface ApiOperation {
  method: string
  path: string
  summary: string
  /** 契约 x-summary-zh */
  summary_zh?: string
  auth: string[]
  api_key: boolean
  tags?: string[]
  deprecated?: boolean
  source: string
  operation_id: string
}
export interface ApiGroup {
  id: string
  prefix: string
  count: number
  api_key_count: number
  operations: ApiOperation[]
}
export interface ApiCatalog {
  sources: string[]
  total: number
  api_key_count: number
  groups: ApiGroup[]
}
export interface ApiField {
  name: string
  in?: string
  type: string
  required?: boolean
  description?: string
  description_zh?: string
}
export interface ApiOperationDetail {
  operation_id: string
  method: string
  path: string
  summary: string
  summary_zh?: string
  auth: string[]
  description?: string
  /** 契约 x-description-zh：与英文原文写在同一处，不机器翻译 */
  description_zh?: string
  /** 全部都要有 */
  permissions?: string[]
  /** 有其一即可 */
  any_permissions?: string[]
  /** 需要已开通的功能模块 */
  features?: string[]
  recent_reauth?: boolean
  params?: ApiField[]
  body?: { content_types: string[]; required?: boolean; fields?: ApiField[] }
  responses?: { status: string; description?: string; description_zh?: string; fields?: ApiField[] }[]
}
export interface ApiGroupDetail {
  id: string
  prefix: string
  operations: ApiOperationDetail[]
}

let cached: ApiCatalog | null = null
const details = new Map<string, ApiGroupDetail>()

export function setCatalog(c: ApiCatalog) {
  cached = c
}
export function getCatalog(): ApiCatalog | null {
  return cached
}
export async function loadCatalog(): Promise<ApiCatalog> {
  if (!cached) cached = (await import('../generated/api-catalog.json')).default as ApiCatalog
  return cached
}

export function setGroupDetails(list: ApiGroupDetail[]) {
  for (const d of list) details.set(d.id, d)
}
export function getGroupDetail(id: string): ApiGroupDetail | undefined {
  return details.get(id)
}
const lazyDetails = import.meta.glob<{ default: ApiGroupDetail }>('../generated/api-operations/*.json')
export async function loadGroupDetail(id: string): Promise<ApiGroupDetail | undefined> {
  const hit = details.get(id)
  if (hit) return hit
  const load = lazyDetails[`../generated/api-operations/${id}.json`]
  if (!load) return undefined
  const d = (await load()).default
  details.set(d.id, d)
  return d
}
