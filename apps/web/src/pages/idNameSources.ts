// 「ID 或名称」筛选的联想来源。每个来源只调用
// 已有的只读列表接口（按现有权限），返回 IdOrNameInput 的选项；无权读取时接口回 403，
// 组件据此退回只按 ID。value 是页面按其过滤的值（UUID 或展示 ID，按页面实际参数）。
import type { IdOrNameOption } from '@cdnca/ui'

import { certificatesApi } from '../api/certificates'
import { nodesApi } from '../api/nodes'
import { sitesApi } from '../api/sites'
import { streamsApi } from '../api/streams'
import { usersApi } from '../api/users'

const limit = 10

type Search = (text: string, signal: AbortSignal) => Promise<IdOrNameOption[]>

// AbortSignal 不进现有 API 函数：迟到结果由组件丢弃（abort 后不再 setState）。
function guarded(load: (text: string) => Promise<IdOrNameOption[]>): Search {
  return async (text, signal) => {
    const result = await load(text)
    if (signal.aborted) return []
    return result
  }
}

/** 用户：按用户名/显示名/邮箱/手机模糊（search），或展示 ID 精确（display_id）。 */
export function userSearch(accessToken: string, filterBy: 'id' | 'display_id' = 'id'): Search {
  return guarded(async (text) => {
    const params = /^\d+$/.test(text) ? { page: 1, limit, display_id: text } : { page: 1, limit, search: text }
    const page = await usersApi.list(accessToken, params)
    return page.items.map((user) => ({
      id: filterBy === 'id' ? user.id : user.display_id,
      code: user.display_id,
      name: user.display_name && user.display_name !== user.username ? `${user.username} ${user.display_name}` : user.username,
    }))
  })
}

/** 站点：按域名模糊（后端 domain 同时认展示 ID）。 */
export function siteSearch(accessToken: string, filterBy: 'id' | 'display_id' = 'display_id'): Search {
  return guarded(async (text) => {
    const page = await sitesApi.list(accessToken, { page: 1, limit, domain: text })
    return page.items.map((site) => ({
      id: filterBy === 'id' ? site.id : site.display_id,
      code: site.display_id,
      name: site.domain,
      detail: site.owner?.display_name,
    }))
  })
}

/** 节点：按名称/IP 模糊（inventory search）。 */
export function nodeSearch(accessToken: string, filterBy: 'id' | 'display_id' = 'id'): Search {
  return guarded(async (text) => {
    const page = await nodesApi.list(accessToken, { limit, search: text })
    return page.items.map((node) => ({
      id: filterBy === 'id' ? node.id : node.display_id,
      code: node.display_id,
      name: node.name,
      detail: [node.ipv4, node.ipv6].filter(Boolean).join(' / ') || undefined,
    }))
  })
}

/** 证书：按名称/域名/展示 ID 模糊（列表 search），过滤值为证书展示 ID。 */
export function certificateSearch(accessToken: string): Search {
  return guarded(async (text) => {
    const page = await certificatesApi.listAssets(accessToken, undefined, { page: 1, limit, search: text })
    return page.items.map((asset) => ({ id: asset.display_id, name: asset.name, detail: asset.owner?.username }))
  })
}

/** 四层转发：按名称/备注/源站/端口/展示 ID 模糊（列表 search），过滤值为转发展示 ID。 */
export function streamSearch(accessToken: string): Search {
  return guarded(async (text) => {
    const page = await streamsApi.list(accessToken, { page: 1, limit, search: text })
    return page.items.map((stream) => ({ id: stream.display_id, name: stream.name || `${stream.protocol.toUpperCase()} ${stream.listen_port}`, detail: `${stream.protocol.toUpperCase()} ${stream.listen_port}` }))
  })
}
