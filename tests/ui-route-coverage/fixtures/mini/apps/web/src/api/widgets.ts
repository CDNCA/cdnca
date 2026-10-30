const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

async function request<T>(token: string, path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(`${apiRoot}${path}`, { ...init, headers: { Authorization: `Bearer ${token}` } })
  return (await response.json()) as T
}

const json = (method: string, body: unknown): RequestInit => ({ method, body: JSON.stringify(body) })

function base(admin: boolean): string {
  return admin ? '/v1/admin/bans' : '/v1/bans'
}

// 形参是普通 id 的函数声明，本文件不直接调用、只经导出对象使用：仍要记为 GET /v1/gadgets/{}
async function getGadget(token: string, gadgetId: string): Promise<unknown> {
  const response = await fetch(`${apiRoot}/v1/gadgets/${gadgetId}`, { headers: { Authorization: `Bearer ${token}` } })
  return response.json()
}

export const widgetsApi = {
  getGadget,
  list: (token: string) => request<unknown>(token, '/v1/widgets'),
  create: (token: string, body: unknown) => request<unknown>(token, '/v1/widgets', { method: 'POST', body: JSON.stringify(body) }),
  // 后端只有 DELETE：方法不符
  rename: (token: string, id: string) => request<unknown>(token, `/v1/widgets/${encodeURIComponent(id)}`, { method: 'PATCH' }),
  // 后端不存在
  missing: (token: string) => request<unknown>(token, '/v1/nope'),
  bans: (token: string, admin: boolean) => request<unknown>(token, base(admin)),
  report: (token: string, id: string) => request<unknown>(token, `/v1/reports/${id}/summary`),
  // 同一条件的三元路径 + 三元方法：按分支配对（PUT /v1/widgets/{} 与 POST /v1/widgets），不产生 POST /v1/widgets/{}
  save: (token: string, w: { id?: string }) =>
    request<unknown>(token, w.id ? `/v1/widgets/${encodeURIComponent(w.id)}` : '/v1/widgets', json(w.id ? 'PUT' : 'POST', w)),
}

// 工厂函数：接口前缀经无默认值的形参传入，由同文件调用点给出（记为 GET /v1/things/count）
function thingsApi(base: string) {
  return { count: (token: string) => request<unknown>(token, `${base}/count`) }
}
export const adminThingsApi = thingsApi('/v1/things')
