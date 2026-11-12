import { ApiError, networkApiError, responseApiError } from './auth'

// 管理员自定义 CNAME 主机名/前缀。仅平台会话可用，租户会话 403。
// 契约：api/openapi/v1/control.yaml 的 /v1/admin/cname-labels/{kind}/{id}*。
export type CnameLabelKind = 'site' | 'line-group'

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

async function request<T>(accessToken: string, method: string, path: string, body?: unknown, idempotencyKey?: string): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      method,
      credentials: 'include',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
        ...(idempotencyKey ? { 'Idempotency-Key': idempotencyKey } : {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  return await response.json() as T
}

function path(kind: CnameLabelKind, id: string, suffix = ''): string {
  return `/v1/admin/cname-labels/${kind}/${encodeURIComponent(id)}${suffix}`
}

function count(body: { sites?: unknown }): number {
  if (typeof body.sites !== 'number' || !Number.isSafeInteger(body.sites) || body.sites < 0) {
    throw new ApiError('Invalid CNAME label response', 502, 'invalid_response')
  }
  return body.sites
}

export const cnameLabelsApi = {
  /** GET: the saved name; '' when none is set. */
  async get(accessToken: string, kind: CnameLabelKind, id: string): Promise<string> {
    const body = await request<{ label?: unknown }>(accessToken, 'GET', path(kind, id))
    return typeof body.label === 'string' ? body.label : ''
  },
  /** PUT: '' clears. A site name re-allocates its CNAME; a line group prefix only affects later ones. */
  async put(accessToken: string, kind: CnameLabelKind, id: string, label: string, idempotencyKey: string): Promise<string> {
    const body = await request<{ label?: unknown }>(accessToken, 'PUT', path(kind, id), { label }, idempotencyKey)
    return typeof body.label === 'string' ? body.label : ''
  },
  /** GET .../affected: how many sites "regenerate under the new prefix" would re-allocate. */
  async affected(accessToken: string, kind: CnameLabelKind, id: string): Promise<number> {
    return count(await request<{ sites?: unknown }>(accessToken, 'GET', path(kind, id, '/affected')))
  },
  /** POST .../regenerate: re-allocates the affected sites; returns how many. */
  async regenerate(accessToken: string, kind: CnameLabelKind, id: string, idempotencyKey: string): Promise<number> {
    return count(await request<{ sites?: unknown }>(accessToken, 'POST', path(kind, id, '/regenerate'), undefined, idempotencyKey))
  },
}
