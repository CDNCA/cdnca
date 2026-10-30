import { networkApiError, responseApiError } from './auth'

/** A website's own traffic caps (ge-analytics, GET/PUT /v1/sites/{id}/traffic-limit). */
export interface SiteTrafficLimitSetting {
  enabled: boolean
  daily_bytes: number | null
  monthly_bytes: number | null
  total_bytes: number | null
  time_zone: string
  notice_html: string
}

export type SiteTrafficLimitPeriod = '' | 'daily' | 'monthly' | 'total'

export interface SiteTrafficLimitState {
  site_id: string
  version: number
  setting: SiteTrafficLimitSetting
  total_since: string | null
  exceeded_period: SiteTrafficLimitPeriod
  exceeded_at: string | null
  evaluated_at: string | null
  updated_at: string | null
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

async function request<T>(accessToken: string, path: string, init: RequestInit = {}): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      headers: { Authorization: `Bearer ${accessToken}`, ...(init.body ? { 'Content-Type': 'application/json' } : {}), ...init.headers },
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  return (await response.json()) as T
}

function get(accessToken: string, siteID: string, signal?: AbortSignal): Promise<SiteTrafficLimitState> {
  return request(accessToken, `/v1/sites/${encodeURIComponent(siteID)}/traffic-limit`, { signal })
}

function put(accessToken: string, siteID: string, version: number, setting: SiteTrafficLimitSetting,
  idempotencyKey: string): Promise<SiteTrafficLimitState> {
  return request(accessToken, `/v1/sites/${encodeURIComponent(siteID)}/traffic-limit`, {
    method: 'PUT', headers: { 'Idempotency-Key': idempotencyKey, 'If-Match': `"${version}"` }, body: JSON.stringify(setting),
  })
}

export const siteTrafficLimitApi = { get, put }
