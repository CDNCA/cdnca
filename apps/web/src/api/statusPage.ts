import { ApiError, networkApiError, responseApiError } from './auth'

// 公开状态页编辑接口。公开页 /status/ 自己读 /v1/status-page/public。

export type ComponentStatus = 'operational' | 'degraded' | 'outage' | 'maintenance'
export type IncidentKind = 'incident' | 'maintenance'
export type IncidentStatus = 'investigating' | 'identified' | 'monitoring' | 'resolved' | 'scheduled' | 'in_progress' | 'completed'

export interface StatusPageSettings { enabled: boolean; title: string; description: string; show_logo: boolean }

export interface StatusPageComponent {
  id: string
  name: string
  description: string
  source: 'manual' | 'line_group'
  line_group_id?: string
  line_group_name?: string
  line_group_missing: boolean
  manual_status: ComponentStatus
  hidden: boolean
  auto_status?: ComponentStatus
  status: ComponentStatus
}

export interface StatusPageComponentInput {
  id?: string
  name: string
  description: string
  source: 'manual' | 'line_group'
  line_group_id?: string
  manual_status: ComponentStatus
  hidden?: boolean
}

export interface StatusPageIncidentUpdate { id: string; status: IncidentStatus; message: string; created_at: string }

export interface StatusPageIncident {
  id: string
  kind: IncidentKind
  title: string
  impact: 'degraded' | 'outage' | 'maintenance'
  status: IncidentStatus
  component_ids: string[]
  scheduled_start?: string
  scheduled_end?: string
  started_at: string
  resolved_at?: string
  updates: StatusPageIncidentUpdate[]
}

export interface StatusPageAdminView {
  revision: number
  settings: StatusPageSettings
  components: StatusPageComponent[]
  incidents: StatusPageIncident[]
  line_groups: { id: string; name: string }[]
  updated_at: string
}

export interface StatusPageIncidentInput {
  kind: IncidentKind
  title: string
  impact: 'degraded' | 'outage' | 'maintenance'
  status: IncidentStatus
  message: string
  component_ids: string[]
  scheduled_start?: string
  scheduled_end?: string
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const root = '/v1/admin/status-page'

function isAdminView(value: unknown): value is StatusPageAdminView {
  const view = value as StatusPageAdminView | null
  return typeof view === 'object' && view !== null && Number.isSafeInteger(view.revision) && typeof view.settings === 'object' &&
    Array.isArray(view.components) && Array.isArray(view.incidents) && Array.isArray(view.line_groups)
}

async function call<T>(path: string, token: string, operation: string, init: RequestInit = {}, check?: (value: unknown) => value is T): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}${root}${path}`, {
      credentials: 'include', ...init,
      headers: {
        Authorization: `Bearer ${token}`, 'X-Request-ID': `status-page-${operation}-${crypto.randomUUID()}`,
        ...(init.body ? { 'Content-Type': 'application/json' } : {}), ...(init.headers as Record<string, string> | undefined),
      },
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  if (response.status === 204) return undefined as T
  let body: unknown
  try { body = await response.json() } catch { throw new ApiError('Invalid API response', 0, 'invalid_response') }
  if (check && !check(body)) throw new ApiError('Invalid API response', 0, 'invalid_response')
  return body as T
}

export const statusPageApi = {
  get: (token: string) => call('', token, 'get', {}, isAdminView),
  save: (token: string, revision: number, settings: StatusPageSettings, components: StatusPageComponentInput[]) =>
    call('', token, 'save', { method: 'PUT', body: JSON.stringify({ settings, components }), headers: { 'If-Match': `"${revision}"` } }, isAdminView),
  createIncident: (token: string, input: StatusPageIncidentInput) =>
    call<StatusPageIncident>('/incidents', token, 'incident-create', { method: 'POST', body: JSON.stringify(input) }),
  addUpdate: (token: string, id: string, status: IncidentStatus, message: string) =>
    call<StatusPageIncident>(`/incidents/${encodeURIComponent(id)}/updates`, token, 'incident-update', {
      method: 'POST', body: JSON.stringify({ status, message }),
    }),
  deleteIncident: (token: string, id: string) =>
    call<void>(`/incidents/${encodeURIComponent(id)}`, token, 'incident-delete', { method: 'DELETE' }),
}

export const incidentStatuses: Record<IncidentKind, IncidentStatus[]> = {
  incident: ['investigating', 'identified', 'monitoring', 'resolved'],
  maintenance: ['scheduled', 'in_progress', 'completed'],
}
