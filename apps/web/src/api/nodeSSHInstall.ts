import { ApiError, networkApiError, responseApiError } from './auth'

// SSH remote node install (control-api internal/nodesshinstall).
export type SSHInstallState = 'awaiting_host_key' | 'pending' | 'running' | 'succeeded' | 'failed' | 'cancelled'

export interface SSHInstallJob {
  id: string
  batch_id: string
  host: string
  port: number
  username: string
  auth_kind: 'password' | 'private_key'
  node_name: string
  host_key_sha256: string
  host_key_confirmed: boolean
  state: SSHInstallState
  failure_code: string
  progress: string[]
  node_id: string | null
  attempts: number
  created_at: string
  started_at: string | null
  finished_at: string | null
}

export interface CreateSSHInstallInput {
  hosts: string[]
  port: number
  names?: string[]
  username: string
  password?: string
  private_key?: string
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const states: readonly string[] = ['awaiting_host_key', 'pending', 'running', 'succeeded', 'failed', 'cancelled']
const hostKeyPattern = /^SHA256:[A-Za-z0-9+/]{43}$/

function isJob(value: unknown): value is SSHInstallJob {
  if (typeof value !== 'object' || value === null) return false
  const job = value as Record<string, unknown>
  return typeof job.id === 'string' && typeof job.host === 'string' && typeof job.port === 'number' &&
    typeof job.state === 'string' && states.includes(job.state) && Array.isArray(job.progress) &&
    job.progress.every((line) => typeof line === 'string') && typeof job.host_key_sha256 === 'string' &&
    (job.host_key_sha256 === '' || hostKeyPattern.test(job.host_key_sha256)) && typeof job.failure_code === 'string'
}

function invalidResponse(): ApiError {
  return new ApiError('unexpected SSH install response', 0, 'invalid_response')
}

async function request(accessToken: string, path: string, init: RequestInit = {}): Promise<unknown> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        ...(init.body ? { 'Content-Type': 'application/json' } : {}),
        ...init.headers,
      },
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  return response.json()
}

async function items(promise: Promise<unknown>): Promise<SSHInstallJob[]> {
  const value = await promise
  const list = (value as { items?: unknown })?.items
  if (!Array.isArray(list) || !list.every(isJob)) throw invalidResponse()
  return list
}

async function one(promise: Promise<unknown>): Promise<SSHInstallJob> {
  const value = await promise
  if (!isJob(value)) throw invalidResponse()
  return value
}

export const nodeSSHInstallApi = {
  list: (accessToken: string, batchID?: string) => items(request(accessToken,
    `/v1/admin/nodes/ssh-installs${batchID ? `?batch_id=${encodeURIComponent(batchID)}` : ''}`)),
  create: (accessToken: string, input: CreateSSHInstallInput) => items(request(accessToken,
    '/v1/admin/nodes/ssh-installs', { method: 'POST', body: JSON.stringify(input) })),
  confirmHostKey: (accessToken: string, id: string, fingerprint: string) => one(request(accessToken,
    `/v1/admin/nodes/ssh-installs/${encodeURIComponent(id)}/confirm-host-key`,
    { method: 'POST', body: JSON.stringify({ host_key_sha256: fingerprint }) })),
  cancel: (accessToken: string, id: string) => one(request(accessToken,
    `/v1/admin/nodes/ssh-installs/${encodeURIComponent(id)}/cancel`, { method: 'POST' })),
}

// parseHosts splits a pasted list (newline, comma or space separated),
// trims, drops blanks and duplicates; at most 100 hosts.
export function parseHosts(value: string): string[] {
  const hosts = [...new Set(value.split(/[\s,，]+/).map((host) => host.trim()).filter(Boolean))]
  return hosts.slice(0, 101)
}
