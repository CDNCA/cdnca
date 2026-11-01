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
  restrict_ssh?: boolean
}

export interface SSHInstallTarget {
  host: string
  port: number
  username: string
  password?: string
  private_key?: string
}

// Either one shared login for hosts, or targets each with its own login
// (batch install). batch_id adds the jobs to an existing batch (retry).
// language is the console UI language (i18n code): the install command run
// on the host then carries --lang zh / --lang en.
export type CreateSSHInstallInput = ({
  hosts: string[]
  port: number
  names?: string[]
  username: string
  password?: string
  private_key?: string
} | { targets: SSHInstallTarget[] }) & { batch_id?: string; restrict_ssh?: boolean; language?: string }

export interface SSHAccess {
  node_id: string
  enabled: boolean
  ssh_port: number
  controller_cidrs: string[]
  allow_cidrs: string[]
  revision: number
  state: 'pending' | 'applied' | 'confirmed' | 'reverted' | 'failed' | ''
  failure_code: string
  updated_at?: string
  /** The node's newest session declared SSH_ACCESS v1; false: the node version cannot apply it. */
  supported?: boolean
}

export interface ControllerEgress {
  controller_cidrs: string[]
  configured: boolean
  rollback_seconds: number
}

export interface NodeSSHEndpoint {
  node_id: string
  node_name: string
  host: string
  saved: { port: number; username: string; auth_kind: 'password' | 'private_key'; host_key_sha256: string; updated_at: string } | null
}

export interface NodeSSHHostKey {
  node_id: string
  host: string
  port: number
  host_key_sha256: string
  saved_host_key_matches: boolean
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
  return send(accessToken, path, init).then((response) => response.status === 204 ? null : response.json())
}

async function send(accessToken: string, path: string, init: RequestInit = {}): Promise<Response> {
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
  return response
}

function isAccess(value: unknown): value is SSHAccess {
  const access = value as Record<string, unknown> | null
  return typeof access === 'object' && access !== null && typeof access.enabled === 'boolean' &&
    typeof access.ssh_port === 'number' && Array.isArray(access.controller_cidrs) && Array.isArray(access.allow_cidrs) &&
    typeof access.state === 'string'
}

async function checked<T>(promise: Promise<unknown>, valid: (value: unknown) => boolean): Promise<T> {
  const value = await promise
  if (!valid(value)) throw invalidResponse()
  return value as T
}

const nodePath = (nodeID: string, suffix: string) => `/v1/nodes/${encodeURIComponent(nodeID)}/${suffix}`

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
  controllerEgress: (accessToken: string) => checked<ControllerEgress>(request(accessToken,
    '/v1/admin/nodes/ssh-access/controller-egress'), (value) => Array.isArray((value as ControllerEgress)?.controller_cidrs)),
  getAccess: (accessToken: string, nodeID: string) => checked<SSHAccess>(request(accessToken, nodePath(nodeID, 'ssh-access')), isAccess),
  setAccess: (accessToken: string, nodeID: string, input: { enabled: boolean; ssh_port: number; allow_cidrs: string[] }) =>
    checked<SSHAccess>(request(accessToken, nodePath(nodeID, 'ssh-access'), { method: 'PUT', body: JSON.stringify(input) }), isAccess),
}

// The console SSH terminal (nodes.ssh, platform administrators only).
export const nodeSSHTerminalApi = {
  endpoint: (accessToken: string, nodeID: string) => checked<NodeSSHEndpoint>(request(accessToken, nodePath(nodeID, 'ssh-endpoint')),
    (value) => typeof (value as NodeSSHEndpoint)?.host === 'string'),
  hostKey: (accessToken: string, nodeID: string, port: number) => checked<NodeSSHHostKey>(request(accessToken,
    nodePath(nodeID, 'ssh-host-key'), { method: 'POST', body: JSON.stringify({ port }) }),
  (value) => hostKeyPattern.test((value as NodeSSHHostKey)?.host_key_sha256 ?? '')),
  forget: (accessToken: string, nodeID: string) => request(accessToken, nodePath(nodeID, 'ssh-credential'), { method: 'DELETE' }),
  // WebSocket URL on the page's own origin (the API sits behind the same host).
  socketURL: (nodeID: string, base: string = apiRoot || window.location.origin) => {
    const url = new URL(nodePath(nodeID, 'ssh-terminal'), base)
    url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:'
    return url.toString()
  },
}

export interface BatchLine {
  line: number
  raw: string
  target?: SSHInstallTarget
  error?: 'columns' | 'host' | 'port' | 'username' | 'duplicate' | 'too_many'
}

const ipv4Pattern = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/
const hostnamePattern = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/
const usernamePattern = /^[a-z_][a-z0-9_.-]{0,31}$/

function validHost(value: string): boolean {
  if (ipv4Pattern.test(value) || hostnamePattern.test(value)) return value !== 'localhost'
  // IPv6: let the URL parser decide.
  if (!value.includes(':')) return false
  try {
    return new URL(`http://[${value}]/`).hostname !== ''
  } catch {
    return false
  }
}

// parseBatchLines reads "IP port user password" (or "IP user password", port
// 22) per line; blank lines and # comments are skipped. The password is the
// rest of the line after the user, so it may contain spaces (not tabs).
export function parseBatchLines(value: string, limit = 100): BatchLine[] {
  const lines: BatchLine[] = []
  const seen = new Set<string>()
  value.split(/\r?\n/).forEach((raw, index) => {
    const text = raw.trim()
    if (!text || text.startsWith('#')) return
    const entry: BatchLine = { line: index + 1, raw: text }
    lines.push(entry)
    const parts = text.split(/\s+/)
    if (parts.length < 3) {
      entry.error = 'columns'
      return
    }
    const host = parts[0].replace(/^\[|\]$/g, '').toLowerCase()
    let port = 22
    let rest = parts.slice(1)
    if (/^\d+$/.test(rest[0]) && rest.length >= 3) {
      port = Number(rest[0])
      rest = rest.slice(1)
    }
    const username = rest[0]
    const password = text.slice(text.indexOf(username, text.indexOf(parts[0]) + parts[0].length) + username.length).trim()
    if (!validHost(host)) entry.error = 'host'
    else if (!Number.isInteger(port) || port < 1 || port > 65535) entry.error = 'port'
    else if (!usernamePattern.test(username) || !password) entry.error = password ? 'username' : 'columns'
    else if (seen.has(`${host}|${port}`)) entry.error = 'duplicate'
    if (entry.error) return
    seen.add(`${host}|${port}`)
    entry.target = { host, port, username, password }
  })
  let valid = 0
  for (const entry of lines) {
    if (!entry.target) continue
    valid += 1
    if (valid > limit) {
      entry.target = undefined
      entry.error = 'too_many'
    }
  }
  return lines
}

// parseHosts splits a pasted list (newline, comma or space separated),
// trims, drops blanks and duplicates; at most 100 hosts.
export function parseHosts(value: string): string[] {
  const hosts = [...new Set(value.split(/[\s,，]+/).map((host) => host.trim()).filter(Boolean))]
  return hosts.slice(0, 101)
}
