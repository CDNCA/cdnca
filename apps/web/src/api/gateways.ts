import { buildInstallerCommand, quoteShellArgument as quote } from '@cdnca/ui/installer-command'

import { ApiError, networkApiError, responseApiError } from './auth'

// Standalone Agent Gateways (ADR 0013 §3.4, GW-06). Server: services/control-api/internal/gatewayregistry.
export type GatewayStatus = 'pending' | 'bound' | 'active' | 'disabled' | 'deleted'

export interface Gateway {
  id: string
  name: string
  host: string
  enrollment_port: number | null
  agent_port: number | null
  status: GatewayStatus
  version: string
  created_at: string
  bound_at: string | null
  ready_at: string | null
  client_certificate_expires_at: string | null
  server_certificate_expires_at: string | null
  /** Address the binding came from; allowed_ips defaults to it (GW-09 allow-list). */
  source_ip?: string | null
  allowed_ips?: string[]
}

export interface GatewayTrustedProxy { cidr: string; header: string }

export interface GatewayEntrypoint { address: string; server_name: string; transport: 'grpc' | 'ws'; tunnel_host: string }

/** Published to every Gateway over ControlInternal GetGatewaySettings (ADR 0013 §4.4/§4.5). */
export interface GatewaySettings { trusted_proxies: GatewayTrustedProxy[]; entrypoints: GatewayEntrypoint[] }

/** Settings plus the ETag (content digest) the next save must send back in If-Match (G1). */
export interface VersionedGatewaySettings { settings: GatewaySettings; etag: string }

export interface GatewayList {
  items: Gateway[]
  installation_id: string
  /** false: install-control.sh did not run with --mode control; binding is refused. */
  standalone_access_open: boolean
}

export interface GatewayCreated {
  gateway: Gateway
  binding_token: string
  token_expires_at: string
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

async function request<T>(accessToken: string, path: string, init: RequestInit = {}): Promise<T> {
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
  return response.status === 204 ? undefined as T : await response.json() as T
}

const path = (id: string) => `/v1/admin/gateways/${encodeURIComponent(id)}`

export const gatewaysApi = {
  list: (token: string) => request<GatewayList>(token, '/v1/admin/gateways'),
  create: (token: string, input: { name: string; host: string }) =>
    request<GatewayCreated>(token, '/v1/admin/gateways', { method: 'POST', body: JSON.stringify(input) }),
  issueToken: (token: string, id: string) => request<GatewayCreated>(token, `${path(id)}/binding-token`, { method: 'POST' }),
  disable: (token: string, id: string) => request<void>(token, `${path(id)}/disable`, { method: 'POST' }),
  enable: (token: string, id: string) => request<void>(token, `${path(id)}/enable`, { method: 'POST' }),
  remove: (token: string, id: string) => request<void>(token, path(id), { method: 'DELETE' }),
  setAllowedIPs: (token: string, id: string, allowedIPs: string[]) =>
    request<{ allowed_ips: string[] }>(token, `${path(id)}/allowed-ips`, { method: 'PUT', body: JSON.stringify({ allowed_ips: allowedIPs }) }),
  settings: (token: string) => versionedSettings(token),
  /** Refused with 409 gateway_settings_changed when someone saved after `etag` was read. */
  updateSettings: (token: string, settings: GatewaySettings, etag: string) =>
    versionedSettings(token, { method: 'PUT', body: JSON.stringify(settings), headers: { 'If-Match': etag } }),
}

const settingsETag = /^"sha256-[0-9a-f]{64}"$/

async function versionedSettings(accessToken: string, init: RequestInit = {}): Promise<VersionedGatewaySettings> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}/v1/admin/gateway-settings`, {
      ...init,
      credentials: 'include',
      headers: { Authorization: `Bearer ${accessToken}`, ...(init.body ? { 'Content-Type': 'application/json' } : {}), ...init.headers },
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  const etag = response.headers.get('ETag') ?? ''
  if (!settingsETag.test(etag)) throw new ApiError('API response was invalid', response.status, 'invalid_response')
  return { settings: await response.json() as GatewaySettings, etag }
}

const ipv4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/

/** Single IPv4 or IPv6 address (the server normalizes and re-validates). */
export function isIPAddress(value: string): boolean {
  if (ipv4.test(value)) return true
  if (!value.includes(':') || !/^[0-9A-Fa-f:.]+$/.test(value)) return false
  try { return new URL(`http://[${value}]/`).hostname !== '' } catch { return false }
}

/** "address server_name grpc|ws [tunnel_host]" per line. */
export function parseEntrypoints(text: string): GatewayEntrypoint[] | null {
  const out: GatewayEntrypoint[] = []
  for (const line of text.split('\n').map((item) => item.trim()).filter(Boolean)) {
    const [address, serverName, transport, tunnelHost = '', ...rest] = line.split(/\s+/)
    if (!address || !serverName || (transport !== 'grpc' && transport !== 'ws') || rest.length || (tunnelHost && transport !== 'ws')) return null
    out.push({ address, server_name: serverName, transport, tunnel_host: tunnelHost })
  }
  return out
}

/** "cidr[=Header]" per line; no header binds X-Forwarded-For. */
export function parseTrustedProxies(text: string): GatewayTrustedProxy[] | null {
  const out: GatewayTrustedProxy[] = []
  for (const line of text.split('\n').map((item) => item.trim()).filter((item) => item && !item.startsWith('#'))) {
    const [cidr, header = ''] = line.split('=').map((item) => item.trim())
    const [address, bits, ...rest] = (cidr ?? '').split('/')
    if (!address || !bits || rest.length || !/^\d{1,3}$/.test(bits) || !isIPAddress(address) || (header && !/^[A-Za-z0-9-]{1,64}$/.test(header))) return null
    out.push({ cidr, header })
  }
  return out
}

const tokenPattern = /^gwt1\.[0-9a-f-]{36}\.[0-9a-f]{32}\.[A-Za-z0-9_-]{43}$/

/**
 * One command for the Gateway host (install-control.sh --mode gateway). The
 * token goes to stdin, never into a process argument; the installer itself
 * comes from the authorization center that published this console, is
 * downloaded to a temporary file and checked before it runs.
 */
export function buildGatewayInstallCommand(bindingToken: string, controlOrigin: string, installerOrigin: string, host: string): string {
  if (!tokenPattern.test(bindingToken)) throw new Error('invalid binding token')
  const control = new URL(controlOrigin)
  const installer = new URL(installerOrigin)
  if (control.protocol !== 'https:' || installer.protocol !== 'https:') throw new Error('installation origins must be https')
  return buildInstallerCommand({
    urls: [`${installer.origin}/downloads/install-control.sh`], protocols: '=https', label: '[cdnca-control]',
    args: `--mode gateway --control ${quote(control.origin)} --gateway-host ${quote(host)} --gateway-token-file -`, stdinSecret: bindingToken,
  })
}

/**
 * One command, run as root on an installed control host, that opens standalone
 * Gateway access in place (install-control.sh enable-gateway-access). Without
 * the authorization center origin the bare form is returned.
 */
export function buildEnableGatewayAccessCommand(installerOrigin: string): string {
  let installer: URL
  try { installer = new URL(installerOrigin) } catch { return 'bash install-control.sh enable-gateway-access' }
  if (installer.protocol !== 'https:') return 'bash install-control.sh enable-gateway-access'
  return buildInstallerCommand({
    urls: [`${installer.origin}/downloads/install-control.sh`], protocols: '=https', label: '[cdnca-control]',
    args: 'enable-gateway-access',
  })
}
