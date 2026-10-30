import { ApiError, networkApiError, responseApiError } from './auth'

export interface ControlBackupBundle {
  backup_id: string
  reason: 'manual' | 'scheduled' | 'migration' | 'pre-restore'
  created_at: string
  version: string
  schema_version: number
  bytes: number
  signer_fingerprint: string
  signature_ok: boolean
  components: string[]
}

export interface ControlBackupRun {
  id: string
  kind: 'backup' | 'delete' | 'migrate' | 'rollback'
  reason: string
  /** stopped: a migration ended by "stop" (error migration_stopped or migration_aborted). */
  state: 'queued' | 'running' | 'succeeded' | 'failed' | 'stopped'
  /** Migration phase reached (connect → prepare_target → backup → transfer → restore → verify → done). */
  phase?: ControlMigrationPhase
  requested_at: string
  requested_by?: string
  started_at?: string
  ended_at?: string
  backup_id?: string
  target?: string
  /** Migration target environment detected on the new host (fix-btenv2). */
  target_env?: 'bt' | 'plain'
  error?: string
  uploads?: Record<string, string>
  log: string[]
}

export const controlMigrationPhases = ['connect', 'prepare_target', 'backup', 'transfer', 'restore', 'verify', 'done'] as const
export type ControlMigrationPhase = typeof controlMigrationPhases[number]

/** The restore on the new host started: stopping now aborts it and the new host needs cleaning. */
export function migrationReachedTarget(phase: ControlMigrationPhase | undefined): boolean {
  return phase === 'restore' || phase === 'verify' || phase === 'done'
}

/** GET /new-master: is the migration target already serving? */
export interface ControlNewMaster {
  host: string
  run_id?: string
  phase?: ControlMigrationPhase
  state?: ControlBackupRun['state']
  restored: boolean
  reachable: boolean
  dns_points_to_new: boolean
  /** restored and (reachable or DNS moved): a rollback needs confirm_new_master_stopped. */
  serving: boolean
  control_domain?: string
  gateway_endpoint?: string
  clean_command?: string
  held: boolean
}

export interface ControlRollbackInput { password: string; confirm_new_master_stopped: boolean }

export interface ControlBackupSchedule { enabled: boolean; weekdays: number[]; hour: number; minute: number }

export interface ControlBackupTargetView {
  name: string
  kind: 's3' | 'sftp'
  enabled: boolean
  endpoint?: string
  region?: string
  bucket?: string
  prefix?: string
  path_style?: boolean
  host?: string
  port?: number
  username?: string
  remote_dir?: string
  host_key_sha256?: string
  auth?: 'password' | 'private_key'
  access_key_fingerprint?: string
}

export interface ControlBackupStatus {
  keys_ready: boolean
  signer_fingerprint: string
  recipient: string
  agent_installed: boolean
  migration_ready: boolean
  freeze: { mode: 'backup' | 'hold'; id: string; acquired_at: string } | null
  bundles: ControlBackupBundle[]
  runs: ControlBackupRun[]
  /** next scheduled backup (UTC); null when the schedule is off. Failed backups are not retried automatically. */
  next_run_at?: string | null
  /** revision: digest of the stored settings; writes send it back as expected_revision. */
  settings: { schedule: ControlBackupSchedule; keep_local: number; keep_remote: number; targets: ControlBackupTargetView[]; revision: string }
}

/** Write shape. stored_name: the saved target this edits (absent for a new
 * one). Secret fields left empty keep the stored value of stored_name, for
 * SFTP only while auth stays the same. */
export interface ControlBackupTargetInput {
  stored_name?: string
  name: string
  kind: 's3' | 'sftp'
  enabled: boolean
  endpoint?: string
  region?: string
  bucket?: string
  prefix?: string
  path_style?: boolean
  host?: string
  port?: number
  username?: string
  remote_dir?: string
  host_key_sha256?: string
  auth?: 'password' | 'private_key'
  access_key?: string
  secret_key?: string
  ca_certificate?: string
  password?: string
  private_key?: string
}

export interface ControlBackupSettingsInput {
  expected_revision: string
  schedule: ControlBackupSchedule
  keep_local: number
  keep_remote: number
  targets: ControlBackupTargetInput[]
}

export interface ControlMigrationInput {
  host: string
  port: number
  user: string
  host_key_sha256: string
  password?: string
  private_key?: string
  /** 新主控环境（fix-btenv）：auto 检测宝塔面板，bt 与宝塔共存，plain 独占。 */
  env: ControlMigrationEnv
  confirm: string
}

export type ControlMigrationEnv = 'auto' | 'bt' | 'plain'

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const root = '/v1/admin/control-backup'

async function call<T>(token: string, method: string, path: string, body?: unknown): Promise<T> {
  if (!token || /\s/.test(token)) throw new ApiError('Authentication required', 401, 'authentication_required')
  let response: Response
  try {
    response = await fetch(`${apiRoot}${root}${path}`, {
      ...(method === 'GET' ? {} : { method }), credentials: 'include',
      headers: { Authorization: `Bearer ${token}`, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
      body: body === undefined ? undefined : JSON.stringify(body),
    })
  } catch { throw networkApiError() }
  if (!response.ok) {
    // A refused target field comes as error.details.field (see controlbackuphttp targetError).
    const details = await response.clone().json().then((body: { error?: { details?: { field?: unknown } } }) => body?.error?.details, () => undefined)
    const error = await responseApiError(response)
    if (typeof details?.field === 'string' && /^[a-z][a-z0-9_]{0,63}$/.test(details.field)) error.field = details.field
    throw error
  }
  const value = await response.json().catch(() => null) as { data?: T } | T | null
  if (value === null || typeof value !== 'object') throw new ApiError('Invalid control backup response', 502, 'invalid_response')
  return ('data' in (value as object) ? (value as { data: T }).data : value) as T
}

/** Frozen console sign-in (migration hold): an in-memory session, not a normal sign-in. */
export async function frozenSession(username: string, password: string): Promise<{ access_token: string; expires_at: string; username: string; can_manage: boolean }> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}${root}/frozen-session`, { method: 'POST', credentials: 'omit',
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username, password }) })
  } catch { throw networkApiError() }
  if (!response.ok) throw await responseApiError(response)
  const value = await response.json().catch(() => null) as { data?: { access_token?: unknown; expires_at?: unknown; username?: unknown; can_manage?: unknown } } | null
  const data = value?.data
  if (!data || typeof data.access_token !== 'string' || typeof data.expires_at !== 'string') throw new ApiError('Invalid frozen session', 502, 'invalid_response')
  return { access_token: data.access_token, expires_at: data.expires_at, username: String(data.username ?? ''), can_manage: data.can_manage === true }
}

export const controlBackupApi = {
  status: (token: string) => call<ControlBackupStatus>(token, 'GET', ''),
  saveSettings: (token: string, settings: ControlBackupSettingsInput) => call<ControlBackupStatus>(token, 'PUT', '/settings', settings),
  backupNow: (token: string) => call<ControlBackupRun>(token, 'POST', '/backups', {}),
  deleteBackup: (token: string, backupID: string) => call<ControlBackupRun>(token, 'DELETE', `/backups/${encodeURIComponent(backupID)}`, { confirm: backupID }),
  restoreCommands: (token: string, backupID: string) =>
    call<{ backup_id: string; signer_fingerprint: string; version: string; commands: string[] }>(token, 'GET', `/backups/${encodeURIComponent(backupID)}/restore-commands`),
  run: (token: string, runID: string) => call<ControlBackupRun>(token, 'GET', `/runs/${encodeURIComponent(runID)}`),
  /** Tests the target as on screen (an edited one is merged over the stored settings at expectedRevision); nothing is saved. */
  probe: (token: string, expectedRevision: string, target: ControlBackupTargetInput) =>
    call<{ ok: boolean; message?: string }>(token, 'POST', '/targets/probe', { expected_revision: expectedRevision, target }),
  hostKey: (token: string, host: string, port: number) => call<{ host_key_sha256: string }>(token, 'POST', '/host-key', { host, port }),
  migrate: (token: string, input: ControlMigrationInput) => call<ControlBackupRun>(token, 'POST', '/migrations', input),
  recoveryKit: (token: string, passphrase: string) => call<Record<string, unknown>>(token, 'POST', '/recovery-kit', { passphrase }),
  /** Stops a running migration at its next safe point (abort once the restore started). */
  stopMigration: (token: string, runID: string) => call<{ run_id: string; phase?: ControlMigrationPhase; abort: boolean }>(token, 'POST', `/runs/${encodeURIComponent(runID)}/stop`, {}),
  newMaster: (token: string) => call<ControlNewMaster>(token, 'GET', '/new-master'),
  rollback: (token: string, input: ControlRollbackInput) => call<ControlBackupRun>(token, 'POST', '/rollback', { ...input, confirm: 'rollback' }),
}
