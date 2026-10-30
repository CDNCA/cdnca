import { ApiError, networkApiError, responseApiError } from './auth'
import type { ControlUpgradeRequestMetadata } from './controlUpgrades'

export interface NativeUpgradePublication {
  schema: 'cdnca.control-plane-upgrade-publication/v1'
  receipt_id: string
  plan_id: string
  bundle_sha256: string
  publication_revision: number
  expected_revision: number
  channel_revision: number
  release_sequence: number
  installation_id: string
  component: 'control-api'
  current_version: string
  current_digest: string
  target_version: string
  target_digest: string
  rollback_version: string
  rollback_digest: string
  protocol_version: number
  idempotency_sha256: string
  request_id: string
  actor_user_id: string
  actor_scope_id: string
  published_at: number
}

export const nativeUpgradePhases = [
  'verified', 'expanded', 'preflighted', 'drained', 'control_stopped', 'database_backed_up', 'database_migrated',
  'activated', 'healthy', 'contracted',
  'completed', 'rolling_back', 'rolled_back', 'failed',
] as const

export interface NativeUpgradeRunnerReceipt {
  id: string
  plan_id: string
  bundle_sha256: string
  sequence: number
  target: 'native-standalone'
  current_version: string
  target_version: string
  result: 'applied' | 'rolled_back' | 'failed'
  error_code?: string
  completed_at: number
  migration?: NativeUpgradeMigration
}

/** Evidence of an append-only database migration (runner MigrationRecord). */
export interface NativeUpgradeMigration {
  applied: string[]
  migrated?: boolean
  backup_path?: string
  backup_bytes?: number
  backup_sha256?: string
  backup_ms?: number
  migrate_ms?: number
  restored?: boolean
  restore_ms?: number
}

export interface NativeUpgradeHistoryEntry {
  phase: typeof nativeUpgradePhases[number]
  error_code?: string
  at: number
  migration?: NativeUpgradeMigration
}

export interface NativeUpgradeStatus {
  schema: 'cdnca.native-control-upgrade-status/v1'
  observed_at: string
  mode: 'native-standalone'
  publication_revision: number
  publication: NativeUpgradePublication | null
  execution: {
    state: 'unavailable' | 'not_started' | 'running' | 'completed'
    phase: typeof nativeUpgradePhases[number] | null
    receipt: NativeUpgradeRunnerReceipt | null
    /** Runner checkpoint journal for this execution, oldest first. */
    history?: NativeUpgradeHistoryEntry[]
  }
  runtime: { ready: boolean; reason: string }
}

/** One runner step event; codes are rendered per locale by the console. */
export interface NativeUpgradeRunLogEntry {
  at: number
  level: 'info' | 'warning' | 'error'
  event: string
  step?: string
  reason?: string
  error_code?: string
  version?: string
  host?: string
  unit?: string
  bytes?: number
  duration_ms?: number
  http_status?: number
  attempt?: number
  count?: number
  /** Append-only migration identifiers a database step covers. */
  migrations?: string[]
}

/** Latest redacted journal tail of one service. */
export interface NativeUpgradeRunLogProgram {
  unit: string
  captured_at: number
  trigger: string
  unavailable?: boolean
  lines: string[]
}

export interface NativeUpgradeRunLog {
  schema: 'cdnca.control-plane-upgrade-runlog/v1'
  plan_id: string
  sequence: number
  started_at: number
  attempts: number
  dropped: number
  entries: NativeUpgradeRunLogEntry[]
  programs: NativeUpgradeRunLogProgram[]
}

export interface NativeUpgradeRunLogStatus {
  schema: 'cdnca.native-control-upgrade-runlog/v1'
  observed_at: string
  state: 'available' | 'unavailable'
  run_log: NativeUpgradeRunLog | null
}

export interface NativeUpgradePreview {
  planID: string
  installationID: string
  currentVersion: string
  targetVersion: string
  rollbackVersion: string
  channelRevision: number
  releaseSequence: number
  protocolVersion: number
  artifactSHA256: string
  rollbackSHA256: string
}

export interface NativeUpgradeAttempt {
  rawJSON: string
  expectedRevision: number
  metadata: ControlUpgradeRequestMetadata
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const endpoint = `${apiRoot}/v1/admin/control-upgrade-plan`
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const hexPattern = /^[0-9a-f]{64}$/
const shaPattern = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/
const metadataPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/
const versionPattern = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$/
const invalid = (write = false) => new ApiError('Invalid native control upgrade contract', write ? 400 : 502, write ? 'invalid_request' : 'invalid_response')
const record = (value: unknown): value is Record<string, unknown> => Boolean(value && typeof value === 'object' && !Array.isArray(value))
const safeInteger = (value: unknown, minimum = 0): value is number => Number.isSafeInteger(value) && (value as number) >= minimum
const unixTime = (value: unknown): value is number => safeInteger(value, 1) && Number.isFinite(new Date(value * 1000).getTime())
const matches = (value: unknown, pattern: RegExp): value is string => typeof value === 'string' && pattern.test(value)
const version = (value: unknown): value is string => typeof value === 'string' && value.length <= 128 && versionPattern.test(value)
const exact = (value: unknown, keys: readonly string[], optional: readonly string[] = []): value is Record<string, unknown> => record(value) &&
  keys.every((key) => Object.hasOwn(value, key)) && Object.keys(value).every((key) => keys.includes(key) || optional.includes(key))
const safeNumbers = (value: unknown): boolean => typeof value === 'number' ? Number.isSafeInteger(value) :
  Array.isArray(value) ? value.every(safeNumbers) : record(value) ? Object.values(value).every(safeNumbers) : true

function parsePublication(value: unknown): NativeUpgradePublication {
  if (!exact(value, ['schema', 'receipt_id', 'plan_id', 'bundle_sha256', 'publication_revision', 'expected_revision',
    'channel_revision', 'release_sequence', 'installation_id', 'component', 'current_version', 'current_digest',
    'target_version', 'target_digest', 'rollback_version', 'rollback_digest', 'protocol_version', 'idempotency_sha256',
    'request_id', 'actor_user_id', 'actor_scope_id', 'published_at']) ||
    value.schema !== 'cdnca.control-plane-upgrade-publication/v1' || value.component !== 'control-api' ||
    !['plan_id', 'installation_id', 'actor_user_id', 'actor_scope_id'].every((key) => matches(value[key], uuidPattern)) ||
    !['bundle_sha256', 'current_digest', 'target_digest', 'rollback_digest', 'idempotency_sha256'].every((key) => matches(value[key], hexPattern)) ||
    !['publication_revision', 'channel_revision', 'release_sequence', 'protocol_version'].every((key) => safeInteger(value[key], 1)) || !unixTime(value.published_at) ||
    !safeInteger(value.expected_revision) || value.publication_revision !== value.expected_revision + 1 ||
    !['current_version', 'target_version', 'rollback_version'].every((key) => version(value[key])) ||
    value.rollback_version !== value.current_version || value.rollback_digest !== value.current_digest ||
    value.receipt_id !== `${value.plan_id}:${value.publication_revision}` || !matches(value.request_id, metadataPattern)) throw invalid()
  return value as unknown as NativeUpgradePublication
}

function validMigrationNames(value: unknown): boolean {
  return Array.isArray(value) && value.length >= 1 && value.length <= 64 &&
    value.every((name) => matches(name, /^[0-9]{3}_[a-z0-9]+(?:_[a-z0-9]+)*$/) && name.length <= 96)
}

function validMigration(value: unknown): boolean {
  return exact(value, ['applied'], ['migrated', 'backup_path', 'backup_bytes', 'backup_sha256', 'backup_ms', 'migrate_ms', 'restored', 'restore_ms']) &&
    validMigrationNames(value.applied) &&
    ['migrated', 'restored'].every((key) => value[key] === undefined || typeof value[key] === 'boolean') &&
    ['backup_bytes', 'backup_ms', 'migrate_ms', 'restore_ms'].every((key) => value[key] === undefined || safeInteger(value[key])) &&
    (value.backup_path === undefined || (typeof value.backup_path === 'string' && value.backup_path.startsWith('/') && value.backup_path.length <= 1024)) &&
    (value.backup_sha256 === undefined || matches(value.backup_sha256, hexPattern))
}

function parseStatus(value: unknown): NativeUpgradeStatus {
  if (!exact(value, ['schema', 'observed_at', 'mode', 'publication_revision', 'publication', 'execution', 'runtime']) ||
    value.schema !== 'cdnca.native-control-upgrade-status/v1' || value.mode !== 'native-standalone' ||
    !safeInteger(value.publication_revision) || typeof value.observed_at !== 'string' ||
    !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:\d\d)$/.test(value.observed_at) || !Number.isFinite(Date.parse(value.observed_at)) ||
    !exact(value.runtime, ['ready', 'reason']) || typeof value.runtime.ready !== 'boolean' ||
    !matches(value.runtime.reason, /^[a-z][a-z0-9_]{0,95}$/) || value.runtime.ready !== (value.runtime.reason === 'ready') ||
    !exact(value.execution, ['state', 'phase', 'receipt'], ['history']) ||
    value.execution.history !== undefined && (!Array.isArray(value.execution.history) ||
      value.execution.history.length > 64 || !value.execution.history.every((entry) =>
        exact(entry, ['phase', 'at'], ['error_code', 'migration']) && nativeUpgradePhases.includes(entry.phase as typeof nativeUpgradePhases[number]) &&
        unixTime(entry.at) && (entry.error_code === undefined || matches(entry.error_code, /^[a-z][a-z0-9_]{0,95}$/)) &&
        (entry.migration === undefined || validMigration(entry.migration)))) ||
    !['unavailable', 'not_started', 'running', 'completed'].includes(String(value.execution.state))) throw invalid()
  const publication = value.publication === null ? null : parsePublication(value.publication)
  if ((publication?.publication_revision ?? 0) !== value.publication_revision) throw invalid()
  const execution = value.execution
  if (execution.state === 'unavailable' || execution.state === 'not_started') {
    if (execution.phase !== null || execution.receipt !== null) throw invalid()
  } else {
    if (!publication || !nativeUpgradePhases.includes(execution.phase as typeof nativeUpgradePhases[number])) throw invalid()
    if (execution.state === 'running') {
      if (execution.receipt !== null || ['completed', 'rolled_back', 'failed'].includes(String(execution.phase))) throw invalid()
    } else {
      const receipt = execution.receipt
      if (!exact(receipt, ['id', 'plan_id', 'bundle_sha256', 'sequence', 'target', 'current_version', 'target_version', 'result', 'completed_at'], ['error_code', 'migration']) ||
        (receipt.migration !== undefined && !validMigration(receipt.migration)) ||
        !matches(receipt.id, /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/) || receipt.plan_id !== publication.plan_id ||
        receipt.bundle_sha256 !== publication.bundle_sha256 || receipt.sequence !== publication.release_sequence ||
        receipt.target !== 'native-standalone' || receipt.current_version !== publication.current_version ||
        receipt.target_version !== publication.target_version || !unixTime(receipt.completed_at) ||
        !['applied', 'rolled_back', 'failed'].includes(String(receipt.result)) ||
        execution.phase !== ({ applied: 'completed', rolled_back: 'rolled_back', failed: 'failed' } as Record<string, string>)[String(receipt.result)] ||
        receipt.error_code !== undefined && !matches(receipt.error_code, /^[a-z][a-z0-9_]{0,95}$/)) throw invalid()
    }
  }
  return value as unknown as NativeUpgradeStatus
}

const runLogCode = /^[a-z][a-z0-9_]{0,63}$/
const runLogEntryNumbers = ['bytes', 'duration_ms', 'http_status', 'attempt', 'count'] as const
const runLogEntryStrings = { step: runLogCode, reason: runLogCode, error_code: /^[a-z][a-z0-9_]{0,95}$/,
  version: /^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$/, host: /^[0-9A-Za-z][0-9A-Za-z.:[\]-]{0,252}$/,
  unit: /^[a-zA-Z0-9][a-zA-Z0-9_.@-]{0,126}$/ } as const

function parseRunLog(value: unknown): NativeUpgradeRunLog {
  if (!exact(value, ['schema', 'plan_id', 'sequence', 'started_at', 'attempts', 'dropped', 'entries', 'programs']) ||
    value.schema !== 'cdnca.control-plane-upgrade-runlog/v1' || typeof value.plan_id !== 'string' ||
    value.plan_id.length < 1 || value.plan_id.length > 128 || !safeInteger(value.sequence, 1) || !unixTime(value.started_at) ||
    !safeInteger(value.attempts, 1) || !safeInteger(value.dropped) ||
    !Array.isArray(value.entries) || value.entries.length < 1 || value.entries.length > 400 ||
    !Array.isArray(value.programs) || value.programs.length > 3) throw invalid()
  for (const entry of value.entries) {
    if (!exact(entry, ['at', 'level', 'event'], [...runLogEntryNumbers, ...Object.keys(runLogEntryStrings), 'migrations']) ||
      (entry.migrations !== undefined && !validMigrationNames(entry.migrations)) ||
      !unixTime(entry.at) || !['info', 'warning', 'error'].includes(String(entry.level)) || !matches(entry.event, runLogCode) ||
      !runLogEntryNumbers.every((key) => entry[key] === undefined || safeInteger(entry[key])) ||
      !Object.entries(runLogEntryStrings).every(([key, pattern]) => entry[key] === undefined || matches(entry[key], pattern))) throw invalid()
  }
  const units = new Set<string>()
  for (const program of value.programs) {
    if (!exact(program, ['unit', 'captured_at', 'trigger', 'lines'], ['unavailable']) ||
      !matches(program.unit, runLogEntryStrings.unit) || units.has(program.unit) || !unixTime(program.captured_at) ||
      !matches(program.trigger, runLogCode) || (program.unavailable !== undefined && typeof program.unavailable !== 'boolean') ||
      !Array.isArray(program.lines) || program.lines.length > 80 ||
      !program.lines.every((line) => typeof line === 'string' && line.length <= 512)) throw invalid()
    units.add(program.unit)
  }
  return value as unknown as NativeUpgradeRunLog
}

function parseRunLogStatus(value: unknown): NativeUpgradeRunLogStatus {
  if (!exact(value, ['schema', 'observed_at', 'state', 'run_log']) || value.schema !== 'cdnca.native-control-upgrade-runlog/v1' ||
    typeof value.observed_at !== 'string' || !Number.isFinite(Date.parse(value.observed_at)) ||
    (value.state !== 'available' && value.state !== 'unavailable') ||
    (value.state === 'unavailable') !== (value.run_log === null)) throw invalid()
  if (value.run_log !== null) parseRunLog(value.run_log)
  return value as unknown as NativeUpgradeRunLogStatus
}

export function previewNativeUpgradeBundle(rawJSON: string): NativeUpgradePreview {
  if (!rawJSON || new TextEncoder().encode(rawJSON).byteLength > 256 * 1024) throw invalid(true)
  let value: unknown
  try {
    value = JSON.parse(rawJSON)
    if (!safeNumbers(value)) throw invalid(true)
  } catch { throw invalid(true) }
  if (!exact(value, ['algorithm', 'key_id', 'bundle', 'signature']) || value.algorithm !== 'Ed25519' ||
    !matches(value.key_id, metadataPattern) || !matches(value.signature, /^[A-Za-z0-9_-]{86}$/) || !record(value.bundle)) throw invalid(true)
  const bundle = value.bundle
  if (!['cdnca.upgrade.plan-artifact-bundle/v1', 'cdnca.upgrade.plan-artifact-bundle/v2'].includes(String(bundle.schema)) ||
    bundle.audience !== 'cdnca-control-plane-upgrade-plan' || bundle.purpose !== 'cdnca-upgrade-plan-artifact-bundle' ||
    bundle.component !== 'control-api' || bundle.initial_plan_revision !== 1 ||
    !matches(bundle.plan_id, uuidPattern) || !matches(bundle.installation_id, uuidPattern) ||
    !version(bundle.current_version) || !version(bundle.version) || !safeInteger(bundle.channel_revision, 1) ||
    !safeInteger(bundle.protocol_version, 1) || !record(bundle.forward) || !record(bundle.rollback) ||
    !record(bundle.forward.manifest) || !record(bundle.rollback.manifest)) throw invalid(true)
  const forward = bundle.forward.manifest
  const rollback = bundle.rollback.manifest
  if (forward.version !== bundle.version || rollback.version !== bundle.current_version ||
    !safeInteger(forward.release_sequence, 1) || !safeInteger(rollback.release_sequence, 1) || forward.release_sequence <= rollback.release_sequence ||
    !matches(forward.sha256_digest, shaPattern) || !matches(rollback.sha256_digest, shaPattern)) throw invalid(true)
  return {
    planID: bundle.plan_id, installationID: bundle.installation_id, currentVersion: bundle.current_version,
    targetVersion: bundle.version, rollbackVersion: rollback.version, channelRevision: bundle.channel_revision,
    releaseSequence: forward.release_sequence, protocolVersion: bundle.protocol_version,
    artifactSHA256: forward.sha256_digest, rollbackSHA256: rollback.sha256_digest,
  }
}

async function request(token: string, url: string, init: RequestInit, allowed: number[]): Promise<unknown> {
  if (!token) throw invalid(true)
  let response: Response
  try {
    response = await fetch(url, { ...init, credentials: 'include', cache: 'no-store', headers: {
      Authorization: `Bearer ${token}`, ...(init.body ? { 'Content-Type': 'application/json' } : {}), ...init.headers,
    } })
  } catch { throw networkApiError() }
  if (!response.ok) throw await responseApiError(response)
  if (!allowed.includes(response.status)) throw invalid()
  try { return await response.json() } catch { throw invalid() }
}

async function digest(value: string): Promise<string> {
  const bytes = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
  return Array.from(new Uint8Array(bytes), (byte) => byte.toString(16).padStart(2, '0')).join('')
}

function manifestHex(value: string): string {
  return Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/') + '='), (byte) => byte.charCodeAt(0).toString(16).padStart(2, '0')).join('')
}

async function publish(token: string, attempt: NativeUpgradeAttempt): Promise<NativeUpgradePublication> {
  const preview = previewNativeUpgradeBundle(attempt.rawJSON)
  if (!safeInteger(attempt.expectedRevision) || attempt.expectedRevision === Number.MAX_SAFE_INTEGER ||
    !matches(attempt.metadata.requestId, metadataPattern) || !matches(attempt.metadata.idempotencyKey, metadataPattern)) throw invalid(true)
  const [bundleHash, keyHash] = await Promise.all([digest(attempt.rawJSON), digest(attempt.metadata.idempotencyKey)])
  const receipt = parsePublication(await request(token, endpoint, {
    method: 'POST', body: attempt.rawJSON, headers: {
      'If-Match': `"${attempt.expectedRevision}"`, 'Idempotency-Key': attempt.metadata.idempotencyKey,
      'X-Request-ID': attempt.metadata.requestId,
    },
  }, [200, 201]))
  if (receipt.expected_revision !== attempt.expectedRevision || receipt.bundle_sha256 !== bundleHash ||
    receipt.idempotency_sha256 !== keyHash || receipt.request_id !== attempt.metadata.requestId ||
    receipt.plan_id !== preview.planID || receipt.installation_id !== preview.installationID ||
    receipt.current_version !== preview.currentVersion || receipt.target_version !== preview.targetVersion ||
    receipt.channel_revision !== preview.channelRevision || receipt.release_sequence !== preview.releaseSequence ||
    receipt.protocol_version !== preview.protocolVersion || receipt.target_digest !== manifestHex(preview.artifactSHA256) ||
    receipt.rollback_digest !== manifestHex(preview.rollbackSHA256)) throw invalid()
  return receipt
}

export interface NativeUpgradeOption {
  artifact_id: string
  version: string
  release_notes: string
  published_at: number
  operation: 'upgrade' | 'rollback' | 'reinstall'
  control_schema_head: number | null
  channel_target: boolean
  pinned: boolean
  selectable: boolean
  reason: string
}

export interface NativeUpgradeOptions {
  schema: 'cdnca.native-control-upgrade-options/v1'
  observed_at: string
  options: {
    current_version: string
    current_schema_head: number | null
    target_mode: 'follow_channel' | 'pinned'
    items: NativeUpgradeOption[]
  }
}

const reasonPattern = /^[a-z][a-z0-9_]{0,63}$/

function parseOptions(value: unknown): NativeUpgradeOptions {
  if (!record(value) || value.schema !== 'cdnca.native-control-upgrade-options/v1' || typeof value.observed_at !== 'string' ||
    Object.hasOwn(value, 'supported')) throw invalid()
  const options = value.options
  if (!record(options) || !version(options.current_version) || !Array.isArray(options.items) || options.items.length > 200 ||
    (options.target_mode !== 'follow_channel' && options.target_mode !== 'pinned') ||
    (options.current_schema_head !== null && !safeInteger(options.current_schema_head, 1))) throw invalid()
  const items = options.items.map((item: unknown): NativeUpgradeOption => {
    if (!record(item) || !matches(item.artifact_id, uuidPattern) || !version(item.version) || typeof item.release_notes !== 'string' ||
      !safeInteger(item.published_at) || !['upgrade', 'rollback', 'reinstall'].includes(item.operation as string) ||
      (item.control_schema_head !== null && !safeInteger(item.control_schema_head, 1)) ||
      typeof item.channel_target !== 'boolean' || typeof item.pinned !== 'boolean' || typeof item.selectable !== 'boolean' ||
      typeof item.reason !== 'string' || (item.selectable ? item.reason !== '' : !reasonPattern.test(item.reason))) throw invalid()
    return item as unknown as NativeUpgradeOption
  })
  return { schema: value.schema, observed_at: value.observed_at, options: {
    current_version: options.current_version as string, current_schema_head: options.current_schema_head as number | null,
    target_mode: options.target_mode, items } }
}

export const nativeControlUpgradesApi = {
  options: async (token: string): Promise<NativeUpgradeOptions> => parseOptions(await request(token, endpoint + '/options', {}, [200])),
  status: async (token: string): Promise<NativeUpgradeStatus> => parseStatus(await request(token, endpoint, {}, [200])),
  runLog: async (token: string): Promise<NativeUpgradeRunLogStatus> => parseRunLogStatus(await request(token, endpoint + '/run-log', {}, [200])),
  publish,
  /** requestedArtifactID: the version the customer chose; omitted = channel latest (or the provider's pin). */
  issue: async (token: string, idempotencyKey: string, requestedArtifactID?: string): Promise<NativeUpgradePublication> => {
    if (requestedArtifactID !== undefined && !matches(requestedArtifactID, uuidPattern)) throw invalid(true)
    return parsePublication(await request(token, endpoint + '/issue', {
      method: 'POST',
      headers: { 'Idempotency-Key': idempotencyKey },
      body: requestedArtifactID ? JSON.stringify({ requested_artifact_id: requestedArtifactID }) : '{}',
    }, [200, 201]))
  },
}
