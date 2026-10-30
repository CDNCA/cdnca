import type { ControlUpgradeRolloutDetail } from '../api/controlUpgrades'
import type { NativeUpgradeHistoryEntry, NativeUpgradeRunLog, NativeUpgradeRunLogEntry, NativeUpgradeStatus } from '../api/controlUpgrades.native'
import { runLogMessage } from '../i18n/controlUpgradeRunLog'
import type { maintenanceUpgradeMessage } from '../i18n/maintenanceUpgrade'

type MessageKey = Parameters<typeof maintenanceUpgradeMessage>[1]
type Translate = (key: MessageKey) => string

const pad = (value: number) => String(value).padStart(2, '0')

// Local wall-clock time, as the competitor's plain-text upgrade logs show it.
export function upgradeLogTime(ms: number): string {
  const at = new Date(ms)
  return `${at.getFullYear()}-${pad(at.getMonth() + 1)}-${pad(at.getDate())} ${pad(at.getHours())}:${pad(at.getMinutes())}:${pad(at.getSeconds())}`
}

const line = (level: 'INFO' | 'WARNING' | 'ERROR', ms: number | null, text: string) =>
  `[${level}]${ms === null ? '' : ` [${upgradeLogTime(ms)}]`} ${text}`

const nativePhaseKeys: Record<string, MessageKey> = {
  verified: 'nativePhaseVerified', expanded: 'nativePhaseExpanded', preflighted: 'nativePhasePreflighted',
  drained: 'nativePhaseDrained', control_stopped: 'nativePhaseControlStopped', database_backed_up: 'nativePhaseDatabaseBackedUp',
  database_migrated: 'nativePhaseDatabaseMigrated', activated: 'nativePhaseActivated', healthy: 'nativePhaseHealthy',
  contracted: 'nativePhaseContracted', completed: 'nativePhaseCompleted', rolling_back: 'nativePhaseRollingBack',
  rolled_back: 'nativePhaseRolledBack', failed: 'nativePhaseFailed',
}

// Database migration evidence the runner journals on its own checkpoints.
function migrationDetail(entry: NativeUpgradeHistoryEntry, mt: Translate): string {
  const migration = entry.migration
  if (!migration) return ''
  if (entry.phase === 'database_backed_up') return ` — ${mt('nativeBackupDetail')} ${migration.backup_path} (${migration.backup_bytes} B, ${migration.backup_ms ?? 0} ms)`
  if (entry.phase === 'database_migrated') return ` — ${mt('nativeMigrationDetail')} ${migration.applied.join(', ')} (${migration.migrate_ms ?? 0} ms)`
  if (entry.phase === 'rolling_back' && migration.restored) return ` — ${mt('nativeDatabaseRestored')} (${migration.restore_ms ?? 0} ms)`
  return ''
}
const errorPhases = new Set(['failed'])
const warningPhases = new Set(['rolling_back', 'rolled_back'])

// The master upgrade log is the runner's checkpoint journal for the current
// publication, rendered oldest first.
export function masterUpgradeLogLines(status: NativeUpgradeStatus, mt: Translate): string[] {
  const publication = status.publication
  const history = status.execution.history ?? []
  if (!publication || history.length === 0) return []
  const lines = [line('INFO', null, `${mt('logUpgradeStarted')} ${publication.current_version} → ${publication.target_version}`)]
  for (const entry of history) {
    const level = errorPhases.has(entry.phase) ? 'ERROR' : warningPhases.has(entry.phase) ? 'WARNING' : 'INFO'
    const code = entry.error_code ? ` (${entry.error_code})` : ''
    lines.push(line(level, entry.at * 1000, `${mt(nativePhaseKeys[entry.phase])}${code}${migrationDetail(entry, mt)}`))
  }
  return lines
}

const eventKeys: Record<string, MessageKey> = {
  start: 'logEventStart', pause: 'logEventPause', resume: 'logEventResume', rollback: 'logEventRollback',
  health_failed: 'logEventHealthFailed', health_succeeded: 'logEventHealthSucceeded', outcome_uncertain: 'logEventOutcomeUncertain',
}
const receiptKeys: Record<string, MessageKey> = {
  accepted: 'logNodeAccepted', claimed: 'logNodeClaimed', installing: 'logNodeInstalling', healthy: 'logNodeHealthy',
  failed: 'logNodeFailed', rolling_back: 'logNodeRollingBack', rolled_back: 'logNodeRolledBack', uncertain: 'logNodeUncertain',
}
const errorEntries = new Set(['health_failed', 'failed'])
const warningEntries = new Set(['pause', 'rollback', 'outcome_uncertain', 'rolling_back', 'rolled_back', 'uncertain'])

// A node's upgrade log merges the plan events that concern it (plan-wide or
// naming the node) with the node's status receipts, in time order.
export function nodeErrorText(code: string, language: string): string {
  return runLogMessage(language, `node_${code}`) ?? runLogMessage(language, 'nodeErrorUnknown', { code })!
}

export function nodeUpgradeLogLines(plan: ControlUpgradeRolloutDetail, nodeID: string, mt: Translate, language = 'zh-CN'): string[] {
  const entries: { at: number; order: number; kind: string; text: string }[] = []
  plan.events.forEach((event, index) => {
    if (event.node_id !== '' && event.node_id !== nodeID) return
    const at = event.occurred_at ? Date.parse(event.occurred_at) : Date.parse(plan.created_at)
    const reason = event.reason ? ` (${event.reason})` : ''
    entries.push({ at, order: index, kind: event.action, text: `${mt(eventKeys[event.action])}${reason}` })
  })
  plan.status_receipts.forEach((receipt, index) => {
    if (receipt.node_id !== nodeID) return
    let text = mt(receiptKeys[receipt.state])
    if (receipt.state === 'healthy' && receipt.current_version) {
      text = runLogMessage(language, 'nodeWithVersion', { text, version: receipt.current_version })!
    }
    // The node's failure code becomes a readable cause and next step.
    if (receipt.error_code) text = runLogMessage(language, 'nodeWithCause', { text, cause: nodeErrorText(receipt.error_code, language) })!
    entries.push({ at: Date.parse(receipt.observed_at), order: plan.events.length + index, kind: receipt.state, text })
  })
  entries.sort((left, right) => left.at - right.at || left.order - right.order)
  return [
    line('INFO', Date.parse(plan.created_at), `${mt('logPlanCreated')} ${plan.current_version} → ${plan.target_version}`),
    ...entries.map((entry) => line(errorEntries.has(entry.kind) ? 'ERROR' : warningEntries.has(entry.kind) ? 'WARNING' : 'INFO', entry.at, entry.text)),
  ]
}

// The runner keeps the first entries and the newest ones; see the API schema.
const runLogKeptHead = 40
const levelTags = { info: 'INFO', warning: 'WARNING', error: 'ERROR' } as const

function bytesText(language: string, value: number): string {
  const units = ['B', 'KB', 'MB', 'GB']
  let amount = value
  let unit = 0
  while (amount >= 1024 && unit < units.length - 1) {
    amount /= 1024
    unit++
  }
  return `${new Intl.NumberFormat(language, { maximumFractionDigits: unit === 0 ? 0 : 1 }).format(amount)} ${units[unit]}`
}

const secondsText = (language: string, ms: number) => new Intl.NumberFormat(language, { maximumFractionDigits: 1 }).format(ms / 1000)

// One runner event as a readable line. Unknown codes fall back to the code
// itself, so a newer runner never produces a blank or broken log.
export function runLogEntryText(entry: NativeUpgradeRunLogEntry, language: string): string {
  const message = (key: string, values?: Record<string, string | number>) => runLogMessage(language, key, values)
  // Health checks report which endpoint answered what; status 0 means no response.
  const result = entry.http_status ? message('httpResult', { status: entry.http_status })! : message('httpNoResponse')!
  const reason = entry.reason === undefined ? '' :
    message(`reason_${entry.reason}`, { status: entry.http_status ?? '', host: entry.host ?? '', result }) ??
      message('reasonUnknown', { reason: entry.reason })!
  const code = entry.error_code === undefined ? '' : message(`code_${entry.error_code}`) === undefined ? entry.error_code :
    message('codeWithText', { text: message(`code_${entry.error_code}`)!, code: entry.error_code })!
  const values = {
    version: entry.version ?? '', host: entry.host ?? '', unit: entry.unit ?? '', count: entry.count ?? 0, attempt: entry.attempt ?? 0,
    bytes: entry.bytes === undefined ? '' : bytesText(language, entry.bytes),
    seconds: secondsText(language, entry.duration_ms ?? 0),
    duration: entry.duration_ms ? message('durationSuffix', { seconds: secondsText(language, entry.duration_ms) })! : '',
    step: entry.step === undefined ? '' : message(`step_${entry.step}`) ?? message('stepUnknown')!,
    phase: entry.step === undefined ? '' : message(`phase_${entry.step}`) ?? entry.step,
    reason: reason || code, code, event: entry.event, migrations: (entry.migrations ?? []).join(', '),
  }
  return message(`event_${entry.event}`, values) ?? message('eventUnknown', values)!
}

// The master upgrade's script log: every runner step, oldest first.
export function masterRunLogLines(log: NativeUpgradeRunLog, language: string): string[] {
  const lines: string[] = []
  log.entries.forEach((entry, index) => {
    if (log.dropped > 0 && index === runLogKeptHead) lines.push(runLogMessage(language, 'dropped', { count: log.dropped })!)
    lines.push(`[${levelTags[entry.level]}] [${upgradeLogTime(entry.at * 1000)}] ${runLogEntryText(entry, language)}`)
  })
  return lines
}

// The services' journal tails captured by the runner, one block per unit.
export function masterProgramLogLines(log: NativeUpgradeRunLog, language: string): string[] {
  const lines: string[] = []
  for (const program of log.programs) {
    if (lines.length > 0) lines.push('')
    lines.push(runLogMessage(language, 'programHeader', {
      unit: program.unit, time: upgradeLogTime(program.captured_at * 1000),
      trigger: runLogMessage(language, `trigger_${program.trigger}`) ?? runLogMessage(language, 'triggerUnknown')!,
    })!)
    if (program.unavailable) lines.push(runLogMessage(language, 'programUnavailable')!)
    else if (program.lines.length === 0) lines.push(runLogMessage(language, 'programNoLines')!)
    else lines.push(...program.lines)
  }
  return lines
}
