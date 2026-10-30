import type { ControlUpgradeRolloutDetail } from '../api/controlUpgrades'
import { nativePublicationFixture, nativeStatusFixture } from '../api/controlUpgrades.native.fixtures'
import { maintenanceUpgradeMessage } from '../i18n/maintenanceUpgrade'
import { masterUpgradeLogLines, nodeErrorText, nodeUpgradeLogLines, upgradeLogTime } from './controlUpgradeLogs'

const mt = (key: Parameters<typeof maintenanceUpgradeMessage>[1]) => maintenanceUpgradeMessage('zh-CN', key)
const nodeA = '00000000-0000-4000-8000-0000000000a1'
const nodeB = '00000000-0000-4000-8000-0000000000b1'
const batch = '00000000-0000-4000-8000-0000000000c1'

describe('upgrade log lines', () => {
  it.each([
    'RUNTIME_SIGNATURE_INVALID', 'RUNTIME_AGENT_MISMATCH', 'RUNTIME_NOT_PACKAGED', 'RUNTIME_INSTALL_FAILED',
    'RUNTIME_PRECHECK_FAILED', 'RUNTIME_SWITCH_FAILED', 'RUNTIME_RELOAD_FAILED', 'RUNTIME_STATUS_UNAVAILABLE',
  ])('explains the native runtime switch failure %s in both languages', (code) => {
    for (const language of ['zh-CN', 'en-US']) {
      const text = nodeErrorText(code, language)
      expect(text).toContain(code)
      expect(text).not.toMatch(/^(错误码|error code) /)
    }
  })

  it('renders the master runner journal oldest first with levels and error codes', () => {
    const status = { ...nativeStatusFixture(), publication_revision: 1, publication: nativePublicationFixture(),
      execution: { state: 'running' as const, phase: 'rolling_back' as const, receipt: null, history: [
        { phase: 'verified' as const, at: 1780000001 },
        { phase: 'failed' as const, at: 1780000002, error_code: 'health_timeout' },
        { phase: 'rolling_back' as const, at: 1780000003 },
      ] } }
    expect(masterUpgradeLogLines(status, mt)).toEqual([
      '[INFO] 开始升级 1.0.0 → 1.1.0',
      `[INFO] [${upgradeLogTime(1780000001000)}] ${mt('nativePhaseVerified')}`,
      `[ERROR] [${upgradeLogTime(1780000002000)}] ${mt('nativePhaseFailed')} (health_timeout)`,
      `[WARNING] [${upgradeLogTime(1780000003000)}] ${mt('nativePhaseRollingBack')}`,
    ])
    expect(masterUpgradeLogLines(nativeStatusFixture(), mt)).toEqual([])
  })

  it('shows the database backup, applied migrations and restore of a migrating plan', () => {
    const base = { applied: ['284_node_delete_cascade', '285_node_delete_audit'], backup_path: '/var/lib/cdnca-upgrade/database-backups/p.dump',
      backup_bytes: 2048, backup_sha256: 'a'.repeat(64), backup_ms: 900 }
    const status = { ...nativeStatusFixture(), publication_revision: 1, publication: nativePublicationFixture(),
      execution: { state: 'running' as const, phase: 'rolling_back' as const, receipt: null, history: [
        { phase: 'database_backed_up' as const, at: 1780000001, migration: base },
        { phase: 'database_migrated' as const, at: 1780000002, migration: { ...base, migrated: true, migrate_ms: 120 } },
        { phase: 'rolling_back' as const, at: 1780000003, error_code: 'target_health_failed', migration: { ...base, migrated: true, restored: true, restore_ms: 3000 } },
      ] } }
    expect(masterUpgradeLogLines(status, mt).slice(1)).toEqual([
      `[INFO] [${upgradeLogTime(1780000001000)}] ${mt('nativePhaseDatabaseBackedUp')} — ${mt('nativeBackupDetail')} /var/lib/cdnca-upgrade/database-backups/p.dump (2048 B, 900 ms)`,
      `[INFO] [${upgradeLogTime(1780000002000)}] ${mt('nativePhaseDatabaseMigrated')} — ${mt('nativeMigrationDetail')} 284_node_delete_cascade, 285_node_delete_audit (120 ms)`,
      `[WARNING] [${upgradeLogTime(1780000003000)}] ${mt('nativePhaseRollingBack')} (target_health_failed) — ${mt('nativeDatabaseRestored')} (3000 ms)`,
    ])
  })

  it('merges plan events and the node receipts in time order and skips other nodes', () => {
    const created = '2026-10-14T08:00:00Z'
    const plan = {
      created_at: created, current_version: '1.0.0', target_version: '1.1.0',
      events: [
        { id: 'e1', revision: '2', from: 'queued', to: 'canary', action: 'start', reason: 'operator_start', batch_id: batch, node_id: '', occurred_at: '2026-10-14T08:01:00Z' },
        { id: 'e2', revision: '3', from: 'canary', to: 'paused', action: 'health_failed', reason: '', batch_id: batch, node_id: nodeB, occurred_at: '2026-10-14T08:02:00Z' },
        { id: 'e3', revision: '4', from: 'canary', to: 'rolling_back', action: 'health_failed', reason: '', batch_id: batch, node_id: nodeA, occurred_at: '2026-10-14T08:04:00Z' },
      ],
      status_receipts: [
        { node_id: nodeA, state: 'installing', observed_at: '2026-10-14T08:03:00Z' },
        { node_id: nodeB, state: 'healthy', observed_at: '2026-10-14T08:03:30Z' },
      ],
    } as unknown as ControlUpgradeRolloutDetail
    const at = (iso: string) => upgradeLogTime(Date.parse(iso))
    expect(nodeUpgradeLogLines(plan, nodeA, mt)).toEqual([
      `[INFO] [${at(created)}] 创建升级任务 1.0.0 → 1.1.0`,
      `[INFO] [${at('2026-10-14T08:01:00Z')}] 开始执行升级任务 (operator_start)`,
      `[INFO] [${at('2026-10-14T08:03:00Z')}] 节点正在安装新版本`,
      `[ERROR] [${at('2026-10-14T08:04:00Z')}] 健康检查失败`,
    ])
  })

  it('masterUpgradeLogLines 当 history 为空时返回空数组', () => {
    expect(masterUpgradeLogLines(nativeStatusFixture(), mt)).toEqual([])
  })

  it('nodeUpgradeLogLines 当 events 与 receipts 均为空时返回只含一行创建信息的数组', () => {
    const created = '2026-10-14T08:00:00Z'
    const plan = {
      created_at: created, current_version: '1.0.0', target_version: '1.1.0',
      events: [], status_receipts: [],
    } as unknown as ControlUpgradeRolloutDetail
    expect(nodeUpgradeLogLines(plan, nodeA, mt)).toEqual([
      '[INFO] [' + upgradeLogTime(Date.parse(created)) + '] 创建升级任务 1.0.0 → 1.1.0',
    ])
  })

  it('explains the node failure code and the installed version from the node receipts', () => {
    const created = '2026-10-14T08:00:00Z'
    const plan = {
      created_at: created, current_version: '2.0.0', target_version: '2.1.0', events: [],
      status_receipts: [
        { node_id: nodeA, state: 'failed', observed_at: '2026-10-14T08:03:00Z', error_code: 'DOWNLOAD_FAILED', current_version: '2.0.0' },
        { node_id: nodeA, state: 'healthy', observed_at: '2026-10-14T08:09:00Z', current_version: '2.1.0' },
        { node_id: nodeA, state: 'failed', observed_at: '2026-10-14T08:10:00Z', error_code: 'NEW_CODE' },
      ],
    } as unknown as ControlUpgradeRolloutDetail
    const at = (iso: string) => upgradeLogTime(Date.parse(iso))
    expect(nodeUpgradeLogLines(plan, nodeA, mt)).toEqual([
      `[INFO] [${at(created)}] 创建升级任务 2.0.0 → 2.1.0`,
      `[ERROR] [${at('2026-10-14T08:03:00Z')}] 节点升级失败：节点下载升级包失败（DOWNLOAD_FAILED），请检查节点到下载源的网络后重试`,
      `[INFO] [${at('2026-10-14T08:09:00Z')}] 节点升级完成，运行正常（2.1.0）`,
      `[ERROR] [${at('2026-10-14T08:10:00Z')}] 节点升级失败：错误码 NEW_CODE`,
    ])
    expect(nodeUpgradeLogLines(plan, nodeA, mt, 'en-US')[1]).toMatch(/: the node could not download the package \(DOWNLOAD_FAILED\)/)
  })
})