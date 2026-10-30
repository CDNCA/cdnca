import { nativeControlUpgradesApi, type NativeUpgradeRunLog } from '../api/controlUpgrades.native'
import i18n from '../i18n'
import success from './testdata/control-upgrade-runlog/success.json'
import downloadFailed from './testdata/control-upgrade-runlog/download-failed.json'
import downloadRetried from './testdata/control-upgrade-runlog/download-retried.json'
import lineageRejected from './testdata/control-upgrade-runlog/lineage-rejected.json'
import healthRolledBack from './testdata/control-upgrade-runlog/health-rolled-back.json'
import migrationApplied from './testdata/control-upgrade-runlog/migration-applied.json'
import migrationRolledBack from './testdata/control-upgrade-runlog/migration-rolled-back.json'
import migrationRestoreFailed from './testdata/control-upgrade-runlog/migration-restore-failed.json'
import migrationRejected from './testdata/control-upgrade-runlog/migration-rejected.json'
import { masterProgramLogLines, masterRunLogLines, runLogEntryText } from './controlUpgradeLogs'

// The fixtures are produced by the Go runner tests (CDNCA_RUNLOG_GOLDEN=1), so
// this suite proves the console accepts and explains what the runner writes.
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status })
const envelope = (run_log: unknown) => ({ schema: 'cdnca.native-control-upgrade-runlog/v1', observed_at: '2026-10-14T10:00:00Z',
  state: run_log === null ? 'unavailable' : 'available', run_log })

async function parsed(log: unknown): Promise<NativeUpgradeRunLog> {
  vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json(envelope(log)))
  const status = await nativeControlUpgradesApi.runLog('token')
  expect(status.state).toBe('available')
  return status.run_log!
}

const script = async (log: unknown, language = 'zh-CN') => masterRunLogLines(await parsed(log), language).join('\n')

afterEach(() => { vi.restoreAllMocks() })

describe('master upgrade run log', () => {
  it('reads the run-log endpoint and accepts an unavailable log', async () => {
    const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json(envelope(null)))
    expect(await nativeControlUpgradesApi.runLog('token')).toMatchObject({ state: 'unavailable', run_log: null })
    expect(fetch).toHaveBeenCalledWith('/v1/admin/control-upgrade-plan/run-log', expect.objectContaining({ cache: 'no-store' }))
  })

  it.each([
    ['unknown key', { ...success, extra: 1 }],
    ['state mismatch', null],
    ['bad level', { ...success, entries: [{ ...success.entries[0], level: 'debug' }] }],
    ['text event', { ...success, entries: [{ ...success.entries[0], event: '下载失败' }] }],
    ['long line', { ...success, programs: [{ ...success.programs[0], lines: ['x'.repeat(513)] }] }],
  ])('rejects a malformed run log: %s', async (_name, log) => {
    const body = log === null ? { ...envelope(success), state: 'unavailable' } : envelope(log)
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json(body))
    await expect(nativeControlUpgradesApi.runLog('token')).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('explains a successful upgrade step by step', async () => {
    const text = await script(success)
    expect(text).toMatch(/^\[INFO\] \[\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\] 开始升级主控到 1\.5\.0$/m)
    expect(text).toContain('开始从 127.0.0.1 下载升级包 1.5.0（')
    expect(text).toMatch(/下载完成：[\d.]+ KB，耗时 [\d.]+ 秒/)
    expect(text).toContain('升级包签名与 SHA-256 校验通过')
    expect(text).toContain('已进入维护模式：暂停写操作')
    expect(text).toContain('已将 current 切换到 1.5.0')
    expect(text).toContain('已重启 control-api 与 agent-gateway')
    expect(text).toMatch(/健康检查通过，耗时 [\d.]+ 秒/)
    expect(text.split('\n').at(-1)).toMatch(/\[INFO\] .* 升级完成$/)
    expect(text).not.toMatch(/undefined|event_|reason_|\{\{/)
  })

  it('says a download failure is retried and later continues', async () => {
    const failed = await script(downloadFailed)
    expect(failed).toContain('[ERROR]')
    expect(failed).toContain('下载升级包失败：下载服务器返回 HTTP 503，将自动重试')
    expect(failed).toContain('失败：下载并校验升级包')
    expect(failed).toContain('升级包暂时无法下载，将自动重试')
    expect(failed).toContain('本次未改动线上版本，执行器稍后会自动重试。')
    const retried = await script(downloadRetried)
    expect(retried).toContain('第 2 次执行，从「已验签」继续')
    expect(retried.split('\n').at(-1)).toContain('升级完成')
  })

  it('explains a rejected lineage as a package that must be reissued', async () => {
    const text = await script(lineageRejected)
    expect(text).toContain('升级包与当前版本不衔接（previous_commit 不匹配），请重新签发升级包')
    expect(text).toContain('升级包不能用于当前版本，本次升级终止')
    expect(text.split('\n').at(-1)).toMatch(/\[ERROR\] .* 升级失败（下载或校验升级包失败，expand_failed）$/)
  })

  it('shows a health failure and the automatic rollback', async () => {
    const log = await parsed(healthRolledBack)
    const text = masterRunLogLines(log, 'zh-CN').join('\n')
    expect(text).toContain('[WARNING]')
    expect(text).toContain('等待服务就绪：control-api 就绪检查 /health/ready 未通过（127.0.0.1:8080，HTTP 503）')
    expect(text).toMatch(/健康检查超时（[\d.]+ 秒）：control-api 就绪检查 \/health\/ready 未通过（127\.0\.0\.1:8080，HTTP 503）/)
    expect(text).toContain('新版本未能正常运行（新版本健康检查未通过，target_health_failed），开始回滚到 1.4.0')
    expect(text).toContain('已回滚到 1.4.0')
    expect(text.split('\n').at(-1)).toContain('升级未成功，已自动回滚到原版本（新版本健康检查未通过，target_health_failed）')
    const program = masterProgramLogLines(log, 'zh-CN').join('\n')
    expect(program).toMatch(/===== cdnca-control-api\.service（\d{4}-.* 回滚完成时采集）=====/)
    expect(program).toContain('listening on 127.0.0.1:8080')
    expect(program).toContain('dsn=postgres://[REDACTED]@127.0.0.1:5432/cdnca')
    expect(program).toContain('token=[REDACTED]')
    expect(program).toContain('===== control-upgrade-runner')
    expect(program).toContain('无法读取该服务的日志（journal 不可用或无权限）。')
    expect(program).not.toContain('never-emit')
  })

  it('shows the database backup, migrations and restore of a migrating upgrade', async () => {
    const applied = await script(migrationApplied)
    expect(applied).toContain('新版本带有 2 个数据库迁移：004_step_4, 005_step_5，切换前会先停止管理 API 并备份数据库')
    expect(applied).toContain('完成：停止管理 API')
    expect(applied).toMatch(/数据库备份完成并已校验：[\d.]+ (B|KB|MB)/)
    expect(applied).toContain('数据库迁移完成（2 个）：004_step_4, 005_step_5')
    expect(applied).not.toContain('还原')
    expect(applied.split('\n').at(-1)).toMatch(/升级完成$/)
    const rolledBack = await script(migrationRolledBack)
    expect(rolledBack).toContain('失败：执行数据库迁移')
    expect(rolledBack).toContain('开始从升级前的备份（')
    expect(rolledBack).toContain('数据库已还原到升级前的备份')
    expect(rolledBack.split('\n').at(-1)).toContain('（数据库迁移失败，database_migration_failed）')
    const restoreFailed = await script(migrationRestoreFailed)
    expect(restoreFailed).toContain('失败：从备份还原数据库')
    expect(restoreFailed.split('\n').at(-1)).toContain('升级失败（数据库还原失败，需要人工处理，database_restore_failed）')
    expect(await script(migrationRejected)).toContain('升级包修改或删除了已有的数据库迁移（只允许追加新迁移）')
    for (const text of [applied, rolledBack, restoreFailed, await script(migrationApplied, 'en-US')]) {
      expect(text).not.toMatch(/undefined|\b(event|reason|step|code|phase)_[a-z]|\{\{/)
    }
  })

  it('rejects a run log entry with a malformed migration name', async () => {
    const entries = [{ ...success.entries[0], migrations: ['../004_step'] }]
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json(envelope({ ...success, entries })))
    await expect(nativeControlUpgradesApi.runLog('token')).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('names the failing health check, its host and answer', () => {
    const entry = (reason: string, host: string, http_status?: number) =>
      runLogEntryText({ at: 1, level: 'warning', event: 'health_check_waiting', reason, host, http_status, duration_ms: 3000 }, 'zh-CN')
    expect(entry('agent_gateway_not_ready', '127.0.0.1:8082'))
      .toBe('等待服务就绪：agent-gateway 就绪检查 /health/ready 未通过（127.0.0.1:8082，无响应）（已等待 3 秒）')
    expect(entry('console_index_mismatch', 'cdnca.com', 200))
      .toBe('等待服务就绪：管理端首页内容与新版本不一致（cdnca.com），可能仍在提供旧版页面（已等待 3 秒）')
    expect(entry('console_index_not_ready', 'cdnca.com', 502)).toContain('管理端首页未能正常打开（cdnca.com，HTTP 502）')
    expect(runLogEntryText({ at: 1, level: 'warning', event: 'health_check_waiting', reason: 'control_api_not_ready',
      host: '127.0.0.1:8080', http_status: 503, duration_ms: 3000 }, 'en-US'))
      .toBe('Waiting for services: control-api readiness check /health/ready failed (127.0.0.1:8080, HTTP 503) (3 s so far)')
  })

  it('marks omitted lines and degrades unknown codes to the code itself', async () => {
    const entries = Array.from({ length: 45 }, (_, index) => ({ at: 1800000000 + index, level: 'info', event: index === 44 ? 'future_event' : 'step_started', step: 'expand' }))
    const lines = masterRunLogLines(await parsed({ ...success, entries, dropped: 12 }), 'zh-CN')
    expect(lines[40]).toBe('…… 中间省略 12 行（仅保留开头和最新的日志）')
    expect(lines.at(-1)).toMatch(/ future_event$/)
    expect(runLogEntryText({ at: 1, level: 'error', event: 'step_failed', step: 'brand_new', reason: 'brand_new_reason' }, 'zh-CN'))
      .toBe('失败：执行步骤。原因 brand_new_reason')
  })

  it('keeps zh-CN, en-US and the pseudo-locale resources in step', () => {
    const zh = i18n.getResourceBundle('zh-CN', 'controlUpgradeRunLog') as Record<string, string>
    const en = i18n.getResourceBundle('en-US', 'controlUpgradeRunLog') as Record<string, string>
    const pseudo = i18n.getResourceBundle('qps-ploc', 'controlUpgradeRunLog') as Record<string, string>
    expect(Object.keys(en).sort()).toEqual(Object.keys(zh).sort())
    const placeholders = (value: string) => (value.match(/\{\{\w+\}\}/g) ?? []).sort()
    for (const key of Object.keys(zh)) {
      expect(placeholders(en[key]), key).toEqual(placeholders(zh[key]))
      expect(placeholders(pseudo[key]), key).toEqual(placeholders(zh[key]))
      expect(pseudo[key]).toMatch(/^［.+］$/)
    }
  })

  it('renders English and the pseudo-locale without missing keys', async () => {
    const english = await script(healthRolledBack, 'en-US')
    expect(english).toContain('Health check timed out')
    expect(english).toContain('Rolled back to 1.4.0')
    expect(english).not.toMatch(/[\u4e00-\u9fff]|undefined|\{\{/)
    const pseudo = await script(lineageRejected, 'qps-ploc')
    expect(pseudo).toContain('［')
    expect(pseudo).not.toMatch(/undefined|event_|\{\{/)
  })
})
