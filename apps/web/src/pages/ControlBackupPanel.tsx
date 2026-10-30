import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { App as AntApp, Alert, Button, Checkbox, Form, Input, InputNumber, Modal, Radio, Space, Switch, Table, Tag, TimePicker, Typography, type TableColumnsType } from 'antd'
import dayjs, { type Dayjs } from 'dayjs'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../api/auth'
import {
  controlBackupApi,
  type ControlBackupBundle,
  type ControlBackupRun,
  type ControlBackupSettingsInput,
  type ControlBackupStatus,
  type ControlBackupTargetInput,
  type ControlMigrationEnv,
} from '../api/controlBackup'
import { useSessionStore } from '../auth/session'
import { controlBackupError, controlBackupMessage, type ControlBackupKey } from '../i18n/controlBackup'
import { formatDateTime } from '../i18n/formatters'
import { useFeedback, FeedbackWhen } from '@cdnca/ui'
import { MigrationPhases, RollbackPanel, StopMigrationButton } from './ControlMigrationControls'

function formatBytes(value: number): string {
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`
  if (value < 1024 * 1024 * 1024) return `${(value / 1024 / 1024).toFixed(1)} MiB`
  return `${(value / 1024 / 1024 / 1024).toFixed(2)} GiB`
}

// X04：动作失败的弹窗 = 动作标题 + 中文原因（下一步）+ 可复制的请求号；不显示服务端原文。
function backupFailure(feedback: ReturnType<typeof useFeedback>, language: string, title: string) {
  return (error: unknown) => {
    const apiError = error instanceof ApiError ? error : undefined
    const reason = controlBackupError(language, apiError?.code)
    feedback.error(title, apiError?.requestId ? <>
      <div>{reason}</div>
      <div className="mono">{controlBackupMessage(language, 'requestId')}<Typography.Text copyable>{apiError.requestId}</Typography.Text></div>
    </> : reason)
  }
}

const stateColor: Record<ControlBackupRun['state'], string> = { queued: 'default', running: 'processing', succeeded: 'success', failed: 'error', stopped: 'warning' }

// A stopped migration names its outcome (stopped = this host serves again; aborted = still frozen).
const runErrorKeys = new Set(['migration_stopped', 'migration_aborted'])
function runError(run: ControlBackupRun, bt: (key: ControlBackupKey) => string): string | undefined {
  if (!run.error) return undefined
  return runErrorKeys.has(run.error) ? bt(`error_${run.error}` as ControlBackupKey) : run.error
}

// 文案 key 单独取出，i18nSafety 不会把三元里的 key 当成界面字面量。
const agentStatusKey = (installed: boolean): ControlBackupKey => installed ? 'agentInstalled' : 'agentNotInstalled'

export default function ControlBackupPanel({ accessToken, canManage, frozen = false }: { accessToken: string; canManage: boolean; frozen?: boolean }) {
  const { i18n } = useTranslation()
  const language = i18n.resolvedLanguage ?? 'zh-CN'
  const bt = (key: ControlBackupKey, values?: Record<string, string>) => controlBackupMessage(language, key, values)
  const { modal } = AntApp.useApp()
  const feedback = useFeedback()
  const queryClient = useQueryClient()
  // Keyed by the session, not the access token: a token renewal must not
  // empty the cache (that unmounted the settings form and lost the draft).
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  // 5 s while a run is queued/running (the opened log follows it), else 15 s.
  const status = useQuery({ queryKey: ['control-backup', sessionEpoch], queryFn: () => controlBackupApi.status(accessToken),
    refetchInterval: (query) => query.state.data?.runs.some((run) => run.state === 'queued' || run.state === 'running') ? 5_000 : 15_000 })
  const failed = backupFailure(feedback, language, bt('errorGeneric'))
  const refresh = () => queryClient.invalidateQueries({ queryKey: ['control-backup'] })
  const backupNow = useMutation({ mutationFn: () => controlBackupApi.backupNow(accessToken), onSuccess: refresh,
    onError: backupFailure(feedback, language, bt('backupNowFailed')) })
  const deleteBackup = useMutation({ mutationFn: (id: string) => controlBackupApi.deleteBackup(accessToken, id), onSuccess: refresh,
    onError: backupFailure(feedback, language, bt('deleteFailed')) })
  const [restore, setRestore] = useState<{ commands: string[]; backup_id: string } | null>(null)
  // The log modal keeps the run id and reads the run from the latest status,
  // so an opened log shows new lines and the final state (X09 同类).
  const [logRunID, setLogRunID] = useState<string | null>(null)
  const data = status.data
  const logRun = logRunID ? data?.runs.find((run) => run.id === logRunID) ?? null : null
  const held = data?.freeze?.mode === 'hold'
  const writable = canManage && Boolean(data?.agent_installed) && !held
  const latestMigration = data?.runs.find((run) => run.kind === 'migrate')
  const rollbackRunning = data?.runs.some((run) => run.kind === 'rollback' && (run.state === 'queued' || run.state === 'running'))
  const nextRun = data?.next_run_at ? formatDateTime(data.next_run_at) : ''
  // b04 遗留: a failed backup is final (the agent never retries it); say when the next one runs.
  const failedHint = (run: ControlBackupRun) => run.kind === 'backup' && run.state === 'failed'
    ? nextRun ? bt('failedNoRetry', { time: nextRun }) : bt('failedManualOnly') : ''

  // fix-btenv2: a finished migration onto a BaoTa host still needs the BaoTa site reverse proxy there.
  const btProxyNeeded = (run: ControlBackupRun) => run.kind === 'migrate' && run.state === 'succeeded' && run.target_env === 'bt'

  const confirmBackup = () => modal.confirm({ title: bt('backupNowConfirmTitle'), content: bt('backupNowConfirm'), onOk: () => backupNow.mutateAsync().catch(() => undefined) })  // 失败已由 onError 弹窗说明
  const confirmDelete = (bundle: ControlBackupBundle) => {
    let typed = ''
    modal.confirm({
      title: bt('delete'), okButtonProps: { danger: true },
      content: <Space direction="vertical"><span>{bt('deleteConfirm')}</span><Input aria-label={bt('deleteConfirm')} onChange={(event) => { typed = event.target.value }} /></Space>,
      onOk: () => typed === bundle.backup_id ? deleteBackup.mutateAsync(bundle.backup_id) : Promise.reject(feedback.error(bt('error_confirmation_mismatch'))),
    })
  }
  const openRestore = async (bundle: ControlBackupBundle) => {
    try { setRestore(await controlBackupApi.restoreCommands(accessToken, bundle.backup_id)) } catch (error) { failed(error) }
  }

  const bundleColumns: TableColumnsType<ControlBackupBundle> = [
    { title: bt('backupID'), dataIndex: 'backup_id', key: 'id' },
    { title: bt('createdAt'), key: 'created', render: (_, item) => formatDateTime(item.created_at) },
    { title: bt('reason'), key: 'reason', render: (_, item) => bt(`reason_${item.reason}` as ControlBackupKey) },
    { title: bt('version'), key: 'version', render: (_, item) => `${item.version} / ${item.schema_version}` },
    { title: bt('size'), key: 'size', render: (_, item) => formatBytes(item.bytes) },
    { title: bt('signature'), key: 'signature', render: (_, item) => <Tag color={item.signature_ok ? 'success' : 'warning'}>{item.signature_ok ? bt('signatureOk') : bt('signatureBad')}</Tag> },
    { title: bt('action'), key: 'actions', render: (_, item) => <Space size={4}>
      <Button type="link" size="small" danger onClick={() => void openRestore(item)}>{bt('restore')}</Button>
      <Button type="link" size="small" danger disabled={!writable} onClick={() => confirmDelete(item)}>{bt('delete')}</Button>
    </Space> },
  ]
  const runColumns: TableColumnsType<ControlBackupRun> = [
    { title: bt('createdAt'), key: 'at', width: 180, render: (_, run) => formatDateTime(run.requested_at) },
    { title: bt('reason'), key: 'kind', width: 120, render: (_, run) => `${bt(`kind_${run.kind}` as ControlBackupKey)}${run.target ? ` → ${run.target}` : ''}` },
    { title: bt('state'), key: 'state', render: (_, run) => <Space direction="vertical" size={2}>
      <Tag color={stateColor[run.state]}>{bt(`state_${run.state}` as ControlBackupKey)}</Tag>
      {run.kind === 'migrate' && run.phase ? <Typography.Text type="secondary">{bt('phaseLabel')}: {bt(`phase_${run.phase}` as ControlBackupKey)}</Typography.Text> : null}
      {failedHint(run) ? <Typography.Text type="secondary" className="control-backup-retry">{failedHint(run)}</Typography.Text> : null}
      {btProxyNeeded(run) ? <Tag color="warning">{bt('btProxyTag')}</Tag> : null}
    </Space> },
    { title: bt('backupID'), key: 'backup', render: (_, run) => run.backup_id ?? '-' },
    { title: bt('action'), key: 'log', render: (_, run) => <Space size={4} wrap>
      <Button type="link" size="small" onClick={() => setLogRunID(run.id)}>{bt('viewLog')}</Button>
      <StopMigrationButton accessToken={accessToken} run={run} canManage={canManage} onStopped={refresh} />
    </Space> },
  ]

  const bundles = data?.bundles ?? []
  const runs = data?.runs ?? []
  const latestBundle = bundles.reduce<ControlBackupBundle | undefined>((latest, bundle) => !latest || bundle.created_at > latest.created_at ? bundle : latest, undefined)
  const targets = data?.settings?.targets ?? []

  // fix-maintui: one heading row, then the main column (backups → schedule and
  // retention → storage → migration) beside a side column (status, security).
  return <section className="control-backup-panel" aria-labelledby="control-backup-title">
    <div className="maintenance-section-heading">
      <div><h2 id="control-backup-title">{bt('title')}</h2><p>{bt('description')}</p></div>
      <Space>
        <Button onClick={() => void refresh()}>{bt('refresh')}</Button>
        {!frozen && <Button type="primary" disabled={!writable} loading={backupNow.isPending} onClick={confirmBackup}>{bt('backupNow')}</Button>}
      </Space>
    </div>
    {status.isError && <FeedbackWhen title={controlBackupError(language, status.error instanceof ApiError ? status.error.code : undefined)} />}
    {data && !data.agent_installed && <Alert type="warning" showIcon message={bt('agentMissing')} />}
    {held && <Alert type="error" showIcon message={bt('heldWarning')} />}
    {latestMigration && (latestMigration.state === 'running' || held) ? <div className="control-migration-progress" aria-labelledby="control-migration-progress-title">
      <h3 id="control-migration-progress-title">{bt('latestMigration')}{latestMigration.target ? ` → ${latestMigration.target}` : ''}</h3>
      <MigrationPhases run={latestMigration} />
      <Space wrap>
        <Button onClick={() => setLogRunID(latestMigration.id)}>{bt('viewLog')}</Button>
        <StopMigrationButton accessToken={accessToken} run={latestMigration} canManage={canManage} onStopped={refresh} />
      </Space>
    </div> : null}
    {held && !rollbackRunning ? <RollbackPanel accessToken={accessToken} canManage={canManage} onQueued={refresh} /> : null}
    <div className="control-backup-layout">
      <div className="control-backup-main">
        <section className="control-backup-card" aria-labelledby="control-backup-list-title">
          <h3 id="control-backup-list-title">{bt('backups')}</h3>
          <Table rowKey="backup_id" size="small" columns={bundleColumns} dataSource={bundles} pagination={false} loading={status.isLoading}
            scroll={{ x: 760 }} locale={{ emptyText: bt('noBackups') }} />
          {runs.length === 0
            ? <p className="control-backup-runs-empty">{bt('runsEmpty')}</p>
            : <>
              <h4 className="control-backup-runs-title">{bt('runs')}</h4>
              {nextRun ? <p className="control-backup-next">{bt('nextRun', { time: nextRun })}</p> : null}
              <Table rowKey="id" size="small" columns={runColumns} dataSource={runs} pagination={{ pageSize: 5, hideOnSinglePage: true }} scroll={{ x: 760 }} />
            </>}
        </section>
        {/* The frozen console serves only the migration routes: no settings, kit or new migration. */}
        {!frozen && data?.settings && <BackupSettings accessToken={accessToken} canManage={canManage} settings={data.settings} onSaved={refresh} bt={bt} />}
        {!frozen && <MigrationWizard accessToken={accessToken} canManage={writable} ready={Boolean(data?.migration_ready)} bt={bt} failed={failed} onQueued={refresh} />}
      </div>
      <aside className="control-backup-side">
        <section className="control-backup-card control-backup-status" aria-labelledby="control-backup-status-title">
          <h3 id="control-backup-status-title">{bt('statusTitle')}</h3>
          <dl>
            <div><dt>{bt('statusAgent')}</dt><dd>{data ? <Tag color={data.agent_installed ? 'success' : 'warning'}>{bt(agentStatusKey(data.agent_installed))}</Tag> : '-'}</dd></div>
            <div><dt>{bt('statusLatest')}</dt><dd>{latestBundle ? formatDateTime(latestBundle.created_at) : bt('statusNone')}</dd></div>
            <div><dt>{bt('statusNext')}</dt><dd>{nextRun || bt('scheduleOff')}</dd></div>
            <div><dt>{bt('statusLocal')}</dt><dd>{bundles.length ? bt('localSummary', { count: String(bundles.length), size: formatBytes(bundles.reduce((sum, bundle) => sum + bundle.bytes, 0)) }) : bt('statusNone')}</dd></div>
            <div><dt>{bt('statusRemote')}</dt><dd>{targets.length ? bt('remoteSummary', { enabled: String(targets.filter((target) => target.enabled).length), total: String(targets.length) }) : bt('remoteNone')}</dd></div>
          </dl>
        </section>
        <section className="control-backup-card control-backup-security" aria-labelledby="control-backup-security-title">
          <h3 id="control-backup-security-title">{bt('securityTitle')}</h3>
          {data?.signer_fingerprint && <div className="control-backup-signer">
            <h4>{bt('signer')}</h4>
            <Typography.Text code copyable>{data.signer_fingerprint}</Typography.Text>
            <p>{bt('signerHint')}</p>
          </div>}
          {!frozen && <RecoveryKit accessToken={accessToken} canManage={canManage && Boolean(data?.keys_ready)} bt={bt} failed={failed} />}
        </section>
      </aside>
    </div>
    <Modal open={restore !== null} title={bt('restoreTitle')} footer={null} onCancel={() => setRestore(null)} width={820}>
      <p>{bt('restoreHint')}</p>
      <pre className="control-backup-commands cdnca-dialog-scroll">{restore?.commands.join('\n')}</pre>
      <Typography.Text copyable={{ text: restore?.commands.filter((line) => !line.startsWith('#')).join('\n') ?? '' }}>{bt('copy')}</Typography.Text>
    </Modal>
    <Modal open={logRunID !== null} title={bt('logTitle')} footer={null} onCancel={() => setLogRunID(null)} width={820}>
      {logRun && <p><Tag color={stateColor[logRun.state]}>{bt(`state_${logRun.state}` as ControlBackupKey)}</Tag></p>}
      {logRun?.kind === 'migrate' && <MigrationPhases run={logRun} />}
      {logRun?.error && <Alert type={logRun.state === 'stopped' ? 'warning' : 'error'} message={runError(logRun, bt)} description={failedHint(logRun) || undefined} />}
      {logRun && btProxyNeeded(logRun) && <Alert type="warning" showIcon message={bt('btProxyTitle')} description={bt('btProxySteps')} />}
      <p className="control-backup-log-note">{bt('logRedacted')}</p>
      <pre className="control-backup-commands cdnca-dialog-scroll" aria-live="polite">{logRun?.log.length ? logRun.log.join('\n') : bt('logEmpty')}</pre>
    </Modal>
  </section>
}

type Translate = (key: ControlBackupKey) => string

type StoredSettings = ControlBackupStatus['settings']
type TargetValues = ControlBackupTargetInput & { stored_auth?: 'password' | 'private_key' }
// frequency and time are form-only: they map onto schedule.weekdays / hour / minute on save.
interface SettingsValues {
  schedule: ControlBackupSettingsInput['schedule']; keep_local: number; keep_remote: number; targets?: TargetValues[]
  frequency?: 'daily' | 'weekly'; time?: Dayjs
}

const everyDay = [0, 1, 2, 3, 4, 5, 6]

function scheduleInput(values: SettingsValues): ControlBackupSettingsInput['schedule'] {
  const weekdays = values.frequency === 'daily' ? everyDay : [...new Set(values.schedule.weekdays ?? [])].sort((a, b) => a - b)
  return { enabled: Boolean(values.schedule.enabled), weekdays, hour: values.time?.hour() ?? values.schedule.hour, minute: values.time?.minute() ?? values.schedule.minute }
}

const secretFields = ['access_key', 'secret_key', 'password', 'private_key'] as const
const inputFields = ['stored_name', 'name', 'kind', 'enabled', 'endpoint', 'region', 'bucket', 'prefix', 'path_style', 'host', 'port',
  'username', 'remote_dir', 'host_key_sha256', 'auth', ...secretFields] as const

// The form starts from the stored settings; secrets are never sent to the
// browser, so their fields start empty ("keep").
function formValues(settings: StoredSettings): SettingsValues {
  const daily = everyDay.every((day) => settings.schedule.weekdays.includes(day))
  return { schedule: settings.schedule, keep_local: settings.keep_local, keep_remote: settings.keep_remote,
    frequency: daily ? 'daily' : 'weekly', time: dayjs().hour(settings.schedule.hour).minute(settings.schedule.minute).second(0).millisecond(0),
    targets: settings.targets.map((target) => ({ ...target, stored_name: target.name, stored_auth: target.auth })) }
}

function targetInput(values: TargetValues): ControlBackupTargetInput {
  const input = Object.fromEntries(inputFields.flatMap((key) => values[key] === undefined || values[key] === '' ? [] : [[key, values[key]]]))
  return input as unknown as ControlBackupTargetInput
}

function BackupSettings({ accessToken, canManage, settings, onSaved, bt }: {
  accessToken: string; canManage: boolean; settings: StoredSettings; onSaved: () => void; bt: Translate
}) {
  const { i18n } = useTranslation()
  const language = i18n.resolvedLanguage ?? 'zh-CN'
  const { message } = AntApp.useApp()
  const feedback = useFeedback()
  const [form] = Form.useForm<SettingsValues>()
  // The stored settings this draft started from. A background refresh only
  // replaces the form while it is untouched; otherwise the draft stays and the
  // save is checked against base.revision (another session's change = conflict).
  const [base, setBase] = useState<StoredSettings | null>(null)
  const reset = (next: StoredSettings) => { form.resetFields(); form.setFieldsValue(formValues(next)); setBase(next) }
  useEffect(() => {
    if (base?.revision === settings.revision) return
    if (!base || !form.isFieldsTouched()) reset(settings)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [settings.revision])
  const stale = base !== null && base.revision !== settings.revision
  const frequency = Form.useWatch('frequency', form)
  const failure = (title: ControlBackupKey) => backupFailure(feedback, language, bt(title))
  const save = useMutation({
    mutationFn: (values: SettingsValues) => controlBackupApi.saveSettings(accessToken, { expected_revision: base?.revision ?? '',
      schedule: scheduleInput(values), keep_local: values.keep_local, keep_remote: values.keep_remote, targets: (values.targets ?? []).map(targetInput) }),
    onSuccess: (next) => { reset(next.settings); message.success(bt('saved')); onSaved() },
    onError: failure('saveFailed'),
  })
  const probe = async (index: number) => {
    const fields = inputFields.map((key) => ['targets', index, key])
    try { await form.validateFields(fields) } catch { return }
    try {
      const result = await controlBackupApi.probe(accessToken, base?.revision ?? '', targetInput(form.getFieldValue(['targets', index]) as TargetValues))
      if (result.ok) message.success(bt('probeOk')); else feedback.error(bt('probeFailed'), result.message ?? bt('errorGeneric'))
    } catch (error) {
      if (error instanceof ApiError && error.field) form.setFields([{ name: ['targets', index, error.field as keyof TargetValues], errors: [controlBackupError(language, error.code)] }])
      failure('probeFailed')(error)
    }
  }
  // getFieldsValue(true): stored_name/stored_auth are kept in the store without an input.
  return <Form form={form} layout="vertical" disabled={!canManage} onFinish={() => save.mutate(form.getFieldsValue(true) as SettingsValues)}
    onValuesChange={(changed: Partial<SettingsValues>) => {
      // Switching the SFTP auth: the stored credential is not kept for the new type.
      changed.targets?.forEach((target, index) => {
        if (!target?.auth) return
        form.setFieldValue(['targets', index, 'password'], undefined)
        form.setFieldValue(['targets', index, 'private_key'], undefined)
      })
    }} className="control-backup-settings">
    {stale && <Alert type="warning" showIcon message={bt('serverChanged')} />}
    <section className="control-backup-card" aria-labelledby="control-backup-schedule-title">
      <h3 id="control-backup-schedule-title">{bt('scheduleTitle')}</h3>
      <div className="control-backup-schedule">
        <Form.Item name={['schedule', 'enabled']} label={bt('scheduleEnabled')} valuePropName="checked"><Switch aria-label={bt('scheduleEnabled')} /></Form.Item>
        <Form.Item name="frequency" label={bt('frequency')}>
          <Radio.Group optionType="button" options={[{ value: 'daily', label: bt('frequencyDaily') }, { value: 'weekly', label: bt('frequencyWeekly') }]} />
        </Form.Item>
        <Form.Item name="time" label={bt('time')}>
          <TimePicker format="HH:mm" allowClear={false} needConfirm={false} aria-label={bt('time')} />
        </Form.Item>
      </div>
      {frequency === 'weekly' && <Form.Item name={['schedule', 'weekdays']} label={bt('weekdays')} rules={[{ validator: (_, days?: number[]) =>
        !form.getFieldValue(['schedule', 'enabled']) || (days?.length ?? 0) > 0 ? Promise.resolve() : Promise.reject(new Error(bt('weekdaysRequired'))) }]}>
        <Checkbox.Group options={[1, 2, 3, 4, 5, 6, 0].map((day) => ({ value: day, label: bt(`weekday${day}` as ControlBackupKey) }))} />
      </Form.Item>}
      <div className="control-backup-retention">
        <Form.Item name="keep_local" label={bt('keepLocal')}><InputNumber min={1} max={100} precision={0} addonAfter={bt('copies')} /></Form.Item>
        <Form.Item name="keep_remote" label={bt('keepRemote')}><InputNumber min={1} max={1000} precision={0} addonAfter={bt('copies')} /></Form.Item>
      </div>
      <p className="control-backup-hint">{bt('retentionHint')}</p>
    </section>
    <section className="control-backup-card" aria-labelledby="control-backup-storage-title">
      <h3 id="control-backup-storage-title">{bt('storageTitle')}</h3>
      <p className="control-backup-hint">{bt('storageLocal')}</p>
      <h4>{bt('targets')}</h4>
      <Form.List name="targets">{(fields, { add, remove }) => <>
        {fields.length === 0 && <p className="control-backup-hint">{bt('targetsEmpty')}</p>}
        {fields.map((field) => <TargetFields key={field.key} index={field.name} form={form} canManage={canManage} bt={bt}
          onProbe={() => void probe(field.name)} onRemove={() => remove(field.name)} />)}
        <Space wrap>
          <Button onClick={() => add({ kind: 's3', name: `s3-${fields.length + 1}`, enabled: true, region: 'us-east-1', prefix: 'cdnca/' })}>{bt('addS3')}</Button>
          <Button onClick={() => add({ kind: 'sftp', name: `sftp-${fields.length + 1}`, enabled: true, port: 22, username: 'backup', remote_dir: '/backups/cdnca', auth: 'password' })}>{bt('addSFTP')}</Button>
        </Space>
      </>}</Form.List>
    </section>
    <div className="control-backup-save"><Button type="primary" htmlType="submit" loading={save.isPending}>{bt('save')}</Button><span>{bt('saveHint')}</span></div>
  </Form>
}

// Same rule as nativebackup Target.Validate: https://host[:port] only.
function validEndpoint(raw: string): boolean {
  const value = raw.trim()
  try {
    const url = new URL(value)
    return url.protocol === 'https:' && Boolean(url.hostname) && !url.username && !url.password && !url.search && !url.hash &&
      url.pathname === '/' && !/^https:\/\/[^/]+\/./i.test(value)
  } catch { return false }
}

function TargetFields({ index, form, canManage, bt, onProbe, onRemove }: {
  index: number; form: ReturnType<typeof Form.useForm<SettingsValues>>[0]; canManage: boolean; bt: Translate; onProbe: () => void; onRemove: () => void
}) {
  const kind = form.getFieldValue(['targets', index, 'kind']) as ControlBackupTargetInput['kind']
  const storedName = Form.useWatch(['targets', index, 'stored_name'], { form, preserve: true }) as string | undefined
  const storedAuth = Form.useWatch(['targets', index, 'stored_auth'], { form, preserve: true }) as string | undefined
  const auth = (Form.useWatch(['targets', index, 'auth'], form) as string | undefined) ?? 'password'
  // A saved target keeps its secrets when the fields stay empty; a new one, or
  // an SFTP target whose auth changed, needs them.
  const keeps = Boolean(storedName) && (kind === 's3' || auth === storedAuth)
  const secret = keeps ? { extra: bt('keepSecret') } : { rules: [{ required: true, message: bt('required') }] }
  return <div className="control-backup-target">
    <div className="control-backup-target-head"><Tag>{kind.toUpperCase()}</Tag></div>
    <div className="control-backup-target-fields">
      <Form.Item name={[index, 'name']} label={bt('targetName')} rules={[{ required: true, message: bt('required') }]}><Input /></Form.Item>
      <Form.Item name={[index, 'enabled']} label={bt('enabled')} valuePropName="checked"><Switch aria-label={bt('enabled')} /></Form.Item>
      {kind === 's3' ? <>
        <Form.Item name={[index, 'endpoint']} label={bt('endpoint')} rules={[{ required: true, message: bt('required') }, { validator: (_, value?: string) =>
          !value || validEndpoint(value) ? Promise.resolve() : Promise.reject(new Error(bt('error_control_backup_invalid_endpoint'))) }]}>
          <Input placeholder={bt('endpointPlaceholder')} />
        </Form.Item>
        <Form.Item name={[index, 'region']} label={bt('region')}><Input placeholder={bt('regionPlaceholder')} /></Form.Item>
        <Form.Item name={[index, 'bucket']} label={bt('bucket')}><Input /></Form.Item>
        <Form.Item name={[index, 'prefix']} label={bt('prefix')}><Input /></Form.Item>
        <Form.Item name={[index, 'path_style']} label={bt('pathStyle')} valuePropName="checked"><Switch aria-label={bt('pathStyle')} /></Form.Item>
        <Form.Item name={[index, 'access_key']} label={bt('accessKey')} {...secret}><Input autoComplete="off" /></Form.Item>
        <Form.Item name={[index, 'secret_key']} label={bt('secretKey')} {...secret}><Input.Password autoComplete="new-password" /></Form.Item>
      </> : <>
        <Form.Item name={[index, 'host']} label={bt('host')} rules={[{ required: true, message: bt('required') }]}><Input /></Form.Item>
        <Form.Item name={[index, 'port']} label={bt('port')}><InputNumber min={1} max={65535} precision={0} /></Form.Item>
        <Form.Item name={[index, 'username']} label={bt('username')}><Input /></Form.Item>
        <Form.Item name={[index, 'remote_dir']} label={bt('remoteDir')}><Input placeholder={bt('remoteDirPlaceholder')} /></Form.Item>
        <Form.Item name={[index, 'host_key_sha256']} label={bt('hostKey')}><Input placeholder={bt('hostKeyPlaceholder')} /></Form.Item>
        <Form.Item name={[index, 'auth']} label={bt('sshAuthTarget')} initialValue="password">
          <Radio.Group options={[{ value: 'password', label: bt('authPassword') }, { value: 'private_key', label: bt('authKey') }]} />
        </Form.Item>
        {auth === 'private_key'
          ? <Form.Item name={[index, 'private_key']} label={bt('privateKey')} {...secret}><Input.TextArea rows={3} autoComplete="off" spellCheck={false} /></Form.Item>
          : <Form.Item name={[index, 'password']} label={bt('password')} {...secret}><Input.Password autoComplete="new-password" /></Form.Item>}
      </>}
    </div>
    <Space wrap>
      <Button disabled={!canManage} onClick={onProbe}>{bt('probe')}</Button>
      <Button danger onClick={onRemove}>{bt('remove')}</Button>
    </Space>
    {kind === 'sftp' && storedName && auth !== storedAuth && <Alert type="warning" showIcon message={bt('authChanged')} />}
  </div>
}

function RecoveryKit({ accessToken, canManage, bt, failed }: { accessToken: string; canManage: boolean; bt: Translate; failed: (error: unknown) => void }) {
  const [passphrase, setPassphrase] = useState('')
  const exportKit = useMutation({
    mutationFn: () => controlBackupApi.recoveryKit(accessToken, passphrase),
    onSuccess: (kit) => {
      setPassphrase('')
      const link = document.createElement('a')
      link.href = URL.createObjectURL(new Blob([JSON.stringify(kit, null, 2)], { type: 'application/json' }))
      link.download = 'cdnca-recovery-kit.json'
      link.click()
      URL.revokeObjectURL(link.href)
    },
    onError: failed,
  })
  return <div className="control-backup-recovery">
    <h4>{bt('recoveryKit')}</h4>
    <p>{bt('recoveryKitHint')}</p>
    <Space.Compact block>
      <Input.Password aria-label={bt('passphrase')} placeholder={bt('passphrase')} value={passphrase} disabled={!canManage} autoComplete="new-password" onChange={(event) => setPassphrase(event.target.value)} />
      <Button disabled={!canManage || [...passphrase].length < 12} loading={exportKit.isPending} onClick={() => exportKit.mutate()}>{bt('exportKit')}</Button>
    </Space.Compact>
  </div>
}

interface MigrationValues { host: string; port: number; user: string; auth: 'password' | 'key'; password?: string; private_key?: string; host_key_sha256: string; env: ControlMigrationEnv; confirm: string }

const migrationEnvHelp = { auto: 'targetEnvAutoHelp', bt: 'targetEnvBtHelp', plain: 'targetEnvPlainHelp' } as const

function MigrationWizard({ accessToken, canManage, ready, bt, failed, onQueued }: {
  accessToken: string; canManage: boolean; ready: boolean; bt: Translate; failed: (error: unknown) => void; onQueued: () => void
}) {
  const feedback = useFeedback()
  const [form] = Form.useForm<MigrationValues>()
  const auth = Form.useWatch('auth', form) ?? 'password'
  const host = Form.useWatch('host', form) ?? ''
  const env: ControlMigrationEnv = Form.useWatch('env', form) ?? 'auto'
  const fetchKey = async () => {
    try {
      const values = form.getFieldsValue()
      const result = await controlBackupApi.hostKey(accessToken, values.host, values.port)
      form.setFieldValue('host_key_sha256', result.host_key_sha256)
    } catch (error) { failed(error) }
  }
  const migrate = useMutation({
    mutationFn: (values: MigrationValues) => controlBackupApi.migrate(accessToken, {
      host: values.host.trim(), port: values.port, user: values.user, host_key_sha256: values.host_key_sha256, env: values.env, confirm: values.confirm,
      ...(values.auth === 'key' ? { private_key: values.private_key } : { password: values.password }),
    }),
    onSuccess: () => { form.resetFields(['password', 'private_key', 'confirm']); feedback.warning(bt('migrationQueued')); onQueued() },
    onError: failed,
  })
  return <section className="control-backup-card control-backup-migration" aria-labelledby="control-migration-title">
    <h3 id="control-migration-title">{bt('migrationTitle')}</h3>
    <p>{bt('migrationDescription')}</p>
    <Alert type="warning" showIcon message={bt('migrationNotice')} />
    <p><Typography.Text code>{bt('migrationCli')}</Typography.Text></p>
    {!ready && <Alert type="info" showIcon message={bt('migrationNotReady')} />}
    <Form form={form} layout="vertical" disabled={!canManage || !ready} initialValues={{ port: 22, user: 'root', auth: 'password', env: 'auto' }} onFinish={(values) => migrate.mutate(values)}>
      <Space wrap align="end">
        <Form.Item name="host" label={bt('newMasterHost')} rules={[{ required: true, message: bt('required') }]}><Input /></Form.Item>
        <Form.Item name="port" label={bt('sshPort')}><InputNumber min={1} max={65535} precision={0} /></Form.Item>
        <Form.Item name="user" label={bt('sshUser')}><Input /></Form.Item>
        <Form.Item name="auth" label={bt('sshAuth')}><Radio.Group options={[{ value: 'password', label: bt('authPassword') }, { value: 'key', label: bt('authKey') }]} /></Form.Item>
      </Space>
      <Form.Item name="env" label={bt('targetEnv')} extra={bt(migrationEnvHelp[env])}>
        <Radio.Group {...{ role: 'radiogroup' }} aria-label={bt('targetEnv')} optionType="button"
          options={[{ value: 'auto', label: bt('targetEnvAuto') }, { value: 'bt', label: bt('targetEnvBt') }, { value: 'plain', label: bt('targetEnvPlain') }]} />
      </Form.Item>
      {auth === 'key'
        ? <Form.Item name="private_key" label={bt('privateKey')} rules={[{ required: true, message: bt('required') }]}><Input.TextArea rows={4} autoComplete="off" /></Form.Item>
        : <Form.Item name="password" label={bt('password')} rules={[{ required: true, message: bt('required') }]}><Input.Password autoComplete="new-password" /></Form.Item>}
      {/* C06/X06: on narrow screens the fingerprint shrinks and the fetch button wraps below, both stay visible. */}
      <Space align="end" wrap className="control-backup-hostkey">
        <Form.Item name="host_key_sha256" label={bt('hostKey')} rules={[{ required: true, pattern: /^SHA256:[A-Za-z0-9+/]{43}$/, message: bt('hostKeyRequired') }]}><Input placeholder={bt('hostKeyPlaceholder')} style={{ width: 460, maxWidth: '100%' }} /></Form.Item>
        <Form.Item><Button disabled={!host} onClick={() => void fetchKey()}>{bt('fetchHostKey')}</Button></Form.Item>
      </Space>
      <Form.Item name="confirm" label={bt('confirmHost')} rules={[{ validator: (_, value) => value === host.trim() && value ? Promise.resolve() : Promise.reject(new Error(bt('error_confirmation_mismatch'))) }]}><Input /></Form.Item>
      <Button type="primary" danger htmlType="submit" loading={migrate.isPending}>{bt('startMigration')}</Button>
    </Form>
  </section>
}
