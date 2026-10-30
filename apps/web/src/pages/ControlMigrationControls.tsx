import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { Alert, Button, Checkbox, Descriptions, Form, Input, Modal, Space, Steps, Tag, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../api/auth'
import {
  controlBackupApi, controlMigrationPhases, migrationReachedTarget,
  type ControlBackupRun, type ControlNewMaster,
} from '../api/controlBackup'
import { controlBackupError, controlBackupMessage, type ControlBackupKey } from '../i18n/controlBackup'
import { useFeedback } from '@cdnca/ui'

// fix-migrollback：迁移进行中的"停止迁移"、冻结后的"回退到本机"、阶段进度。

type Translate = (key: ControlBackupKey, values?: Record<string, string>) => string

function useTranslate(): { bt: Translate; language: string } {
  const { i18n } = useTranslation()
  const language = i18n.resolvedLanguage ?? 'zh-CN'
  return { bt: (key, values) => controlBackupMessage(language, key, values), language }
}

/** Phase progress of one migration run; a stopped/failed run marks its phase red. */
export function MigrationPhases({ run }: { run: ControlBackupRun }) {
  const { bt } = useTranslate()
  const current = run.phase ? controlMigrationPhases.indexOf(run.phase) : -1
  const status = run.state === 'failed' || run.state === 'stopped' ? 'error' : run.state === 'succeeded' ? 'finish' : 'process'
  return <Steps size="small" className="control-migration-phases" current={Math.max(current, 0)} status={current < 0 ? 'wait' : status}
    items={controlMigrationPhases.map((phase) => ({ title: bt(`phase_${phase}` as ControlBackupKey) }))} />
}

/** "Stop migration": a safe stop before the restore, an abort after it started. */
export function StopMigrationButton({ accessToken, run, canManage, onStopped }: {
  accessToken: string; run: ControlBackupRun; canManage: boolean; onStopped: () => void
}) {
  const { bt, language } = useTranslate()
  const feedback = useFeedback()
  const [open, setOpen] = useState(false)
  const abort = migrationReachedTarget(run.phase)
  const stop = useMutation({
    mutationFn: () => controlBackupApi.stopMigration(accessToken, run.id),
    onSuccess: () => { setOpen(false); feedback.warning(bt('stopRequested')); onStopped() },
    onError: (error) => feedback.error(bt('stopFailed'), controlBackupError(language, error instanceof ApiError ? error.code : undefined)),
  })
  if (run.kind !== 'migrate' || run.state !== 'running') return null
  return <>
    <Button danger disabled={!canManage} onClick={() => setOpen(true)}>{bt('stopMigration')}</Button>
    <Modal open={open} title={bt('stopTitle')} okText={bt('stopConfirm')} okButtonProps={{ danger: true, loading: stop.isPending }}
      onOk={() => stop.mutate()} onCancel={() => setOpen(false)}>
      <Alert type={abort ? 'error' : 'warning'} showIcon message={bt(abort ? 'stopAbort' : 'stopSafe')} />
    </Modal>
  </>
}

function NewMasterFacts({ master }: { master: ControlNewMaster }) {
  const { bt } = useTranslate()
  const tag = (ok: boolean, yes: ControlBackupKey, no: ControlBackupKey, danger = ok) =>
    <Tag color={danger ? 'error' : 'default'}>{bt(ok ? yes : no)}</Tag>
  if (!master.host) return <p>{bt('newMasterNone')}</p>
  return <Descriptions size="small" column={1} bordered labelStyle={{ whiteSpace: 'nowrap' }}>
    <Descriptions.Item label={bt('newMasterTarget')}><Typography.Text code>{master.host}</Typography.Text></Descriptions.Item>
    <Descriptions.Item label={bt('phaseLabel')}>{master.phase ? bt(`phase_${master.phase}` as ControlBackupKey) : '-'}</Descriptions.Item>
    <Descriptions.Item label={bt('state')}>
      <Space wrap size={4}>
        {tag(master.restored, 'newMasterRestored', 'newMasterNotRestored')}
        {tag(master.reachable, 'newMasterReachable', 'newMasterUnreachable')}
        {tag(master.dns_points_to_new, 'newMasterDnsMoved', 'newMasterDnsNotMoved')}
      </Space>
    </Descriptions.Item>
  </Descriptions>
}

/** Commands and DNS names the operator needs after a rollback. */
export function RollbackFollowUp({ master }: { master: ControlNewMaster }) {
  const { bt } = useTranslate()
  return <div className="control-rollback-follow-up">
    <h4>{bt('dnsHintTitle')}</h4>
    <p>{bt('dnsHint', { control: master.control_domain || '-', gateway: master.gateway_endpoint || '-' })}</p>
    <h4>{bt('cleanHintTitle')}</h4>
    {master.clean_command
      ? <>
        <p>{bt('cleanHint')}</p>
        <Typography.Paragraph className="control-backup-commands cdnca-dialog-scroll" copyable={{ text: master.clean_command }}>{master.clean_command}</Typography.Paragraph>
      </>
      : <p>{bt('cleanHintNone')}</p>}
  </div>
}

interface RollbackValues { password: string; understood: boolean; confirm_new_master_stopped?: boolean }

/** "Roll back to this host": second confirmation + password, and a forced tick when the new host may be serving. */
export function RollbackPanel({ accessToken, canManage, onQueued }: { accessToken: string; canManage: boolean; onQueued: () => void }) {
  const { bt, language } = useTranslate()
  const feedback = useFeedback()
  const [open, setOpen] = useState(false)
  const [form] = Form.useForm<RollbackValues>()
  const [refused, setRefused] = useState<ControlNewMaster | null>(null)
  const master = useQuery({ queryKey: ['control-backup', 'new-master', accessToken], queryFn: () => controlBackupApi.newMaster(accessToken),
    enabled: open, staleTime: 0, refetchOnWindowFocus: false })
  const view = refused ?? master.data
  const serving = Boolean(view?.serving)
  const close = () => { setOpen(false); setRefused(null); form.resetFields() }
  const rollback = useMutation({
    mutationFn: (values: RollbackValues) => controlBackupApi.rollback(accessToken, {
      password: values.password, confirm_new_master_stopped: Boolean(values.confirm_new_master_stopped) }),
    onSuccess: () => { close(); feedback.warning(bt('rollbackQueued')); onQueued() },
    onError: (error) => {
      form.setFieldValue('password', '')
      const code = error instanceof ApiError ? error.code : undefined
      if (code === 'control_backup_new_master_serving') {
        // The server saw the new host serving: show its view and require the tick.
        void master.refetch().then((result) => setRefused(result.data ? { ...result.data, serving: true } : null))
        form.setFields([{ name: 'confirm_new_master_stopped', errors: [bt('confirmNewMasterRequired')] }])
        return
      }
      if (code === 'control_backup_password_invalid') {
        form.setFields([{ name: 'password', errors: [controlBackupError(language, code)] }])
        return
      }
      feedback.error(bt('rollbackFailed'), controlBackupError(language, code))
    },
  })
  return <div className="maintenance-action-panel control-rollback" aria-labelledby="control-rollback-title">
    <h3 id="control-rollback-title">{bt('rollbackTitle')}</h3>
    <p>{bt('rollbackIntro')}</p>
    <Button type="primary" danger disabled={!canManage} onClick={() => setOpen(true)}>{bt('rollback')}</Button>
    <Modal open={open} title={bt('rollbackTitle')} width={720} destroyOnHidden onCancel={close} okText={bt('rollbackSubmit')}
      okButtonProps={{ danger: true, loading: rollback.isPending, disabled: master.isFetching && !view }}
      onOk={() => form.submit()}>
      <Space direction="vertical" size={12} style={{ width: '100%' }}>
        {master.isFetching && !view ? <Alert type="info" showIcon message={bt('rollbackChecking')} /> : null}
        {view ? <NewMasterFacts master={view} /> : null}
        {serving ? <Alert type="error" showIcon message={bt('newMasterServing')} /> : null}
        {view ? <RollbackFollowUp master={view} /> : null}
        <Form form={form} name="control-rollback" layout="vertical" requiredMark={false} onFinish={(values) => rollback.mutate(values)}>
          {serving ? <Form.Item name="confirm_new_master_stopped" valuePropName="checked"
            rules={[{ validator: (_, checked) => checked ? Promise.resolve() : Promise.reject(new Error(bt('confirmNewMasterRequired'))) }]}>
            <Checkbox>{bt('confirmNewMasterStopped')}</Checkbox>
          </Form.Item> : null}
          <Form.Item name="understood" valuePropName="checked"
            rules={[{ validator: (_, checked) => checked ? Promise.resolve() : Promise.reject(new Error(bt('error_confirmation_mismatch'))) }]}>
            <Checkbox>{bt('rollbackConfirmText')}</Checkbox>
          </Form.Item>
          <Form.Item name="password" label={bt('rollbackPassword')} rules={[{ required: true, message: bt('required') }]}>
            <Input.Password autoComplete="current-password" />
          </Form.Item>
        </Form>
      </Space>
    </Modal>
  </div>
}
