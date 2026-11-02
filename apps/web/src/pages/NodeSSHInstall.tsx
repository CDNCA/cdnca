import { useEffect, useRef, useState, type ReactNode } from 'react'
import { Button, Checkbox, Form, Input, InputNumber, Radio, Space, Table, Tag } from 'antd'
import { useTranslation } from 'react-i18next'
import { ApiError } from '../api/auth'
import { nodeSSHInstallApi, parseHosts, restrictAllowOf, restrictErrorText, type SSHInstallJob } from '../api/nodeSSHInstall'
import './NodeSSHInstall.locale'
import { FeedbackWhen } from '@cdnca/ui'

interface FormValues {
  hosts: string
  port: number
  username: string
  auth: 'password' | 'private_key'
  password?: string
  private_key?: string
  restrict_ssh?: boolean
  restrict_allow?: string
}

// A succeeded job with one of these codes: installed and connected but not
// serving yet (waiting for the first license ticket, installation banned, or
// ticket expired); shown on its own instead of "done", with the cause.
const notServingCodes = ['installed_pending_initialization', 'installed_pending_ticket', 'installed_banned', 'installed_ticket_expired', 'installed_resume_failed']
const notServing = (job: SSHInstallJob) => job.state === 'succeeded' && notServingCodes.includes(job.failure_code)

const stateColors: Record<string, string> = {
  awaiting_host_key: 'gold', pending: 'blue', running: 'processing', succeeded: 'success', failed: 'error', cancelled: 'default',
}

// SSH remote install: the controller logs in to each host (after the
// operator confirms its host key fingerprint) and runs the same install
// command the "copy command" tab shows. Secrets are sent once and never
// shown again.
export default function NodeSSHInstall({ getAccessToken, errorText, single = false }: {
  getAccessToken: () => string | null
  errorText: (error: ApiError) => string
  // single: one server per submit (the SSH tab's single install card).
  single?: boolean
}) {
  const { t, i18n } = useTranslation('nodeSSHInstall')
  const [form] = Form.useForm<FormValues>()
  const [jobs, setJobs] = useState<SSHInstallJob[]>([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  // Last successful status read, and the failure of the latest read (the
  // previous rows stay on screen, marked as possibly out of date).
  const [refreshedAt, setRefreshedAt] = useState<Date | null>(null)
  const [refreshError, setRefreshError] = useState<string | null>(null)
  const [acting, setActing] = useState<string[]>([])
  const active = useRef(true)
  const auth = Form.useWatch('auth', form) ?? 'password'
  const restrict = Form.useWatch('restrict_ssh', form) === true

  const fail = (cause: unknown) => setError(restrictErrorText(cause, errorText))

  // Install jobs run on the controller: reading the newest jobs (every
  // batch) brings back the ones started before this dialog was closed.
  const refresh = (accessToken: string) => nodeSSHInstallApi.list(accessToken).then((next) => {
    if (!active.current) return
    setJobs(next)
    setRefreshedAt(new Date())
    setRefreshError(null)
  }, (cause: unknown) => {
    if (!active.current) return
    if (cause instanceof ApiError && cause.status === 403) {
      // No longer allowed: drop the rows so nothing stays actionable.
      setJobs([])
      setRefreshedAt(null)
    }
    setRefreshError(cause instanceof ApiError ? errorText(cause) : t('errors.unavailable'))
  })

  useEffect(() => {
    active.current = true
    const accessToken = getAccessToken()
    if (accessToken) void refresh(accessToken)
    return () => { active.current = false }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- read once on open
  }, [])

  // Poll while any job can still change; a failed read keeps polling.
  useEffect(() => {
    if (!jobs.some((job) => ['awaiting_host_key', 'pending', 'running'].includes(job.state))) return
    const timer = window.setInterval(() => {
      const accessToken = getAccessToken()
      if (accessToken) void refresh(accessToken)
    }, 3000)
    return () => window.clearInterval(timer)
    // eslint-disable-next-line react-hooks/exhaustive-deps -- refresh only sets state
  }, [jobs, getAccessToken])

  const submit = async (values: FormValues) => {
    const accessToken = getAccessToken()
    if (!accessToken) return
    const hosts = parseHosts(values.hosts)
    if (hosts.length === 0 || hosts.length > 100 || (single && hosts.length !== 1)) {
      setError(t('validation.hosts'))
      return
    }
    setBusy(true)
    setError(null)
    try {
      const created = await nodeSSHInstallApi.create(accessToken, {
        hosts, port: values.port, username: values.username.trim(), restrict_ssh: values.restrict_ssh === true,
        language: i18n.resolvedLanguage ?? 'zh-CN', ...restrictAllowOf(values.restrict_ssh === true, values.restrict_allow ?? ''),
        ...(values.auth === 'password' ? { password: values.password } : { private_key: values.private_key }),
      })
      if (!active.current) return
      const ids = new Set(created.map((job) => job.id))
      setJobs((current) => [...created, ...current.filter((job) => !ids.has(job.id))])
      // The secret is not kept in the form once sent.
      form.setFieldsValue({ password: undefined, private_key: undefined })
    } catch (cause) {
      if (active.current) fail(cause)
    } finally {
      if (active.current) setBusy(false)
    }
  }

  const act = async (job: SSHInstallJob, action: 'confirm' | 'cancel') => {
    const accessToken = getAccessToken()
    if (!accessToken || acting.includes(job.id)) return
    setActing((current) => [...current, job.id])
    try {
      const updated = action === 'confirm'
        ? await nodeSSHInstallApi.confirmHostKey(accessToken, job.id, job.host_key_sha256)
        : await nodeSSHInstallApi.cancel(accessToken, job.id)
      if (active.current) setJobs((current) => current.map((item) => item.id === updated.id ? updated : item))
    } catch (cause) {
      if (active.current) fail(cause)
    } finally {
      if (active.current) setActing((current) => current.filter((id) => id !== job.id))
    }
  }

  return <div className="node-ssh-install">
    <p className="node-install-description">{t('description')}</p>
    {error ? <FeedbackWhen title={error} onClose={() => setError(null)} /> : null}
    <Form form={form} layout="vertical" onFinish={(values) => void submit(values)} requiredMark={false}
      initialValues={{ port: 22, username: 'root', auth: 'password' }}>
      {single
        ? <Form.Item name="hosts" label={t('fields.host')} rules={[{ required: true, whitespace: true, message: t('validation.host') }]}>
          <Input aria-label={t('fields.host')} autoComplete="off" spellCheck={false} placeholder={t('placeholders.host')} />
        </Form.Item>
        : <Form.Item name="hosts" label={t('fields.hosts')} extra={t('help.hosts')}
          rules={[{ required: true, whitespace: true, message: t('validation.hosts') }]}>
          <Input.TextArea aria-label={t('fields.hosts')} rows={4} placeholder={t('placeholders.hosts')} />
        </Form.Item>}
      <Space wrap align="start">
        <Form.Item name="port" label={t('fields.port')} rules={[{ required: true, type: 'integer', min: 1, max: 65535, message: t('validation.port') }]}>
          <InputNumber aria-label={t('fields.port')} min={1} max={65535} precision={0} />
        </Form.Item>
        <Form.Item name="username" label={t('fields.username')} rules={[{ required: true, pattern: /^[a-z_][a-z0-9_.-]{0,31}$/, message: t('validation.username') }]}>
          <Input aria-label={t('fields.username')} autoComplete="off" />
        </Form.Item>
      </Space>
      <Form.Item name="auth" label={t('fields.auth')}>
        <Radio.Group optionType="button" options={[
          { value: 'password', label: t('values.password') }, { value: 'private_key', label: t('values.privateKey') },
        ]} />
      </Form.Item>
      {auth === 'password'
        ? <Form.Item name="password" label={t('fields.password')} extra={t('help.password')} rules={[{ required: true, message: t('validation.secret') }]}>
          <Input.Password aria-label={t('fields.password')} autoComplete="new-password" />
        </Form.Item>
        : <Form.Item name="private_key" label={t('fields.privateKey')} extra={t('help.privateKey')} rules={[{ required: true, message: t('validation.secret') }]}>
          <Input.TextArea aria-label={t('fields.privateKey')} rows={4} autoComplete="off" spellCheck={false} />
        </Form.Item>}
      <Form.Item name="restrict_ssh" valuePropName="checked" extra={t('help.restrictSSH')}>
        <Checkbox>{t('fields.restrictSSH')}</Checkbox>
      </Form.Item>
      {restrict ? <Form.Item name="restrict_allow" label={t('fields.restrictAllow')} extra={t('help.restrictAllow')}>
        <Input.TextArea aria-label={t('fields.restrictAllow')} rows={2} placeholder={t('placeholders.restrictAllow')} spellCheck={false} />
      </Form.Item> : null}
      <Button type="primary" htmlType="submit" loading={busy}>{t('actions.start')}</Button>
    </Form>
    {refreshError ? <FeedbackWhen type="warning" title={t('errors.refreshFailed', { reason: refreshError })} /> : null}
    {jobs.length > 0 ? <>
      <p className="node-install-description">{t('help.hostKey')}</p>
      {refreshedAt ? <p className="node-install-description">{t('help.refreshedAt', { time: refreshedAt.toLocaleTimeString() })}</p> : null}
      <SSHInstallJobsTable jobs={jobs} acting={acting} onAct={(job, action) => void act(job, action)} />
    </> : null}
  </div>
}

// RestrictAllowField: "also allow" addresses next to "only the controller may
// SSH" (batch install); empty: the controller's egress only.
export function RestrictAllowField({ id, value, onChange }: { id: string; value: string; onChange: (value: string) => void }) {
  const { t } = useTranslation('nodeSSHInstall')
  return <div className="node-ssh-restrict-allow">
    <label className="node-ssh-label" htmlFor={id}>{t('fields.restrictAllow')}</label>
    <Input.TextArea id={id} rows={2} value={value} onChange={(event) => onChange(event.target.value)}
      placeholder={t('placeholders.restrictAllow')} spellCheck={false} />
    <p className="node-ssh-help">{t('help.restrictAllow')}</p>
  </div>
}

// SSHInstallJobsTable lists install jobs with their host key and progress;
// extraAction adds a per-row action (batch retry).
export function SSHInstallJobsTable({ jobs, acting, onAct, extraAction }: {
  jobs: SSHInstallJob[]
  acting: string[]
  onAct: (job: SSHInstallJob, action: 'confirm' | 'cancel') => void
  extraAction?: (job: SSHInstallJob) => ReactNode
}) {
  const { t } = useTranslation('nodeSSHInstall')
  return <div className="node-ssh-jobs">
    <Table<SSHInstallJob> rowKey="id" size="small" pagination={false} dataSource={jobs} columns={[
        { title: t('columns.host'), render: (_, job) => `${job.host}:${job.port}` },
        { title: t('columns.state'), render: (_, job) => notServing(job)
          ? <Tag color={job.failure_code === 'installed_pending_ticket' || job.failure_code === 'installed_pending_initialization' ? 'warning' : 'error'}>{t(`states.${job.failure_code}`)}</Tag>
          : <Tag color={stateColors[job.state]}>{t(`states.${job.state}`)}</Tag> },
        { title: t('columns.hostKey'), render: (_, job) => <code>{job.host_key_sha256 || '-'}</code> },
        { title: t('columns.detail'), render: (_, job) => job.failure_code
          ? t(`failures.${job.failure_code}`, { defaultValue: job.failure_code })
          : (job.progress.at(-1) ?? '').replace(/^\[cdnca-edge\] /, '') },
        { title: t('columns.actions'), render: (_, job) => <Space>
          {job.state === 'awaiting_host_key'
            ? <Button size="small" type="primary" loading={acting.includes(job.id)} onClick={() => onAct(job, 'confirm')}>{t('actions.confirm')}</Button> : null}
          {['awaiting_host_key', 'pending', 'running'].includes(job.state)
            ? <Button size="small" danger disabled={acting.includes(job.id)} onClick={() => onAct(job, 'cancel')}>{t('actions.cancel')}</Button> : null}
          {extraAction?.(job)}
        </Space> },
      ]} />
  </div>
}
