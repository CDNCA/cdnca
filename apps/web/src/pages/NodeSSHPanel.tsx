import { lazy, Suspense, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Button, Checkbox, Form, Input, InputNumber, Radio, Segmented, Select, Space, Switch, Table, Tag, Tooltip } from 'antd'
import { KeyRound, ListChecks, Server, ShieldCheck, TerminalSquare } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { FeedbackWhen } from '@cdnca/ui'
import { ApiError } from '../api/auth'
import { nodesApi, type NodeInventoryItem } from '../api/nodes'
import {
  nodeSSHInstallApi, nodeSSHTerminalApi, parseBatchLines, type BatchLine, type NodeSSHEndpoint, type SSHAccess, type SSHInstallJob,
} from '../api/nodeSSHInstall'
import NodeSSHInstall, { SSHInstallJobsTable } from './NodeSSHInstall'
import type { TerminalLogin, TerminalStatus } from './NodeSSHTerminal'
import './NodeSSHPanel.locale'

// xterm.js only loads when a terminal opens.
const NodeSSHTerminal = lazy(() => import('./NodeSSHTerminal'))

type Section = 'terminal' | 'single' | 'batch'

interface PanelProps {
  getAccessToken: (permission: 'read' | 'manage') => string | null
  canManage: boolean
  // Platform administrator (platform.admin): the terminal needs nodes.ssh,
  // which only administrators hold.
  canTerminal: boolean
  errorText: (error: ApiError) => string
}

// NodeSSHPanel is the node management "SSH" tab: a browser SSH terminal to
// a connected node, single install and batch install over SSH.
export default function NodeSSHPanel({ getAccessToken, canManage, canTerminal, errorText }: PanelProps) {
  const { t } = useTranslation('nodeSSHPanel')
  const [section, setSection] = useState<Section>(canTerminal ? 'terminal' : 'single')
  const options: { value: Section; label: ReactNode }[] = [
    ...(canTerminal ? [{ value: 'terminal' as const, label: <span className="node-ssh-segment"><TerminalSquare size={15} aria-hidden="true" />{t('sections.terminal')}</span> }] : []),
    ...(canManage ? [
      { value: 'single' as const, label: <span className="node-ssh-segment"><Server size={15} aria-hidden="true" />{t('sections.single')}</span> },
      { value: 'batch' as const, label: <span className="node-ssh-segment"><ListChecks size={15} aria-hidden="true" />{t('sections.batch')}</span> },
    ] : []),
  ]
  if (options.length === 0) return <FeedbackWhen type="warning" title={t('noPermission')} />
  return <section className="node-ssh-panel" aria-labelledby="node-ssh-title">
    <header className="node-ssh-header">
      <div>
        <h2 id="node-ssh-title" className="node-ssh-title">{t('title')}</h2>
        <p className="node-ssh-subtitle">{t('subtitle')}</p>
      </div>
      <Segmented<Section> aria-label={t('sectionsLabel')} value={section} onChange={setSection} options={options} />
    </header>
    {section === 'terminal' && canTerminal ? <TerminalCard getAccessToken={getAccessToken} canManage={canManage} errorText={errorText} /> : null}
    {section === 'single' && canManage ? <div className="node-ssh-card">
      <h3 className="node-ssh-card-title">{t('single.title')}</h3>
      <NodeSSHInstall single getAccessToken={() => getAccessToken('manage')} errorText={errorText} />
    </div> : null}
    {section === 'batch' && canManage ? <BatchCard getAccessToken={() => getAccessToken('manage')} errorText={errorText} /> : null}
  </section>
}

function nodeLabel(node: NodeInventoryItem) {
  return `${node.name}（${node.ipv4 ?? node.ipv6 ?? '-'}）`
}

interface TerminalForm {
  node_id?: string
  port: number
  username: string
  auth: 'password' | 'private_key' | 'saved'
  password?: string
  private_key?: string
  remember?: boolean
}

function TerminalCard({ getAccessToken, canManage, errorText }: Omit<PanelProps, 'canTerminal'>) {
  const { t } = useTranslation('nodeSSHPanel')
  const [form] = Form.useForm<TerminalForm>()
  const [search, setSearch] = useState('')
  const [endpoint, setEndpoint] = useState<NodeSSHEndpoint | null>(null)
  const [hostKey, setHostKey] = useState<string | null>(null)
  const [keyConfirmed, setKeyConfirmed] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [session, setSession] = useState<{ key: number; login: TerminalLogin; token: string; socket: string } | null>(null)
  const [status, setStatus] = useState<{ value: TerminalStatus; code?: string } | null>(null)
  const nodeID = Form.useWatch('node_id', form)
  const auth = Form.useWatch('auth', form) ?? 'password'
  const port = Form.useWatch('port', form) ?? 22

  const nodes = useQuery({
    queryKey: ['node-ssh-terminal-nodes', search],
    queryFn: async () => {
      const token = getAccessToken('read')
      if (!token) throw new ApiError('signed out', 401, 'unauthorized')
      return nodesApi.list(token, { limit: 50, search: search || undefined })
    },
  })
  const choices = (nodes.data?.items ?? []).filter((node) => node.admin_state !== 'retired' && (node.ipv4 || node.ipv6))

  const fail = (cause: unknown) => setError(cause instanceof ApiError ? errorText(cause) : t('errors.unavailable'))

  // A node change resets what was confirmed for the previous one.
  useEffect(() => {
    setEndpoint(null)
    setHostKey(null)
    setKeyConfirmed(false)
    if (!nodeID) return
    const token = getAccessToken('read')
    if (!token) return
    let active = true
    nodeSSHTerminalApi.endpoint(token, nodeID).then((value) => {
      if (!active) return
      setEndpoint(value)
      if (value.saved) form.setFieldsValue({ port: value.saved.port, username: value.saved.username, auth: 'saved' })
      else if (form.getFieldValue('auth') === 'saved') form.setFieldsValue({ auth: 'password' })
    }, (cause) => active && fail(cause))
    return () => { active = false }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodeID])

  useEffect(() => { setHostKey(null); setKeyConfirmed(false) }, [port])

  const readHostKey = async () => {
    const token = getAccessToken('read')
    if (!token || !nodeID) return
    setBusy(true)
    setError(null)
    try {
      const value = await nodeSSHTerminalApi.hostKey(token, nodeID, port)
      setHostKey(value.host_key_sha256)
      setKeyConfirmed(false)
    } catch (cause) {
      fail(cause)
    } finally {
      setBusy(false)
    }
  }

  const connect = (values: TerminalForm) => {
    const token = getAccessToken('read')
    if (!token || !values.node_id) return
    setError(null)
    const login: TerminalLogin = values.auth === 'saved'
      ? { port: values.port, use_saved: true, remember: false }
      : { port: values.port, username: values.username.trim(), host_key_sha256: hostKey ?? '', use_saved: false, remember: values.remember === true,
        ...(values.auth === 'password' ? { password: values.password } : { private_key: values.private_key }) }
    setSession({ key: Date.now(), login, token, socket: nodeSSHTerminalApi.socketURL(values.node_id) })
    form.setFieldsValue({ password: undefined, private_key: undefined })
  }

  const forget = async () => {
    const token = getAccessToken('read')
    if (!token || !nodeID) return
    try {
      await nodeSSHTerminalApi.forget(token, nodeID)
      setEndpoint((current) => current ? { ...current, saved: null } : current)
      form.setFieldsValue({ auth: 'password' })
    } catch (cause) {
      fail(cause)
    }
  }

  const needsKey = auth !== 'saved'
  const canConnect = Boolean(nodeID) && (!needsKey || (hostKey && keyConfirmed))
  const live = status?.value === 'connecting' || status?.value === 'open'

  return <div className="node-ssh-grid">
    <div className="node-ssh-card">
      <h3 className="node-ssh-card-title">{t('terminal.title')}</h3>
      <p className="node-ssh-help">{t('terminal.description')}</p>
      {error ? <FeedbackWhen title={error} onClose={() => setError(null)} /> : null}
      <Form form={form} layout="vertical" requiredMark={false} onFinish={connect}
        initialValues={{ port: 22, username: 'root', auth: 'password' }} disabled={live}>
        <Form.Item name="node_id" label={t('terminal.node')} rules={[{ required: true, message: t('validation.node') }]}>
          <Select showSearch filterOption={false} onSearch={setSearch} loading={nodes.isFetching} aria-label={t('terminal.node')}
            placeholder={t('terminal.nodePlaceholder')} notFoundContent={nodes.isFetching ? t('loading') : t('terminal.noNodes')}
            options={choices.map((node) => ({ value: node.id, label: nodeLabel(node) }))} />
        </Form.Item>
        <Space wrap align="start">
          <Form.Item name="port" label={t('fields.port')} rules={[{ required: true, type: 'integer', min: 1, max: 65535, message: t('validation.port') }]}>
            <InputNumber aria-label={t('fields.port')} min={1} max={65535} precision={0} />
          </Form.Item>
          {auth !== 'saved' ? <Form.Item name="username" label={t('fields.username')}
            rules={[{ required: true, pattern: /^[a-z_][a-z0-9_.-]{0,31}$/, message: t('validation.username') }]}>
            <Input aria-label={t('fields.username')} autoComplete="off" spellCheck={false} />
          </Form.Item> : null}
        </Space>
        <Form.Item name="auth" label={t('fields.auth')}>
          <Radio.Group optionType="button" options={[
            ...(endpoint?.saved ? [{ value: 'saved', label: t('values.saved') }] : []),
            { value: 'password', label: t('values.password') }, { value: 'private_key', label: t('values.privateKey') },
          ]} />
        </Form.Item>
        {auth === 'saved' && endpoint?.saved ? <p className="node-ssh-help">
          {t('terminal.savedHint', { username: endpoint.saved.username, port: endpoint.saved.port })}{' '}
          <Button type="link" size="small" onClick={() => void forget()}>{t('actions.forget')}</Button>
        </p> : null}
        {auth === 'password' ? <Form.Item name="password" label={t('fields.password')} rules={[{ required: true, message: t('validation.secret') }]}>
          <Input.Password aria-label={t('fields.password')} autoComplete="new-password" />
        </Form.Item> : null}
        {auth === 'private_key' ? <Form.Item name="private_key" label={t('fields.privateKey')} rules={[{ required: true, message: t('validation.secret') }]}>
          <Input.TextArea aria-label={t('fields.privateKey')} rows={4} autoComplete="off" spellCheck={false} />
        </Form.Item> : null}
        {needsKey ? <div className="node-ssh-hostkey">
          <Button icon={<KeyRound size={14} aria-hidden="true" />} disabled={!nodeID} loading={busy} onClick={() => void readHostKey()}>
            {t('actions.readHostKey')}
          </Button>
          {hostKey ? <>
            <code className="node-ssh-fingerprint" aria-label={t('terminal.fingerprint')}>{hostKey}</code>
            <Checkbox checked={keyConfirmed} onChange={(event) => setKeyConfirmed(event.target.checked)}>{t('terminal.confirmKey')}</Checkbox>
          </> : <p className="node-ssh-help">{t('terminal.hostKeyHelp')}</p>}
        </div> : null}
        {needsKey ? <Form.Item name="remember" valuePropName="checked" extra={t('terminal.rememberHelp')}>
          <Checkbox>{t('terminal.remember')}</Checkbox>
        </Form.Item> : null}
        <Space>
          <Button type="primary" htmlType="submit" disabled={!canConnect}>{t('actions.connect')}</Button>
          {live ? <Button disabled={false} onClick={() => { setSession(null); setStatus(null) }}>{t('actions.disconnect')}</Button> : null}
        </Space>
      </Form>
      {nodeID && canManage ? <AccessSwitch nodeID={nodeID} getAccessToken={() => getAccessToken('manage')} errorText={errorText} /> : null}
    </div>
    <div className="node-ssh-card node-ssh-terminal-card">
      <div className="node-ssh-terminal-bar">
        <span>{endpoint ? `${endpoint.node_name} · ${endpoint.host}:${port}` : t('terminal.idle')}</span>
        {status ? <Tag color={status.value === 'open' ? 'success' : status.value === 'connecting' ? 'processing' : status.value === 'error' ? 'error' : 'default'}>
          {t(`status.${status.value}`)}</Tag> : null}
      </div>
      {status && (status.value === 'error' || status.value === 'closed') && status.code
        ? <p className="node-ssh-help" role="status">{t(`codes.${status.code}`, { defaultValue: status.code })}</p> : null}
      {session ? <Suspense fallback={<div className="node-ssh-terminal-placeholder">{t('loading')}</div>}>
        <NodeSSHTerminal key={session.key} socketURL={session.socket} accessToken={session.token} login={session.login}
          label={t('terminal.screenLabel')} onStatus={(value, code) => setStatus({ value, code })} />
      </Suspense> : <div className="node-ssh-terminal-placeholder">{t('terminal.placeholder')}</div>}
      <p className="node-ssh-help">{t('terminal.limits')}</p>
    </div>
  </div>
}

// AccessSwitch turns "only the controller may SSH" on or off for one node.
function AccessSwitch({ nodeID, getAccessToken, errorText }: { nodeID: string; getAccessToken: () => string | null; errorText: (error: ApiError) => string }) {
  const { t } = useTranslation('nodeSSHPanel')
  const [access, setAccess] = useState<SSHAccess | null>(null)
  const [egress, setEgress] = useState<string[] | null>(null)
  const [allow, setAllow] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const load = useRef(0)

  useEffect(() => {
    const token = getAccessToken()
    if (!token) return
    const current = ++load.current
    Promise.all([nodeSSHInstallApi.getAccess(token, nodeID), nodeSSHInstallApi.controllerEgress(token)]).then(([value, controller]) => {
      if (current !== load.current) return
      setAccess(value)
      setAllow(value.allow_cidrs.join('\n'))
      setEgress(controller.controller_cidrs)
    }, (cause) => current === load.current && setError(cause instanceof ApiError ? errorText(cause) : t('errors.unavailable')))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodeID])

  const save = async (enabled: boolean) => {
    const token = getAccessToken()
    if (!token || !access) return
    setBusy(true)
    setError(null)
    try {
      setAccess(await nodeSSHInstallApi.setAccess(token, nodeID, {
        enabled, ssh_port: access.ssh_port, allow_cidrs: allow.split(/[\s,，]+/).map((value) => value.trim()).filter(Boolean),
      }))
    } catch (cause) {
      setError(cause instanceof ApiError ? (cause.code === 'controller_egress_unknown' ? t('access.egressUnknown') : errorText(cause)) : t('errors.unavailable'))
    } finally {
      setBusy(false)
    }
  }

  const unknown = egress !== null && egress.length === 0
  // A node whose agent does not declare SSH_ACCESS cannot apply it: say so
  // instead of leaving a revision pending forever (turning it off stays possible).
  const unsupported = access !== null && (access.supported === false || access.failure_code === 'not_supported')
  const blocked = unknown || unsupported
  const blockedText = unsupported ? t('access.unsupported') : t('access.egressUnknown')
  const failure = access && (access.state === 'failed' || access.state === 'reverted') && access.failure_code &&
    access.failure_code !== 'not_supported' ? access.failure_code : ''
  return <div className="node-ssh-access">
    <div className="node-ssh-access-head">
      <ShieldCheck size={16} aria-hidden="true" />
      <span className="node-ssh-access-title" id={`ssh-access-${nodeID}`}>{t('access.title')}</span>
      <Tooltip title={blocked && !access?.enabled ? blockedText : undefined}>
        <Switch aria-labelledby={`ssh-access-${nodeID}`} checked={access?.enabled ?? false} loading={busy || !access}
          disabled={!access || (blocked && !access.enabled)} onChange={(checked) => void save(checked)} />
      </Tooltip>
      {unsupported ? <Tag color="warning">{t('access.unsupportedTag')}</Tag>
        : access && access.state ? <Tag>{t(`access.states.${access.state}`)}</Tag> : null}
    </div>
    <p className="node-ssh-help">{t('access.description')}</p>
    {unsupported ? <p className="node-ssh-help" role="status">{t('access.unsupported')}</p> : null}
    {failure ? <p className="node-ssh-help" role="status">{t('access.failure', { code: failure })}</p> : null}
    {egress && egress.length > 0 ? <p className="node-ssh-help">{t('access.egress', { cidrs: egress.join(', ') })}</p> : null}
    <label className="node-ssh-label" htmlFor={`ssh-allow-${nodeID}`}>{t('access.allow')}</label>
    <Input.TextArea id={`ssh-allow-${nodeID}`} rows={2} value={allow} onChange={(event) => setAllow(event.target.value)}
      placeholder={t('access.allowPlaceholder')} spellCheck={false} disabled={busy} />
    {access?.enabled ? <Button size="small" className="node-ssh-access-save" disabled={busy} onClick={() => void save(true)}>{t('access.saveAllow')}</Button> : null}
    {error ? <FeedbackWhen title={error} onClose={() => setError(null)} /> : null}
  </div>
}

function BatchCard({ getAccessToken, errorText }: { getAccessToken: () => string | null; errorText: (error: ApiError) => string }) {
  const { t, i18n } = useTranslation('nodeSSHPanel')
  const [text, setText] = useState('')
  const [restrict, setRestrict] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [batchID, setBatchID] = useState<string | null>(null)
  const [jobs, setJobs] = useState<SSHInstallJob[]>([])
  const [acting, setActing] = useState<string[]>([])
  const [retrying, setRetrying] = useState<SSHInstallJob | null>(null)
  const lines = useMemo(() => parseBatchLines(text), [text])
  const valid = lines.filter((line) => line.target)
  const invalid = lines.filter((line) => line.error)

  const fail = (cause: unknown) => setError(cause instanceof ApiError
    ? (cause.code === 'controller_egress_unknown' ? t('access.egressUnknown') : errorText(cause)) : t('errors.unavailable'))

  useEffect(() => {
    if (!batchID || !jobs.some((job) => ['awaiting_host_key', 'pending', 'running'].includes(job.state))) return
    const timer = window.setInterval(() => {
      const token = getAccessToken()
      if (token) void nodeSSHInstallApi.list(token, batchID).then(setJobs, () => undefined)
    }, 3000)
    return () => window.clearInterval(timer)
  }, [batchID, jobs, getAccessToken])

  const submit = async () => {
    const token = getAccessToken()
    if (!token || valid.length === 0 || invalid.length > 0) return
    setBusy(true)
    setError(null)
    try {
      const created = await nodeSSHInstallApi.create(token, { targets: valid.map((line) => line.target!), restrict_ssh: restrict,
        language: i18n.resolvedLanguage ?? 'zh-CN' })
      setBatchID(created[0]?.batch_id ?? null)
      setJobs(created)
      // Passwords are not kept on screen once sent.
      setText('')
    } catch (cause) {
      fail(cause)
    } finally {
      setBusy(false)
    }
  }

  const act = async (job: SSHInstallJob, action: 'confirm' | 'cancel') => {
    const token = getAccessToken()
    if (!token || acting.includes(job.id)) return
    setActing((current) => [...current, job.id])
    try {
      const updated = action === 'confirm' ? await nodeSSHInstallApi.confirmHostKey(token, job.id, job.host_key_sha256)
        : await nodeSSHInstallApi.cancel(token, job.id)
      setJobs((current) => current.map((item) => item.id === updated.id ? updated : item))
    } catch (cause) {
      fail(cause)
    } finally {
      setActing((current) => current.filter((id) => id !== job.id))
    }
  }

  const confirmAll = async () => {
    for (const job of jobs.filter((item) => item.state === 'awaiting_host_key')) await act(job, 'confirm')
  }

  const retry = async (job: SSHInstallJob, password: string) => {
    const token = getAccessToken()
    if (!token) return
    try {
      const created = await nodeSSHInstallApi.create(token, { batch_id: job.batch_id, restrict_ssh: job.restrict_ssh === true,
        language: i18n.resolvedLanguage ?? 'zh-CN',
        targets: [{ host: job.host, port: job.port, username: job.username, password }] })
      setJobs((current) => [...created, ...current])
      setRetrying(null)
    } catch (cause) {
      fail(cause)
    }
  }

  const awaiting = jobs.filter((job) => job.state === 'awaiting_host_key').length
  return <div className="node-ssh-card">
    <h3 className="node-ssh-card-title">{t('batch.title')}</h3>
    <p className="node-ssh-help">{t('batch.description')}</p>
    {error ? <FeedbackWhen title={error} onClose={() => setError(null)} /> : null}
    <label className="node-ssh-label" htmlFor="node-ssh-batch-lines">{t('batch.lines')}</label>
    <Input.TextArea id="node-ssh-batch-lines" rows={8} value={text} onChange={(event) => setText(event.target.value)}
      placeholder={t('batch.placeholder')} spellCheck={false} autoComplete="off" className="node-ssh-batch-input"
      aria-describedby="node-ssh-batch-format" />
    <p id="node-ssh-batch-format" className="node-ssh-help">{t('batch.format')}</p>
    {lines.length > 0 ? <>
      <p className="node-ssh-help" role="status">{t('batch.summary', { valid: valid.length, invalid: invalid.length })}</p>
      <Table<BatchLine> rowKey="line" size="small" pagination={false} dataSource={lines} className="node-ssh-preview"
        rowClassName={(line) => line.error ? 'node-ssh-preview-invalid' : ''} columns={[
          { title: t('batch.columns.line'), dataIndex: 'line', width: 64 },
          { title: t('batch.columns.host'), render: (_, line) => line.target ? `${line.target.host}:${line.target.port}` : line.raw.split(/\s+/)[0] },
          { title: t('batch.columns.username'), render: (_, line) => line.target?.username ?? '-' },
          { title: t('batch.columns.password'), render: (_, line) => line.target ? '••••••' : '-' },
          { title: t('batch.columns.check'), render: (_, line) => line.error
            ? <Tag color="error">{t(`batch.errors.${line.error}`)}</Tag> : <Tag color="success">{t('batch.ok')}</Tag> },
        ]} />
    </> : null}
    <Checkbox checked={restrict} onChange={(event) => setRestrict(event.target.checked)} className="node-ssh-restrict">{t('fields.restrictSSH')}</Checkbox>
    <p className="node-ssh-help">{t('batch.concurrency')}</p>
    <Button type="primary" loading={busy} disabled={valid.length === 0 || invalid.length > 0} onClick={() => void submit()}>
      {t('batch.start', { count: valid.length })}
    </Button>
    {jobs.length > 0 ? <div className="node-ssh-jobs-block">
      <div className="node-ssh-jobs-head">
        <p className="node-ssh-help">{t('batch.hostKeyHelp')}</p>
        {awaiting > 0 ? <Button size="small" onClick={() => void confirmAll()}>{t('batch.confirmAll', { count: awaiting })}</Button> : null}
      </div>
      <SSHInstallJobsTable jobs={jobs} acting={acting} onAct={(job, action) => void act(job, action)}
        extraAction={(job) => job.state === 'failed' || job.state === 'cancelled'
          ? <Button size="small" onClick={() => setRetrying(job)}>{t('actions.retry')}</Button> : null} />
      {retrying ? <RetryForm job={retrying} onCancel={() => setRetrying(null)} onSubmit={(password) => void retry(retrying, password)} /> : null}
    </div> : null}
  </div>
}

function RetryForm({ job, onCancel, onSubmit }: { job: SSHInstallJob; onCancel: () => void; onSubmit: (password: string) => void }) {
  const { t } = useTranslation('nodeSSHPanel')
  const [password, setPassword] = useState('')
  return <form className="node-ssh-retry" onSubmit={(event) => { event.preventDefault(); if (password) onSubmit(password) }}>
    <label className="node-ssh-label" htmlFor="node-ssh-retry-password">{t('batch.retryPassword', { host: `${job.host}:${job.port}`, username: job.username })}</label>
    <Space wrap>
      <Input.Password id="node-ssh-retry-password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="new-password" />
      <Button type="primary" htmlType="submit" disabled={!password}>{t('actions.retry')}</Button>
      <Button onClick={onCancel}>{t('actions.cancel')}</Button>
    </Space>
  </form>
}
