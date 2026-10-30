import { useState } from 'react'
import { Alert, Button, Form, Input, Switch } from 'antd'
import { ChevronDown } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { ApiError, type ScopeKind } from '../api/auth'
import { streamsApi, type BatchCreateStreamsRequest, type BatchCreateStreamsResult, type StreamFields } from '../api/streams'
import { useSessionStore } from '../auth/session'
import StreamGroupSelect from './StreamGroupSelect'
import StreamOwnerSelect from './StreamOwnerSelect'
import { useStreamDraftDefaults } from './streamDraftDefaults'
import { batchLines, currentPrincipalCanManageStreams, defaultDomainDNSPolicy, emptyGeoPolicy, errorMessage, writeKey, writeOutcomeUnknown } from './streamForm'
import { useWriteRecovery } from './streamWriteRecovery'

interface BatchCreateValues {
  owner_id?: string
  target_scope_id?: string
  lines_text: string
  ignore_errors: boolean
  group_ids: string[]
  remark: string
}

// 「添加转发 > 批量」：用户选择、用户套餐、转发数据（每行「监听端口|IP|回源端口」）、忽略错误；
// 虚线「展开更多」后是 所属分组、备注。我方另需所属站点（必填，同单个）。整批一个幂等键；未开忽略错误时
// 有失败行则整批不写入，逐行结果列在下方。
export default function StreamBatchCreatePanel({ isAdmin, scopeKind, scopeID, sessionEpoch, disabled, onCancel, onCreated }: {
  isAdmin: boolean
  scopeKind: ScopeKind
  scopeID: string
  sessionEpoch: number
  disabled: boolean
  onCancel: () => void
  onCreated: (result: BatchCreateStreamsResult) => void
}) {
  const { t } = useTranslation('streams')
  const [form] = Form.useForm<BatchCreateValues>()
  const [advancedOpen, setAdvancedOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<BatchCreateStreamsResult | null>(null)
  const [failure, setFailure] = useState<ApiError | null>(null)
  // L4-007：整批一个幂等键。结果未知时记下原请求（关掉弹窗再打开也在），只能按原请求重试。
  const recovery = useWriteRecovery<{ input: BatchCreateStreamsRequest; key: string }>({ scopeKind, scopeID, sessionEpoch }, 'batch-create')
  const unknown = recovery.attempt
  const targetScopeID = Form.useWatch('target_scope_id', form)
  const ownerID = Form.useWatch('owner_id', form)
  const groupIDs = Form.useWatch('group_ids', form)
  // L4-DEFAULT-01：未写 /tcp|/udp 的端口与负载方式取「默认设置」（归属+所选分组）。批量没有访问控制区，
  // 接收 PROXY 需同时配置可信代理，仍按关闭提交。
  const { defaults, ready: defaultsReady } = useStreamDraftDefaults({ open: true, isAdmin, scopeKind, scopeID, sessionEpoch, targetScopeID, ownerID, groupIDs })
  const createScopeID = isAdmin ? targetScopeID?.trim().toLowerCase() ?? '' : scopeID

  const send = (attempt: { input: BatchCreateStreamsRequest; key: string }) => {
    if (!currentPrincipalCanManageStreams(scopeKind, scopeID, sessionEpoch)) return
    setBusy(true)
    setFailure(null)
    streamsApi.batchCreate(useSessionStore.getState().accessToken ?? '', attempt.input, attempt.key).then((response) => {
      recovery.settle(attempt, false)
      setResult(response)
      if (response.committed) onCreated(response)
    }, (error: unknown) => {
      recovery.settle(attempt, writeOutcomeUnknown(error))
      setFailure(error instanceof ApiError ? error : new ApiError(t('errors.operationFailed')))
    }).finally(() => setBusy(false))
  }

  const submit = () => unknown ? send(unknown) : void form.validateFields().then((values) => {
    if (!currentPrincipalCanManageStreams(scopeKind, scopeID, sessionEpoch) || !defaultsReady) return
    // 各行共用字段；监听与源站由每行给出。域名源站用默认 DNS 缓存策略，IP 源站服务端会忽略。
    const template: StreamFields = {
      name: '', remark: values.remark?.trim() ?? '', protocol: defaults.protocol, listen_address: '*', listen_port: 0,
      upstream_address: '', upstream_host: '', upstream_port: 0, dns_policy: defaultDomainDNSPolicy(), geo_policy: emptyGeoPolicy(),
      connect_timeout_ms: 3000, response_timeout_ms: 30000, max_connections_per_client: 100,
      proxy_protocol_inbound: false, proxy_protocol_v1: false, balance_way: defaults.balance_way, enabled: true,
      tls_passthrough: false, server_names: [], max_new_connections_per_client_per_second: 0, new_connection_burst: 0,
      new_connection_ban_seconds: 0, toa: false, session_log_enabled: false,
    }
    send({ key: writeKey('batch-create-streams'), input: {
      ...(isAdmin ? { target_scope_id: values.target_scope_id?.trim(), owner_id: values.owner_id?.trim() } : {}),
      group_ids: values.group_ids ?? [], template, lines: batchLines(values.lines_text), ignore_errors: Boolean(values.ignore_errors),
    } })
  }, () => setAdvancedOpen(true))

  const lineStatus = (status: 'created' | 'failed' | 'skipped', code?: string) => status === 'failed'
    ? t('batchCreate.lineFailed', { reason: t(`errors.${code ?? 'operationFailed'}`, { defaultValue: t('errors.unknownCode', { code }) }) })
    : t(`batchCreate.line_${status}`)

  return (
    <Form form={form} layout="horizontal" labelCol={{ flex: '110px' }} wrapperCol={{ flex: 1 }} labelWrap requiredMark={false}
      disabled={Boolean(unknown)}
      initialValues={unknown ? {
        owner_id: unknown.input.owner_id, target_scope_id: unknown.input.target_scope_id,
        lines_text: unknown.input.lines.join('\n'), ignore_errors: unknown.input.ignore_errors, group_ids: unknown.input.group_ids, remark: unknown.input.template.remark,
      } : { lines_text: '', ignore_errors: false, group_ids: [], remark: '' }}
      onValuesChange={(changed) => {
        setResult(null)
        if ('target_scope_id' in changed) form.setFieldsValue({ group_ids: [] })
      }}>
      {isAdmin ? <>
        <Form.Item name="target_scope_id" hidden><Input /></Form.Item>
        <Form.Item name="owner_id" label={t('form.ownerSelect')} rules={[{ required: true, message: t('form.ownerSelectRequired') }]}>
          <StreamOwnerSelect scopeKind={scopeKind} scopeID={scopeID} sessionEpoch={sessionEpoch}
            onPick={(user) => form.setFieldsValue({ owner_id: user?.id, target_scope_id: user?.scope_id ?? '', group_ids: [] })} />
        </Form.Item>
      </> : null}
      <Form.Item name="lines_text" label={t('batchCreate.lines')} rules={[{
        validator: (_, value: string) => {
          const lines = batchLines(value)
          if (lines.length === 0) return Promise.reject(new Error(t('batchCreate.linesRequired')))
          if (lines.length > 200) return Promise.reject(new Error(t('batchCreate.linesTooMany')))
          const bad = lines.findIndex((line) => line.split('|').length !== 3)
          return bad >= 0 ? Promise.reject(new Error(t('batchCreate.lineFormat', { line: bad + 1 }))) : Promise.resolve()
        },
      }]}>
        <Input.TextArea aria-label={t('batchCreate.lines')} autoSize={{ minRows: 4, maxRows: 12 }} placeholder={t('batchCreate.linesPlaceholder')} />
      </Form.Item>
      <p className="stream-batch-defaults" aria-live="polite">{t('batchCreate.defaultsHint', {
        protocol: defaults.protocol.toUpperCase(),
        balance: t(defaults.balance_way === 'ip_hash' ? 'detail.ipHash' : 'detail.roundRobin'),
      })}</p>
      <Form.Item label={t('batchCreate.ignoreErrors')} extra={t('batchCreate.ignoreErrorsHint')}>
        <Form.Item name="ignore_errors" valuePropName="checked" noStyle><Switch aria-label={t('batchCreate.ignoreErrors')} /></Form.Item>
      </Form.Item>
      <div className="stream-advanced-divider">
        <button className="stream-advanced-toggle" type="button" aria-expanded={advancedOpen} onClick={() => setAdvancedOpen((value) => !value)}>
          {t('form.expandMore')} <ChevronDown size={14} aria-hidden="true" className={advancedOpen ? 'is-open' : undefined} />
        </button>
      </div>
      <div hidden={!advancedOpen}>
        <Form.Item name="group_ids" label={t('form.group')}>
          <StreamGroupSelect open scopeKind={scopeKind} scopeID={scopeID} sessionEpoch={sessionEpoch} targetScopeID={createScopeID} groups={[]} />
        </Form.Item>
        <Form.Item name="remark" label={t('form.remark')} rules={[{ max: 256, message: t('form.remarkTooLong') }]}>
          <Input placeholder={t('form.remarkPlaceholder')} />
        </Form.Item>
      </div>
      {unknown ? <Alert className="stream-batch-alert" type="warning" showIcon role="alert" message={t('batchCreate.unknown')} />
        : failure ? <Alert className="stream-batch-alert" type="error" showIcon message={errorMessage(failure, t)} /> : null}
      {result ? <div className="stream-batch-result" role="status">
        <Alert type={result.committed ? (result.failed ? 'warning' : 'success') : 'error'} showIcon
          message={result.committed ? t('batchCreate.committed', { created: result.created, failed: result.failed }) : t('batchCreate.rolledBack')} />
        <ol>
          {result.items.map((item) => <li key={item.line} className={`is-${item.status}`}>
            <code>{item.text}</code> <span>{lineStatus(item.status, item.error?.code)}</span>
          </li>)}
        </ol>
      </div> : null}
      <div className="ant-modal-footer stream-batch-footer">
        <Button type="primary" loading={busy || (!unknown && !defaultsReady)} disabled={disabled || busy || (!unknown && !defaultsReady)} onClick={submit}>{t('form.confirm')}</Button>
        <Button onClick={onCancel} disabled={busy}>{t('actions.cancel')}</Button>
      </div>
    </Form>
  )
}
