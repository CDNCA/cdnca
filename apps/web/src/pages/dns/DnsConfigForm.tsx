import { useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Form, Input, Modal, Select, Switch } from 'antd'
import { useFeedbackMessage, useFeedback, FeedbackWhen, fieldReasonText, submitErrorFields } from '@cdnca/ui'
import { Check, PlugZap, Trash2, Wrench } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'

import { ApiError } from '../../api/auth'
import { dnsProviderSplitsCarrierLines, dnsProviderWritesWeights } from '../../api/dns'
import { dnsPlatformApi, type PlatformDNSConfig, type PlatformDNSOperation } from '../../api/dnsPlatform'
import { pluginProvidersApi, usableDNSPlugins } from '../../api/pluginProviders'
import '../../i18n/dnsConfig'
import {
  dnsComPlanLineHint, dnsComPlanOf, dnsComPlans, dnsConfigCredentials, huaweiRegions, pluginChoice, pluginChoicePrefix, pluginCredentials, providerChoices, providerSpecs,
  validTTL, type ProviderChoice,
} from './dnsProviderSpecs'
import DnsErrorStatus from './DnsErrorStatus'

const newKey = (action: string) => `dns-config-${action}-${crypto.randomUUID()}`

interface Fields { identifier: string; secret: string; region: string; projectID: string; plan: string; ttl: string; weight: boolean }

function fieldsFrom(config: PlatformDNSConfig | undefined, type: ProviderChoice): Fields {
  const same = config?.provider_type === type
  const identifier = providerSpecs[type].identifier
  return {
    identifier: same && identifier ? config?.identifiers[identifier] ?? '' : '', secret: '',
    region: (same && config?.identifiers.region) || huaweiRegions[0], projectID: (same && config?.identifiers.project_id) || '',
    plan: dnsComPlanOf(same ? config?.identifiers.plan : undefined),
    ttl: String(config?.ttl ?? 600), weight: config?.ip_weight ?? false,
  }
}

// The form box a refused save field is shown under (fix-fielderr-be3).
type RefusedBox = 'provider' | 'secret' | 'ttl'
const refusedBoxes: Record<string, RefusedBox> = { provider_type: 'provider', credentials: 'secret', ttl: 'ttl' }

export default function DnsConfigForm({ accessToken, owner, canManage }: { accessToken: string; owner: string[]; canManage: boolean }) {
  const { t, i18n } = useTranslation('dnsConfig')
  const queryClient = useQueryClient()
  const [messageApi, messageContext] = useFeedbackMessage()
  const feedback = useFeedback()
  const [modal, modalContext] = Modal.useModal()
  const queryKey = ['dns-platform-config', ...owner]
  const configQuery = useQuery({ queryKey, queryFn: () => dnsPlatformApi.config(accessToken), retry: false })
  const config = configQuery.data
  // Third-party DNS plugins that passed their contract and are enabled.
  const pluginsQuery = useQuery({ queryKey: ['plugin-providers', ...owner], queryFn: () => pluginProvidersApi.list(accessToken),
    retry: false, enabled: canManage })
  const dnsPlugins = usableDNSPlugins(pluginsQuery.data ?? [])
  const savedChoice = config?.provider_type === 'plugin' && config.identifiers.plugin_id
    ? pluginChoice(config.identifiers.plugin_id) : config?.provider_type
  const [choice, setChoice] = useState<string | null>(null)
  const selected = choice ?? savedChoice ?? 'aliyun'
  const type: ProviderChoice = selected.startsWith(pluginChoicePrefix) ? 'plugin' : selected as ProviderChoice
  const spec = providerSpecs[type]
  const [edited, setEdited] = useState<Partial<Fields>>({})
  const fields = { ...fieldsFrom(config, type), ...edited }
  const keys = useRef<Record<string, string>>({})
  // NET-UX-2: the tasks the last repair/cleanup created, linked to 后台任务.
  const [queued, setQueued] = useState<PlatformDNSOperation[]>([])
  const keyFor = (action: string) => (keys.current[action] ??= newKey(action))
  // 连接测试 result for the fields as entered; any edit makes it stale, and a
  // result that arrives after an edit is dropped (draftEpoch).
  const [connection, setConnection] = useState<{ ok: boolean; text: string } | null>(null)
  const draftEpoch = useRef(0)
  // A refused save field, shown under its box until the next edit.
  const [refused, setRefused] = useState<{ box: RefusedBox; help: string } | null>(null)
  const edit = (patch: Partial<Fields>) => {
    delete keys.current.save; draftEpoch.current++; setConnection(null); setRefused(null); setEdited((value) => ({ ...value, ...patch }))
  }
  const refusedStatus = (box: RefusedBox) => refused?.box === box ? { validateStatus: 'error' as const, help: refused.help } : {}
  // DNS维护 P2-1（审测卡 10）：记录修复/清除只用已保存配置；有未保存的修改时先问。
  const dirty = choice !== null || Object.keys(edited).length > 0
  const discardDraft = () => { draftEpoch.current++; delete keys.current.save; setEdited({}); setChoice(null); setConnection(null); setRefused(null) }
  const [idLabel, secretLabel] = spec.labels
  const failure = (fallback: string, cause: unknown) => {
    const code = cause instanceof ApiError ? cause.code : ''
    return t(`errors.codes.${code}`, { defaultValue: '' }) || `${fallback}${code ? ` (${code})` : ''}`
  }

  // The saved credentials apply only to the same provider with the same identifiers.
  const unchanged = config?.provider_type === type && config.secret_saved &&
    (!spec.identifier || fields.identifier.trim() === (config.identifiers[spec.identifier] ?? '')) &&
    (type !== 'huawei' || (fields.region === config.identifiers.region && fields.projectID.trim() === config.identifiers.project_id)) &&
    (type !== 'dns_com' || fields.plan === dnsComPlanOf(config.identifiers.plan))
  const validate = (): string | null => {
    if (type === 'plugin') {
      if (!pluginCredentials(selected)) return t('errors.pluginRequired')
      return validTTL(type, fields.ttl) ? null : t('errors.ttlRange', { min: spec.minTTL, max: spec.maxTTL })
    }
    if (spec.identifier && !fields.identifier.trim()) return t('errors.identifierRequired', { label: idLabel })
    if (type === 'huawei' && !/^[a-f0-9]{32}$/.test(fields.projectID.trim())) return t('errors.projectRequired')
    if (!validTTL(type, fields.ttl)) return t('errors.ttlRange', { min: spec.minTTL, max: spec.maxTTL })
    if (!fields.secret.trim() && !unchanged) {
      return config?.secret_saved ? t('errors.secretNeeded', { label: secretLabel }) : t('errors.secretRequired', { label: secretLabel })
    }
    return null
  }
  const saveMutation = useMutation({
    mutationKey: ['dns-platform-config-write', ...owner],
    mutationFn: () => {
      const credentials = type === 'plugin' ? pluginCredentials(selected)
        : fields.secret.trim() ? dnsConfigCredentials(type, fields) : null
      return dnsPlatformApi.save(accessToken, { provider_type: type, ...(credentials ? { credentials } : {}),
        ttl: Number(fields.ttl), ip_weight: fields.weight && dnsProviderWritesWeights(type) }, config!.version, keyFor('save'))
    },
    onSuccess: (value) => {
      delete keys.current.save
      draftEpoch.current++
      setEdited({}); setChoice(null)
      queryClient.setQueryData(queryKey, value)
      messageApi.success(t('messages.saved'))
    },
    onError: (cause) => {
      const field = submitErrorFields(cause)[0]
      const box = field ? refusedBoxes[field.field] : undefined
      if (field && box && (box !== 'secret' || type !== 'plugin')) {
        const locale = i18n.resolvedLanguage === 'en-US' ? 'en' : i18n.resolvedLanguage === 'zh-TW' ? 'zh-tw' : 'zh-cn'
        setRefused({ box, help: fieldReasonText(field.reason, locale) })
        return
      }
      feedback.error(failure(t('errors.saveFailed'), cause))
    },
  })
  const operation = useMutation({
    mutationFn: (kind: 'repair' | 'cleanup') => dnsPlatformApi.start(accessToken, kind, keyFor(kind)),
    onSuccess: (result, kind) => {
      delete keys.current[kind]
      setQueued(result.operations ?? [])
      messageApi.success(t(kind === 'repair' ? 'messages.repairQueued' : 'messages.cleanupQueued'))
      void queryClient.invalidateQueries({ queryKey })
    },
    onError: (cause, kind) => feedback.error(failure(t(kind === 'repair' ? 'errors.repairFailed' : 'errors.cleanupFailed'), cause)),
  })
  // 连接测试: the entered credentials, or the saved ones when the secret is
  // left blank. Read-only: nothing is saved and no record is written.
  const testMutation = useMutation({
    mutationFn: ({ credentials }: { credentials: Record<string, string> | null; epoch: number }) =>
      dnsPlatformApi.testConnection(accessToken, { provider_type: type, ...(credentials ? { credentials } : {}) }),
    onSuccess: (result, { epoch }) => {
      if (epoch !== draftEpoch.current) return // the input changed since
      const missing = result.zones.filter((zone) => zone.status === 'not_hosted').map((zone) => zone.name)
      const hosted = result.zones.filter((zone) => zone.status === 'hosted').map((zone) => zone.name)
      const text = missing.length > 0 ? t('connection.notHosted', { names: missing.join('、') })
        : result.zones.length === 0 ? t('connection.noZones')
          : hosted.length === result.zones.length ? t('connection.hosted', { names: hosted.join('、') }) : t('connection.unchecked')
      setConnection({ ok: missing.length === 0, text })
    },
    onError: (cause, { epoch }) => {
      if (epoch !== draftEpoch.current) return
      setConnection({ ok: false, text: t('connection.failed', { reason: failure(t('errors.saveFailed'), cause) }) })
    },
  })
  const testConnection = () => {
    if (type === 'plugin') {
      const credentials = pluginCredentials(selected)
      if (!credentials) { setConnection({ ok: false, text: t('errors.pluginRequired') }); return }
      testMutation.mutate({ credentials, epoch: draftEpoch.current }); return
    }
    if (spec.identifier && !fields.identifier.trim()) { setConnection({ ok: false, text: t('errors.identifierRequired', { label: idLabel }) }); return }
    if (type === 'huawei' && !/^[a-f0-9]{32}$/.test(fields.projectID.trim())) { setConnection({ ok: false, text: t('errors.projectRequired') }); return }
    if (fields.secret.trim()) testMutation.mutate({ credentials: dnsConfigCredentials(type, fields), epoch: draftEpoch.current })
    else if (unchanged) testMutation.mutate({ credentials: null, epoch: draftEpoch.current })
    else setConnection({ ok: false, text: t('connection.noSaved', { label: secretLabel }) })
  }
  const save = (then?: () => void) => {
    const problem = validate()
    if (problem) { feedback.error(problem); return }
    // A failed save runs nothing after it.
    saveMutation.mutate(undefined, then ? { onSuccess: then } : undefined)
  }
  const confirmCleanup = () => void modal.confirm({
    title: t('actions.cleanup'), content: t('messages.cleanupConfirm'), okText: t('actions.ok'), cancelText: t('actions.cancel'),
    onOk: () => operation.mutate('cleanup'),
  })
  const runMaintenance = (kind: 'repair' | 'cleanup') => {
    const run = kind === 'repair' ? () => operation.mutate('repair') : confirmCleanup
    if (!dirty) { run(); return }
    const dialog = modal.confirm({
      title: t(kind === 'repair' ? 'actions.repair' : 'actions.cleanup'), content: t('draft.maintenancePrompt'),
      footer: <div className="dns-draft-choices">
        <Button onClick={() => dialog.destroy()}>{t('actions.cancel')}</Button>
        <Button onClick={() => { dialog.destroy(); discardDraft(); run() }}>{t('draft.discardThenRun')}</Button>
        <Button type="primary" onClick={() => { dialog.destroy(); save(run) }}>{t('draft.saveThenRun')}</Button>
      </div>,
    })
  }
  // C11/X13-b: nothing is written before a first successful read; the provider
  // defaults below are only placeholders until then. A failed background
  // refresh keeps the last snapshot (and its version) usable.
  const disabled = !canManage || !config
  // One write at a time for this configuration: save, test and maintenance
  // share the gate (the server's version check stays).
  const busy = saveMutation.isPending || testMutation.isPending || operation.isPending
  const carrierLines = dnsProviderSplitsCarrierLines(type)
  // Weights are a separate capability (only DNSPod writes them).
  const weights = dnsProviderWritesWeights(type)
  const configured = Boolean(config?.provider_type)
  const enter = (label: string) => t('placeholders.enter', { label })

  return <div className="dns-config-panel">
    {messageContext}{modalContext}
    {configQuery.isError ? <FeedbackWhen title={config ? t('errors.refreshFailed') : t('errors.loadFailedNoWrite')} action={<Button size="small" onClick={() => void configQuery.refetch()}>{t('actions.retry')}</Button>} /> : null}
    {configQuery.isPending ? <Alert className="identity-alert" type="info" showIcon message={t('hints.loading')} /> : null}
    {!canManage ? <Alert className="identity-alert" type="info" showIcon message={t('hints.readOnly')} /> : null}
    {queued.length > 0 ? <Alert className="identity-alert" type="success" showIcon closable onClose={() => setQueued([])}
      message={t('messages.operationsQueued', { count: queued.length, subject: queued[0].subject,
        ids: queued.map((item) => item.id).join('、') })}
      action={<Link to={queued.length === 1 ? `/sys/task?task_id=${encodeURIComponent(queued[0].id)}`
        : `/sys/task?resource_id=${encodeURIComponent(queued[0].subject)}`}>{t('messages.viewTasks')}</Link>} /> : null}
    <Form className="dns-config-form" labelCol={{ flex: '112px' }} labelAlign="right" colon={false} requiredMark={false}>
      <Form.Item label={t('fields.provider')} className="dns-field-provider" {...refusedStatus('provider')}
        extra={!spec.supported ? <span className="dns-field-warning">{t('hints.dnspodIntl')}</span>
          : !carrierLines ? <span className="dns-field-warning" role="note">{t('hints.linesUnsupported')}</span>
            : <span className="dns-field-note">{t(`hints.lines.${spec.lines === 'plan'
              ? dnsComPlanLineHint(dnsComPlanOf(fields.plan)) : spec.lines}`)}</span>}>
        <Select aria-label={t('fields.provider')} value={selected} disabled={disabled} virtual={false}
          options={[
            { label: t('groups.official'), options: providerChoices.filter((value) => value !== 'plugin')
              .map((value) => ({ value, label: t(`providers.${value}`) })) },
            ...(dnsPlugins.length > 0 ? [{ label: t('groups.thirdParty'), options: dnsPlugins.map((plugin) => ({
              value: pluginChoice(plugin.plugin_id), label: t('providers.plugin', { id: plugin.plugin_id, version: plugin.version }) })) }] : []),
          ]}
          onChange={(value: string) => {
            setChoice(value)
            draftEpoch.current++
            setConnection(null)
            setRefused(null)
            // Keep only what was edited (an absent field falls back to the saved value).
            setEdited((current) => ({ ...(current.ttl !== undefined ? { ttl: current.ttl } : {}),
              ...(current.weight !== undefined ? { weight: current.weight } : {}) }))
          }} />
      </Form.Item>
      {spec.identifier ? <Form.Item label={idLabel} className="dns-field-wide">
        <Input aria-label={idLabel} value={fields.identifier} disabled={disabled || !spec.supported} autoComplete="off"
          placeholder={enter(idLabel)} onChange={(event) => edit({ identifier: event.target.value })} />
      </Form.Item> : null}
      {type === 'plugin' ? <Alert className="identity-alert" type="info" showIcon message={t('hints.plugin')} /> : null}
      {type !== 'plugin' ? <Form.Item label={secretLabel} className="dns-field-wide" {...refusedStatus('secret')} extra={type === 'cloudflare' ? t('hints.cloudflareToken') : type === 'namecom' ? t('hints.nameComToken') : type === 'custom_http' ? t('hints.customHTTP') : undefined}>
        <Input.Password aria-label={secretLabel} value={fields.secret} disabled={disabled || !spec.supported} autoComplete="new-password"
          placeholder={config?.secret_saved && config.provider_type === type ? t('placeholders.secretKept') : enter(secretLabel)}
          onChange={(event) => edit({ secret: event.target.value })} />
      </Form.Item> : null}
      {type === 'huawei' ? <>
        <Form.Item label={t('fields.region')} className="dns-field-provider">
          <Select aria-label={t('fields.region')} value={fields.region} disabled={disabled}
            options={huaweiRegions.map((value) => ({ value, label: value }))} onChange={(value: string) => edit({ region: value })} />
        </Form.Item>
        <Form.Item label={t('fields.projectID')} className="dns-field-wide">
          <Input aria-label={t('fields.projectID')} value={fields.projectID} disabled={disabled} autoComplete="off"
            placeholder={enter(t('fields.projectID'))} onChange={(event) => edit({ projectID: event.target.value })} />
        </Form.Item>
      </> : null}
      {type === 'dns_com' ? <Form.Item label={t('fields.dnsComPlan')} className="dns-field-provider" extra={t('hints.dnsComPlan')}>
        <Select aria-label={t('fields.dnsComPlan')} value={dnsComPlanOf(fields.plan)} disabled={disabled}
          options={dnsComPlans.map((value) => ({ value, label: t(`dnsComPlans.${value}`) }))}
          onChange={(value: string) => edit({ plan: value })} />
      </Form.Item> : null}
      <Form.Item label={t('fields.ttl')} className="dns-field-ttl" {...refusedStatus('ttl')}>
        <Input aria-label={t('fields.ttl')} value={fields.ttl} disabled={disabled} inputMode="numeric" placeholder={t('placeholders.ttl')}
          addonAfter={t('units.seconds')} onChange={(event) => edit({ ttl: event.target.value })} />
      </Form.Item>
      <Form.Item label={t('fields.ipWeight')}>
        <Switch aria-label={t('fields.ipWeight')} checked={fields.weight && weights} disabled={disabled || !weights}
          onChange={(weight) => edit({ weight })} />
        <span className="dns-field-note">{weights ? t('hints.weightSupported') : t('hints.weightUnsupported')}</span>
      </Form.Item>
      <Form.Item label={t('fields.dnsError')}>
        {config ? <DnsErrorStatus error={config.last_error ?? null} />
          : <span className="dns-status is-unknown" role="status">{t('status.unread')}</span>}
      </Form.Item>
      <Form.Item label=" " className="dns-config-actions">
        <Button type="primary" icon={<Check size={14} />} loading={saveMutation.isPending} disabled={disabled || !spec.supported || busy}
          onClick={() => save()}>{t('actions.save')}</Button>
        <Button icon={<PlugZap size={14} />} loading={testMutation.isPending} disabled={disabled || !spec.supported || busy}
          title={t('connection.readOnly')} onClick={testConnection}>{t('actions.test')}</Button>
        <Button icon={<Wrench size={14} />} loading={operation.isPending && operation.variables === 'repair'}
          disabled={disabled || !configured || busy} onClick={() => runMaintenance('repair')}>{t('actions.repair')}</Button>
        <Button className="dns-button-warning" icon={<Trash2 size={14} />}
          loading={operation.isPending && operation.variables === 'cleanup'} disabled={disabled || !configured || busy}
          onClick={() => runMaintenance('cleanup')}>{t('actions.cleanup')}</Button>
        <span className="dns-field-note dns-config-scope">
          {dirty ? t('draft.unsavedNote') : t('draft.scopeNote')}
        </span>
      </Form.Item>
      {testMutation.isPending || connection ? <Form.Item label=" " className="dns-config-connection">
        <span className={`dns-status ${testMutation.isPending ? '' : connection?.ok ? 'is-ok' : 'is-error'}`} role="status" aria-live="polite">
          <i aria-hidden="true" />{testMutation.isPending ? t('connection.testing') : connection?.text}
        </span>
      </Form.Item> : null}
    </Form>
  </div>
}
