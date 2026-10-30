import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  Button,
  Checkbox,
  Dropdown,
  Empty,
  Form,
  Input,
  InputNumber,
  Radio,
  Result,
  Select,
  Space,
  Spin,
  Switch,
  Tabs,
  type FormInstance,
  type FormRule,
} from 'antd'
import { useFeedbackMessage, FeedbackWhen, OutcomeUnknown } from '@cdnca/ui'
import { ChevronDown, RefreshCw, RotateCcw, Save, Trash2 } from 'lucide-react'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'

import { ApiError, type Principal } from '../api/auth'
import { securityPoliciesApi } from '../api/securityPolicies'
import {
  newSystemConfigurationIdempotencyKey,
  newSystemConfigurationRequestId,
  systemConfigurationApi,
  type DefaultConfiguration,
  type NginxConfiguration,
  type ResourceConfiguration,
  type SystemConfigurationDocument,
  type SystemConfigurationWriteValueMap,
} from '../api/systemConfiguration'
import { useSessionStore } from '../auth/session'
import AcmeCACredentialsCard from './system-settings/AcmeCACredentialsCard'
import ConfigurationOverridesEditor from './system-settings/ConfigurationOverridesEditor'
import { CategoryScopeNotice, PendingCategoriesNotice } from './system-settings/PendingCategories'
import {
  formatByteSize,
  formatDuration,
  formatHeaderBuffers,
  parseByteSize,
  parseDuration,
  parseHeaderBuffers,
} from './system-settings/nginxDirectiveValues'
import '../i18n/systemSettings'
import './SystemSettingsPage.css'

type EditableCategory = 'nginx' | 'resources' | 'defaults'
type SystemConfigurationPermission = 'system_configuration.read' | 'system_configuration.manage'
type SystemSettingsOwner = readonly [Principal['scope_kind'], string, string | null, string, number]
type FieldName = Array<string | number>
type SettingsFormValues = {
  nginx?: NginxConfiguration
  resources?: ResourceConfiguration
  defaults?: DefaultConfiguration
}
type SaveAttempt = { ownerKey: string } & {
  [C in EditableCategory]: {
    category: C
    value: SystemConfigurationWriteValueMap[C]
    expectedHeadRevision: number
    idempotencyKey: string
    requestId: string
  }
}[EditableCategory]

type ArrayControlProps<T> = {
  value?: T
  disabled?: boolean
  onChange?: (value: T) => void
  'aria-label'?: string
}

type PortRange = { from: number; to: number }

const staleSystemSettingsAttempt = new Error('stale system settings attempt')
const recommendedCipherSuites = 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305'
const legacyTls12CipherSuites = `${recommendedCipherSuites}:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA`
const tlsProtocols = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']
const wafModuleNames = ['sqli', 'xss', 'upload', 'fi', 'cmdi', 'java', 'jdeser', 'php', 'phpdeser', 'ssti'] as const
const wafModuleModes = ['off', 'detect', 'on'] as const
const loadBalancingValues = ['round_robin', 'ip_hash', 'url_hash', 'least_conn', 'random'] as const
type WafModuleMode = (typeof wafModuleModes)[number]

function systemSettingsOwner(principal: Principal, sessionEpoch: number): SystemSettingsOwner | null {
  if (!principal.scope_id || !principal.user_id || !sessionEpoch) return null
  if (principal.scope_kind === 'platform' && principal.tenant_id !== null) return null
  return [principal.scope_kind, principal.scope_id, principal.tenant_id, principal.user_id, sessionEpoch]
}

function systemSettingsPrincipalCan(principal: Principal, permission: SystemConfigurationPermission): boolean {
  return principal.scope_kind === 'platform' && (
    principal.permissions.includes(permission) || principal.permissions.includes('platform.admin')
  )
}

function currentSystemSettingsAccess(ownerKey: string, requireManage = false): string | null {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (
    !accessToken ||
    !principal ||
    !systemSettingsPrincipalCan(principal, 'system_configuration.read') ||
    (requireManage && !systemSettingsPrincipalCan(principal, 'system_configuration.manage'))
  ) return null
  const owner = systemSettingsOwner(principal, sessionEpoch)
  return owner && JSON.stringify(owner) === ownerKey ? accessToken : null
}

function cloneValue<T>(value: T): T {
  return typeof structuredClone === 'function'
    ? structuredClone(value)
    : JSON.parse(JSON.stringify(value)) as T
}

function formValues(document: SystemConfigurationDocument<EditableCategory>): SettingsFormValues {
  return { [document.category]: cloneValue(document.value) } as SettingsFormValues
}

function normalizeWriteValue(category: EditableCategory, values: SettingsFormValues): SaveAttempt['value'] {
  if (category === 'nginx') {
    const value = cloneValue(values.nginx!)
    value.worker.logs_dir = value.worker.logs_dir.trim()
    value.http.server = value.http.server.trim()
    value.http.default_type = value.http.default_type.trim()
    return value
  }
  if (category === 'resources') {
    const value = cloneValue(values.resources!)
    value.site.access_log_tmp_dir = value.site.access_log_tmp_dir.trim()
    return value
  }
  const value = cloneValue(values.defaults!)
  value.website.https.ssl.cipher_suites = value.website.https.ssl.cipher_suites.trim()
  value.website.other.gzip_types = value.website.other.gzip_types.map((item) => item.trim())
  value.website.security.default_cc_policy_id = value.website.security.default_cc_policy_id?.trim() || null
  value.website.cache_rules = value.website.cache_rules.map((item, position) => ({ ...item, position }))
  value.website.origin_request_headers = value.website.origin_request_headers.map((item, position) => ({
    ...item,
    name: item.name.trim(),
    value: item.action === 'delete' ? null : (item.value?.trim() ?? ''),
    position,
  }))
  return value
}

function performSave(accessToken: string, attempt: SaveAttempt): Promise<SystemConfigurationDocument<EditableCategory>> {
  switch (attempt.category) {
    case 'nginx':
      return systemConfigurationApi.put(accessToken, attempt.category, attempt.value, attempt.expectedHeadRevision, attempt.idempotencyKey, attempt.requestId)
    case 'resources':
      return systemConfigurationApi.put(accessToken, attempt.category, attempt.value, attempt.expectedHeadRevision, attempt.idempotencyKey, attempt.requestId)
    case 'defaults':
      return systemConfigurationApi.put(accessToken, attempt.category, attempt.value, attempt.expectedHeadRevision, attempt.idempotencyKey, attempt.requestId)
  }
}

function isUnknownWriteOutcome(error: unknown): boolean {
  return !(error instanceof ApiError) || error.status === 0 || error.status === 408 || error.status === 429 || error.status >= 500
}

function errorText(error: unknown, t: TFunction<'systemSettings'>): string {
  const code = error instanceof ApiError ? error.code : 'request_failed'
  const known = new Set([
    'invalid_session', 'system_configuration_unauthenticated', 'system_configuration_validation_error',
    'system_configuration_permission_denied', 'system_configuration_active_not_found',
    'system_configuration_revision_conflict', 'system_configuration_idempotency_conflict',
    'system_configuration_entitlement_denied', 'system_configuration_unavailable',
    'active_not_found', 'revision_conflict', 'idempotency_conflict', 'entitlement_denied',
    'validation_error', 'internal_error', 'invalid_response', 'network_error', 'request_failed',
  ])
  const text = t(known.has(code) ? `errors.${code}` : 'errors.request_failed')
  return error instanceof ApiError && error.requestId
    ? t('errors.withRequestId', { message: text, requestId: error.requestId })
    : text
}

function integerRules(t: TFunction<'systemSettings'>, minimum: number, maximum: number): FormRule[] {
  return [{ required: true, type: 'integer', min: minimum, max: maximum, message: t('validation.integerRange', { minimum, maximum }) }]
}

function SectionIntro({ title, description }: { title: string; description: string }) {
  return <div className="configuration-section-intro">
    <h2>{title}</h2>
    <p>{description}</p>
  </div>
}

function ConfigCard({ title, description, action, wide = false, children }: {
  title: string
  description: string
  action?: ReactNode
  wide?: boolean
  children: ReactNode
}) {
  return <section className={`configuration-card${wide ? ' configuration-card--wide' : ''}`}>
    <header className="configuration-card-header">
      <div><h3>{title}</h3><p>{description}</p></div>
      {action}
    </header>
    <div className="configuration-card-body">{children}</div>
  </section>
}

function NumberControl({ value, disabled, onChange, label, minimum, maximum, suffix, clampMaximum = true }: {
  value?: number | null
  disabled?: boolean
  onChange?: (value: number | null) => void
  label: string
  minimum: number
  maximum: number
  suffix?: string
  clampMaximum?: boolean
}) {
  const input = <InputNumber
    aria-label={label}
    value={value}
    disabled={disabled}
    min={minimum}
    max={clampMaximum ? maximum : undefined}
    precision={0}
    onChange={onChange}
  />
  return suffix ? <Space.Compact className="configuration-number-control">
    {input}
    <span className="configuration-number-control-unit">{suffix}</span>
  </Space.Compact> : input
}

function NumberField({ name, label, t, minimum = 0, maximum = Number.MAX_SAFE_INTEGER, suffix, extra, clampMaximum }: {
  name: FieldName
  label: string
  t: TFunction<'systemSettings'>
  minimum?: number
  maximum?: number
  suffix?: string
  extra?: ReactNode
  clampMaximum?: boolean
}) {
  return <Form.Item className="configuration-field" name={name} label={label} rules={integerRules(t, minimum, maximum)} extra={extra}>
    <NumberControl label={label} minimum={minimum} maximum={maximum} suffix={suffix} clampMaximum={clampMaximum} />
  </Form.Item>
}

function parseIntegerDirective(value: string, minimum: number, maximum: number, allowAuto: boolean): number | null {
  const normalized = value.trim().toLowerCase()
  if (allowAuto && normalized === 'auto') return 0
  const parsed = Number(normalized)
  return Number.isInteger(parsed) && parsed >= minimum && parsed <= maximum ? parsed : null
}

function DirectiveTextControl<T>({ value, disabled, onChange, label, format, parse }: {
  value?: T
  disabled?: boolean
  onChange?: (value: T) => void
  label: string
  format: (value: T) => string
  parse: (value: string) => T | null
}) {
  const formatted = value === undefined ? '' : format(value)
  const [draft, setDraft] = useState(formatted)
  const [editing, setEditing] = useState(false)
  useEffect(() => {
    if (!editing) setDraft(formatted)
  }, [editing, formatted])
  const updateDraft = (next: string) => {
    setEditing(true)
    setDraft(next)
    const parsed = parse(next)
    if (parsed !== null) onChange?.(parsed)
  }
  const commit = () => {
    const parsed = parse(draft)
    setEditing(false)
    if (parsed === null) {
      setDraft(formatted)
      return
    }
    onChange?.(parsed)
    setDraft(format(parsed))
  }
  return <Input aria-label={label} value={draft} disabled={disabled} onChange={(event) => updateDraft(event.target.value)} onBlur={commit} onPressEnter={commit} />
}

function DirectiveField<T>({ name, label, format, parse, extra }: {
  name: FieldName
  label: string
  format: (value: T) => string
  parse: (value: string) => T | null
  extra?: ReactNode
}) {
  return <Form.Item className="configuration-field" name={name} label={label} rules={[{ required: true }]} extra={extra}>
    <DirectiveTextControl label={label} format={format} parse={parse} />
  </Form.Item>
}

function NginxIntegerField({ name, label, minimum = 0, maximum = Number.MAX_SAFE_INTEGER, allowAuto = false }: {
  name: FieldName
  label: string
  minimum?: number
  maximum?: number
  allowAuto?: boolean
}) {
  return <DirectiveField<number>
    name={name}
    label={label}
    format={(value) => allowAuto && value === 0 ? 'auto' : String(value)}
    parse={(value) => parseIntegerDirective(value, minimum, maximum, allowAuto)}
  />
}

function NginxDurationField({ name, label, minimum, maximum }: { name: FieldName; label: string; minimum: number; maximum: number }) {
  return <DirectiveField<number> name={name} label={label} format={formatDuration} parse={(value) => parseDuration(value, minimum, maximum)} />
}

function NginxByteSizeField({ name, label, minimum = 0, maximum, extra }: { name: FieldName; label: string; minimum?: number; maximum: number; extra?: ReactNode }) {
  return <DirectiveField<number> name={name} label={label} format={formatByteSize} parse={(value) => parseByteSize(value, minimum, maximum)} extra={extra} />
}

function NginxHeaderBuffersField({ name, label }: { name: FieldName; label: string }) {
  return <DirectiveField<{ count: number; size_bytes: number }> name={name} label={label} format={formatHeaderBuffers} parse={parseHeaderBuffers} />
}

function TextField({ name, label, extra, maxLength = 4096, required = true }: { name: FieldName; label: string; extra?: ReactNode; maxLength?: number; required?: boolean }) {
  return <Form.Item className="configuration-field" name={name} label={label} rules={[{ required, whitespace: required, max: maxLength }]} extra={extra}>
    <Input aria-label={label} maxLength={maxLength} />
  </Form.Item>
}

function SwitchField({ name, label, extra }: { name: FieldName; label: string; extra?: ReactNode }) {
  return <Form.Item className="configuration-field configuration-field--switch" name={name} label={label} valuePropName="checked" extra={extra}>
    <Switch aria-label={label} />
  </Form.Item>
}

function SelectField({ name, label, options, mode, extra }: {
  name: FieldName
  label: string
  options: Array<{ value: string; label: string }>
  mode?: 'multiple' | 'tags'
  extra?: ReactNode
}) {
  return <Form.Item className="configuration-field" name={name} label={label} rules={[{ required: true }]} extra={extra}>
    <Select aria-label={label} mode={mode} options={options} virtual={false} tokenSeparators={[',', ' ']} classNames={{ popup: { root: 'configuration-select-popup' } }} />
  </Form.Item>
}

function WafModuleDropdownControl({ value = 'off', disabled, onChange, label, t }: {
  value?: WafModuleMode
  disabled?: boolean
  onChange?: (value: WafModuleMode) => void
  label: string
  t: TFunction<'systemSettings'>
}) {
  const mode = wafModuleModes.includes(value) ? value : 'off'
  const modeLabel = t(`parity.defaults.wafModes.${mode}`)
  return <Dropdown
    disabled={disabled}
    trigger={['click']}
    placement="bottom"
    overlayClassName="configuration-dropdown-popup configuration-waf-mode-popup"
    menu={{
      selectable: true,
      selectedKeys: [mode],
      items: wafModuleModes.map((item) => ({ key: item, label: t(`parity.defaults.wafModes.${item}`) })),
      onClick: ({ key }) => onChange?.(key as WafModuleMode),
    }}
  >
    <Button
      htmlType="button"
      aria-label={`${label}：${modeLabel}`}
      className={`configuration-waf-mode-button configuration-waf-mode-button--${mode}`}
      disabled={disabled}
    >
      <span className="configuration-waf-mode-content">
        <span>{modeLabel}</span>
        <ChevronDown className="configuration-waf-mode-chevron" size={14} strokeWidth={2} aria-hidden="true" />
      </span>
    </Button>
  </Dropdown>
}

function WafModuleField({ name, label, t }: { name: FieldName; label: string; t: TFunction<'systemSettings'> }) {
  return <Form.Item className="configuration-field configuration-field--waf-module" name={name} label={label} rules={[{ required: true }]}>
    <WafModuleDropdownControl label={label} t={t} />
  </Form.Item>
}

function NullableSelectControl({ value, disabled, loading, onChange, label, options }: {
  value?: string | null
  disabled?: boolean
  loading?: boolean
  onChange?: (value: string | null) => void
  label: string
  options: Array<{ value: string; label: string }>
}) {
  return <Select
    aria-label={label}
    value={value ?? '__off__'}
    disabled={disabled}
    loading={loading}
    options={options}
    virtual={false}
    onChange={(next) => onChange?.(next === '__off__' ? null : next)}
    classNames={{ popup: { root: 'configuration-select-popup' } }}
  />
}

function ProtocolCheckboxField({ name, label }: { name: FieldName; label: string }) {
  return <Form.Item className="configuration-field configuration-field--protocols" name={name} label={label} rules={[{ required: true, type: 'array', min: 1 }]}>
    <Checkbox.Group options={tlsProtocols.map((value) => ({ value, label: value }))} />
  </Form.Item>
}

function StringListControl({ value = [], disabled, onChange, 'aria-label': ariaLabel }: ArrayControlProps<string[]>) {
  const format = (items: string[]) => items.join(' ')
  const [draft, setDraft] = useState(() => format(value))
  useEffect(() => setDraft(format(value)), [value])
  const commit = () => onChange?.([...new Set(draft.split(/[\s,]+/u).map((item) => item.trim()).filter(Boolean))])
  return <Input aria-label={ariaLabel} value={draft} disabled={disabled} onChange={(event) => setDraft(event.target.value)} onBlur={commit} onPressEnter={commit} />
}

function StringListField({ name, label }: { name: FieldName; label: string }) {
  return <Form.Item className="configuration-field" name={name} label={label} rules={[{ required: true, type: 'array', min: 1 }]}>
    <StringListControl aria-label={label} />
  </Form.Item>
}

function NumberListControl({ value = [], disabled, onChange, 'aria-label': ariaLabel }: ArrayControlProps<number[]>) {
  const [draft, setDraft] = useState(() => value.join(', '))
  useEffect(() => setDraft(value.join(', ')), [value])
  const commit = () => {
    const parsed = draft.split(/[\s,]+/).filter(Boolean).map(Number)
    if (parsed.length > 0 && parsed.every((item) => Number.isInteger(item) && item >= 1 && item <= 65_535)) {
      onChange?.([...new Set(parsed)])
    }
  }
  return <Input aria-label={ariaLabel} value={draft} disabled={disabled} onChange={(event) => setDraft(event.target.value)} onBlur={commit} onPressEnter={commit} />
}

function PortRangesControl({ value = [], disabled, onChange, 'aria-label': ariaLabel }: ArrayControlProps<PortRange[]>) {
  const format = (ranges: PortRange[]) => ranges.map((item) => item.from === item.to ? String(item.from) : `${item.from}-${item.to}`).join(', ')
  const [draft, setDraft] = useState(() => format(value))
  useEffect(() => setDraft(format(value)), [value])
  const commit = () => {
    const parsed: PortRange[] = []
    for (const token of draft.split(/[\s,]+/).filter(Boolean)) {
      const match = token.match(/^(\d+)(?:-(\d+))?$/)
      if (!match) return
      const from = Number(match[1])
      const to = Number(match[2] ?? match[1])
      if (!Number.isInteger(from) || !Number.isInteger(to) || from < 1 || to > 65_535 || to < from) return
      parsed.push({ from, to })
    }
    parsed.sort((left, right) => left.from - right.from || left.to - right.to)
    if (parsed.some((item, index) => index > 0 && parsed[index - 1]!.to >= item.from)) return
    onChange?.(parsed)
  }
  return <Input aria-label={ariaLabel} value={draft} disabled={disabled} onChange={(event) => setDraft(event.target.value)} onBlur={commit} onPressEnter={commit} />
}

function NumberListField({ name, label, extra }: { name: FieldName; label: string; extra?: ReactNode }) {
  return <Form.Item className="configuration-field" name={name} label={label} rules={[{ required: true, type: 'array', min: 1 }]} extra={extra}>
    <NumberListControl aria-label={label} />
  </Form.Item>
}

function PortRangesField({ name, label, extra }: { name: FieldName; label: string; extra?: ReactNode }) {
  return <Form.Item className="configuration-field" name={name} label={label} extra={extra}>
    <PortRangesControl aria-label={label} />
  </Form.Item>
}

function NginxFields({ form, t, editable, onOverridesChange }: {
  form: FormInstance<SettingsFormValues>
  t: TFunction<'systemSettings'>
  editable: boolean
  onOverridesChange: () => void
}) {
  const [scope, setScope] = useState('global')
  const [tab, setTab] = useState('worker')
  const root = ['nginx']
  const http = [...root, 'http']
  return <>
    <Tabs className="configuration-scope-tabs" activeKey={scope} onChange={setScope} items={[
      { key: 'global', label: t('parity.tabs.global') },
      { key: 'regional', label: t('parity.tabs.regionNode') },
    ]} />
    {scope === 'regional' ? <ConfigurationOverridesEditor category="nginx" form={form} t={t} editable={editable} onChange={onOverridesChange} /> : <>
      <Tabs className="configuration-detail-tabs" activeKey={tab} onChange={setTab} items={[
        // 日志目录与 Stream 超时不在界面上：节点 error.log 固定在运行目录（agent 读它做心跳汇总，
        // systemd 沙箱也不放行 /var/log/cdnca）；每个四层转发都必填自己的连接/空闲超时，stream 级默认永远被覆盖。
        { key: 'worker', label: 'Worker' }, { key: 'http', label: 'Http' },
      ]} />
      {tab === 'worker' ? <>
        <SectionIntro title={t('parity.nginx.worker.title')} description={t('parity.nginx.worker.description')} />
        <div className="configuration-card-grid">
          <ConfigCard title={t('parity.nginx.worker.processTitle')} description={t('parity.nginx.worker.processDescription')}>
            <NginxIntegerField name={[...root, 'worker', 'worker_processes']} label="worker_processes" maximum={256} allowAuto />
            <NginxIntegerField name={[...root, 'worker', 'worker_connections']} label="worker_connections" minimum={128} maximum={1_048_576} />
          </ConfigCard>
          <ConfigCard title={t('parity.nginx.worker.resourceTitle')} description={t('parity.nginx.worker.resourceDescription')}>
            <NginxIntegerField name={[...root, 'worker', 'worker_rlimit_nofile']} label="worker_rlimit_nofile" minimum={1_024} maximum={1_048_576} />
            <NginxDurationField name={[...root, 'worker', 'worker_shutdown_timeout_ms']} label="worker_shutdown_timeout" minimum={1_000} maximum={300_000} />
          </ConfigCard>
        </div>
      </> : tab === 'http' ? <>
        <SectionIntro title={t('parity.nginx.http.title')} description={t('parity.nginx.http.description')} />
        <div className="configuration-card-grid">
          <ConfigCard title={t('parity.nginx.http.gzipTitle')} description={t('parity.nginx.http.gzipDescription')}>
            <NginxIntegerField name={[...http, 'gzip_comp_level']} label="gzip_comp_level" minimum={1} maximum={9} />
            <SelectField name={[...http, 'gzip_http_version']} label="gzip_http_version" options={['1.0', '1.1'].map((value) => ({ value, label: value }))} />
            <NginxByteSizeField name={[...http, 'gzip_min_length_bytes']} label="gzip_min_length" maximum={2 ** 30} />
            <SwitchField name={[...http, 'gzip_vary']} label="gzip_vary" />
          </ConfigCard>
          <ConfigCard title={t('parity.nginx.http.cacheTitle')} description={t('parity.nginx.http.cacheDescription')}>
            <SwitchField name={[...http, 'server_addr_outgoing']} label={t('parity.nginx.http.entryOrigin')} />
            <SwitchField name={[...http, 'proxy_request_buffering']} label="proxy_request_buffering" />
            <SwitchField name={[...http, 'proxy_buffering']} label="proxy_buffering" />
            <NginxByteSizeField name={[...http, 'proxy_cache_max_size_bytes']} label="proxy_cache_max_size" maximum={2 ** 50} />
            <NginxByteSizeField name={[...http, 'proxy_cache_min_free_bytes']} label={t('parity.nginx.http.cacheMinFree')} maximum={2 ** 44} />
            <StringListField name={[...http, 'proxy_cache_methods']} label="proxy_cache_methods" />
            <SelectField name={[...http, 'proxy_http_version']} label="proxy_http_version" options={['1.0', '1.1'].map((value) => ({ value, label: value }))} />
            <NginxByteSizeField name={[...http, 'proxy_max_temp_file_size_bytes']} label="proxy_max_temp_file_size" maximum={2 ** 40} />
            <StringListField name={[...http, 'proxy_next_upstream']} label="proxy_next_upstream" />
            <NginxDurationField name={[...http, 'proxy_connect_timeout_ms']} label="proxy_connect_timeout" minimum={100} maximum={75_000} />
            <NginxDurationField name={[...http, 'proxy_send_timeout_ms']} label="proxy_send_timeout" minimum={100} maximum={3_600_000} />
            <NginxDurationField name={[...http, 'proxy_read_timeout_ms']} label="proxy_read_timeout" minimum={100} maximum={3_600_000} />
          </ConfigCard>
          <ConfigCard wide title={t('parity.nginx.http.connectionTitle')} description={t('parity.nginx.http.connectionDescription')}>
            <div className="configuration-field-columns">
              <NginxByteSizeField name={[...http, 'client_body_buffer_size_bytes']} label="client_body_buffer_size" minimum={1} maximum={2 ** 30} extra={t('parity.nginx.http.bufferHint')} />
              <TextField name={[...http, 'server']} label="server" maxLength={64} />
              <NginxByteSizeField name={[...http, 'client_max_body_size_bytes']} label="client_max_body_size" minimum={1_024} maximum={10 * 2 ** 30} />
              <SelectField name={[...http, 'default_type']} label="default_type" options={['application/json', 'text/html', 'text/plain'].map((value) => ({ value, label: value }))} />
              <NginxIntegerField name={[...http, 'keepalive_requests']} label="keepalive_requests" minimum={1} maximum={1_000_000} />
              <NginxDurationField name={[...http, 'keepalive_timeout_ms']} label="keepalive_timeout" minimum={100} maximum={3_600_000} />
              <SwitchField name={[...http, 'log_not_found']} label="log_not_found" />
              <SwitchField name={[...http, 'server_tokens']} label="server_tokens" />
              <NginxHeaderBuffersField name={[...http, 'large_client_header_buffers']} label="large_client_header_buffers" />
              <NginxIntegerField name={[...http, 'server_names_hash_max_size']} label="server_names_hash_max_size" minimum={512} maximum={65_536} />
              <NginxIntegerField name={[...http, 'server_names_hash_bucket_size']} label="server_names_hash_bucket_size" minimum={32} maximum={1024} />
            </div>
          </ConfigCard>
        </div>
      </> : null}
    </>}
  </>
}

function ResourceFields({ t }: { t: TFunction<'systemSettings'> }) {
  const [tab, setTab] = useState('site')
  const root = ['resources']
  const site = [...root, 'site']
  // 资源配置没有可按节点生效的项（都在建站/建转发时取值），不提供区域配置。
  return <>
      <Tabs className="configuration-detail-tabs" activeKey={tab} onChange={setTab} items={[
        { key: 'site', label: t('parity.tabs.site') },
        { key: 'stream', label: t('parity.tabs.stream') },
        { key: 'common', label: t('parity.tabs.common') },
      ]} />
      {tab === 'site' ? <>
        <SectionIntro title={t('parity.resources.site.title')} description={t('parity.resources.site.description')} />
        <div className="configuration-card-grid">
          <ConfigCard title={t('parity.resources.site.configurationTitle')} description={t('parity.resources.site.configurationDescription')}>
            <NumberField name={[...site, 'related_config_min_limit']} label={t('parity.resources.fields.relatedMin')} t={t} minimum={1} maximum={100_000} suffix={t('parity.units.items')} />
            <NumberField name={[...site, 'related_config_max_times_limit']} label={t('parity.resources.fields.relatedMultiplier')} t={t} minimum={1} maximum={1000} suffix={t('parity.units.multiplier')} />
          </ConfigCard>
          <ConfigCard title={t('parity.resources.site.listsTitle')} description={t('parity.resources.site.listsDescription')}>
            <NumberField name={[...site, 'black_ip_limit']} label={t('parity.resources.fields.blacklist')} t={t} minimum={1} maximum={1_000_000} suffix={t('parity.units.items')} />
            <NumberField name={[...site, 'white_ip_limit']} label={t('parity.resources.fields.whitelist')} t={t} minimum={1} maximum={1_000_000} suffix={t('parity.units.items')} />
          </ConfigCard>
          <ConfigCard wide title={t('parity.resources.site.cacheTitle')} description={t('parity.resources.site.cacheDescription')}>
            <div className="configuration-field-columns">
              <NumberField name={[...site, 'daily_clean_url_limit']} label={t('parity.resources.fields.cleanUrl')} t={t} minimum={1} maximum={10_000_000} suffix={t('parity.units.perDay')} />
              <NumberField name={[...site, 'daily_clean_dir_limit']} label={t('parity.resources.fields.cleanDir')} t={t} minimum={1} maximum={1_000_000} suffix={t('parity.units.perDay')} />
              <NumberField name={[...site, 'daily_pre_cache_url_limit']} label={t('parity.resources.fields.prewarm')} t={t} minimum={1} maximum={10_000_000} suffix={t('parity.units.perDay')} />
              <NumberField name={[...site, 'daily_ip_unlock_limit']} label={t('parity.resources.fields.unlockDaily')} t={t} minimum={1} maximum={10_000_000} suffix={t('parity.units.perDay')} />
              <NumberField name={[...site, 'ip_unlock_per_request_limit']} label={t('parity.resources.fields.unlockBatch')} t={t} minimum={1} maximum={100_000} clampMaximum={false} suffix={t('parity.units.perRequest')} />
            </div>
          </ConfigCard>
          <ConfigCard title={t('parity.resources.site.rulesTitle')} description={t('parity.resources.site.rulesDescription')}>
            <NumberField name={[...site, 'cc_rule_max_limit']} label={t('parity.resources.fields.ccRules')} t={t} minimum={1} maximum={100_000} suffix={t('parity.units.rules')} />
            <NumberField name={[...site, 'max_domains_per_site']} label={t('parity.resources.fields.domains')} t={t} minimum={1} maximum={100} clampMaximum={false} suffix={t('parity.units.items')} />
            <SwitchField name={[...site, 'listen_default_http_80']} label={t('parity.resources.fields.listen80')} />
          </ConfigCard>
          <ConfigCard title={t('parity.resources.site.logsTitle')} description={t('parity.resources.site.logsDescription')}>
            <NumberField name={[...site, 'daily_access_log_download_limit']} label={t('parity.resources.fields.logDownloads')} t={t} minimum={1} maximum={100_000} suffix={t('parity.units.perDay')} />
            <TextField name={[...site, 'access_log_tmp_dir']} label={t('parity.resources.fields.logDirectory')} maxLength={512} />
            <NumberField name={[...site, 'access_log_retain_hours']} label={t('parity.resources.fields.logRetention')} t={t} minimum={1} maximum={720} clampMaximum={false} suffix={t('parity.units.hours')} />
          </ConfigCard>
        </div>
      </> : tab === 'stream' ? <>
        <SectionIntro title={t('parity.resources.stream.title')} description={t('parity.resources.stream.description')} />
        <div className="configuration-card-grid">
          <ConfigCard title={t('parity.resources.stream.portsTitle')} description={t('parity.resources.stream.portsDescription')}>
            <PortRangesField name={[...root, 'stream', 'custom_port_not_allow']} label={t('parity.resources.fields.deniedPorts')} extra={t('parity.resources.fields.portHint')} />
          </ConfigCard>
          <ConfigCard title={t('parity.resources.stream.configurationTitle')} description={t('parity.resources.stream.configurationDescription')}>
            <NumberField name={[...root, 'stream', 'related_config_min_limit']} label={t('parity.resources.fields.relatedMin')} t={t} minimum={1} maximum={100_000} suffix={t('parity.units.items')} />
            <NumberField name={[...root, 'stream', 'related_config_max_times_limit']} label={t('parity.resources.fields.relatedMultiplier')} t={t} minimum={1} maximum={100} clampMaximum={false} suffix={t('parity.units.multiplier')} />
            <NumberField name={[...root, 'stream', 'acl_max_limit']} label={t('parity.resources.fields.aclRules')} t={t} minimum={1} maximum={100_000} suffix={t('parity.units.rules')} extra={t('parity.resources.fields.aclRulesHint')} />
          </ConfigCard>
        </div>
      </> : <>
        <SectionIntro title={t('parity.resources.common.title')} description={t('parity.resources.common.description')} />
        <div className="configuration-card-grid">
          <ConfigCard wide title={t('parity.resources.common.portsTitle')} description={t('parity.resources.common.portsDescription')}>
            <div className="configuration-field-columns">
              <PortRangesField name={[...root, 'site_stream', 'custom_port_not_allow']} label={t('parity.resources.fields.deniedCustomPorts')} extra={t('parity.resources.fields.portHint')} />
              <PortRangesField name={[...root, 'site_stream', 'custom_port_allow']} label={t('parity.resources.fields.allowedCustomPorts')} extra={t('parity.resources.fields.portHint')} />
            </div>
          </ConfigCard>
        </div>
      </>}
  </>
}

function SSLModeField({ form, t }: { form: FormInstance<SettingsFormValues>; t: TFunction<'systemSettings'> }) {
  const applyMode = (mode: string) => {
    const preset = mode === 'recommended'
      ? { protocols: ['TLSv1.2', 'TLSv1.3'], cipher_suites: recommendedCipherSuites, prefer_server_ciphers: false }
      : mode === 'legacy_tls12'
        ? { protocols: ['TLSv1.2', 'TLSv1.3'], cipher_suites: legacyTls12CipherSuites, prefer_server_ciphers: true }
        : { protocols: ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'], cipher_suites: 'DEFAULT:@SECLEVEL=0', prefer_server_ciphers: true }
    form.setFieldValue(['defaults', 'website', 'https', 'ssl'], { mode, ...preset })
  }
  return <Form.Item className="configuration-field configuration-field--choice-grid" name={['defaults', 'website', 'https', 'ssl', 'mode']} label={t('parity.defaults.fields.sslMode')}>
    <Radio.Group className="configuration-choice-grid" onChange={(event) => applyMode(event.target.value)}>
      {(['recommended', 'legacy_tls12', 'legacy_full'] as const).map((mode) => <Radio key={mode} value={mode}>
        <strong>{t(`parity.defaults.sslModes.${mode}.title`)}</strong>
        <span>{t(`parity.defaults.sslModes.${mode}.description`)}</span>
      </Radio>)}
    </Radio.Group>
  </Form.Item>
}

function CacheRulesEditor({ t }: { t: TFunction<'systemSettings'> }) {
  return <Form.List name={['defaults', 'website', 'cache_rules']}>
    {(fields, { add, remove }) => {
      const addRule = (preset: 'standard' | 'static' = 'standard') => add({
        id: `cache_${Date.now().toString(36)}`,
        match: 'suffix',
        content: preset === 'static' ? '.css .js .jpg .jpeg .png .gif .svg .webp .woff .woff2' : null,
        ttl_seconds: preset === 'static' ? 86_400 : 3_600,
        ignore_query: preset === 'static',
        force_cache: false,
        range: true,
        ignore_vary: false,
        no_cache: [],
        enabled: true,
        position: fields.length,
      })
      return <ConfigCard wide title={t('parity.defaults.cache.title')} description={t('parity.defaults.cache.description')}>
        <div className="configuration-embedded-panel">
          <div className="configuration-list-toolbar">
            <div className="configuration-list-toolbar-meta">
              <strong>{t('parity.defaults.cache.ruleTitle')}</strong>
              <span>{t('parity.defaults.shared.count', { count: fields.length })}</span>
            </div>
            <div className="configuration-list-toolbar-actions">
              <Button type="primary" size="small" onClick={() => addRule()}>{t('parity.defaults.cache.add')}</Button>
              <Dropdown
                trigger={['click']}
                overlayClassName="configuration-dropdown-popup"
                menu={{
                  items: [
                    { key: 'standard', label: t('parity.defaults.cache.quickStandard') },
                    { key: 'static', label: t('parity.defaults.cache.quickStatic') },
                  ],
                  onClick: ({ key }) => addRule(key === 'static' ? 'static' : 'standard'),
                }}
              >
                <Button size="small">{t('parity.defaults.cache.quick')}<ChevronDown size={14} /></Button>
              </Dropdown>
            </div>
          </div>
          {fields.length === 0 ? <Empty className="configuration-list-empty" image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('parity.defaults.cache.empty')}>
            <p>{t('parity.defaults.cache.emptyHint')}</p>
            <Button type="primary" size="small" onClick={() => addRule()}>{t('parity.defaults.cache.addFirst')}</Button>
          </Empty> : <div className="configuration-list-editor">
            {fields.map((field) => <section className="configuration-list-row" key={field.key}>
              <div className="configuration-field-columns">
                <TextField name={[field.name, 'id']} label={t('parity.defaults.fields.ruleId')} maxLength={32} />
                <TextField name={[field.name, 'match']} label={t('parity.defaults.fields.match')} maxLength={64} />
                <TextField name={[field.name, 'content']} label={t('parity.defaults.fields.content')} maxLength={2_048} required={false} />
                <NumberField name={[field.name, 'ttl_seconds']} label={t('parity.defaults.fields.ttl')} t={t} minimum={0} maximum={31_536_000} suffix={t('parity.units.seconds')} />
                <SwitchField name={[field.name, 'ignore_query']} label={t('parity.defaults.fields.ignoreQuery')} />
                <SwitchField name={[field.name, 'force_cache']} label={t('parity.defaults.fields.forceCache')} />
                <SwitchField name={[field.name, 'range']} label={t('parity.defaults.fields.range')} />
                <SwitchField name={[field.name, 'ignore_vary']} label={t('parity.defaults.fields.ignoreVary')} />
                <SwitchField name={[field.name, 'enabled']} label={t('parity.defaults.fields.enabled')} />
                <Form.Item name={[field.name, 'position']} hidden><InputNumber /></Form.Item>
              </div>
              <Form.List name={[field.name, 'no_cache']}>
                {(conditionFields, conditionActions) => <div className="configuration-list-nested">
                  <div className="configuration-list-nested-toolbar">
                    <strong>{t('parity.defaults.fields.noCache')}</strong>
                    <Button type="link" size="small" onClick={() => conditionActions.add({ variable: '', string: '' })}>{t('parity.defaults.cache.addNoCache')}</Button>
                  </div>
                  {conditionFields.map((condition) => <div className="configuration-list-nested-row" key={condition.key}>
                    <TextField name={[condition.name, 'variable']} label={t('parity.defaults.fields.noCacheVariable')} maxLength={256} />
                    <TextField name={[condition.name, 'string']} label={t('parity.defaults.fields.noCacheString')} maxLength={2_048} />
                    <Button danger type="text" icon={<Trash2 size={15} />} aria-label={t('parity.defaults.cache.deleteNoCache')} onClick={() => conditionActions.remove(condition.name)} />
                  </div>)}
                </div>}
              </Form.List>
              <Button danger type="text" icon={<Trash2 size={15} />} aria-label={t('actions.delete')} onClick={() => remove(field.name)} />
            </section>)}
          </div>}
        </div>
      </ConfigCard>
    }}
  </Form.List>
}

function OriginHeadersEditor({ t }: { t: TFunction<'systemSettings'> }) {
  return <Form.List name={['defaults', 'website', 'origin_request_headers']}>
    {(fields, { add, remove }) => {
      const addHeader = () => add({
        id: `header_${Date.now().toString(36)}`,
        name: 'Host',
        value: '',
        action: 'set',
        allow_duplicate: false,
        enabled: true,
        position: fields.length,
      })
      return <ConfigCard wide title={t('parity.defaults.headers.title')} description={t('parity.defaults.headers.description')}>
        <div className="configuration-embedded-panel configuration-embedded-panel--headers">
          <div className="configuration-list-toolbar">
            <div>
              <div className="configuration-list-toolbar-meta">
                <strong>{t('parity.defaults.headers.ruleTitle')}</strong>
                <span>{t('parity.defaults.shared.count', { count: fields.length })}</span>
              </div>
              <p>{t('parity.defaults.headers.hint')}</p>
            </div>
            <Button type="primary" size="small" onClick={addHeader}>{t('parity.defaults.headers.add')}</Button>
          </div>
          {fields.length === 0 ? <div className="configuration-simple-empty">{t('parity.defaults.headers.empty')}</div> : <div className="configuration-list-editor">
            {fields.map((field) => <section className="configuration-list-row" key={field.key}>
              <div className="configuration-field-columns">
                <TextField name={[field.name, 'id']} label={t('parity.defaults.fields.ruleId')} maxLength={32} />
                <TextField name={[field.name, 'name']} label={t('parity.defaults.fields.headerName')} maxLength={256} />
                <TextField name={[field.name, 'value']} label={t('parity.defaults.fields.headerValue')} maxLength={4_096} required={false} />
                <SelectField name={[field.name, 'action']} label={t('parity.defaults.fields.action')} options={['set', 'append', 'delete'].map((value) => ({ value, label: t(`parity.defaults.headerActions.${value}`) }))} />
                <SwitchField name={[field.name, 'allow_duplicate']} label={t('parity.defaults.fields.allowDuplicate')} />
                <SwitchField name={[field.name, 'enabled']} label={t('parity.defaults.fields.enabled')} />
                <Form.Item name={[field.name, 'position']} hidden><InputNumber /></Form.Item>
              </div>
              <Button danger type="text" icon={<Trash2 size={15} />} aria-label={t('actions.delete')} onClick={() => remove(field.name)} />
            </section>)}
          </div>}
        </div>
      </ConfigCard>
    }}
  </Form.List>
}

type CcPolicyOption = { value: string; label: string }

function DefaultWebsiteFields({ form, t, ccPolicyOptions, ccPolicyLoading }: {
  form: FormInstance<SettingsFormValues>
  t: TFunction<'systemSettings'>
  ccPolicyOptions: CcPolicyOption[]
  ccPolicyLoading: boolean
}) {
  const root = ['defaults', 'website'] as const
  const setWafModules = (mode: 'off' | 'detect' | 'on') => {
    for (const name of wafModuleNames) form.setFieldValue([...root, 'security', 'waf_modules', name], mode)
  }
  return <div className="configuration-card-grid configuration-default-website">
    <ConfigCard wide title="HTTP" description={t('parity.defaults.http.description')}>
      <NumberListField name={[...root, 'http', 'listen_ports']} label={t('parity.defaults.fields.listenPorts')} />
    </ConfigCard>
    <ConfigCard wide title="HTTPS" description={t('parity.defaults.https.description')}>
      <div className="configuration-default-field-grid">
        <NumberListField name={[...root, 'https', 'listen_ports']} label={t('parity.defaults.fields.listenPorts')} />
        <SwitchField name={[...root, 'https', 'hsts_enabled']} label={t('parity.defaults.fields.hsts')} />
        <SwitchField name={[...root, 'https', 'http2_enabled']} label={t('parity.defaults.fields.http2')} />
        <SwitchField name={[...root, 'https', 'http3_enabled']} label={t('parity.defaults.fields.http3')} />
        <SwitchField name={[...root, 'https', 'force_https']} label={t('parity.defaults.fields.forceHttps')} />
      </div>
      <SSLModeField form={form} t={t} />
      <SwitchField name={[...root, 'https', 'ocsp_stapling_enabled']} label={t('parity.defaults.fields.ocspStapling')} />
    </ConfigCard>
    <ConfigCard wide title={t('parity.defaults.origin.title')} description={t('parity.defaults.origin.description')}>
      <Form.Item className="configuration-field configuration-field--choice-grid" name={[...root, 'origin', 'scheme']} label={t('parity.defaults.fields.originScheme')}>
        <Radio.Group className="configuration-choice-grid configuration-choice-grid--compact">
          {(['http', 'https', 'follow', 'follow_with_port'] as const).map((value) => <Radio key={value} value={value}>
            <strong>{t(`parity.defaults.originSchemes.${value}.title`)}</strong>
            <span>{t(`parity.defaults.originSchemes.${value}.description`)}</span>
          </Radio>)}
        </Radio.Group>
      </Form.Item>
      <div className="configuration-default-field-grid">
        <NumberField name={[...root, 'origin', 'http_port']} label={t('parity.defaults.fields.originHttpPort')} t={t} minimum={1} maximum={65_535} />
        <NumberField name={[...root, 'origin', 'https_port']} label={t('parity.defaults.fields.originHttpsPort')} t={t} minimum={1} maximum={65_535} />
        <NumberField name={[...root, 'origin', 'response_timeout_seconds']} label={t('parity.defaults.fields.originTimeout')} t={t} minimum={1} maximum={3600} suffix={t('parity.units.seconds')} />
        <NumberField name={[...root, 'origin', 'connect_timeout_seconds']} label={t('parity.defaults.fields.connectTimeout')} t={t} minimum={1} maximum={75} suffix={t('parity.units.seconds')} />
        <ProtocolCheckboxField name={[...root, 'origin', 'ssl_protocols']} label={t('parity.defaults.fields.originSslProtocols')} />
      </div>
    </ConfigCard>
    <CacheRulesEditor t={t} />
    <OriginHeadersEditor t={t} />
    <ConfigCard wide title={t('parity.defaults.accessLog.title')} description={t('parity.defaults.accessLog.description')}>
      <div className="configuration-default-field-grid">
        <SwitchField name={[...root, 'access_log', 'capture_request_headers']} label={t('parity.defaults.fields.captureRequestHeaders')} extra={t('parity.defaults.hints.captureRequestHeaders')} />
        <SwitchField name={[...root, 'access_log', 'capture_response_headers']} label={t('parity.defaults.fields.captureResponseHeaders')} extra={t('parity.defaults.hints.captureResponseHeaders')} />
        <SwitchField name={[...root, 'access_log', 'capture_request_body']} label={t('parity.defaults.fields.captureRequestBody')} extra={t('parity.defaults.hints.captureRequestBody')} />
        <NumberField name={[...root, 'access_log', 'request_body_limit_kb']} label={t('parity.defaults.fields.requestBodyLimit')} t={t} maximum={10_240} suffix="KB" />
      </div>
    </ConfigCard>
    <ConfigCard wide title={t('parity.defaults.security.title')} description={t('parity.defaults.security.description')}>
      <div className="configuration-default-field-grid">
        <Form.Item
          className="configuration-field"
          name={[...root, 'security', 'default_cc_policy_id']}
          label={t('parity.defaults.fields.defaultCcPolicy')}
        >
          <NullableSelectControl
            label={t('parity.defaults.fields.defaultCcPolicy')}
            loading={ccPolicyLoading}
            options={[{ value: '__off__', label: t('parity.defaults.shared.off') }, ...ccPolicyOptions]}
          />
        </Form.Item>
        <SwitchField name={[...root, 'security', 'waf_enabled']} label={t('parity.defaults.fields.wafEnabled')} extra={t('parity.defaults.hints.wafEnabled')} />
        <div className="configuration-waf-auto-block">
          <div className="configuration-waf-auto-block-head">
            <div>
              <strong>{t('parity.defaults.security.autoBlockTitle')}</strong>
              <p>{t('parity.defaults.security.autoBlockDescription')}</p>
            </div>
            <Form.Item noStyle name={[...root, 'security', 'waf_auto_block', 'enabled']} valuePropName="checked">
              <Switch aria-label={t('parity.defaults.fields.autoBlock')} />
            </Form.Item>
          </div>
          <div className="configuration-waf-auto-block-fields">
            <NumberField name={[...root, 'security', 'waf_auto_block', 'window_seconds']} label={t('parity.defaults.fields.windowSeconds')} t={t} minimum={1} maximum={86_400} />
            <NumberField name={[...root, 'security', 'waf_auto_block', 'hit_threshold']} label={t('parity.defaults.fields.hitThreshold')} t={t} minimum={1} maximum={1_000_000} />
            <NumberField name={[...root, 'security', 'waf_auto_block', 'block_seconds']} label={t('parity.defaults.fields.blockSeconds')} t={t} minimum={1} maximum={604_800} />
          </div>
        </div>
      </div>
      <div className="configuration-waf-title-row">
        <strong>{t('parity.defaults.security.modulesTitle')}</strong>
        <Dropdown
          trigger={['click']}
          overlayClassName="configuration-dropdown-popup"
          menu={{
            items: wafModuleModes.map((mode) => ({ key: mode, label: t(`parity.defaults.wafModes.${mode}`) })),
            onClick: ({ key }) => setWafModules(key as WafModuleMode),
          }}
        >
          <Button type="primary" size="small">{t('parity.defaults.security.batch')}<ChevronDown size={14} /></Button>
        </Dropdown>
      </div>
      <p className="configuration-waf-description">{t('parity.defaults.security.modulesDescription')}</p>
      <div className="configuration-waf-modules">
        {wafModuleNames.map((name) => <WafModuleField key={name} name={[...root, 'security', 'waf_modules', name]} label={t(`parity.defaults.wafModules.${name}`)} t={t} />)}
      </div>
    </ConfigCard>
    <ConfigCard wide title={t('parity.defaults.other.title')} description={t('parity.defaults.other.description')}>
      <div className="configuration-default-field-grid">
        <Form.Item className="configuration-field" name={[...root, 'other', 'load_balancing']} label={t('parity.defaults.fields.loadBalancing')}>
          <Radio.Group>
            {loadBalancingValues.map((value) => <Radio key={value} value={value}>{t(`parity.defaults.loadBalancing.${value}`)}</Radio>)}
          </Radio.Group>
        </Form.Item>
        <SwitchField name={[...root, 'other', 'gzip_enabled']} label={t('parity.defaults.fields.gzip')} />
        <StringListField name={[...root, 'other', 'gzip_types']} label="gzip types" />
        <SwitchField name={[...root, 'other', 'websocket_enabled']} label={t('parity.defaults.fields.websocket')} />
      </div>
    </ConfigCard>
  </div>
}

function DefaultsFields({ form, t, ccPolicyOptions, ccPolicyLoading, editable, onOverridesChange }: {
  form: FormInstance<SettingsFormValues>
  t: TFunction<'systemSettings'>
  ccPolicyOptions: CcPolicyOption[]
  ccPolicyLoading: boolean
  editable: boolean
  onOverridesChange: () => void
}) {
  const [scope, setScope] = useState('global')
  const [tab, setTab] = useState('website')
  return <>
    <Tabs className="configuration-scope-tabs" activeKey={scope} onChange={setScope} items={[
      { key: 'global', label: t('parity.tabs.global') },
      { key: 'regional', label: t('parity.tabs.region') },
    ]} />
    {scope === 'regional' ? <ConfigurationOverridesEditor category="defaults" form={form} t={t} editable={editable} onChange={onOverridesChange} /> : <>
      <Tabs className="configuration-detail-tabs" activeKey={tab} onChange={setTab} items={[
        { key: 'website', label: t('parity.tabs.site') },
        { key: 'stream', label: t('parity.tabs.stream') },
        { key: 'certificate', label: t('parity.tabs.certificate') },
      ]} />
      {tab === 'website' ? <DefaultWebsiteFields form={form} t={t} ccPolicyOptions={ccPolicyOptions} ccPolicyLoading={ccPolicyLoading} /> : tab === 'stream' ? <div className="configuration-card-grid configuration-default-simple-grid">
        <ConfigCard wide title={t('parity.defaults.stream.title')} description={t('parity.defaults.stream.description')}>
          <div className="configuration-field-columns">
            <Form.Item className="configuration-field" name={['defaults', 'stream', 'protocol']} label={t('parity.defaults.fields.listenProtocol')}>
              <Radio.Group options={['tcp', 'udp'].map((value) => ({ value, label: value.toUpperCase() }))} />
            </Form.Item>
            <Form.Item className="configuration-field" name={['defaults', 'stream', 'load_balancing']} label={t('parity.defaults.fields.loadBalancing')}>
              <Radio.Group options={['round_robin', 'ip_hash'].map((value) => ({ value, label: t(`parity.defaults.loadBalancing.${value}`) }))} />
            </Form.Item>
          </div>
          <SwitchField name={['defaults', 'stream', 'proxy_protocol_enabled']} label={t('parity.defaults.fields.proxyProtocol')} />
        </ConfigCard>
      </div> : <div className="configuration-card-grid configuration-default-simple-grid">
        <ConfigCard wide title={t('parity.defaults.certificate.title')} description={t('parity.defaults.certificate.description')}>
          <Form.Item className="configuration-field" name={['defaults', 'certificate', 'issuer']} label={t('parity.defaults.fields.defaultCertificateType')}>
            <Radio.Group options={[
              { value: 'lets_encrypt', label: "Let's Encrypt" },
              { value: 'zerossl', label: 'ZeroSSL' },
              { value: 'google_trust', label: 'Google Trust Services' },
            ]} />
          </Form.Item>
          <AcmeCACredentialsCard t={t} editable={editable} />
        </ConfigCard>
      </div>}
    </>}
  </>
}

function CategoryFields({ category, form, t, ccPolicyOptions, ccPolicyLoading, editable, onOverridesChange }: {
  category: EditableCategory
  form: FormInstance<SettingsFormValues>
  t: TFunction<'systemSettings'>
  ccPolicyOptions: CcPolicyOption[]
  ccPolicyLoading: boolean
  editable: boolean
  onOverridesChange: () => void
}) {
  switch (category) {
    case 'nginx': return <NginxFields form={form} t={t} editable={editable} onOverridesChange={onOverridesChange} />
    case 'resources': return <ResourceFields t={t} />
    case 'defaults': return <DefaultsFields form={form} t={t} ccPolicyOptions={ccPolicyOptions} ccPolicyLoading={ccPolicyLoading} editable={editable} onOverridesChange={onOverridesChange} />
  }
}

interface SystemSettingsPageContentProps {
  category: EditableCategory
  owner: SystemSettingsOwner
  ownerKey: string
  principal: Principal
}

function SystemSettingsPageContent({ category, owner, ownerKey, principal }: SystemSettingsPageContentProps) {
  const { t } = useTranslation('systemSettings')
  const queryClient = useQueryClient()
  const queryOwner = useRef(owner).current
  const ownerQueryPrefix = useMemo(() => ['system-configuration', ...queryOwner] as const, [queryOwner])
  const ownerMutationKey = useMemo(() => ['system-configuration-write', ...queryOwner] as const, [queryOwner])
  const lineageActiveRef = useRef(true)
  const cleanupGenerationRef = useRef(0)
  const [messageApi, messageContext] = useFeedbackMessage()
  const [form] = Form.useForm<SettingsFormValues>()
  const [attempt, setAttempt] = useState<SaveAttempt | null>(null)
  const [writeError, setWriteError] = useState<unknown>(null)
  const [conflictRefreshed, setConflictRefreshed] = useState(false)
  const [manageDenied, setManageDenied] = useState(false)
  const [dirty, setDirty] = useState(false)
  const sessionCanManage = systemSettingsPrincipalCan(principal, 'system_configuration.manage')
  const queryKey = useMemo(() => [...ownerQueryPrefix, category] as const, [category, ownerQueryPrefix])
  const currentSessionMatchesReader = useCallback(() => lineageActiveRef.current && Boolean(currentSystemSettingsAccess(ownerKey)), [ownerKey])
  const attemptMatchesReader = useCallback((candidate: SaveAttempt) => candidate.ownerKey === ownerKey && currentSessionMatchesReader(), [currentSessionMatchesReader, ownerKey])

  useEffect(() => {
    const generation = ++cleanupGenerationRef.current
    lineageActiveRef.current = true
    const cleanupOwnerCache = (all = false) => {
      // A sibling category may already be mounted when deferred cleanup runs.
      // Only an identity change may remove that owner's active queries.
      queryClient.removeQueries({ queryKey: ownerQueryPrefix, type: all ? 'all' : 'inactive' })
      const mutationCache = queryClient.getMutationCache()
      for (const mutation of mutationCache.findAll({ mutationKey: ownerMutationKey, exact: true })) mutationCache.remove(mutation)
    }
    return () => {
      lineageActiveRef.current = false
      const current = useSessionStore.getState()
      const currentOwner = current.principal ? systemSettingsOwner(current.principal, current.sessionEpoch) : null
      if (!currentOwner || JSON.stringify(currentOwner) !== ownerKey) {
        cleanupOwnerCache(true)
        return
      }
      queueMicrotask(() => {
        if (cleanupGenerationRef.current === generation) cleanupOwnerCache()
      })
    }
  }, [ownerKey, ownerMutationKey, ownerQueryPrefix, queryClient])

  const query = useQuery({
    queryKey,
    // A configuration read is already bounded by the API gateway timeout. Retrying
    // the whole document request here only keeps the page on the loading spinner
    // and hides the actionable error state from administrators.
    retry: false,
    queryFn: async () => {
      const token = currentSystemSettingsAccess(ownerKey)
      if (!token) throw staleSystemSettingsAttempt
      try {
        const document = await systemConfigurationApi.get(token, category)
        if (!currentSessionMatchesReader()) throw staleSystemSettingsAttempt
        return document
      } catch (error) {
        if (!currentSessionMatchesReader()) throw staleSystemSettingsAttempt
        throw error
      }
    },
  })

  const canReadSecurityPolicies = principal.permissions.includes('security_policies.read') || principal.permissions.includes('platform.admin')
  const ccPoliciesQuery = useQuery({
    queryKey: [...ownerQueryPrefix, 'default-cc-policy-options'],
    enabled: category === 'defaults' && canReadSecurityPolicies,
    retry: false,
    queryFn: async () => {
      const token = currentSystemSettingsAccess(ownerKey)
      if (!token) throw staleSystemSettingsAttempt
      const page = await securityPoliciesApi.list(token, { page: 1, limit: 100, kind: 'cc', status: 'enabled' })
      if (!currentSessionMatchesReader()) throw staleSystemSettingsAttempt
      return page
    },
  })
  const ccPolicyOptions = useMemo(() => ccPoliciesQuery.data?.items.map((policy) => ({
    value: policy.id,
    label: policy.owner?.display_name ? `${policy.name} · ${policy.owner.display_name}` : policy.name,
  })) ?? [], [ccPoliciesQuery.data])

  const mutation = useMutation({
    mutationKey: ownerMutationKey,
    mutationFn: async (next: SaveAttempt) => {
      const token = next.ownerKey === ownerKey && lineageActiveRef.current
        ? currentSystemSettingsAccess(next.ownerKey, true)
        : null
      if (!token) throw staleSystemSettingsAttempt
      try {
        const document = await performSave(token, next)
        if (!attemptMatchesReader(next)) throw staleSystemSettingsAttempt
        return document
      } catch (error) {
        if (!attemptMatchesReader(next)) throw staleSystemSettingsAttempt
        throw error
      }
    },
    onSuccess: (document, completedAttempt) => {
      if (!attemptMatchesReader(completedAttempt)) return
      queryClient.setQueryData([...ownerQueryPrefix, document.category], document)
      setAttempt(null)
      setWriteError(null)
      setConflictRefreshed(false)
      setManageDenied(false)
      setDirty(false)
      messageApi.success(t('notices.saved'))
    },
    onError: (error, failedAttempt) => {
      if (error === staleSystemSettingsAttempt || !attemptMatchesReader(failedAttempt)) return
      setWriteError(error)
      if (isUnknownWriteOutcome(error)) {
        setAttempt(failedAttempt)
        return
      }
      setAttempt(null)
      const apiError = error instanceof ApiError ? error : null
      if (apiError?.code === 'system_configuration_revision_conflict' ||
        apiError?.code === 'system_configuration_idempotency_conflict' ||
        apiError?.code === 'revision_conflict' || apiError?.code === 'idempotency_conflict') {
        setConflictRefreshed(true)
        void query.refetch()
      }
      if (apiError?.code === 'system_configuration_permission_denied') setManageDenied(true)
    },
  })

  useEffect(() => {
    if (!query.data || !currentSessionMatchesReader()) return
    form.setFieldsValue(formValues(query.data))
    setDirty(false)
  }, [currentSessionMatchesReader, form, query.data])

  if (query.error instanceof ApiError && query.error.status === 403) {
    return <Result status="403" title={t('errors.forbiddenTitle')} subTitle={errorText(query.error, t)} />
  }

  const uncertain = Boolean(attempt && writeError && isUnknownWriteOutcome(writeError))
  const writeLocked = mutation.isPending || uncertain || !sessionCanManage || manageDenied
  const save = () => {
    if (!query.data || writeLocked || !currentSystemSettingsAccess(ownerKey, true)) return
    const values = form.getFieldsValue(true)
    const next = {
      ownerKey,
      category,
      value: normalizeWriteValue(category, values),
      expectedHeadRevision: query.data.head_revision,
      idempotencyKey: newSystemConfigurationIdempotencyKey(category),
      requestId: newSystemConfigurationRequestId(category),
    } as SaveAttempt
    setAttempt(null)
    setWriteError(null)
    setConflictRefreshed(false)
    mutation.mutate(next)
  }
  const retryExact = () => {
    if (!attempt || mutation.isPending || !currentSystemSettingsAccess(attempt.ownerKey, true)) return
    mutation.mutate(attempt)
  }
  const refresh = () => {
    setAttempt(null)
    setWriteError(null)
    setConflictRefreshed(false)
    setDirty(false)
    void query.refetch()
  }
  const reset = () => {
    if (!query.data) return
    form.setFieldsValue(formValues(query.data))
    setDirty(false)
  }

  return <div className={`system-settings-category-page system-settings-category-${category}`} data-testid="system-settings-page">
    {messageContext}
    {query.isPending ? <div className="configuration-loading"><Spin aria-label={t('states.loading')} /></div>
      : query.error instanceof ApiError && query.error.status === 404 ? <Empty description={t('empty.category')}><Button icon={<RefreshCw size={15} />} onClick={refresh}>{t('actions.refresh')}</Button></Empty>
        : query.isError ? <FeedbackWhen title={t('errors.loadTitle')} detail={errorText(query.error, t)} action={<Button onClick={refresh}>{t('actions.retry')}</Button>} />
          : query.data ? <>
            <CategoryScopeNotice />
            <PendingCategoriesNotice current={category} pending={query.data.pending_categories} />
            {uncertain ? <OutcomeUnknown title={t('uncertain.title')} detail={t('uncertain.description')} action={<Space wrap><Button icon={<RotateCcw size={15} />} loading={mutation.isPending} disabled={!sessionCanManage || manageDenied} onClick={retryExact}>{t('actions.retryExact')}</Button><Button onClick={refresh}>{t('actions.discardAndRefresh')}</Button></Space>} className="configuration-feedback" />
              : writeError ? <FeedbackWhen title={conflictRefreshed ? t('errors.conflictRefreshed') : t('errors.saveTitle')} detail={errorText(writeError, t)} /> : null}
            {!sessionCanManage || manageDenied ? <Alert className="configuration-feedback" type="info" showIcon message={t('readOnly.title')} description={t('readOnly.description')} /> : null}
            <Form<SettingsFormValues>
              className="configuration-form"
              form={form}
              layout="horizontal"
              colon={false}
              requiredMark={false}
              disabled={mutation.isPending || uncertain || !sessionCanManage || manageDenied}
              onValuesChange={() => setDirty(true)}
              onFinish={save}
            >
              <CategoryFields
                category={category}
                form={form}
                t={t}
                ccPolicyOptions={ccPolicyOptions}
                ccPolicyLoading={ccPoliciesQuery.isPending && canReadSecurityPolicies}
                editable={sessionCanManage && !manageDenied}
                onOverridesChange={() => setDirty(true)}
              />
              {dirty ? <div className="configuration-save-bar">
                <Button onClick={reset} disabled={mutation.isPending || uncertain}>{t('actions.reset')}</Button>
                <Button type="primary" htmlType="submit" icon={<Save size={15} />} loading={mutation.isPending} disabled={writeLocked}>{t('actions.save')}</Button>
              </div> : null}
            </Form>
          </> : null}
  </div>
}

export default function SystemSettingsPage({ initialCategory = 'nginx' }: { initialCategory?: EditableCategory }) {
  const { t } = useTranslation('systemSettings')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)

  if (!accessToken) return null
  const owner = principal ? systemSettingsOwner(principal, sessionEpoch) : null
  if (!principal || !owner || !systemSettingsPrincipalCan(principal, 'system_configuration.read')) {
    return <Result status="403" title={t('errors.forbiddenTitle')} subTitle={t('errors.system_configuration_permission_denied')} />
  }
  const ownerKey = JSON.stringify(owner)
  return <SystemSettingsPageContent
    key={`${ownerKey}:${initialCategory}`}
    category={initialCategory}
    owner={owner}
    ownerKey={ownerKey}
    principal={principal}
  />
}
