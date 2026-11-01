import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert, Button, Collapse, Descriptions, Grid, Input, Popconfirm, Progress, Result, Select, Space, Steps, Table, Tag, Typography,
  type TableColumnsType,
} from 'antd'
import { ArrowLeft, Check, CircleCheck, CircleDashed, Play, RefreshCw, Search, X } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { useLocation, useNavigate, useParams } from 'react-router-dom'

import { ApiError, type Principal } from '../api/auth'
import {
  dnsReconcileApi,
  type DNSReconcileCheckRequest,
  type DNSReconcileCommandIdentity,
  type DNSReconcileObservation,
  type DNSReconcileOperationResult,
  type DNSReconcileProviderOperation,
  type DNSReconcileTask,
} from '../api/dnsReconcile'
import { dnsApi } from '../api/dns'
import { dnsZonesApi, type DNSZone } from '../api/dnsZones'
import { sitesApi, type SiteListItem } from '../api/sites'
import { useSessionStore } from '../auth/session'
import { DataState } from '../components/DataState'
import '../i18n/dnsReconcilePage'
import { FeedbackWhen, OutcomeUnknown } from '@cdnca/ui'
import type { SiteDnsCheckContext } from './SiteDnsCheckPanel'
import './DnsReconcilePage.css'

type Owner = readonly ['tenant', string, string, string, number]
type WriteKind = 'apply' | 'commit' | 'cancel'
type ApplyAttempt = { input: DNSReconcileCheckRequest; identity: DNSReconcileCommandIdentity }
type CommandAttempt = { kind: 'commit' | 'cancel'; identity: DNSReconcileCommandIdentity }
type FieldName = 'name' | 'expectedValue' | 'ttl' | 'line' | 'weight' | 'propagationWindow' | 'zoneID' | 'providerRevision'
type FieldErrors = Partial<Record<FieldName, string>>

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const staleRead = new Error('stale DNS reconciliation read')
const unknownCodes = new Set(['dns_reconcile_result_unknown', 'network_error', 'request_timeout', 'dns_reconcile_request_timeout'])
// 等待生效期间每 5 秒刷新一次任务；到「待确认」或终态就停。
const pollInterval = 5000
const pollingStatuses = new Set(['applying', 'propagating'])
const doneStatuses = new Set(['committed', 'cancelled'])

function reconcileOwner(principal: Principal, sessionEpoch: number): Owner | null {
  if (principal.scope_kind !== 'tenant' || !principal.tenant_id ||
    !principal.scope_id || !principal.user_id || sessionEpoch < 1) return null
  return ['tenant', principal.scope_id, principal.tenant_id, principal.user_id, sessionEpoch]
}

function canRead(principal: Principal): boolean {
  return principal.scope_kind === 'tenant' && principal.permissions.includes('dns.read')
}

function canManage(principal: Principal): boolean {
  return principal.scope_kind === 'tenant' && principal.permissions.includes('dns.manage')
}

function currentAccess(ownerKey: string, permission: 'read' | 'manage'): string | null {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (!accessToken || !principal || (permission === 'read' ? !canRead(principal) : !canManage(principal))) return null
  const owner = reconcileOwner(principal, sessionEpoch)
  return owner && JSON.stringify(owner) === ownerKey ? accessToken : null
}

function errorKey(error: unknown): string {
  if (!(error instanceof ApiError)) return 'errors.requestFailed'
  if (error.status === 403 || error.code === 'permission_denied' || error.code === 'dns_reconcile_entitlement_denied') return 'errors.forbidden'
  if (error.status === 404 || error.code === 'dns_reconcile_not_found') return 'errors.notFound'
  if (error.status === 409 || error.status === 412 || error.code === 'dns_reconcile_operation_in_flight' || error.code === 'dns_reconcile_commit_not_ready') return 'errors.conflict'
  if (error.status === 429) return 'errors.rateLimited'
  if (error.status === 503 || error.status === 504 || error.code === 'dns_reconcile_unavailable') return 'errors.unavailable'
  if (error.code === 'dns_reconcile_invalid_request' || error.status === 400) return 'errors.invalidRequest'
  return 'errors.requestFailed'
}

function isUnknown(error: unknown): boolean {
  return error instanceof ApiError ? unknownCodes.has(error.code) || [408, 429, 500, 502, 503, 504].includes(error.status) : true
}

function newIdentity(kind: WriteKind, revision?: number): DNSReconcileCommandIdentity {
  const suffix = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
  const requestID = `dns-reconcile-${kind}-${suffix}`
  const traceID = `${'a'.repeat(31)}${(Date.now() % 16).toString(16)}`
  const spanID = `${'b'.repeat(15)}${(Date.now() % 16).toString(16)}`
  return {
    requestID,
    traceparent: `00-${traceID}-${spanID}-01`,
    idempotencyKey: `dns-reconcile-${kind}-${suffix}`,
    expectedRevision: revision ?? 1,
  }
}

// 域名所在区域：取名称是域名本身或其后缀的区域里最长的一个（www.a.example.com 优先 a.example.com，再 example.com）。
function matchZone(zones: readonly DNSZone[], domain: string): DNSZone | null {
  const name = domain.trim().toLowerCase().replace(/\.$/u, '')
  let best: DNSZone | null = null
  for (const zone of zones) {
    const zoneName = zone.name.toLowerCase().replace(/\.$/u, '')
    if ((name === zoneName || name.endsWith(`.${zoneName}`)) && (!best || zoneName.length > best.name.replace(/\.$/u, '').length)) best = zone
  }
  return best
}

// 字段级校验：范围与原实现一致（TTL/传播窗口 1–604800，权重 0–100，线路 ≤64 字节、无首尾空格与控制字符，修订 ≥1）。
function lineInvalid(line: string): boolean {
  const lineValue = line.trim()
  return line !== lineValue || new TextEncoder().encode(lineValue).length > 64 || [...lineValue].some((character) => {
    const codePoint = character.codePointAt(0) ?? 0
    return codePoint <= 0x1f || codePoint === 0x7f
  })
}

function intIn(raw: string, minimum: number, maximum: number): boolean {
  const value = Number(raw)
  return raw.trim() !== '' && Number.isSafeInteger(value) && value >= minimum && value <= maximum
}

// DC-UX-DETAIL-01（审测卡 12）：从解析检测进入时先给只读诊断（哪一层、哪个对象、什么原因、下一步），不发写请求。
type Diagnosis = { layer: 'account' | 'cname' | 'provider' | 'propagation' | 'ok'; reason: string; next: 'configureDnsApi' | 'sync' | 'wait' | 'none' }

function diagnose(context: SiteDnsCheckContext): Diagnosis {
  if (!context.provider || !context.task) return { layer: 'account', reason: 'noAccount', next: 'configureDnsApi' }
  if (context.task.state === 'pending') return { layer: 'provider', reason: 'pending', next: 'wait' }
  const code = (context.task.code ?? '').replace(/^retries_exhausted:/u, '')
  if (context.resolve === 'done') return { layer: 'ok', reason: 'resolved', next: 'none' }
  if (code === 'cname_pending') return { layer: 'cname', reason: code, next: 'wait' }
  if (code === 'zone_not_hosted') return { layer: 'account', reason: code, next: 'configureDnsApi' }
  if (code === 'dns_record_unconfirmed') return { layer: 'propagation', reason: code, next: 'sync' }
  return { layer: 'provider', reason: code || 'unknown', next: 'sync' }
}
// 从网站列表项推出与解析检测同形的上下文（无上下文进入、选完域名后用），这样两条入口的诊断展示一致。
function contextFromSite(site: SiteListItem, domain: string): SiteDnsCheckContext {
  const task = site.auto_dns
  const code = task?.results.find((item) => item.domain === domain)?.code ?? task?.failure_code ?? undefined
  const resolve = !task ? 'none' : task.state === 'pending' ? 'pending' : code || task.state === 'failed' ? 'failed' : 'done'
  return {
    siteID: site.id, siteDisplayID: String(site.display_id), domain, cname: site.cname,
    provider: task ? { id: task.provider_id, name: task.provider_name } : null,
    task: task ? { state: task.state, code, attempts: task.attempts, updatedAt: task.updated_at } : null,
    resolve, back: { filter: 'all', page: 1, limit: 10, search: { domain: '', siteIds: '' } },
  }
}

// 每个设置项：可见标签 + 一句帮助 + 字段下方的错误（aria-describedby 关联）。
function Field({ id, label, help, error, children }: {
  id: string; label: string; help: string; error?: string; children: (props: { id: string; 'aria-describedby': string; 'aria-invalid': boolean; status?: 'error' }) => ReactNode
}) {
  const describedBy = error ? `${id}-help ${id}-error` : `${id}-help`
  return (
    <div className="dns-fix-field">
      <label className="dns-fix-field-label" htmlFor={id}>{label}</label>
      {children({ id, 'aria-describedby': describedBy, 'aria-invalid': Boolean(error), status: error ? 'error' : undefined })}
      <span id={`${id}-help`} className="dns-fix-field-help">{help}</span>
      {error ? <span id={`${id}-error`} className="dns-fix-field-error">{error}</span> : null}
    </div>
  )
}

function DnsDiagnosis({ context, zone, action, showNext }: { context: SiteDnsCheckContext; zone: string; action: ReactNode; showNext: boolean }) {
  const { t } = useTranslation('dnsReconcilePage')
  const diagnosis = diagnose(context)
  return (
    <section className="dns-fix-diagnosis" aria-labelledby="dns-diagnosis-title">
      <div className="dns-fix-section-head">
        <Typography.Title id="dns-diagnosis-title" level={3}>{t('diagnosis.title', { domain: context.domain })}</Typography.Title>
        {action}
      </div>
      <Alert type={diagnosis.layer === 'ok' ? 'success' : diagnosis.next === 'wait' ? 'info' : 'warning'} showIcon
        message={t(`diagnosis.layers.${diagnosis.layer}`)}
        description={<>
          <span>{t(`diagnosis.reasons.${diagnosis.reason}`, { defaultValue: t('diagnosis.reasons.unknown', { code: diagnosis.reason }) })}</span>
          {showNext ? <span className="dns-fix-next">{t(`diagnosis.next.${diagnosis.next}`)}</span> : null}
        </>} />
      <Descriptions size="small" column={{ xs: 1, sm: 2, lg: 3 }} className="dns-fix-facts">
        <Descriptions.Item label={t('diagnosis.domain')}>{context.domain}</Descriptions.Item>
        <Descriptions.Item label={t('diagnosis.cname')}>{context.cname || t('values.empty')}</Descriptions.Item>
        <Descriptions.Item label={t('diagnosis.account')}>{context.provider?.name ?? t('diagnosis.noAccount')}</Descriptions.Item>
        <Descriptions.Item label={t('diagnosis.zone')}>{zone}</Descriptions.Item>
        <Descriptions.Item label={t('diagnosis.task')}>{context.task
          ? t('diagnosis.taskState', { state: t(`diagnosis.taskStates.${context.task.state}`), attempts: context.task.attempts })
          : t('diagnosis.noTask')}</Descriptions.Item>
        <Descriptions.Item label={t('diagnosis.site')}>{context.siteDisplayID}</Descriptions.Item>
      </Descriptions>
    </section>
  )
}
// 无上下文进入：先选域名（下拉带搜索），选中后带着与解析检测同形的上下文重新进入本页，不出现空表单。
function DomainPicker({ ownerKey, siteID }: { ownerKey: string; siteID: string }) {
  const { t } = useTranslation('dnsReconcilePage')
  const navigate = useNavigate()
  const [draft, setDraft] = useState('')
  const [search, setSearch] = useState('')
  useEffect(() => {
    const timer = window.setTimeout(() => setSearch(draft.trim()), 300)
    return () => window.clearTimeout(timer)
  }, [draft])
  const listSites = async (params: Parameters<typeof sitesApi.list>[1]) => {
    const token = currentAccess(ownerKey, 'read')
    if (!token) throw staleRead
    return sitesApi.list(token, params)
  }
  const currentQuery = useQuery({
    queryKey: ['dns-reconcile-picker', ownerKey, 'current', siteID], retry: false, refetchOnWindowFocus: false,
    queryFn: () => listSites({ page: 1, limit: 1, site_ids: siteID }),
  })
  const searchQuery = useQuery({
    queryKey: ['dns-reconcile-picker', ownerKey, 'search', search], retry: false, refetchOnWindowFocus: false,
    queryFn: () => listSites({ page: 1, limit: 20, site: search || undefined }),
  })
  const sites = new Map<string, SiteListItem>()
  for (const site of [...(currentQuery.data?.items ?? []), ...(searchQuery.data?.items ?? [])]) sites.set(site.id, site)
  const optionsOf = (items: SiteListItem[]) => items.flatMap((site) => (site.domains?.length ? site.domains : [site.domain])
    .filter((domain) => !search || domain.includes(search) || String(site.display_id) === search)
    .map((domain) => ({ value: `${site.id}|${domain}`, label: <span className="dns-fix-option"><span>{domain}</span>
      <span className="dns-fix-option-meta">{t('picker.site', { id: site.display_id })}</span></span> })))
  const current = [...sites.values()].filter((site) => site.id === siteID)
  const others = [...sites.values()].filter((site) => site.id !== siteID)
  const options = [
    ...(current.length ? [{ label: t('picker.currentSite'), options: optionsOf(current) }] : []),
    ...(others.length ? [{ label: t('picker.otherSites'), options: optionsOf(others) }] : []),
  ].filter((group) => group.options.length)
  const loading = currentQuery.isPending || searchQuery.isFetching
  const failed = currentQuery.isError && searchQuery.isError
  const choose = (value: string) => {
    const [id, domain] = value.split('|')
    const site = sites.get(id)
    if (!site || !domain) return
    navigate(`/site/${site.id}/dns-reconcile`, { state: { dnsCheck: contextFromSite(site, domain) } })
  }
  return (
    <section className="dns-fix-panel dns-fix-picker" aria-labelledby="dns-picker-title">
      <Typography.Title id="dns-picker-title" level={3}>{t('picker.title')}</Typography.Title>
      <Field id="dns-fix-domain" label={t('picker.label')} help={t('picker.help')}>
        {(props) => (
          <Select {...props} showSearch filterOption={false} className="dns-fix-picker-select" size="large"
            placeholder={t('picker.placeholder')} suffixIcon={<Search size={16} aria-hidden="true" />}
            searchValue={draft} onSearch={setDraft} onChange={choose} options={options} loading={loading}
            notFoundContent={loading ? t('picker.loading') : t('picker.empty')} />
        )}
      </Field>
      {failed ? <DataState status="error" message={t('picker.error')} onRetry={() => { void currentQuery.refetch(); void searchQuery.refetch() }} /> : null}
    </section>
  )
}

// 方案用「新增/修改/删除」分组，修改项给出改前 → 改后。
function PlanChanges({ operations }: { operations: DNSReconcileProviderOperation[] }) {
  const { t } = useTranslation('dnsReconcilePage')
  const groups = (['create', 'update', 'delete'] as const).map((action) => ({ action, items: operations.filter((item) => item.action === action) }))
  const lineText = (value?: string) => value || t('plan.defaultLine')
  return (
    <div className="dns-fix-groups">
      {groups.filter((group) => group.items.length).map((group) => (
        <section key={group.action} className={`dns-fix-group dns-fix-group-${group.action}`} aria-labelledby={`dns-plan-${group.action}`}>
          <Typography.Title id={`dns-plan-${group.action}`} level={4}>
            <Tag className="dns-fix-action-tag">{t(`operations.${group.action}`)}</Tag>
            {t(`plan.groups.${group.action}`)}<span className="dns-fix-count">{group.items.length}</span>
          </Typography.Title>
          <ul className="dns-fix-records">
            {group.items.map((item) => {
              const changes: string[] = []
              if (item.previous_value !== undefined && item.previous_value !== item.value) changes.push(t('plan.change', { label: t('columns.value'), from: item.previous_value, to: item.value }))
              if (item.previous_ttl !== undefined && item.previous_ttl !== item.ttl) changes.push(t('plan.change', { label: 'TTL', from: item.previous_ttl, to: item.ttl }))
              if (item.previous_line !== undefined && item.previous_line !== item.line) changes.push(t('plan.change', { label: t('plan.line'), from: lineText(item.previous_line), to: lineText(item.line) }))
              if (item.previous_weight !== undefined && item.previous_weight !== item.weight) changes.push(t('plan.change', { label: t('plan.weight'), from: item.previous_weight, to: item.weight ?? 0 }))
              return (
                <li key={item.sequence} className="dns-fix-record">
                  <div className="dns-fix-record-main">
                    <span className="dns-fix-record-name">{item.name}</span>
                    <Tag>{item.type}</Tag>
                    <span className="dns-fix-record-value">{item.value}</span>
                  </div>
                  <div className="dns-fix-record-meta">
                    {changes.length ? changes.map((change) => <span key={change}>{change}</span>) : <span>{t('plan.ttl', { ttl: item.ttl })}</span>}
                  </div>
                </li>
              )
            })}
          </ul>
          {group.action === 'delete' ? <p className="dns-fix-note">{t('plan.deleteNote')}</p> : null}
        </section>
      ))}
    </div>
  )
}
// 四步指示：窄屏改为一行「第 n / 4 步：标题」，避免步骤标题被截断。
function FixSteps({ current }: { current: number }) {
  const { t } = useTranslation('dnsReconcilePage')
  const narrow = Grid.useBreakpoint().md === false
  const titles = [t('steps.diagnose'), t('steps.plan'), t('steps.apply'), t('steps.finish')]
  if (narrow) {
    return <div className="dns-fix-steps-compact" aria-label={t('steps.label')}>
      <Progress percent={(current + 1) * 25} showInfo={false} size="small" />
      <span>{t('steps.compact', { current: current + 1, total: titles.length, title: titles[current] })}</span>
    </div>
  }
  return <Steps className="dns-fix-steps" size="small" current={current} responsive={false} aria-label={t('steps.label')}
    items={titles.map((title) => ({ title }))} />
}

function DnsReconcileContent({ owner, ownerKey, siteID, context }: {
  owner: Owner; ownerKey: string; siteID: string; context: SiteDnsCheckContext
}) {
  const { t } = useTranslation('dnsReconcilePage')
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const fixedOwner = useRef(owner).current
  const prefix = useMemo(() => ['dns-reconcile', ...fixedOwner, siteID] as const, [fixedOwner, siteID])
  const lineageActive = useRef(true)
  const target = context
  const [expectedValue, setExpectedValue] = useState(target.cname)
  const [authoritativeNS, setAuthoritativeNS] = useState('')
  const [ttl, setTtl] = useState('300')
  const [line, setLine] = useState('')
  const [weight, setWeight] = useState('0')
  const [propagationWindow, setPropagationWindow] = useState('900')
  const [zoneID, setZoneID] = useState('')
  const [providerRevision, setProviderRevision] = useState('')
  const [recordType, setRecordType] = useState<'A' | 'AAAA' | 'CNAME'>(target.cname ? 'CNAME' : 'A')
  const [advancedOpen, setAdvancedOpen] = useState(false)
  const [fieldErrors, setFieldErrors] = useState<FieldErrors>({})
  const [plan, setPlan] = useState<Awaited<ReturnType<typeof dnsReconcileApi.dryRun>> | null>(null)
  const [dryRunError, setDryRunError] = useState<unknown>(null)
  const [dryRunPending, setDryRunPending] = useState(false)
  const [taskID, setTaskID] = useState<string | null>(null)
  const [applyAttempt, setApplyAttempt] = useState<ApplyAttempt | null>(null)
  const [commandAttempt, setCommandAttempt] = useState<CommandAttempt | null>(null)
  const [writeError, setWriteError] = useState<unknown>(null)
  const [writePending, setWritePending] = useState(false)
  const errorSummary = useRef<HTMLDivElement>(null)

  // DNS 区域与区域版本从租户 DNS 账号下的区域列表按域名自动匹配，不让用户手填。
  const zonesQuery = useQuery({
    queryKey: [...prefix, 'zones'], retry: false, refetchOnWindowFocus: false,
    queryFn: async () => {
      const token = currentAccess(ownerKey, 'read')
      if (!token) throw staleRead
      const providers = await dnsApi.list(token)
      return (await dnsZonesApi.listZones(token, {
        scopeKind: 'tenant', scopeID: fixedOwner[1],
        providers: providers.items.map((provider) => ({ id: provider.id, scope_id: provider.scope_id })),
      })).items
    },
  })
  const zones = useMemo(() => zonesQuery.data ?? [], [zonesQuery.data])
  const matchedZone = useMemo(() => matchZone(zones, target.domain), [zones, target.domain])
  useEffect(() => {
    if (!matchedZone || zoneID) return
    setZoneID(matchedZone.id)
    setProviderRevision(String(matchedZone.version))
  }, [matchedZone, zoneID])

  const guardedRead = useCallback(async () => {
    const token = lineageActive.current ? currentAccess(ownerKey, 'read') : null
    if (!token || !taskID) throw staleRead
    try {
      const value = await dnsReconcileApi.get(token, siteID, taskID, newIdentity('apply'))
      if (!lineageActive.current || !currentAccess(ownerKey, 'read')) throw staleRead
      return value
    } catch (error) {
      if (!lineageActive.current || !currentAccess(ownerKey, 'read')) throw staleRead
      throw error
    }
  }, [ownerKey, siteID, taskID])

  const taskQuery = useQuery({
    queryKey: [...prefix, 'task', taskID ?? ''],
    enabled: Boolean(taskID), retry: false, refetchOnWindowFocus: false, refetchOnReconnect: false,
    queryFn: guardedRead,
    refetchInterval: (query) => pollingStatuses.has((query.state.data as DNSReconcileTask | undefined)?.result.status ?? '') ? pollInterval : false,
  })

  useEffect(() => {
    lineageActive.current = true
    return () => {
      lineageActive.current = false
      void queryClient.cancelQueries({ queryKey: prefix })
      queryClient.removeQueries({ queryKey: prefix })
    }
  }, [prefix, queryClient])

  // 改了任何设置，已生成的方案就不再对应当前设置，退回第一步重新检查。
  const edit = <T,>(setter: (value: T) => void) => (value: T) => {
    setter(value)
    if (!taskID) setPlan(null)
  }

  const inputFromForm = (): DNSReconcileCheckRequest | null => {
    const trimmedName = target.domain.trim()
    const values = expectedValue.split(',').map((value) => value.trim()).filter(Boolean)
    const nameservers = authoritativeNS.split(',').map((value) => value.trim()).filter(Boolean)
    const errors: FieldErrors = {}
    if (!trimmedName) errors.name = t('fieldErrors.name')
    if (!values.length) errors.expectedValue = t('fieldErrors.expectedValue')
    if (!intIn(ttl, 1, 604800)) errors.ttl = t('fieldErrors.ttl')
    if (lineInvalid(line)) errors.line = t('fieldErrors.line')
    if (!intIn(weight, 0, 100)) errors.weight = t('fieldErrors.weight')
    if (!intIn(propagationWindow, 1, 604800)) errors.propagationWindow = t('fieldErrors.propagationWindow')
    if (!zoneID.trim()) errors.zoneID = t('fieldErrors.zoneID')
    if (!intIn(providerRevision, 1, Number.MAX_SAFE_INTEGER)) errors.providerRevision = t('fieldErrors.providerRevision')
    setFieldErrors(errors)
    if (Object.keys(errors).length) {
      setAdvancedOpen(true)
      window.setTimeout(() => errorSummary.current?.focus(), 0)
      return null
    }
    return {
      name: trimmedName,
      expected: [{ type: recordType, values }],
      authoritative_ns: nameservers,
      ttl: Number(ttl),
      line: line.trim(),
      weight: Number(weight),
      propagation_window_seconds: Number(propagationWindow),
      provider: { zone_id: zoneID.trim(), revision: Number(providerRevision), records: [] },
    }
  }

  const doDryRun = async () => {
    if (dryRunPending) return
    const input = inputFromForm()
    const token = currentAccess(ownerKey, 'read')
    if (!input || !token) return
    setDryRunPending(true)
    setDryRunError(null)
    try {
      const value = await dnsReconcileApi.dryRun(token, siteID, input, newIdentity('apply'))
      if (!lineageActive.current || !currentAccess(ownerKey, 'read')) return
      setPlan(value)
    } catch (error) {
      if (lineageActive.current) setDryRunError(error)
    } finally {
      if (lineageActive.current) setDryRunPending(false)
    }
  }
  const executeApply = async (attempt: ApplyAttempt) => {
    const token = currentAccess(ownerKey, 'manage')
    if (!token || writePending) return
    setWritePending(true)
    setWriteError(null)
    try {
      const value = await dnsReconcileApi.apply(token, siteID, attempt.input, attempt.identity)
      if (!lineageActive.current || !currentAccess(ownerKey, 'manage')) return
      setTaskID(value.id)
      setApplyAttempt(null)
    } catch (error) {
      if (!lineageActive.current || !currentAccess(ownerKey, 'manage')) return
      setWriteError(error)
      if (!isUnknown(error)) setApplyAttempt(null)
    } finally {
      if (lineageActive.current) setWritePending(false)
    }
  }

  const startApply = () => {
    if (!plan || applyAttempt || writePending) return
    const input = inputFromForm()
    const token = currentAccess(ownerKey, 'manage')
    if (!input || !token) return
    const attempt: ApplyAttempt = { input, identity: newIdentity('apply', plan.plan.precondition_revision) }
    setApplyAttempt(attempt)
    void executeApply(attempt)
  }

  const executeCommand = async (attempt: CommandAttempt) => {
    const token = currentAccess(ownerKey, 'manage')
    const currentTask = taskQuery.data
    if (!token || !currentTask || !taskID || writePending) return
    setWritePending(true)
    setWriteError(null)
    try {
      const value = attempt.kind === 'commit'
        ? await dnsReconcileApi.commit(token, siteID, taskID, attempt.identity)
        : await dnsReconcileApi.cancel(token, siteID, taskID, attempt.identity)
      if (!lineageActive.current || !currentAccess(ownerKey, 'manage')) return
      queryClient.setQueryData([...prefix, 'task', taskID], value)
      setCommandAttempt(null)
    } catch (error) {
      if (!lineageActive.current || !currentAccess(ownerKey, 'manage')) return
      setWriteError(error)
      if (!isUnknown(error)) setCommandAttempt(null)
    } finally {
      if (lineageActive.current) setWritePending(false)
    }
  }

  const startCommand = (kind: 'commit' | 'cancel') => {
    const currentTask = taskQuery.data
    const token = currentAccess(ownerKey, 'manage')
    if (!currentTask || !taskID || !token || commandAttempt || writePending) return
    const attempt: CommandAttempt = { kind, identity: newIdentity(kind, currentTask.revision) }
    setCommandAttempt(attempt)
    void executeCommand(attempt)
  }

  const abandonWrite = () => {
    setApplyAttempt(null)
    setCommandAttempt(null)
    setWriteError(null)
    setWritePending(false)
    void taskQuery.refetch()
  }

  const task = taskQuery.data
  const resultColumns: TableColumnsType<DNSReconcileOperationResult> = [
    { title: t('columns.sequence'), dataIndex: 'source_sequence', width: 70 },
    { title: t('columns.action'), dataIndex: ['operation', 'action'], width: 90, render: (value: DNSReconcileProviderOperation['action']) => t(`operations.${value}`) },
    { title: t('columns.status'), dataIndex: 'status', width: 150, render: (value: string) => t(`operationStatuses.${value}`, { defaultValue: value }) },
    { title: t('columns.providerRequestID'), dataIndex: 'provider_request_id', width: 220, render: (value?: string) => value ? <Typography.Text copyable>{value}</Typography.Text> : t('values.empty') },
    { title: t('columns.providerRecordID'), dataIndex: 'provider_record_id', width: 220, render: (value?: string) => value ? <Typography.Text copyable>{value}</Typography.Text> : t('values.empty') },
    { title: t('columns.errorCode'), dataIndex: 'error_code', width: 180, render: (value: string) => value || t('values.empty') },
  ]
  const observationColumns: TableColumnsType<DNSReconcileObservation> = [
    { title: t('observations.role'), dataIndex: 'role', width: 130, render: (value: DNSReconcileObservation['role']) => t(`observations.roles.${value}`) },
    { title: t('observations.resolver'), dataIndex: 'resolver', width: 180 },
    { title: t('columns.type'), dataIndex: 'record_type', width: 80 },
    { title: t('columns.status'), dataIndex: 'status', width: 150 },
    { title: t('observations.values'), dataIndex: 'values', width: 220, render: (values: string[]) => values.join(', ') || t('values.empty') },
    { title: t('observations.minimumTTL'), dataIndex: 'minimum_ttl', width: 100 },
  ]
  const taskError = taskQuery.error
  const taskForbidden = taskError instanceof ApiError && taskError.status === 403
  const taskNotFound = taskError instanceof ApiError && taskError.status === 404
  const uncertain = Boolean(writeError && ((applyAttempt && isUnknown(writeError)) || (commandAttempt && isUnknown(writeError))))
  const manage = canManage(useSessionStore.getState().principal!)
  const status = task?.result.status
  const canCommit = Boolean(task && status === 'ready_to_commit' && manage)
  const canCancel = Boolean(task && !doneStatuses.has(status ?? '') && manage)
  const finished = Boolean(status && (status === 'ready_to_commit' || status === 'commit_failed' || doneStatuses.has(status)))
  const failed = status === 'failed' || status === 'timed_out'
  const currentStep = taskID ? (finished ? 3 : 2) : plan ? 1 : 0
  const operations = plan?.plan.operations ?? []
  const counts = { create: 0, update: 0, delete: 0 }
  for (const item of operations) counts[item.action] += 1
  const zoneText = zonesQuery.isPending ? t('diagnosis.zoneLoading') : matchedZone?.name ?? (zoneID ? zoneID : t('diagnosis.zoneMissing'))
  const errorCount = Object.keys(fieldErrors).length
  const backToCheck = () => navigate('/site/list', { state: { siteSubnav: 'dnsCheck', dnsCheckBack: context.back } })
  const failureReason = status === 'timed_out' ? t('failureReasons.timed_out') : task?.result.error_code ? t('failureReasons.provider') : t('failureReasons.unknown')
  const observations = task?.result.last_check?.observations ?? []
  const waitMinutes = Math.max(1, Math.ceil((task?.request.propagation_window_seconds ?? Number(propagationWindow)) / 60))
  const seconds = <span className="dns-fix-unit">{t('units.seconds')}</span>
  const advancedFields = (
    <div className="dns-fix-advanced-grid">
      <Field id="dns-fix-type" label={t('fields.type.label')} help={t('fields.type.help')}>
        {(props) => <Select {...props} value={recordType} onChange={edit(setRecordType)} options={['CNAME', 'A', 'AAAA'].map((value) => ({ value, label: value }))} />}
      </Field>
      <Field id="dns-fix-expected" label={t('fields.expectedValue.label')} help={t('fields.expectedValue.help')} error={fieldErrors.expectedValue}>
        {(props) => <Input {...props} value={expectedValue} onChange={(event) => edit(setExpectedValue)(event.target.value)} />}
      </Field>
      <Field id="dns-fix-ttl" label={t('fields.ttl.label')} help={t('fields.ttl.help')} error={fieldErrors.ttl}>
        {(props) => <Input {...props} inputMode="numeric" suffix={seconds} value={ttl} onChange={(event) => edit(setTtl)(event.target.value)} />}
      </Field>
      <Field id="dns-fix-window" label={t('fields.propagationWindow.label')} help={t('fields.propagationWindow.help')} error={fieldErrors.propagationWindow}>
        {(props) => <Input {...props} inputMode="numeric" suffix={seconds} value={propagationWindow} onChange={(event) => edit(setPropagationWindow)(event.target.value)} />}
      </Field>
      <Field id="dns-fix-line" label={t('fields.line.label')} help={t('fields.line.help')} error={fieldErrors.line}>
        {(props) => <Input {...props} value={line} onChange={(event) => edit(setLine)(event.target.value)} />}
      </Field>
      <Field id="dns-fix-weight" label={t('fields.weight.label')} help={t('fields.weight.help')} error={fieldErrors.weight}>
        {(props) => <Input {...props} inputMode="numeric" value={weight} onChange={(event) => edit(setWeight)(event.target.value)} />}
      </Field>
      {zonesQuery.isError ? (
        <Field id="dns-fix-zone" label={t('fields.zoneIDManual.label')} help={t('fields.zoneIDManual.help')} error={fieldErrors.zoneID}>
          {(props) => <Input {...props} value={zoneID} onChange={(event) => edit(setZoneID)(event.target.value)} />}
        </Field>
      ) : (
        <Field id="dns-fix-zone" label={t('fields.zoneID.label')} help={t('fields.zoneID.help')} error={fieldErrors.zoneID}>
          {(props) => <Select {...props} value={zoneID || undefined} loading={zonesQuery.isPending} showSearch optionFilterProp="label"
            options={zones.map((zone) => ({ value: zone.id, label: zone.name }))}
            onChange={(value: string) => {
              edit(setZoneID)(value)
              const zone = zones.find((item) => item.id === value)
              if (zone) setProviderRevision(String(zone.version))
            }} />}
        </Field>
      )}
      <Field id="dns-fix-revision" label={t('fields.providerRevision.label')} help={t('fields.providerRevision.help')} error={fieldErrors.providerRevision}>
        {(props) => <Input {...props} inputMode="numeric" value={providerRevision} onChange={(event) => edit(setProviderRevision)(event.target.value)} />}
      </Field>
      <Field id="dns-fix-ns" label={t('fields.authoritativeNS.label')} help={t('fields.authoritativeNS.help')}>
        {(props) => <Input {...props} value={authoritativeNS} onChange={(event) => edit(setAuthoritativeNS)(event.target.value)} />}
      </Field>
    </div>
  )

  const technical = (
    <Collapse className="dns-fix-technical" size="small" items={[{
      key: 'technical', label: t('technical.title'),
      children: <div className="dns-fix-technical-body">
        {plan ? <Descriptions size="small" bordered column={{ xs: 1, md: 3 }} title={t('technical.plan')}>
          <Descriptions.Item label={t('technical.planRevision')}>{plan.plan.precondition_revision}</Descriptions.Item>
          <Descriptions.Item label={t('technical.digest')}><Typography.Text copyable>{plan.plan.digest}</Typography.Text></Descriptions.Item>
          <Descriptions.Item label={t('technical.planStatus')}><Tag>{t(`statuses.${plan.status}`)}</Tag></Descriptions.Item>
        </Descriptions> : null}
        {task ? <>
          <Descriptions size="small" bordered column={{ xs: 1, md: 3 }}>
            <Descriptions.Item label={t('technical.taskID')}><Typography.Text copyable>{task.id}</Typography.Text></Descriptions.Item>
            <Descriptions.Item label={t('technical.jobAttempt')}>{t('technical.attempt', { attempt: task.job.attempt, maximum: task.job.max_attempts })}</Descriptions.Item>
            <Descriptions.Item label={t('technical.providerRevision')}>{task.result.provider_revision}</Descriptions.Item>
          </Descriptions>
          {task.result.error_code ? <Typography.Text type="secondary">{t('technical.failure', { code: task.result.error_code })}</Typography.Text> : null}
          <Typography.Title level={5}>{t('operationResults.title')}</Typography.Title>
          {task.result.operations.length === 0 ? <DataState status="empty" message={t('operationResults.empty')} /> : <Table
            rowKey="client_request_id" size="small" pagination={false} scroll={{ x: 930 }}
            dataSource={task.result.operations} columns={resultColumns} />}
          <Typography.Title level={5}>{t('propagation.title')}</Typography.Title>
          {task.result.propagation.length === 0 ? <DataState status="empty" message={t('propagation.empty')} /> : <Table rowKey="number" size="small" pagination={false} dataSource={task.result.propagation} columns={[
            { title: t('propagation.attempt'), dataIndex: 'number' },
            { title: t('propagation.status'), dataIndex: 'status', render: (value: string) => t(`propagation.states.${value}`, { defaultValue: value }) },
            { title: t('propagation.healthy'), dataIndex: 'consecutive_healthy' },
          ]} />}
          {observations.length ? <>
            <Typography.Title level={5}>{t('observations.title')}</Typography.Title>
            <Table rowKey={(item) => `${item.role}:${item.resolver}:${item.record_type}`} size="small" pagination={false}
              scroll={{ x: 860 }} dataSource={observations} columns={observationColumns} />
          </> : null}
          {task.result.compensation_plan.length ? <>
            <Typography.Title level={5}>{t('compensation.title')}</Typography.Title>
            <PlanChanges operations={task.result.compensation_plan} />
          </> : null}
        </> : null}
      </div>,
    }]} />
  )
  return (
    <section className="identity-page dns-fix-page" aria-labelledby="dns-reconcile-title">
      <header className="dns-fix-header">
        <div>
          <Typography.Title id="dns-reconcile-title" level={2}>{t('title')}</Typography.Title>
          <Typography.Paragraph type="secondary">{t('description')}</Typography.Paragraph>
        </div>
        <Button icon={<ArrowLeft size={16} aria-hidden="true" />} onClick={backToCheck}>{t('actions.back')}</Button>
      </header>

      <FixSteps current={currentStep} />

      <div className="dns-fix-panel">
        <DnsDiagnosis context={context} zone={zoneText} showNext={!plan && !taskID} action={taskID ? null : (
          <Button type="link" onClick={() => navigate(`/site/${siteID}/dns-reconcile`, { state: null })}>{t('check.changeDomain')}</Button>
        )} />
        {!taskID ? <>
          <Collapse className="dns-fix-advanced" activeKey={advancedOpen ? ['advanced'] : []} onChange={(keys) => setAdvancedOpen(keys.length > 0)}
            items={[{ key: 'advanced', label: <span>{t('advanced.title')}<span className="dns-fix-advanced-summary">{t('advanced.summary')}</span></span>, children: advancedFields }]} />
          {errorCount ? (
            <div ref={errorSummary} tabIndex={-1} role="alert" className="dns-fix-error-summary">
              {t('fieldErrors.summary', { count: errorCount })}
            </div>
          ) : null}
          {dryRunError ? <DataState status="error" message={t(errorKey(dryRunError))} onRetry={() => void doDryRun()} /> : null}
          <div className="dns-fix-actions">
            <Button type={plan ? 'default' : 'primary'} size="large" icon={<Search size={16} aria-hidden="true" />} loading={dryRunPending}
              onClick={() => void doDryRun()}>{plan ? t('plan.recheck') : t('check.action')}</Button>
            {dryRunPending ? <span className="dns-fix-pending" role="status" aria-label={t('check.loading')}>{t('check.loading')}</span> : null}
          </div>
        </> : null}
      </div>

      {plan ? (
        <section className="dns-fix-panel" aria-labelledby="dns-plan-title">
          <div className="dns-fix-section-head">
            <Typography.Title id="dns-plan-title" level={3}>{t('plan.title')}</Typography.Title>
            {operations.length ? <span className="dns-fix-summary">{t('plan.summary', { count: operations.length })}{(['create', 'update', 'delete'] as const)
              .filter((action) => counts[action]).map((action) => t(`plan.summaryParts.${action}`, { count: counts[action] })).join(t('plan.summarySeparator'))}</span> : null}
          </div>
          {operations.length === 0
            ? <Alert type="success" showIcon message={t('plan.none')} />
            : <PlanChanges operations={operations} />}
          {!taskID && operations.length ? (manage
            ? <div className="dns-fix-actions">
              <Popconfirm title={t('confirmations.apply')} okText={t('actions.apply')} cancelText={t('actions.cancel')} onConfirm={startApply}>
                <Button type="primary" size="large" icon={<Play size={16} aria-hidden="true" />} disabled={writePending || Boolean(applyAttempt)} loading={writePending && Boolean(applyAttempt)}>{t('actions.apply')}</Button>
              </Popconfirm>
            </div>
            : <Alert type="info" showIcon message={t('plan.readOnly')} />) : null}
        </section>
      ) : null}

      {uncertain ? (
        <OutcomeUnknown title={t('unknown.title')} detail={t('unknown.description')} action={<Space wrap>
          <Button type="primary" loading={writePending} onClick={() => applyAttempt ? void executeApply(applyAttempt) : commandAttempt ? void executeCommand(commandAttempt) : undefined}>{t('actions.retrySameRequest')}</Button>
          <Button disabled={writePending} onClick={abandonWrite}>{t('actions.abandonRefresh')}</Button>
        </Space>} />
      ) : writeError ? <DataState status="error" message={t(errorKey(writeError))} onRetry={abandonWrite} /> : null}

      {taskID ? (
        <section className="dns-fix-panel" aria-labelledby="dns-task-title" aria-busy={taskQuery.isFetching}>
          <div className="dns-fix-section-head">
            <Typography.Title id="dns-task-title" level={3}>{finished ? t('steps.finish') : t('steps.apply')}</Typography.Title>
            <Space wrap>
              {status ? <Tag color={status === 'committed' ? 'success' : failed || status === 'commit_failed' ? 'error' : status === 'cancelled' ? 'default' : 'processing'}>{t(`statuses.${status}`)}</Tag> : null}
              <Button icon={<RefreshCw size={16} aria-hidden="true" />} loading={taskQuery.isFetching} onClick={() => void taskQuery.refetch()}>{t('actions.refreshTask')}</Button>
            </Space>
          </div>
          {taskQuery.isPending ? <DataState status="loading" message={t('progress.applying')} />
            : taskForbidden ? <DataState status="forbidden" message={t('errors.forbiddenTitle')} description={t('errors.forbiddenDescription')} />
            : taskNotFound ? <Result status="404" title={t('errors.notFoundTitle')} subTitle={t('errors.notFoundDescription')} />
            : taskQuery.isError ? <DataState status="error" message={t(errorKey(taskError))} onRetry={() => void taskQuery.refetch()} />
            : task ? <>
              {status === 'ready_to_commit' ? <Alert type="success" showIcon message={t('finish.readyTitle')} description={t('finish.readyDescription')} />
                : status === 'committed' ? <Result status="success" title={t('finish.committedTitle')} subTitle={t('finish.committedDescription')} />
                : status === 'cancelled' ? <Alert type="info" showIcon message={t('finish.cancelledTitle')} description={t('finish.cancelledDescription')} />
                : status === 'commit_failed' ? <Alert type="error" showIcon message={t('finish.commitFailedTitle', { reason: failureReason })} description={t('finish.commitFailedDescription')} />
                : failed ? <Alert type="error" showIcon message={t('progress.failed', { reason: failureReason })} description={t('progress.failedHint')} />
                : <div className="dns-fix-progress">
                  <Typography.Text strong>{status === 'applying' ? t('progress.applying') : t('progress.propagating')}</Typography.Text>
                  <Progress percent={task.job.progress.total ? Math.round(task.job.progress.completed / task.job.progress.total * 100) : 0}
                    format={() => t('progress.done', task.job.progress)} />
                  <Typography.Text type="secondary">{t('progress.wait', { minutes: waitMinutes })}</Typography.Text>
                </div>}
              {failed || status === 'commit_failed' ? (task.result.last_check ? <FeedbackWhen type="warning" title={t('observations.lkg')} /> : null) : null}
              {!doneStatuses.has(status ?? '') ? <div className="dns-fix-resolvers">
                <Typography.Title level={4}>{t('progress.resolvers')}</Typography.Title>
                {observations.length ? <ul className="dns-fix-resolver-list">
                  {observations.map((item) => {
                    const live = item.status === 'healthy'
                    return <li key={`${item.role}:${item.resolver}:${item.record_type}`} className={live ? 'is-live' : undefined}>
                      {live ? <CircleCheck size={16} aria-hidden="true" /> : <CircleDashed size={16} aria-hidden="true" />}
                      <span className="dns-fix-resolver-name">{t(`observations.roles.${item.role}`)} · {item.resolver}</span>
                      <span className="dns-fix-resolver-state">{live ? t('progress.healthy') : t('progress.pending')}</span>
                      <span className="dns-fix-resolver-values">{item.values.join(', ') || t('values.empty')}</span>
                    </li>
                  })}
                </ul> : <Typography.Text type="secondary">{t('progress.noCheck')}</Typography.Text>}
              </div> : null}
              <div className="dns-fix-actions">
                {canCommit ? <Popconfirm title={t('confirmations.commit')} okText={t('actions.commit')} cancelText={t('actions.cancel')} onConfirm={() => startCommand('commit')}><Button type="primary" size="large" icon={<Check size={16} aria-hidden="true" />} disabled={writePending || Boolean(commandAttempt)}>{t('actions.commit')}</Button></Popconfirm> : null}
                {canCancel ? <Popconfirm title={t('confirmations.cancel')} okText={t('actions.cancelTask')} cancelText={t('actions.keep')} onConfirm={() => startCommand('cancel')}><Button danger icon={<X size={16} aria-hidden="true" />} disabled={writePending || Boolean(commandAttempt)}>{t('actions.cancelTask')}</Button></Popconfirm> : null}
              </div>
            </> : null}
        </section>
      ) : null}

      {plan || task ? technical : null}
    </section>
  )
}

function DnsReconcileStart({ ownerKey, siteID }: { ownerKey: string; siteID: string }) {
  const { t } = useTranslation('dnsReconcilePage')
  return (
    <section className="identity-page dns-fix-page" aria-labelledby="dns-reconcile-title">
      <header className="dns-fix-header">
        <div>
          <Typography.Title id="dns-reconcile-title" level={2}>{t('title')}</Typography.Title>
          <Typography.Paragraph type="secondary">{t('description')}</Typography.Paragraph>
        </div>
      </header>
      <FixSteps current={0} />
      <DomainPicker ownerKey={ownerKey} siteID={siteID} />
    </section>
  )
}

export default function DnsReconcilePage() {
  const { t } = useTranslation('dnsReconcilePage')
  const { id = '' } = useParams()
  const routeState = useLocation().state as { dnsCheck?: SiteDnsCheckContext } | null
  const context = routeState?.dnsCheck?.siteID === id ? routeState.dnsCheck : null
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const owner = principal ? reconcileOwner(principal, sessionEpoch) : null
  if (!accessToken || !principal) return null
  if (!uuidPattern.test(id)) return <Result status="404" title={t('errors.notFoundTitle')} subTitle={t('errors.notFoundDescription')} />
  if (!owner || !canRead(principal)) return <Result status="403" title={t('errors.forbiddenTitle')} subTitle={t('errors.forbiddenDescription')} />
  const ownerKey = JSON.stringify(owner)
  if (!context) return <DnsReconcileStart key={ownerKey} ownerKey={ownerKey} siteID={id} />
  return <DnsReconcileContent key={`${ownerKey}|${context.domain}`} owner={owner} ownerKey={ownerKey} siteID={id} context={context} />
}
