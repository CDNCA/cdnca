import { useEffect, useMemo, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Modal, Result, type TableColumnsType } from 'antd'
import { RotateCcw, Search, Unlock } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import type { AnalyticsAudience } from '../api/analytics'
import { analyticsLogsApi, type BlockStateFilters, type CCCoordinationState } from '../api/analyticsLogs'
import { ApiError, type Principal } from '../api/auth'
import { useSessionStore } from '../auth/session'
import { formatDateTime, formatNumber } from '../i18n/formatters'
import { FeedbackWhen, Table } from '@cdnca/ui'
import { useSearchParams } from 'react-router-dom'
import { sitesApi } from '../api/sites'
import { usersApi } from '../api/users'
import { FieldErrorText, filterFieldProps, useFieldFocus } from '../components/FilterFieldError'
import SearchSelect from '../components/SearchSelect'
import TenantScopeSelect from '../components/TenantScopeSelect'
import { filterParam, useFilterUrl } from './filterUrl'

type CoordinationFieldErrors = Partial<Record<'tenant' | 'site', string>>

type BlockOwner = readonly [Principal['scope_kind'], string, string | null, string, number]

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const staleBlockRead = new Error('Block-state owner changed during read')

function blockOwner(principal: Principal, sessionEpoch: number): BlockOwner | null {
  if (!principal.scope_id?.trim() || !principal.user_id?.trim() || sessionEpoch < 1) return null
  if (principal.scope_kind === 'tenant' && !principal.tenant_id) return null
  if (principal.scope_kind === 'platform' && principal.tenant_id !== null) return null
  return [principal.scope_kind, principal.scope_id, principal.tenant_id, principal.user_id, sessionEpoch]
}

function canReadBlocks(principal: Principal): boolean {
  return principal.permissions.includes('sites.read') ||
    principal.scope_kind === 'platform' && principal.permissions.includes('platform.admin')
}

function currentBlockAccess(ownerKey: string): string | null {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (!accessToken || !principal || !canReadBlocks(principal)) return null
  const owner = blockOwner(principal, sessionEpoch)
  return owner && JSON.stringify(owner) === ownerKey ? accessToken : null
}

function createCoordinationIdentity(kind: 'release' | 'request'): string {
  if (typeof crypto.randomUUID === 'function') return `cc-${kind}-${crypto.randomUUID()}`
  const bytes = new Uint32Array(4)
  crypto.getRandomValues(bytes)
  return `cc-${kind}-${Array.from(bytes, (value) => value.toString(16).padStart(8, '0')).join('')}`
}

export default function CCCoordinationPage() {
  const { t, i18n } = useTranslation('analyticsLogs')
  const queryClient = useQueryClient()
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const owner = useMemo(() => principal ? blockOwner(principal, sessionEpoch) : null, [principal, sessionEpoch])
  // 租户按用户名、邮箱或用户编号选，站点按域名选
  // 并受所选租户约束；已生效的 tenant_id、site_id 写进 URL，刷新后首条请求原样带上。链接里的值无效或站点不属于该租户时
  // 不生效、不查询（不悄悄扩成平台范围），错误挂在字段上并给焦点。请求仍提交实体 UUID，由服务端校验权限。
  const [searchParams] = useSearchParams()
  const [linked] = useState(() => ({ tenant: filterParam(searchParams, 'tenant_id'), site: filterParam(searchParams, 'site_id') }))
  const platformSession = principal?.scope_kind === 'platform'
  const linkErrors = (): CoordinationFieldErrors => ({
    ...(platformSession && linked.tenant && !uuidPattern.test(linked.tenant) ? { tenant: t('blockState.coordination.states.tenantInvalid') } : {}),
    ...(linked.site && !uuidPattern.test(linked.site) ? { site: t('blockState.coordination.states.siteInvalid') } : {}),
  })
  const [fieldErrors, setFieldErrors] = useState<CoordinationFieldErrors>(linkErrors)
  const linkValid = Object.keys(fieldErrors).length === 0
  const [draftTenant, setDraftTenant] = useState(platformSession ? linked.tenant : '')
  const [tenantOwner, setTenantOwner] = useState('')
  const [draftSite, setDraftSite] = useState(linked.site)
  const [applied, setApplied] = useState<BlockStateFilters>(() => linkValid ? {
    ...(linked.site ? { siteId: linked.site } : {}), ...(platformSession && linked.tenant ? { tenantId: linked.tenant } : {}),
  } : {})
  // A linked tenant + site is confirmed before the first read: the site's owner must belong to that tenant.
  const [linkChecked, setLinkChecked] = useState(() => !(linkValid && applied.tenantId && applied.siteId))
  const [blocked, setBlocked] = useState(!linkValid)
  const focusField = useFieldFocus()
  const tenantFieldID = 'cc-coordination-tenant'
  const siteFieldID = 'cc-coordination-site'
  const [generation, setGeneration] = useState(0)
  const [selected, setSelected] = useState<CCCoordinationState | null>(null)
  const [idempotencyKey, setIdempotencyKey] = useState('')
  const [requestId, setRequestId] = useState('')
  const [releasing, setReleasing] = useState(false)
  const [releaseError, setReleaseError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)

  const allowed = Boolean(accessToken && principal && canReadBlocks(principal))
  const ownerKey = owner ? JSON.stringify(owner) : ''
  const audience: AnalyticsAudience = owner?.[0] === 'platform' ? 'admin' : 'tenant'
  const canManage = Boolean(principal?.permissions.includes('security_policies.manage'))
  const locale = i18n.resolvedLanguage ?? 'zh-CN'
  const queryKey = ['analytics-cc-coordination', ownerKey, applied, generation] as const
  const siteOptions = useMemo(() => async (text: string) => {
    const page = await sitesApi.list(currentBlockAccess(ownerKey) ?? '', {
      page: 1, limit: 10, ...(text ? { domain: text } : {}), ...(audience === 'admin' && tenantOwner ? { owner: tenantOwner } : {}),
    })
    return page.items.map((site) => ({ id: site.id, name: site.domain, code: site.display_id, detail: site.owner?.display_name }))
  }, [audience, ownerKey, tenantOwner])

  const coordinationErrorKey = (error: unknown): string => {
    if (!(error instanceof ApiError)) return 'blockState.coordination.states.requestFailed'
    if (error.status === 400 || error.code === 'cc_coordination_invalid_request') {
      return 'blockState.coordination.states.invalidRequest'
    }
    if (error.status === 401 || error.status === 403 || error.code === 'cc_coordination_permission_denied') {
      return 'blockState.coordination.states.permissionDenied'
    }
    if (error.status === 409 || error.code === 'cc_coordination_conflict') return 'blockState.coordination.states.conflict'
    if (error.status === 504 || error.code === 'cc_coordination_timeout') return 'blockState.coordination.states.timeout'
    if (error.status === 503 || error.code === 'cc_coordination_unavailable') {
      return 'blockState.coordination.states.unavailable'
    }
    return 'blockState.coordination.states.requestFailed'
  }

  const query = useQuery({
    queryKey,
    queryFn: async () => {
      const token = currentBlockAccess(ownerKey)
      if (!token) throw staleBlockRead
      // Opens on every state in scope (platform-wide for operators), newest first.
      const result = audience === 'admin'
        ? await analyticsLogsApi.listCCCoordinationStates(token, 'admin', applied)
        : await analyticsLogsApi.listCCCoordinationStates(token, 'tenant', { ...(applied.siteId ? { siteId: applied.siteId } : {}) })
      if (!currentBlockAccess(ownerKey)) throw staleBlockRead
      return result
    },
    enabled: allowed && !blocked && linkChecked && Boolean(currentBlockAccess(ownerKey)),
    retry: false,
    refetchOnReconnect: false,
    refetchOnWindowFocus: false,
  })

  useEffect(() => {
    if (linkChecked || !applied.tenantId || !applied.siteId) return undefined
    let current = true
    const token = currentBlockAccess(ownerKey)
    void (async () => {
      try {
        const site = (await sitesApi.list(token ?? '', { page: 1, limit: 1, site_ids: applied.siteId })).items.find((item) => item.id === applied.siteId)
        const owner = site?.owner ? await usersApi.get(token ?? '', site.owner.id) : null
        if (!current) return
        if (!site || owner?.tenant_id !== applied.tenantId) {
          setFieldErrors({ site: t('blockState.coordination.states.siteNotInTenant') })
          setBlocked(true)
          setApplied({})
          focusField(siteFieldID)
        } else if (owner) setTenantOwner(owner.id)
      } catch {
        // The lookup is a courtesy: when it cannot run, the server still checks the request.
      }
      if (current) setLinkChecked(true)
    })()
    return () => { current = false }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- once, for the link the page opened with
  }, [])
  useEffect(() => {
    if (fieldErrors.tenant) focusField(tenantFieldID)
    else if (fieldErrors.site) focusField(siteFieldID)
    // eslint-disable-next-line react-hooks/exhaustive-deps -- the errors of the link the page opened with
  }, [])
  useFilterUrl({ tenant_id: applied.tenantId, site_id: applied.siteId })

  const apply = () => {
    const tenant = draftTenant.trim()
    const site = draftSite.trim()
    const errors: CoordinationFieldErrors = {
      ...(audience === 'admin' && tenant !== '' && !uuidPattern.test(tenant) ? { tenant: t('blockState.coordination.states.tenantInvalid') } : {}),
      ...(site !== '' && !uuidPattern.test(site) ? { site: t('blockState.coordination.states.siteInvalid') } : {}),
    }
    setFieldErrors(errors)
    if (errors.tenant || errors.site) {
      focusField(errors.tenant ? tenantFieldID : siteFieldID)
      return
    }
    setBlocked(false)
    setLinkChecked(true)
    setSuccess(null)
    setApplied({ ...(site ? { siteId: site } : {}), ...(audience === 'admin' && tenant ? { tenantId: tenant } : {}) })
    setGeneration((value) => value + 1)
  }

  const reset = () => {
    setDraftTenant('')
    setTenantOwner('')
    setDraftSite('')
    setApplied({})
    setFieldErrors({})
    setBlocked(false)
    setLinkChecked(true)
    setSuccess(null)
    setGeneration((value) => value + 1)
  }

  const openRelease = (state: CCCoordinationState) => {
    setSelected(state)
    setIdempotencyKey(createCoordinationIdentity('release'))
    setRequestId(createCoordinationIdentity('request'))
    setReleaseError(null)
  }

  const confirmRelease = async () => {
    if (!selected || !idempotencyKey || !requestId) return
    const token = currentBlockAccess(ownerKey)
    if (!token) {
      setReleaseError(t('blockState.coordination.states.permissionDenied'))
      return
    }
    setReleasing(true)
    setReleaseError(null)
    try {
      const input = {
        stateId: selected.id,
        siteId: selected.site_id,
        expectedGeneration: selected.generation,
        idempotencyKey,
        requestId,
      }
      const result = audience === 'admin'
        ? await analyticsLogsApi.releaseCCCoordinationState(token, 'admin', {
          ...input, tenantId: selected.tenant_id,
        })
        : await analyticsLogsApi.releaseCCCoordinationState(token, 'tenant', input)
      if (!currentBlockAccess(ownerKey)) throw staleBlockRead
      setSelected(null)
      setIdempotencyKey('')
      setRequestId('')
      setSuccess(t('blockState.coordination.states.releaseAccepted', { generation: result.state.generation }))
      await queryClient.invalidateQueries({ queryKey: ['analytics-cc-coordination', ownerKey] })
    } catch (error) {
      setReleaseError(t(coordinationErrorKey(error)))
    } finally {
      setReleasing(false)
    }
  }

  const columns: TableColumnsType<CCCoordinationState> = [
    { title: t('blockState.coordination.table.site'), dataIndex: 'site_id', key: 'site_id', width: 300 },
    { title: t('blockState.coordination.table.cidr'), dataIndex: 'client_cidr', key: 'client_cidr', width: 180 },
    {
      title: t('blockState.coordination.table.request'), key: 'request', width: 340,
      render: (_value, row) => `${row.method} ${row.host}:${row.listen_port}${row.path}`,
    },
    {
      title: t('blockState.coordination.table.hits'), key: 'hits', width: 150,
      render: (_value, row) => t('blockState.coordination.values.hits', {
        hits: formatNumber(row.hit_count, locale), nodes: formatNumber(row.node_count, locale),
      }),
    },
    { title: t('blockState.coordination.table.generation'), dataIndex: 'generation', key: 'generation', width: 100 },
    {
      title: t('blockState.coordination.table.state'), dataIndex: 'state', key: 'state', width: 140,
      render: (value: CCCoordinationState['state']) => t(`blockState.coordination.state.${value}`),
    },
    {
      title: t('blockState.coordination.table.reason'), dataIndex: 'reason_code', key: 'reason_code', width: 210,
      render: (value: CCCoordinationState['reason_code']) => t(`blockState.coordination.reason.${value}`),
    },
    {
      title: t('blockState.coordination.table.policyVersions'), key: 'policyVersions', width: 170,
      render: (_value, row) => t('blockState.coordination.values.policyVersions', {
        current: formatNumber(row.current_policy_version, locale), lkg: formatNumber(row.lkg_policy_version, locale),
      }),
    },
    {
      title: t('blockState.coordination.table.updatedAt'), dataIndex: 'updated_at', key: 'updated_at', width: 190,
      render: (value: string) => formatDateTime(value, locale),
    },
    {
      title: t('blockState.table.actions'), key: 'actions', fixed: 'right', width: 120,
      render: (_value, row) => row.state === 'blocked' ? (
        <Button
          type="link"
          icon={<Unlock size={15} />}
          disabled={!canManage}
          onClick={() => openRelease(row)}
        >
          {t('blockState.coordination.actions.release')}
        </Button>
      ) : null,
    },
  ]

  if (!allowed) {
    return (
      <Result
        className="analytics-page analytics-page-error"
        status="403"
        title={t('states.permissionTitle')}
        subTitle={t('states.permissionDescription')}
      />
    )
  }

  return (
    <section className="analytics-page analytics-log-page" aria-labelledby="analytics-cc-coordination-title">
      <div className="analytics-panel">
        <h1 id="analytics-cc-coordination-title" className="visually-hidden">{t('title.coordination')}</h1>
        <div className="analytics-filter-bar">
          {audience === 'admin' ? (
            <label className="analytics-filter-field">
              <span>{t('filters.tenant')}</span>
              <TenantScopeSelect {...filterFieldProps(tenantFieldID, fieldErrors.tenant)} accessToken={accessToken} ownerKey={ownerKey}
                canList={Boolean(principal?.permissions.some((code) => code === 'identity.users.manage' || code === 'platform.admin'))}
                queryKeyPrefix="cc-coordination-tenants" valueKey="tenant_id" lazy allowClear className="cc-coordination-picker"
                ariaLabel={t('filters.tenant')} placeholder={t('filters.tenantSearchPlaceholder')} emptyText={t('filters.tenantSearchEmpty')}
                value={draftTenant}
                onChange={(tenant) => { setDraftTenant(tenant); setDraftSite(''); setFieldErrors({}) }}
                onPickUser={(user) => setTenantOwner(user?.id ?? '')} />
              <FieldErrorText id={tenantFieldID} error={fieldErrors.tenant} />
            </label>
          ) : null}
          <label className="analytics-filter-field">
            <span>{t('filters.siteName')}</span>
            <SearchSelect {...filterFieldProps(siteFieldID, fieldErrors.site)} className="cc-coordination-picker" allowClear
              queryKey={['cc-coordination-sites', ownerKey, audience === 'admin' ? draftTenant : '', tenantOwner]} search={siteOptions}
              ariaLabel={t('filters.siteName')} placeholder={t('filters.siteSearchPlaceholder')} emptyText={t('filters.siteSearchEmpty')}
              value={draftSite} onChange={(site) => { setDraftSite(site as string); setFieldErrors((current) => ({ ...current, site: undefined })) }} />
            <FieldErrorText id={siteFieldID} error={fieldErrors.site} />
          </label>
          <Button type="primary" icon={<Search size={15} />} onClick={apply}>{t('actions.query')}</Button>
          <Button icon={<RotateCcw size={15} />} onClick={reset}>{t('actions.reset')}</Button>
        </div>
        {success ? <Alert type="success" showIcon message={success} /> : null}
        {query.error && !query.isFetching ? (
          <FeedbackWhen title={t(coordinationErrorKey(query.error))} action={<Button size="small" onClick={() => void query.refetch()}>{t('actions.retry')}</Button>} />
        ) : null}
        <Table<CCCoordinationState>
          data-testid="cc-coordination-state"
          rowKey="id"
          size="small"
          columns={columns}
          dataSource={query.data?.items ?? []}
          loading={query.isFetching && !query.data}
          pagination={false}
          scroll={{ x: 1900 }}
          locale={{
            emptyText: query.error ? ' ' : t('blockState.coordination.states.empty'),
          }}
        />
      </div>
      <Modal
        title={t('blockState.coordination.release.title')}
        open={selected !== null}
        okText={t('blockState.coordination.release.confirm')}
        cancelText={t('blockState.unlock.cancel')}
        okButtonProps={{ danger: true }}
        confirmLoading={releasing}
        onOk={() => void confirmRelease()}
        onCancel={() => {
          if (!releasing) {
            setSelected(null)
            setIdempotencyKey('')
            setRequestId('')
            setReleaseError(null)
          }
        }}
      >
        <p>{t('blockState.coordination.release.description', {
          cidr: selected?.client_cidr ?? '', generation: selected?.generation ?? 0,
        })}</p>
        <p>{t('blockState.coordination.release.reason')}</p>
        {releaseError ? <Alert type="error" showIcon message={releaseError} /> : null}
      </Modal>
    </section>
  )
}
