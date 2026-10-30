import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Button, Descriptions, Drawer, Input, Result, Space, Table, Tag, Tooltip, Typography, type TableColumnsType } from 'antd'
import { ChevronLeft, ChevronRight, Eye, RefreshCw, Search, Stethoscope } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { useSearchParams } from 'react-router-dom'

import { ApiError, type Principal } from '../api/auth'
import {
  cnameAllocationsApi,
  type CnameAllocation,
  type CnameAllocationAudience,
  type CnameAllocationDiagnosisParams,
  type CnameAllocationMode,
  type CnameAllocationState,
} from '../api/cnameAllocations'
import { useSessionStore } from '../auth/session'
import { DataState } from '../components/DataState'
import { formatDateTime } from '../i18n/formatters'
import '../i18n/cnameAllocations'
import './CnameAllocationsPage.css'

type Owner = readonly ['tenant' | 'platform', string, string, string, number]

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const staleRead = new Error('CNAME allocation owner changed during read')
const stateColors: Record<CnameAllocationState, string> = { pending: 'processing', failed: 'error', done: 'success' }

function cnameAllocationOwner(principal: Principal, sessionEpoch: number): Owner | null {
  if (!principal.scope_id || !principal.user_id || sessionEpoch < 1) return null
  if (principal.scope_kind === 'tenant' && principal.tenant_id) {
    return ['tenant', principal.scope_id, principal.tenant_id, principal.user_id, sessionEpoch]
  }
  if (principal.scope_kind === 'platform' && principal.tenant_id === null) {
    return ['platform', principal.scope_id, '', principal.user_id, sessionEpoch]
  }
  return null
}

function canRead(principal: Principal): boolean {
  return principal.scope_kind === 'tenant'
    ? principal.permissions.includes('dns.read')
    : principal.scope_kind === 'platform' && principal.permissions.includes('platform.admin')
}

function currentCnameAccess(ownerKey: string): string | null {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (!accessToken || !principal || !canRead(principal)) return null
  const owner = cnameAllocationOwner(principal, sessionEpoch)
  return owner && JSON.stringify(owner) === ownerKey ? accessToken : null
}

function cnameErrorKey(error: unknown): string {
  if (!(error instanceof ApiError)) return 'errors.requestFailed'
  if (error.status === 404 || error.code === 'cname_allocation_not_found') return 'errors.notFound'
  if (error.status === 408 || error.code === 'request_timeout') return 'errors.requestTimeout'
  if (error.status === 503 || error.code === 'cname_allocation_unavailable') return 'errors.unavailable'
  if (error.code === 'network_error') return 'errors.network'
  if (error.code === 'cname_allocation_invalid_response') return 'errors.invalidResponse'
  if (error.status === 400 || error.code === 'validation_error') return 'errors.validation'
  return 'errors.requestFailed'
}

function isForbidden(error: unknown) {
  return error instanceof ApiError && (error.status === 403 || error.code === 'permission_denied')
}

function validName(value: string) {
  return value.length <= 253 && value === value.trim() && value === value.toLowerCase() &&
    !/\s/.test(value) && !value.startsWith('.') && !value.endsWith('.')
}

export default function CnameAllocationsPage() {
  const { t } = useTranslation('cnameAllocations')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const owner = useMemo(() => principal ? cnameAllocationOwner(principal, sessionEpoch) : null, [principal, sessionEpoch])

  if (!accessToken || !principal) return null
  if (!owner || !canRead(principal)) {
    return <Result status="403" title={t('errors.forbiddenTitle')} subTitle={t('errors.forbiddenDescription')} />
  }
  const ownerKey = JSON.stringify(owner)
  return <CnameAllocationsContent key={ownerKey} owner={owner} ownerKey={ownerKey} />
}

function CnameAllocationsContent({ owner, ownerKey }: { owner: Owner; ownerKey: string }) {
  const { t, i18n } = useTranslation('cnameAllocations')
  const queryClient = useQueryClient()
  const [searchParams, setSearchParams] = useSearchParams()
  const initialScope = owner[0] === 'platform' ? searchParams.get('scope_id') ?? '' : owner[2]
  const [scopeDraft, setScopeDraft] = useState(initialScope)
  const [scopeError, setScopeError] = useState(Boolean(owner[0] === 'platform' && initialScope && !uuidPattern.test(initialScope)))
  const activeScope = owner[0] === 'tenant' ? owner[2] : uuidPattern.test(initialScope) ? initialScope : ''
  const [cursors, setCursors] = useState<string[]>([])
  const [selectedID, setSelectedID] = useState<string>()
  const [siteID, setSiteID] = useState('')
  const [domain, setDomain] = useState('')
  const [hostname, setHostname] = useState('')
  const [diagnosisError, setDiagnosisError] = useState(false)
  const [diagnosisRequest, setDiagnosisRequest] = useState<CnameAllocationDiagnosisParams>()
  const fixedOwner = useRef(owner).current
  const lineageActive = useRef(true)
  const cursor = cursors.at(-1)
  const prefix = useMemo(() => ['cname-allocations', ...fixedOwner] as const, [fixedOwner])
  const audience = useMemo<CnameAllocationAudience>(() => owner[0] === 'tenant'
    ? { kind: 'tenant' }
    : { kind: 'platform', scopeID: activeScope }, [activeScope, owner])
  const identity = JSON.stringify([...prefix, activeScope, 20, cursor ?? ''])
  const activeIdentity = useRef(identity)
  activeIdentity.current = identity

  const guardedRead = useCallback(async <T,>(read: (token: string) => Promise<T>, requestIdentity?: string) => {
    const token = lineageActive.current ? currentCnameAccess(ownerKey) : null
    if (!token) throw staleRead
    try {
      const value = await read(token)
      if (!currentCnameAccess(ownerKey) || (requestIdentity && activeIdentity.current !== requestIdentity)) throw staleRead
      return value
    } catch (error) {
      if (!currentCnameAccess(ownerKey) || (requestIdentity && activeIdentity.current !== requestIdentity)) throw staleRead
      throw error
    }
  }, [ownerKey])

  const listQuery = useQuery({
    queryKey: [...prefix, activeScope, 20, cursor ?? ''],
    queryFn: () => guardedRead((token) => cnameAllocationsApi.list(token, audience, { limit: 20, cursor }), identity),
    enabled: Boolean(activeScope), retry: false, refetchOnWindowFocus: false, refetchOnReconnect: false,
  })
  const detailQuery = useQuery({
    queryKey: [...prefix, 'detail', activeScope, selectedID ?? ''],
    queryFn: () => guardedRead((token) => cnameAllocationsApi.get(token, audience, selectedID!)),
    enabled: Boolean(activeScope && selectedID), retry: false, refetchOnWindowFocus: false, refetchOnReconnect: false,
  })
  const diagnosisQuery = useQuery({
    queryKey: [...prefix, 'diagnosis', activeScope, diagnosisRequest ?? null],
    queryFn: () => guardedRead((token) => cnameAllocationsApi.diagnose(token, audience, diagnosisRequest!)),
    enabled: Boolean(activeScope && diagnosisRequest), retry: false, refetchOnWindowFocus: false, refetchOnReconnect: false,
  })

  useEffect(() => () => {
    lineageActive.current = false
    queryClient.removeQueries({ queryKey: prefix })
  }, [prefix, queryClient])

  const locale = i18n.resolvedLanguage ?? i18n.language
  const columns: TableColumnsType<CnameAllocation> = [
    { title: t('columns.id'), dataIndex: 'id', width: 285 },
    { title: t('columns.mode'), dataIndex: 'mode', width: 90, render: (value: CnameAllocationMode) => t(`modes.${value}`) },
    { title: t('columns.domain'), dataIndex: 'domain', width: 180 },
    { title: t('columns.hostname'), dataIndex: 'hostname', width: 210 },
    { title: t('columns.state'), dataIndex: 'state', width: 100, render: (value: CnameAllocationState) => <Tag color={stateColors[value]}>{t(`states.${value}`)}</Tag> },
    { title: t('columns.generation'), dataIndex: 'generation', width: 90 },
    { title: t('columns.revision'), dataIndex: 'current_revision', width: 100 },
    { title: t('columns.updated'), dataIndex: 'updated_at', width: 180, render: (value: string) => formatDateTime(value, locale) || value },
    { title: t('columns.actions'), key: 'actions', width: 80, fixed: 'right', render: (_, row) => <Tooltip title={t('actions.detail')}><Button aria-label={t('actions.detail')} icon={<Eye size={15} />} onClick={() => setSelectedID(row.id)} /></Tooltip> },
  ]

  if (isForbidden(listQuery.error)) {
    return <Result status="403" title={t('errors.forbiddenTitle')} subTitle={t('errors.forbiddenDescription')} />
  }
  const applyScope = () => {
    const value = scopeDraft.trim()
    if (!uuidPattern.test(value)) { setScopeError(true); return }
    setScopeError(false); setCursors([]); setSelectedID(undefined); setDiagnosisRequest(undefined)
    setSearchParams({ scope_id: value })
  }
  const diagnose = () => {
    const next = { siteID: siteID.trim(), domain: domain.trim() || undefined, hostname: hostname.trim() || undefined }
    if (!uuidPattern.test(next.siteID) || (next.domain !== undefined && !validName(next.domain)) || (next.hostname !== undefined && !validName(next.hostname))) {
      setDiagnosisError(true); return
    }
    setDiagnosisError(false)
    if (JSON.stringify(next) === JSON.stringify(diagnosisRequest)) void diagnosisQuery.refetch()
    else setDiagnosisRequest(next)
  }
  const items = listQuery.data?.items ?? []

  return <section className="identity-page cname-allocations-page" aria-labelledby="cname-allocations-title">
    <header className="cname-allocations-header"><div><Typography.Title id="cname-allocations-title" level={2}>{t('title')}</Typography.Title><Typography.Paragraph type="secondary">{t(`description.${owner[0]}`)}</Typography.Paragraph></div><Button icon={<RefreshCw size={16} />} loading={listQuery.isFetching} disabled={!activeScope} onClick={() => void listQuery.refetch()}>{t('actions.refresh')}</Button></header>
    {owner[0] === 'platform' ? <><Space wrap className="cname-allocations-toolbar"><Input aria-label={t('scope.label')} value={scopeDraft} status={scopeError ? 'error' : undefined} onChange={(event) => { setScopeDraft(event.target.value); setScopeError(false) }} onPressEnter={applyScope} /><Button type="primary" icon={<Search size={15} />} onClick={applyScope}>{t('scope.query')}</Button></Space>{scopeError ? <div role="alert" className="data-state data-state-error">{t('scope.invalid')}</div> : null}</> : null}
    {!activeScope ? <DataState status="empty" message={t('scope.prompt')} /> : listQuery.isPending ? <DataState status="loading" message={t('data.loading')} /> : listQuery.isError ? <DataState status="error" message={t(cnameErrorKey(listQuery.error))} onRetry={() => void listQuery.refetch()} /> : items.length === 0 ? <DataState status="empty" message={t('data.empty')} /> : <div aria-busy={listQuery.isFetching}><Table<CnameAllocation> rowKey="id" size="small" columns={columns} dataSource={items} pagination={false} scroll={{ x: 1320 }} /></div>}
    {activeScope ? <footer className="identity-pagination"><Button aria-label={t('actions.previous')} icon={<ChevronLeft size={16} />} disabled={!cursors.length || listQuery.isFetching} onClick={() => setCursors((value) => value.slice(0, -1))} /><span>{t('pagination.page', { page: cursors.length + 1 })}</span><Button aria-label={t('actions.next')} icon={<ChevronRight size={16} />} disabled={!listQuery.data?.next_cursor || listQuery.isFetching} onClick={() => { if (listQuery.data?.next_cursor) setCursors((value) => [...value, listQuery.data!.next_cursor!]) }} /></footer> : null}

    {activeScope ? <section className="cname-allocations-diagnosis"><Typography.Title level={3}>{t('diagnosis.title')}</Typography.Title><Space wrap className="cname-allocations-toolbar"><Input aria-label={t('diagnosis.site')} value={siteID} onChange={(event) => setSiteID(event.target.value)} /><Input aria-label={t('diagnosis.domain')} value={domain} onChange={(event) => setDomain(event.target.value)} /><Input aria-label={t('diagnosis.hostname')} value={hostname} onChange={(event) => setHostname(event.target.value)} /><Button icon={<Stethoscope size={15} />} onClick={diagnose}>{t('actions.diagnose')}</Button></Space>{diagnosisError ? <div role="alert" className="data-state data-state-error">{t('diagnosis.invalid')}</div> : diagnosisQuery.isPending && diagnosisRequest ? <DataState status="loading" message={t('data.diagnosisLoading')} /> : isForbidden(diagnosisQuery.error) ? <DataState status="forbidden" message={t('errors.forbiddenTitle')} description={t('errors.forbiddenDescription')} /> : diagnosisQuery.isError ? <DataState status="error" message={t(cnameErrorKey(diagnosisQuery.error))} onRetry={() => void diagnosisQuery.refetch()} /> : diagnosisQuery.data ? <div aria-label={t('diagnosis.result')}><Tag color={diagnosisQuery.data.ready ? 'success' : 'error'}>{t(diagnosisQuery.data.ready ? 'diagnosis.ready' : 'diagnosis.blocked')}</Tag><ul>{diagnosisQuery.data.reason_codes.map((code) => <li key={code}>{t(`reasons.${code}`, { defaultValue: t('reasons.unknown') })}</li>)}</ul></div> : null}</section> : null}

    <Drawer title={t('actions.detail')} open={Boolean(selectedID)} width={680} onClose={() => setSelectedID(undefined)}>{detailQuery.isPending ? <DataState status="loading" message={t('data.detailLoading')} /> : isForbidden(detailQuery.error) ? <DataState status="forbidden" message={t('errors.forbiddenTitle')} description={t('errors.forbiddenDescription')} /> : detailQuery.isError ? <DataState status="error" message={t(cnameErrorKey(detailQuery.error))} onRetry={detailQuery.error instanceof ApiError && detailQuery.error.status === 404 ? undefined : () => void detailQuery.refetch()} /> : detailQuery.data ? <Descriptions bordered size="small" column={1}><Descriptions.Item label={t('columns.id')}>{detailQuery.data.id}</Descriptions.Item><Descriptions.Item label={t('columns.owner')}>{detailQuery.data.owner_id}</Descriptions.Item><Descriptions.Item label={t('columns.provider')}>{detailQuery.data.provider_id}</Descriptions.Item><Descriptions.Item label={t('columns.zone')}>{detailQuery.data.zone_id}</Descriptions.Item><Descriptions.Item label={t('columns.job')}>{detailQuery.data.job_id}</Descriptions.Item><Descriptions.Item label={t('columns.explicit')}>{t(detailQuery.data.explicit_hostname ? 'values.yes' : 'values.no')}</Descriptions.Item><Descriptions.Item label={t('columns.lkg')}>{detailQuery.data.lkg_revision ?? t('values.none')}</Descriptions.Item></Descriptions> : null}</Drawer>
  </section>
}
