import { useCallback, useEffect, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  Button,
  Descriptions,
  Input,
  Result,
  Space,
  Spin,
  Table,
  Tag,
  type TableColumnsType,
} from 'antd'
import { ChevronLeft, ChevronRight, Eye, RefreshCw, Search, X } from 'lucide-react'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'
import { useLocation } from 'react-router-dom'

import { ApiError, type Principal } from '../api/auth'
import { cachePoliciesApi, type CachePolicyView } from '../api/cachePolicies'
import { useSessionStore } from '../auth/session'
import { DataState } from '../components/DataState'
import SiteCacheTabs from '../components/SiteCacheTabs'
import '../i18n/cachePolicyHistory'
import { formatBytes, formatDateTime, formatNumber } from '../i18n/formatters'
import './CachePolicyHistoryPage.css'
import CacheOperationHistoryPage from './CacheOperationHistoryPage'

const pageSize = 20
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

type CachePolicyHistoryOwner = readonly ['tenant', string, string, string, number]

const staleHistoryOwner = new ApiError('Cache policy history owner changed', 403, 'permission_denied')

function historyOwner(principal: Principal | null, sessionEpoch: number): CachePolicyHistoryOwner | null {
  if (!principal || principal.scope_kind !== 'tenant' || !sessionEpoch ||
    !uuidPattern.test(principal.scope_id) || !principal.tenant_id ||
    !uuidPattern.test(principal.user_id)) return null
  return ['tenant', principal.scope_id, principal.tenant_id, principal.user_id, sessionEpoch]
}

function currentOwnerCanRead(owner: CachePolicyHistoryOwner): boolean {
  const { accessToken, principal, sessionEpoch, status } = useSessionStore.getState()
  if (!accessToken || status !== 'authenticated' || !principal ||
    !principal.permissions.includes('sites.read')) return false
  const current = historyOwner(principal, sessionEpoch)
  return current !== null && current.every((value, index) => value === owner[index])
}

function localizedError(error: unknown, t: TFunction<'cachePolicyHistory'>): string {
  if (!(error instanceof ApiError)) return t('errors.request_failed')
  const known = new Set([
    'network_error',
    'invalid_response',
    'permission_denied',
    'not_found',
    'invalid_request',
    'service_unavailable',
    'request_failed',
  ])
  return t(known.has(error.code) ? `errors.${error.code}` : 'errors.request_failed')
}

function isForbidden(error: unknown): boolean {
  return error instanceof ApiError && (error.status === 403 || error.code === 'permission_denied')
}

function isNotFound(error: unknown): boolean {
  return error instanceof ApiError && (error.status === 404 || error.code === 'not_found')
}

function CachePolicyHistoryPageOwned({
  accessToken,
  owner,
}: {
  accessToken: string
  owner: CachePolicyHistoryOwner
}) {
  const { t, i18n } = useTranslation('cachePolicyHistory')
  const queryClient = useQueryClient()
  const tokenRef = useRef(accessToken)
  tokenRef.current = accessToken
  const queryPrefixRef = useRef(['cache-policy-history-page', ...owner] as const)
  const queryPrefix = queryPrefixRef.current
  const [siteDraft, setSiteDraft] = useState('')
  const [siteID, setSiteID] = useState('')
  const [validationError, setValidationError] = useState<string>()
  const [pageIndex, setPageIndex] = useState(0)
  const [pageCursors, setPageCursors] = useState<Array<string | undefined>>([undefined])
  const [queryGeneration, setQueryGeneration] = useState(0)
  const [selectedRevision, setSelectedRevision] = useState<number>()
  const cursor = pageCursors[pageIndex]
  const locale = i18n.resolvedLanguage ?? 'zh-CN'

  useEffect(() => () => {
    queryClient.removeQueries({ queryKey: queryPrefix })
  }, [queryClient, queryPrefix])

  const historyQuery = useQuery({
    queryKey: [...queryPrefix, 'list', siteID, queryGeneration, cursor],
    queryFn: async () => {
      if (!currentOwnerCanRead(owner)) throw staleHistoryOwner
      const token = tokenRef.current
      const result = await cachePoliciesApi.history(token, siteID, {
        limit: pageSize,
        ...(cursor ? { cursor } : {}),
      })
      if (!currentOwnerCanRead(owner)) throw staleHistoryOwner
      return result
    },
    enabled: siteID !== '',
    retry: false,
    staleTime: Infinity,
    gcTime: Infinity,
  })
  const nextCursor = historyQuery.data?.next_cursor
  const canAdvance = Boolean(nextCursor && nextCursor !== cursor && !pageCursors.includes(nextCursor))

  const detailQuery = useQuery({
    queryKey: [...queryPrefix, 'detail', siteID, selectedRevision],
    queryFn: async () => {
      if (!currentOwnerCanRead(owner) || selectedRevision === undefined) throw staleHistoryOwner
      const token = tokenRef.current
      const result = await cachePoliciesApi.getRevision(token, siteID, selectedRevision)
      if (!currentOwnerCanRead(owner)) throw staleHistoryOwner
      return result
    },
    enabled: siteID !== '' && selectedRevision !== undefined,
    retry: false,
    staleTime: Infinity,
    gcTime: Infinity,
  })

  const applySite = useCallback(() => {
    const normalized = siteDraft.trim().toLowerCase()
    if (!uuidPattern.test(normalized)) {
      setValidationError(t('filters.invalidSite'))
      return
    }
    setValidationError(undefined)
    setSiteDraft(normalized)
    setSiteID(normalized)
    setPageIndex(0)
    setPageCursors([undefined])
    setSelectedRevision(undefined)
    setQueryGeneration((value) => value + 1)
  }, [siteDraft, t])

  const nextPage = () => {
    if (!nextCursor || !canAdvance) return
    setPageCursors((current) => {
      const next = current.slice(0, pageIndex + 1)
      next.push(nextCursor)
      return next
    })
    setPageIndex((current) => current + 1)
    setSelectedRevision(undefined)
  }

  const previousPage = () => {
    if (pageIndex === 0) return
    setPageIndex((current) => current - 1)
    setSelectedRevision(undefined)
  }

  const columns: TableColumnsType<CachePolicyView> = [
    {
      title: t('table.revision'),
      dataIndex: 'revision',
      key: 'revision',
      width: 90,
      render: (value: number) => formatNumber(value, locale),
    },
    {
      title: t('table.mode'),
      dataIndex: ['document', 'mode'],
      key: 'mode',
      width: 150,
      render: (value: CachePolicyView['document']['mode']) => <Tag>{t(`modes.${value}`)}</Tag>,
    },
    {
      title: t('table.createdAt'),
      dataIndex: 'created_at',
      key: 'created_at',
      width: 190,
      render: (value: string) => formatDateTime(value, locale),
    },
    {
      title: t('table.createdBy'),
      dataIndex: 'created_by_user_id',
      key: 'created_by_user_id',
      width: 300,
    },
    {
      title: t('table.requestId'),
      dataIndex: 'request_id',
      key: 'request_id',
      width: 220,
    },
    {
      title: t('table.action'),
      key: 'action',
      width: 120,
      fixed: 'right',
      render: (_value, item) => (
        <Button
          type="link"
          size="small"
          icon={<Eye size={14} aria-hidden="true" />}
          onClick={() => setSelectedRevision(item.revision)}
        >
          {t('actions.view')}
        </Button>
      ),
    },
  ]

  const historyError = historyQuery.error
  const forbidden = isForbidden(historyError)
  const notFound = isNotFound(historyError)

  return (
    <div className="identity-page cache-policy-history-page" style={{ minWidth: 0, maxWidth: '100%' }}>
      <SiteCacheTabs active="history" />
      <header className="identity-page-header">
        <div>
          <h1 className="cache-page-heading">{t('title')}</h1>
          <p className="cache-page-subtitle">{t('subtitle')}</p>
        </div>
        <Button
          icon={<RefreshCw size={15} aria-hidden="true" />}
          disabled={!siteID || historyQuery.isFetching}
          onClick={() => void historyQuery.refetch()}
        >
          {t('actions.refresh')}
        </Button>
      </header>

      <form
        className="identity-toolbar"
        onSubmit={(event) => {
          event.preventDefault()
          applySite()
        }}
      >
        <label style={{ minWidth: 260, flex: '1 1 360px' }}>
          <span>{t('filters.siteId')}</span>
          <Input
            aria-label={t('filters.siteId')}
            value={siteDraft}
            placeholder={t('filters.sitePlaceholder')}
            maxLength={64}
            onChange={(event) => {
              setSiteDraft(event.target.value)
              setValidationError(undefined)
            }}
          />
        </label>
        <Button type="primary" htmlType="submit" icon={<Search size={15} aria-hidden="true" />}>
          {t('actions.search')}
        </Button>
      </form>

      {validationError ? <Alert type="warning" showIcon message={validationError} /> : null}

      {!siteID ? <DataState status="empty" message={t('states.selectSite')} /> : null}

      {siteID && historyQuery.isPending ? (
        <div className="data-state" aria-label={t('states.loading')} aria-busy="true">
          <Spin size="small" />
        </div>
      ) : null}

      {siteID && forbidden ? (
        <Result
          status="403"
          title={t('states.forbiddenTitle')}
          subTitle={t('states.forbiddenDescription')}
        />
      ) : null}

      {siteID && notFound ? (
        <Result
          status="404"
          title={t('states.notFoundTitle')}
          subTitle={t('states.notFoundDescription')}
          extra={(
            <Button type="primary" onClick={() => void historyQuery.refetch()}>
              {t('actions.retry')}
            </Button>
          )}
        />
      ) : null}

      {siteID && historyQuery.isError && !forbidden && !notFound ? (
        <DataState
          status="error"
          message={localizedError(historyError, t)}
          onRetry={() => void historyQuery.refetch()}
        />
      ) : null}

      {siteID && historyQuery.isSuccess && historyQuery.data.items.length === 0 ? (
        <DataState status="empty" message={t('states.empty')} />
      ) : null}

      {siteID && historyQuery.isSuccess && historyQuery.data.items.length > 0 ? (
        <section aria-busy={historyQuery.isFetching} style={{ minWidth: 0, maxWidth: '100%' }}>
          <Table
            rowKey="revision"
            size="small"
            loading={historyQuery.isFetching}
            columns={columns}
            dataSource={historyQuery.data.items}
            pagination={false}
            scroll={{ x: 1070 }}
          />
          <Space wrap style={{ width: '100%', justifyContent: 'flex-end', marginTop: 12 }}>
            <Button
              icon={<ChevronLeft size={15} aria-hidden="true" />}
              disabled={pageIndex === 0 || historyQuery.isFetching}
              onClick={previousPage}
            >
              {t('actions.previous')}
            </Button>
            <span>{t('table.page', { page: formatNumber(pageIndex + 1, locale) })}</span>
            <Button
              icon={<ChevronRight size={15} aria-hidden="true" />}
              disabled={!canAdvance || historyQuery.isFetching}
              onClick={nextPage}
            >
              {t('actions.next')}
            </Button>
          </Space>
        </section>
      ) : null}

      {historyQuery.isSuccess && selectedRevision !== undefined ? (
        <section
          role="region"
          aria-label={t('detail.title', { revision: selectedRevision })}
          aria-busy={detailQuery.isPending || detailQuery.isFetching}
          style={{ minWidth: 0, maxWidth: '100%', marginTop: 16 }}
        >
          <Space wrap style={{ width: '100%', justifyContent: 'space-between' }}>
            <h2>{t('detail.title', { revision: selectedRevision })}</h2>
            <Button
              icon={<X size={15} aria-hidden="true" />}
              onClick={() => setSelectedRevision(undefined)}
            >
              {t('actions.close')}
            </Button>
          </Space>
          {detailQuery.isPending ? (
            <div className="data-state" aria-label={t('states.detailLoading')} aria-busy="true">
              <Spin size="small" />
            </div>
          ) : null}
          {detailQuery.isError ? (
            <DataState
              status="error"
              message={isNotFound(detailQuery.error)
                ? t('states.detailNotFound')
                : localizedError(detailQuery.error, t)}
              onRetry={() => void detailQuery.refetch()}
            />
          ) : null}
          {detailQuery.data ? (
            <Descriptions bordered size="small" column={{ xs: 1, sm: 1, md: 2 }}>
              <Descriptions.Item label={t('detail.siteId')}>{detailQuery.data.site_id}</Descriptions.Item>
              <Descriptions.Item label={t('detail.revision')}>
                {formatNumber(detailQuery.data.revision, locale)}
              </Descriptions.Item>
              <Descriptions.Item label={t('detail.mode')}>
                {t(`modes.${detailQuery.data.document.mode}`)}
              </Descriptions.Item>
              <Descriptions.Item label={t('detail.queryMode')}>
                {t(`queryModes.${detailQuery.data.document.query_mode}`)}
              </Descriptions.Item>
              <Descriptions.Item label={t('detail.ruleCount')}>
                {formatNumber(detailQuery.data.document.rules.length, locale)}
              </Descriptions.Item>
              <Descriptions.Item label={t('detail.diskQuota')}>
                {formatBytes(detailQuery.data.document.disk_quota_bytes, locale)}
              </Descriptions.Item>
              <Descriptions.Item label={t('detail.createdAt')}>
                {formatDateTime(detailQuery.data.created_at, locale)}
              </Descriptions.Item>
              <Descriptions.Item label={t('detail.createdBy')}>
                {detailQuery.data.created_by_user_id}
              </Descriptions.Item>
              <Descriptions.Item label={t('detail.requestId')}>
                {detailQuery.data.request_id}
              </Descriptions.Item>
            </Descriptions>
          ) : null}
        </section>
      ) : null}
    </div>
  )
}

export default function CachePolicyHistoryPage() {
  const location = useLocation()
  if (location.pathname === '/site/cache-clean/history') {
    return <CacheOperationHistoryPage />
  }
  return <CachePolicyHistoryContent />
}

function CachePolicyHistoryContent() {
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const status = useSessionStore((state) => state.status)
  const { t } = useTranslation('cachePolicyHistory')
  const owner = historyOwner(principal, sessionEpoch)
  const canRead = status === 'authenticated' && accessToken !== null && owner !== null &&
    principal?.permissions.includes('sites.read')

  if (!canRead || !accessToken || !owner) {
    return (
      <Result
        status="403"
        title={t('states.forbiddenTitle')}
        subTitle={t('states.forbiddenDescription')}
      />
    )
  }

  return (
    <CachePolicyHistoryPageOwned
      key={JSON.stringify(owner)}
      accessToken={accessToken}
      owner={owner}
    />
  )
}
