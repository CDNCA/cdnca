import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Button, Modal, Result, Space, Table, Tag, Typography, type TableColumnsType } from 'antd'
import { ChevronLeft, ChevronRight, RefreshCw, ShieldOff } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApiError, type Principal } from '../api/auth'
import {
  createIdentitySessionRevokeAttempt,
  identitySessionsApi,
  type IdentitySessionFamily,
  type IdentitySessionFamilyPage,
  type IdentitySessionRevokeAttempt,
} from '../api/identitySessions'
import { useSessionStore } from '../auth/session'
import { DataState } from '../components/DataState'
import { formatDateTime } from '../i18n/formatters'
import '../i18n/identitySessions'
import './IdentitySessionsPage.css'
import { FeedbackWhen, OutcomeUnknown } from '@cdnca/ui'

type Owner = readonly [Principal['scope_kind'], string, string | null, string, number]

const queryRoot = 'identity-sessions'
const staleRead = new Error('identity session owner changed during read')

function sessionOwner(principal: Principal, sessionEpoch: number): Owner | null {
  const { scope_id: scopeID, tenant_id: tenantID, user_id: userID } = principal
  if (!scopeID || scopeID.trim() !== scopeID || !userID || userID.trim() !== userID || sessionEpoch < 1) return null
  if (principal.scope_kind === 'tenant' && !tenantID) return null
  if (principal.scope_kind === 'platform' && tenantID !== null) return null
  return [principal.scope_kind, scopeID, tenantID, userID, sessionEpoch]
}

function currentAccess(ownerKey: string): string | null {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (!accessToken || !principal) return null
  const owner = sessionOwner(principal, sessionEpoch)
  return owner && JSON.stringify(owner) === ownerKey ? accessToken : null
}

function unknownOutcome(error: unknown): boolean {
  return !(error instanceof ApiError) || error.status === 0 || error.status === 408 ||
    error.status >= 500 || error.code === 'identity_session_invalid_response'
}

function errorKey(error: unknown): string {
  if (!(error instanceof ApiError)) return 'errors.requestFailed'
  if (error.status === 401 || error.code === 'identity_session_unauthenticated') return 'errors.unauthenticated'
  if (error.status === 404 || error.code === 'identity_session_not_found') return 'errors.notFound'
  if (error.code === 'identity_session_revision_conflict') return 'errors.revisionConflict'
  if (error.code === 'identity_session_idempotency_conflict') return 'errors.idempotencyConflict'
  if (error.code === 'identity_session_already_revoked') return 'errors.alreadyRevoked'
  if (error.status === 503 || error.code === 'identity_session_unavailable') return 'errors.unavailable'
  return 'errors.requestFailed'
}

function deviceLabel(value: string): string {
  return value.replace(' on ', ' / ')
}

function IdentitySessionsContent({ owner }: { owner: Owner }) {
  const { t, i18n } = useTranslation('identitySessions')
  const queryClient = useQueryClient()
  const fixedOwner = useRef(owner).current
  const ownerKey = JSON.stringify(fixedOwner)
  const queryPrefix = useMemo(() => [queryRoot, ...fixedOwner] as const, [fixedOwner])
  const [cursors, setCursors] = useState<Array<string | undefined>>([undefined])
  const [confirmFamily, setConfirmFamily] = useState<IdentitySessionFamily | null>(null)
  const [attempt, setAttempt] = useState<IdentitySessionRevokeAttempt | null>(null)
  const [writeError, setWriteError] = useState<unknown>(null)
  const [writePending, setWritePending] = useState(false)
  const [abandonPending, setAbandonPending] = useState(false)
  const activeRef = useRef(true)
  const cursor = cursors.at(-1)
  const queryKey = useMemo(() => [...queryPrefix, 20, cursor ?? null] as const, [cursor, queryPrefix])
  const access = useCallback(() => activeRef.current ? currentAccess(ownerKey) : null, [ownerKey])

  const query = useQuery({
    queryKey,
    retry: false,
    refetchOnReconnect: false,
    refetchOnWindowFocus: false,
    queryFn: async ({ signal }) => {
      const token = access()
      if (!token) throw staleRead
      try {
        const page = await identitySessionsApi.list(token, { limit: 20, cursor }, signal)
        if (!access()) throw staleRead
        return page
      } catch (error) {
        if (!access()) throw staleRead
        throw error
      }
    },
  })

  useEffect(() => {
    activeRef.current = true
    return () => {
      activeRef.current = false
      void queryClient.cancelQueries({ queryKey: queryPrefix })
      queryClient.removeQueries({ queryKey: queryPrefix })
    }
  }, [queryClient, queryPrefix])

  const executeRevoke = async (nextAttempt: IdentitySessionRevokeAttempt) => {
    if (writePending || abandonPending) return
    const token = access()
    if (!token) return
    setWritePending(true)
    setWriteError(null)
    try {
      const result = await identitySessionsApi.revoke(token, nextAttempt)
      if (!access()) return
      setAttempt(null)
      if (result.current) {
        useSessionStore.getState().clearSession()
        return
      }
      queryClient.setQueryData(queryKey, (page: IdentitySessionFamilyPage | undefined) => page && ({
        ...page,
        items: page.items.map((item) => item.family_id === result.family_id ? {
          ...item, active: false, revoked_at: result.revoked_at, revision: result.revision,
        } : item),
      }))
    } catch (error) {
      if (!access()) return
      setWriteError(error)
      if (!unknownOutcome(error)) setAttempt(null)
    } finally {
      if (access()) setWritePending(false)
    }
  }

  const confirmRevoke = () => {
    if (!confirmFamily || attempt || writePending || abandonPending) return
    const nextAttempt = createIdentitySessionRevokeAttempt(confirmFamily.family_id, confirmFamily.revision)
    setConfirmFamily(null)
    setAttempt(nextAttempt)
    void executeRevoke(nextAttempt)
  }

  const abandonAndRefresh = async () => {
    if (!attempt || writePending || abandonPending) return
    setAbandonPending(true)
    const result = await query.refetch()
    if (!access()) return
    if (result.isSuccess) {
      setAttempt(null)
      setWriteError(null)
    }
    setAbandonPending(false)
  }

  const error = query.error
  if (error instanceof ApiError && error.status === 403) {
    return <Result status="403" title={t('errors.forbiddenTitle')} subTitle={t('errors.forbiddenDescription')} />
  }

  const uncertain = Boolean(attempt && writeError && unknownOutcome(writeError))
  const writesLocked = writePending || abandonPending || uncertain
  const locale = i18n.resolvedLanguage ?? i18n.language
  const columns: TableColumnsType<IdentitySessionFamily> = [
    {
      title: t('columns.device'), dataIndex: 'device_label', width: 210,
      render: (value, item) => <Space wrap><span>{deviceLabel(value)}</span>{item.current ? <Tag color="blue">{t('values.current')}</Tag> : null}</Space>,
    },
    { title: t('columns.network'), dataIndex: 'ip_prefix', width: 180, render: (value) => value ?? t('values.unknownNetwork') },
    { title: t('columns.lastActive'), dataIndex: 'last_used_at', width: 190, render: (value) => formatDateTime(value, locale) },
    { title: t('columns.sessions'), dataIndex: 'session_count', width: 100, render: (value) => t('values.count', { count: value }) },
    {
      title: t('columns.status'), key: 'status', width: 110,
      render: (_, item) => item.revoked_at || !item.active
        ? <Tag>{item.revoked_at ? t('values.revoked') : t('values.expired')}</Tag>
        : <Tag color="green">{t('values.active')}</Tag>,
    },
    {
      title: t('columns.actions'), key: 'actions', width: 130,
      render: (_, item) => <Button
        danger size="small" icon={<ShieldOff size={15} aria-hidden="true" />}
        disabled={writesLocked || !item.active} onClick={() => setConfirmFamily(item)}
      >{t('actions.revoke')}</Button>,
    },
  ]

  return (
    <section className="identity-page identity-sessions-page" aria-labelledby="identity-sessions-title">
      <header className="identity-page-header identity-sessions-header">
        <div>
          <Typography.Title id="identity-sessions-title" level={2}>{t('title')}</Typography.Title>
          <Typography.Paragraph type="secondary">{t('description')}</Typography.Paragraph>
        </div>
        <Button
          icon={<RefreshCw size={16} aria-hidden="true" />} loading={query.isFetching}
          disabled={writesLocked} onClick={() => void query.refetch()}
        >{t('actions.refresh')}</Button>
      </header>

      {uncertain ? <OutcomeUnknown title={t('uncertainty.title')} detail={t('uncertainty.description')} action={<Space wrap>
          <Button type="primary" loading={writePending} onClick={() => attempt && void executeRevoke(attempt)}>{t('actions.retrySame')}</Button>
          <Button loading={abandonPending} disabled={writePending} onClick={() => void abandonAndRefresh()}>{t('actions.abandonRefresh')}</Button>
        </Space>} className="identity-alert" /> : writeError ? <FeedbackWhen title={t(errorKey(writeError))} /> : null}

      {query.isPending ? <DataState status="loading" message={t('loading')} /> : query.isError ? (
        <DataState status="error" message={t(errorKey(query.error))} onRetry={() => void query.refetch()} />
      ) : query.data.items.length === 0 ? <DataState status="empty" message={t('empty')} /> : (
        <div className="identity-table-scroll identity-sessions-table-scroll">
          <Table rowKey="family_id" size="small" pagination={false} dataSource={query.data.items} columns={columns} scroll={{ x: 920 }} />
          <Space className="identity-sessions-pagination">
            <Button icon={<ChevronLeft size={16} aria-hidden="true" />} disabled={writesLocked || cursors.length === 1} onClick={() => setCursors((value) => value.slice(0, -1))}>{t('actions.previous')}</Button>
            <Button icon={<ChevronRight size={16} aria-hidden="true" />} disabled={writesLocked || !query.data.next_cursor} onClick={() => query.data.next_cursor && setCursors((value) => [...value, query.data.next_cursor])}>{t('actions.next')}</Button>
          </Space>
        </div>
      )}

      <Modal
        className="identity-sessions-modal"
        open={Boolean(confirmFamily)} title={t('confirmation.title')}
        okText={t('actions.confirmRevoke')} cancelText={t('actions.cancel')}
        okButtonProps={{ danger: true }} onOk={confirmRevoke} onCancel={() => setConfirmFamily(null)}
      >
        <Typography.Paragraph>{t(confirmFamily?.current ? 'confirmation.current' : 'confirmation.other')}</Typography.Paragraph>
      </Modal>
    </section>
  )
}

export default function IdentitySessionsPage() {
  const { t } = useTranslation('identitySessions')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const owner = useMemo(() => principal ? sessionOwner(principal, sessionEpoch) : null, [principal, sessionEpoch])

  if (!accessToken || !principal) return null
  if (!owner) return <Result status="403" title={t('errors.forbiddenTitle')} subTitle={t('errors.forbiddenDescription')} />
  return <IdentitySessionsContent key={JSON.stringify(owner)} owner={owner} />
}
