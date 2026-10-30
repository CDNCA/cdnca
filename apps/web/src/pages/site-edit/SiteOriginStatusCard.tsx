import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Tag } from 'antd'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import { siteOriginStatusApi, type OriginProbeStatus } from '../../api/siteOriginStatus'
import { formatDateTime } from '../../i18n/formatters'
import '../../i18n/siteOriginForwarding'
import { FeedbackWhen } from '@cdnca/ui'

const statusColor: Record<OriginProbeStatus, string> = { healthy: 'success', unhealthy: 'error', unknown: 'default' }

/**
 * 网站“基本”页“源站状态”：each origin's probe state,
 * the level the edge uses now, and (manual failback) "switch back".
 */
export function SiteOriginStatusCard({ siteId, accessToken, canManage }: {
  siteId: string
  accessToken: string
  canManage: boolean
}) {
  const { t, i18n } = useTranslation('siteOriginForwarding')
  const language = i18n.resolvedLanguage ?? 'zh-CN'
  const queryClient = useQueryClient()
  const queryKey = ['site-origin-status', siteId]
  const statusQuery = useQuery({
    queryKey,
    retry: false,
    refetchInterval: 30_000,
    queryFn: ({ signal }) => siteOriginStatusApi.get(accessToken, siteId, signal),
  })
  const failback = useMutation({
    mutationFn: () => siteOriginStatusApi.failback(accessToken, siteId, `origin-failback-${siteId}-${crypto.randomUUID()}`),
    onSuccess: (updated) => {
      queryClient.setQueryData(queryKey, updated)
      void queryClient.invalidateQueries({ queryKey: ['site'] })
    },
  })
  if (statusQuery.isPending) return null
  const status = statusQuery.data
  if (statusQuery.isError || !status) {
    return <FeedbackWhen title={t('failover.loadFailed')} action={<Button size="small" onClick={() => void statusQuery.refetch()}>{t('failover.retry')}</Button>} />
  }
  const levelName = (level: number) => level === 0 ? t('failover.level0') : t('failover.levelN', { level })
  const time = (value: string | null) => value ? formatDateTime(value, language) : t('failover.notChecked')
  // the best healthy level above the active one (what a switch back moves to)
  const target = status.levels.find((level) => level.level < status.active_level && level.status === 'healthy')
  const errorCode = failback.error instanceof ApiError ? failback.error.code : ''
  return <section className="site-basic-section site-origin-status" aria-labelledby="site-origin-status-title">
    <div className="site-basic-section-heading">
      <div>
        <h3 id="site-origin-status-title">{t('failover.statusTitle')}</h3>
        <p>{t('failover.statusHelp')}</p>
      </div>
      {status.failback_mode === 'manual' && status.active_level > 0 ? (
        <Button type="primary" disabled={!canManage || !target || failback.isPending} loading={failback.isPending}
          onClick={() => failback.mutate()}>
          {target && target.level > 0 ? t('failover.failbackTo', { level: levelName(target.level) }) : t('failover.failback')}
        </Button>
      ) : null}
    </div>
    <div className="site-basic-facts">
      <div className="site-basic-fact"><span>{t('failover.activeLevel')}</span>
        <strong><Tag color={status.active_level === 0 ? 'success' : 'warning'}>{levelName(status.active_level)}</Tag></strong></div>
      <div className="site-basic-fact"><span>{t('failover.overall')}</span>
        <strong><Tag color={statusColor[status.overall]}>{t(`failover.status.${status.overall}`)}</Tag></strong></div>
      <div className="site-basic-fact"><span>{t('failover.lastChecked')}</span><strong>{time(status.checked_at)}</strong></div>
      {status.switched_at ? <div className="site-basic-fact"><span>{t('failover.switchedAt')}</span>
        <strong>{time(status.switched_at)}</strong></div> : null}
    </div>
    {status.failback_ready && status.failback_mode === 'manual' ? <Alert type="info" showIcon message={t('failover.failbackReady')} /> : null}
    {failback.isSuccess ? <Alert type="success" showIcon message={t('failover.failbackDone')} /> : null}
    {failback.isError ? <FeedbackWhen title={errorCode === 'origin_failback_unavailable'
      ? t('failover.failbackUnavailable') : t('failover.failbackFailed', { code: errorCode || (failback.error as Error).message })} /> : null}
    <table className="site-origin-status-table">
      <thead><tr><th scope="col">{t('failover.originColumn')}</th><th scope="col">{t('failover.stateColumn')}</th><th scope="col">{t('failover.lastChecked')}</th></tr></thead>
      <tbody>
        {status.origins.map((origin) => (
          <tr key={origin.position} aria-current={origin.enabled && origin.level === status.active_level ? 'true' : undefined}>
            <td><Tag>{levelName(origin.level)}</Tag>{origin.host.includes(':') ? `[${origin.host}]:${origin.port}` : `${origin.host}:${origin.port}`}</td>
            <td>{origin.enabled
              ? <><Tag color={statusColor[origin.status]}>{t(`failover.status.${origin.status}`)}</Tag>
                {origin.reason ? <span>{t(`failover.reason.${origin.reason}`, { defaultValue: origin.reason })}</span> : null}</>
              : <Tag>{t('failover.disabled')}</Tag>}</td>
            <td>{time(origin.checked_at)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  </section>
}
