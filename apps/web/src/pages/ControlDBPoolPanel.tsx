// 主控数据库连接池：应答本页的主控进程当前值、最近 1 小时、常驻连接与告警状态。
// 数值来自 control-api internal/poolmon（内存，每 10 秒采样）；告警走通知中心 control.db_pool.saturated / recovered。
import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Descriptions, List, Tag, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../api/auth'
import { controlDBPoolApi, type DBPoolSample, type DBPoolStatus } from '../api/controlDBPool'
import { formatDateTime } from '../i18n/formatters'
import '../i18n/controlDBPool'

const POLL_MS = 10_000

/** In use over the last hour against the pool size (one point per sample). */
function Sparkline({ series }: { series: DBPoolSample[] }) {
  if (series.length < 2) return null
  const width = 240, height = 40
  const top = Math.max(...series.map((s) => s.max_conns), 1)
  const x = (i: number) => (i / (series.length - 1)) * width
  const y = (v: number) => height - (v / top) * height
  const points = series.map((s, i) => `${x(i).toFixed(1)},${y(s.in_use).toFixed(1)}`).join(' ')
  const limit = y(series[series.length - 1].max_conns)
  return <svg role="img" aria-hidden="true" width={width} height={height} viewBox={`0 0 ${width} ${height}`} style={{ display: 'block' }}>
    <line x1={0} x2={width} y1={limit} y2={limit} stroke="var(--cdnca-color-error)" strokeDasharray="3 3" strokeWidth={1} />
    <polyline points={points} fill="none" stroke="var(--cdnca-color-primary)" strokeWidth={1.5} />
  </svg>
}

function Status({ data }: { data: DBPoolStatus }) {
  const { t, i18n } = useTranslation('controlDBPool')
  const when = (value: string | null) => value ? formatDateTime(value, i18n.resolvedLanguage) : ''
  if (!data.firing) return <Alert type="success" showIcon message={t('healthy')} />
  const reasons = data.firing_reasons.map((r) => t(`reason.${r}`)).join(t('reasonSeparator'))
  return <Alert type="error" showIcon message={t('firing')} description={<>
    <div>{t('firingSince', { time: when(data.firing_since), reasons })}</div>
    {!data.notified && <div>{t('folded', { minutes: data.thresholds.dedup_minutes })}</div>}
  </>} />
}

function Current({ s }: { s: DBPoolSample }) {
  const { t } = useTranslation('controlDBPool')
  return <Descriptions size="small" column={{ xs: 1, sm: 2, lg: 4 }} colon={false} items={[
    { key: 'in_use', label: t('inUse'), children: `${s.in_use} / ${s.max_conns}` },
    { key: 'idle', label: t('idle'), children: s.idle },
    { key: 'constructing', label: t('constructing'), children: s.constructing },
    { key: 'resident', label: t('residentConns'), children: s.resident_conns },
    { key: 'share', label: t('requestShare'),
      children: t('requestShareValue', { free: Math.max(s.max_conns - s.in_use, 0), capacity: s.request_capacity }) },
    { key: 'queued', label: t('queued'), children: s.queued },
    { key: 'canceled', label: t('canceled'), children: s.canceled },
    { key: 'wait', label: t('avgWait'), children: t('ms', { value: s.avg_wait_ms.toFixed(1) }) },
  ]} />
}

function LastHour({ series }: { series: DBPoolSample[] }) {
  const { t } = useTranslation('controlDBPool')
  const sum = (pick: (s: DBPoolSample) => number) => series.reduce((total, s) => total + pick(s), 0)
  const peak = (pick: (s: DBPoolSample) => number) => series.reduce((top, s) => Math.max(top, pick(s)), 0)
  return <div style={{ display: 'flex', flexWrap: 'wrap', gap: 16, alignItems: 'center', marginTop: 12 }}>
    <Typography.Text strong>{t('lastHour')}</Typography.Text>
    <Sparkline series={series} />
    <Descriptions size="small" column={{ xs: 1, sm: 2, lg: 4 }} colon={false} style={{ flex: 1, minWidth: 280 }} items={[
      { key: 'peak', label: t('peakInUse'), children: peak((s) => s.in_use) },
      { key: 'queued', label: t('totalQueued'), children: sum((s) => s.queued) },
      { key: 'canceled', label: t('totalCanceled'), children: sum((s) => s.canceled) },
      { key: 'wait', label: t('maxWait'), children: t('ms', { value: peak((s) => s.avg_wait_ms).toFixed(1) }) },
    ]} />
  </div>
}

function Residents({ data }: { data: DBPoolStatus }) {
  const { t, i18n } = useTranslation('controlDBPool')
  return <>
    <Typography.Text strong style={{ display: 'block', marginTop: 12 }}>{t('residents')}</Typography.Text>
    <List size="small" dataSource={data.residents} locale={{ emptyText: t('residentsEmpty') }} renderItem={(r) => <List.Item>
      <span>{t(`residentName.${r.name}`, { defaultValue: r.name })}</span>
      <span>
        <Tag color={r.in_pool ? 'processing' : undefined}>{t(r.in_pool ? 'residentInPool' : 'residentOutOfPool')}</Tag>
        <Typography.Text type="secondary">{t('residentSince', { time: formatDateTime(r.since, i18n.resolvedLanguage) })}</Typography.Text>
      </span>
    </List.Item>} />
  </>
}

export default function ControlDBPoolPanel({ accessToken }: { accessToken: string }) {
  const { t, i18n } = useTranslation('controlDBPool')
  const pool = useQuery({ queryKey: ['system', 'db-pool'], queryFn: () => controlDBPoolApi.get(accessToken), refetchInterval: POLL_MS, retry: false })
  const data = pool.data
  const status = pool.error instanceof ApiError ? pool.error.status : 0
  return <section className="maintenance-card control-db-pool" aria-labelledby="control-db-pool-title">
    <div className="maintenance-section-heading"><div>
      <h2 id="control-db-pool-title">{t('title')}{data && <Tag style={{ marginLeft: 8 }}>{t('instance', { name: data.instance })}</Tag>}</h2>
      <p>{t('description', { interval: data?.interval_seconds ?? 10 })}</p>
    </div></div>
    {pool.isPending ? null
      : status === 404 ? <Typography.Text type="secondary">{t('missing')}</Typography.Text>
        : status === 403 ? <Alert type="info" showIcon message={t('forbidden')} />
          : pool.error || !data ? <Alert type="error" showIcon message={t('failed')}
            action={<Button size="small" onClick={() => void pool.refetch()}>{t('retry')}</Button>} />
            : <>
              <Status data={data} />
              {data.pending_notifications > 0 && <Alert type="warning" showIcon style={{ marginTop: 8 }}
                message={t('pending', { count: data.pending_notifications })} />}
              <div style={{ marginTop: 12 }}>
                {data.current ? <Current s={data.current} />
                  : <Typography.Text type="secondary">{t('noSample', { interval: data.interval_seconds })}</Typography.Text>}
              </div>
              <LastHour series={data.series} />
              <Residents data={data} />
              <Typography.Paragraph type="secondary" style={{ marginTop: 8, marginBottom: 0 }}>{t('rule', {
                enter: data.thresholds.enter_cycles, recover: data.thresholds.recover_cycles, margin: data.thresholds.saturation_margin,
                slow: data.thresholds.slow_acquire_ms, dedup: data.thresholds.dedup_minutes })}
                {data.last_notified_at ? ` ${t('lastNotified', { time: formatDateTime(data.last_notified_at, i18n.resolvedLanguage) })}` : ''}
              </Typography.Paragraph>
            </>}
  </section>
}
