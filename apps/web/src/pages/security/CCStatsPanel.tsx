import { useEffect, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, Segmented, Space, Table, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { useTranslation } from 'react-i18next'

import { ccStatsRanges, getCCSiteStats, type CCRuleTotal, type CCSiteStats, type CCStatsRange, type CCTopValue } from '../../api/ccStats'
import '../../i18n/securityPoliciesCCStats'
import { themeColor, useThemeRevision } from '../../theme/themeColor'
import { FeedbackWhen } from '@cdnca/ui'

// The CC page's statistics tab: one site's rule activity
// as a trend chart, per-rule totals and the triggering top lists.

const seriesFields = ['matched', 'triggered', 'challenged', 'blocked', 'passed'] as const
const seriesColors = () => [
  themeColor('--cdnca-chart-color1', '#2d8cf0'), themeColor('--cdnca-chart-color3', '#ff9900'),
  themeColor('--cdnca-chart-color5', '#9a66e4'), themeColor('--cdnca-chart-color4', '#ed4014'),
  themeColor('--cdnca-chart-color2', '#19be6b'),
]

function CCStatsChart({ stats }: { stats: CCSiteStats }) {
  const { t } = useTranslation('securityPolicies')
  const containerRef = useRef<HTMLDivElement>(null)
  const [failed, setFailed] = useState(false)
  const themeRevision = useThemeRevision()

  useEffect(() => {
    if (containerRef.current === null || stats.series.length === 0) return
    let disposed = false
    let chart: import('../../components/echartsRuntime').ECharts | undefined
    void import('../../components/echartsRuntime')
      .then((echarts) => {
        if (disposed || containerRef.current === null) return
        chart = echarts.init(containerRef.current)
        const colors = seriesColors()
        chart.setOption({
          animationDuration: 180,
          grid: { left: 42, right: 16, top: 36, bottom: 30 },
          tooltip: { trigger: 'axis' },
          legend: { top: 0, data: seriesFields.map((field) => t(`ccStats.fields.${field}`)) },
          xAxis: {
            type: 'category', boundaryGap: false,
            data: stats.series.map((point) => new Date(point.at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })),
          },
          yAxis: { type: 'value', minInterval: 1 },
          series: seriesFields.map((field, index) => ({
            name: t(`ccStats.fields.${field}`), type: 'line', showSymbol: false,
            lineStyle: { color: colors[index], width: 2 }, itemStyle: { color: colors[index] },
            data: stats.series.map((point) => point[field]),
          })),
        })
      })
      .catch(() => setFailed(true))
    const resize = () => chart?.resize()
    window.addEventListener('resize', resize)
    return () => {
      disposed = true
      window.removeEventListener('resize', resize)
      chart?.dispose()
    }
  }, [stats, t, themeRevision])

  if (failed) return <FeedbackWhen title={t('ccStats.error')} />
  return <div ref={containerRef} className="metric-chart" role="img" aria-label={t('ccStats.chart')} />
}

export default function CCStatsPanel({ accessToken, siteID, tenantScopeID, admin }: {
  accessToken: string
  siteID: string | null
  tenantScopeID: string | null
  admin: boolean
}) {
  const { t } = useTranslation('securityPolicies')
  const [range, setRange] = useState<CCStatsRange>('1h')
  const ready = Boolean(siteID) && (!admin || Boolean(tenantScopeID))
  const query = useQuery({
    queryKey: ['cc-stats', siteID, admin ? tenantScopeID : null, range],
    enabled: ready,
    refetchInterval: 30_000,
    queryFn: () => getCCSiteStats(accessToken, { siteID: siteID!, range, tenantScopeID: admin ? tenantScopeID! : undefined }),
  })

  if (!siteID) return <Alert type="info" showIcon message={t('ccStats.needSite')} />
  if (!ready) return <Alert type="info" showIcon message={t('ccStats.needTenant')} />

  const countColumns = (['matched', 'triggered', 'challenged', 'blocked', 'passed', 'ja4_unavailable'] as const).map((field) => ({
    title: t(`ccStats.fields.${field}`), dataIndex: field, key: field, width: 90, align: 'right' as const,
  }))
  const ruleColumns: ColumnsType<CCRuleTotal> = [
    {
      title: t('ccStats.columns.rule'), key: 'rule', ellipsis: true,
      render: (_value, row) => row.rule_id ? <Typography.Text code copyable>{row.rule_id}</Typography.Text> : t('ccStats.siteLevel'),
    },
    ...countColumns,
  ]
  const topColumns = (title: string): ColumnsType<CCTopValue> => [
    { title, dataIndex: 'value', key: 'value', ellipsis: true },
    { title: t('ccStats.count'), dataIndex: 'count', key: 'count', width: 90, align: 'right' },
  ]
  const stats = query.data
  const empty = stats !== undefined && stats.rules.length === 0

  return <section className="cc-stats-panel" aria-labelledby="cc-stats-title">
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Space wrap style={{ justifyContent: 'space-between', width: '100%' }}>
        <div>
          <Typography.Title level={5} id="cc-stats-title" style={{ margin: 0 }}>{t('ccStats.title')}</Typography.Title>
          <Typography.Text type="secondary">{t('ccStats.help')}</Typography.Text>
        </div>
        <Segmented<CCStatsRange>
          value={range}
          onChange={setRange}
          options={ccStatsRanges.map((value) => ({ value, label: t(`ccStats.range.${value}`) }))}
        />
      </Space>
      {query.isError ? <FeedbackWhen title={t('ccStats.error')} /> : null}
      {empty ? <Alert type="info" showIcon message={t('ccStats.empty')} /> : null}
      {stats && !empty ? <>
        <CCStatsChart stats={stats} />
        <Table<CCRuleTotal> size="small" rowKey={(row) => row.rule_id ?? 'site'} columns={ruleColumns}
          dataSource={stats.rules} pagination={false} scroll={{ x: 760 }} />
        <Space wrap align="start" size={16} style={{ width: '100%' }}>
          <Table<CCTopValue> size="small" rowKey="value" columns={topColumns(t('ccStats.topClients'))}
            dataSource={stats.top_clients} pagination={false} style={{ minWidth: 320 }} />
          <Table<CCTopValue> size="small" rowKey="value" columns={topColumns(t('ccStats.topPaths'))}
            dataSource={stats.top_paths} pagination={false} style={{ minWidth: 320 }} />
        </Space>
      </> : null}
      {query.isPending ? <Table size="small" loading columns={ruleColumns} dataSource={[]} pagination={false} /> : null}
    </Space>
  </section>
}
