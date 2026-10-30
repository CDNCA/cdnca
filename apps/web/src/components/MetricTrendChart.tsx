import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { DataState, type DataStatus } from './DataState'
import { themeColor, themeColorAlpha, useThemeRevision } from '../theme/themeColor'

export interface TrendPoint {
  label: string
  value: number
}

interface MetricTrendChartProps {
  points: TrendPoint[]
  status: DataStatus | 'success'
}

export function MetricTrendChart({ points, status }: MetricTrendChartProps) {
  const { t } = useTranslation('common')
  const containerRef = useRef<HTMLDivElement>(null)
  const [chartFailed, setChartFailed] = useState(false)
  const themeRevision = useThemeRevision()

  useEffect(() => {
    if (status !== 'success' || points.length === 0 || containerRef.current === null) {
      return
    }

    let disposed = false
    let chart: import('./echartsRuntime').ECharts | undefined

    void import('./echartsRuntime')
      .then((echarts) => {
        if (disposed || containerRef.current === null) return
        chart = echarts.init(containerRef.current)
        chart.setOption({
          animationDuration: 180,
          grid: { left: 42, right: 16, top: 16, bottom: 30 },
          tooltip: { trigger: 'axis' },
          xAxis: {
            type: 'category',
            boundaryGap: false,
            data: points.map((point) => point.label),
          },
          yAxis: { type: 'value' },
          series: [
            {
              type: 'line',
              data: points.map((point) => point.value),
              showSymbol: false,
              lineStyle: { color: themeColor('--cdnca-chart-color1', '#2d8cf0'), width: 2 },
              areaStyle: { color: themeColorAlpha('--cdnca-chart-color1', '#2d8cf0', '0.08') },
            },
          ],
        })
      })
      .catch(() => setChartFailed(true))

    const resize = () => chart?.resize()
    window.addEventListener('resize', resize)

    return () => {
      disposed = true
      window.removeEventListener('resize', resize)
      chart?.dispose()
    }
  }, [points, status, themeRevision])

  if (chartFailed || status === 'error') return <DataState status="error" />
  if (status !== 'success' || points.length === 0) {
    return <DataState status={status === 'success' ? 'empty' : status} />
  }

  return <div ref={containerRef} className="metric-chart" aria-label={t('metricTrend')} />
}
