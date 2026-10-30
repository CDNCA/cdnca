import { act, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { EChartsOption } from 'echarts'

import { DashboardAnalyticsView } from '../components/DashboardOverview'
import type { DashboardAnalyticsOverview } from '../api/dashboard'
import i18n from '../i18n'
import { renderWithProviders } from '../test/render'

const renderer = vi.hoisted(() => ({ setOption: vi.fn() }))
vi.mock('../components/echartsRuntime', () => ({
  init: () => ({ setOption: renderer.setOption, resize: vi.fn(), dispose: vi.fn() }),
}))

const summary: DashboardAnalyticsOverview['summary'] = {
  metric_version: 1, request_count: '2', request_bytes: '0', response_bytes: '960', total_bytes: '960',
  average_bandwidth_bps: 1.42, status_2xx: '2', status_3xx: '0', status_4xx: '0', status_5xx: '0', security_events: '0',
}

async function trendOption(locale = 'zh-CN', hour = '2026-09-25T05:00:00Z') {
  renderer.setOption.mockClear()
  renderWithProviders(<DashboardAnalyticsView variant="admin" mode="trend" locale={locale} analytics={{
    summary, trend: [{ ...summary, hour }], top: [],
  }} />)
  await waitFor(() => expect(renderer.setOption).toHaveBeenCalled())
  return renderer.setOption.mock.calls.at(-1)![0]
}

describe('dashboard trend display', () => {
  it('updates the existing chart after light-dark-light changes', async () => {
    await trendOption()
    act(() => document.body.classList.add('i-theme-dark'))
    await waitFor(() => expect(renderer.setOption.mock.calls.at(-1)![0].xAxis.axisLine.lineStyle.color).toBe('#1f2a3d'))
    expect(renderer.setOption.mock.calls.at(-1)![0].xAxis.axisLabel.color).toBe('#98a2b3')
    act(() => document.body.classList.remove('i-theme-dark'))
    await waitFor(() => expect(renderer.setOption.mock.calls.at(-1)![0].xAxis.axisLine.lineStyle.color).toBe('#e8eaec'))
  })

  it('does not shift ranking tabs with arrows when they fit', () => {
    renderWithProviders(<DashboardAnalyticsView variant="admin" mode="rankings" locale="zh-CN" analytics={{ summary, trend: [], top: [] }} />)
    expect(screen.queryByRole('button', { name: '上一组排行' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '下一组排行' })).not.toBeInTheDocument()
  })

  it('shows scroll arrows only while ranking tabs overflow and removes them after expansion', async () => {
    const originalObserver = window.ResizeObserver
    let update: ResizeObserverCallback | undefined
    window.ResizeObserver = class { constructor(callback: ResizeObserverCallback) { update = callback } observe() {} unobserve() {} disconnect() {} }
    try {
      const view = renderWithProviders(<DashboardAnalyticsView variant="admin" mode="rankings" locale="zh-CN" analytics={{ summary, trend: [], top: [] }} />)
      const viewport = view.container.querySelector<HTMLElement>('.dashboard-rank-tablist')!
      Object.defineProperty(viewport, 'scrollWidth', { value: 350 })
      Object.defineProperty(viewport.parentElement, 'clientWidth', { value: 300, configurable: true })
      act(() => update!([], {} as ResizeObserver))
      await userEvent.setup().click(screen.getByRole('button', { name: '下一组排行' }))
      expect(viewport.scrollLeft).toBe(112)
      Object.defineProperty(viewport.parentElement, 'clientWidth', { value: 360, configurable: true })
      act(() => update!([], {} as ResizeObserver))
      expect(screen.queryByRole('button', { name: '下一组排行' })).not.toBeInTheDocument()
    } finally {
      window.ResizeObserver = originalObserver
    }
  })

  it.each(['zh-CN', 'en-US', 'qps-ploc'])('formats timestamps in the business timezone for %s', async (locale) => {
    const option = await trendOption(locale, '2026-09-25T20:00:00Z')
    const expected = new Intl.DateTimeFormat(locale === 'en-US' ? 'en-US' : 'zh-CN', {
      timeZone: 'Asia/Shanghai', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23',
    }).format(new Date('2026-09-25T20:00:00Z'))
    expect(option.xAxis.data).toEqual([expected])
    expect(option.xAxis.data[0]).toContain('04:00')
    expect(option.xAxis.data[0]).not.toMatch(/[TZ]/)
  })

  it('uses the localized placeholder for an invalid timestamp', async () => {
    const option = await trendOption('zh-CN', 'invalid')
    expect(option.xAxis.data).toEqual([i18n.t('dashboardOverview:values.placeholder')])
  })

  it.each([false, true])('renders a visible ring for a single sample (dark=%s)', async (dark) => {
    document.body.classList.toggle('i-theme-dark', dark)
    // SVG rendering can use ECharts' text-measurement fallback without jsdom Canvas.
    const canvasContext = vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue(null)
    const echarts = await vi.importActual<typeof import('echarts')>('echarts')
    const chart = echarts.init(null, undefined, { renderer: 'svg', ssr: true, width: 600, height: 300 })
    try {
      const option = await trendOption()
      chart.setOption({ ...option, animation: false } as EChartsOption)
      const svg = new DOMParser().parseFromString(chart.renderToSVGString(), 'image/svg+xml')
      const ring = svg.querySelector('path[ecmeta_data_index="0"]')
      expect(ring).not.toBeNull()
      expect(ring?.getAttribute('stroke')).toBe(dark ? '#60a5fa' : '#2d8cf0')
    } finally {
      chart.dispose()
      canvasContext.mockRestore()
      document.body.classList.remove('i-theme-dark')
    }
  })
})
