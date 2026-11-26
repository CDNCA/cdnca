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

  // overflow compares the tab bar with the tabs' own
  // track, so showing the arrows (which shrinks the scroll viewport) cannot
  // flip the decision back.
  function observeRankTabs() {
    const callbacks: ResizeObserverCallback[] = []
    const observed: Element[] = []
    window.ResizeObserver = class {
      constructor(callback: ResizeObserverCallback) { callbacks.push(callback) }
      observe(target: Element) { observed.push(target) }
      unobserve() {}
      disconnect() {}
    }
    const fire = () => act(() => { for (const callback of callbacks) callback([], {} as ResizeObserver) })
    return { observed, fire }
  }

  function sizeRankTabs(container: HTMLElement, barWidth: number, tabsWidth: number) {
    const bar = container.querySelector<HTMLElement>('.dashboard-rank-tabbar')!
    const viewport = container.querySelector<HTMLElement>('.dashboard-rank-tablist')!
    const track = container.querySelector<HTMLElement>('.dashboard-rank-tabtrack')!
    Object.defineProperty(bar, 'clientWidth', { value: barWidth, configurable: true })
    Object.defineProperty(track, 'scrollWidth', { value: tabsWidth, configurable: true })
    // The viewport loses the arrows' width once they show, as in a browser.
    Object.defineProperty(viewport, 'clientWidth', { configurable: true,
      get: () => barWidth - (container.querySelectorAll('.dashboard-rank-tab-arrow').length > 0 ? 52 : 0) })
    Object.defineProperty(viewport, 'scrollWidth', { configurable: true, get: () => Math.max(tabsWidth, viewport.clientWidth) })
    return { bar, viewport, track }
  }

  const arrows = () => screen.queryAllByRole('button', { name: /一组排行$/ }).length

  it.each(['admin', 'tenant'] as const)('keeps ranking tabs without arrows while they fit (%s caller)', (caller) => {
    const originalObserver = window.ResizeObserver
    const { observed, fire } = observeRankTabs()
    try {
      const view = renderWithProviders(<DashboardAnalyticsView variant="admin" mode="rankings" locale="zh-CN"
        rankingsTitle={caller === 'tenant' ? 'TOP10 数据' : undefined} analytics={{ summary, trend: [], top: [] }} />)
      const { bar, viewport, track } = sizeRankTabs(view.container, 288, 246)
      expect(observed).toEqual([bar, track])
      expect(observed).not.toContain(viewport)
      for (let round = 0; round < 5; round++) {
        fire()
        expect(arrows()).toBe(0)
      }
      expect(screen.getAllByRole('tab').map((tab) => tab.textContent)).toEqual(['域名', 'URL', 'IP', '国家'])
    } finally {
      window.ResizeObserver = originalObserver
    }
  })

  it('shows stable scroll arrows while ranking tabs overflow and removes them after widening', async () => {
    const originalObserver = window.ResizeObserver
    const { fire } = observeRankTabs()
    try {
      const view = renderWithProviders(<DashboardAnalyticsView variant="admin" mode="rankings" locale="zh-CN" analytics={{ summary, trend: [], top: [] }} />)
      const { viewport } = sizeRankTabs(view.container, 238, 246)
      for (let round = 0; round < 5; round++) {
        fire()
        expect(arrows()).toBe(2)
      }
      await userEvent.setup().click(screen.getByRole('button', { name: '下一组排行' }))
      expect(viewport.scrollLeft).toBe(112)
      sizeRankTabs(view.container, 360, 246)
      fire()
      fire()
      expect(arrows()).toBe(0)
    } finally {
      window.ResizeObserver = originalObserver
    }
  })

  it('scrolls overflowing ranking tabs sideways with a vertical wheel', () => {
    const originalObserver = window.ResizeObserver
    const { fire } = observeRankTabs()
    try {
      const view = renderWithProviders(<DashboardAnalyticsView variant="admin" mode="rankings" locale="zh-CN" analytics={{ summary, trend: [], top: [] }} />)
      const { viewport } = sizeRankTabs(view.container, 238, 300)
      fire()
      const wheel = new WheelEvent('wheel', { deltaY: 40, cancelable: true })
      viewport.dispatchEvent(wheel)
      expect(viewport.scrollLeft).toBe(40)
      expect(wheel.defaultPrevented).toBe(true)
    } finally {
      window.ResizeObserver = originalObserver
    }
  })

  it('scrolls a selected ranking tab fully into the viewport', async () => {
    const originalObserver = window.ResizeObserver
    const { fire } = observeRankTabs()
    try {
      const view = renderWithProviders(<DashboardAnalyticsView variant="admin" mode="rankings" locale="zh-CN" analytics={{
        summary, trend: [], top: [{ dimension: 'domain', snapshot_at: '2026-09-25T05:00:00Z', items: [] }, { dimension: 'region', snapshot_at: '2026-09-25T05:00:00Z', items: [] }],
      }} />)
      const { viewport } = sizeRankTabs(view.container, 238, 246)
      fire()
      const rect = (left: number, width: number) => ({ left, right: left + width, width, top: 0, bottom: 32, height: 32, x: left, y: 0, toJSON: () => ({}) })
      vi.spyOn(Element.prototype, 'getBoundingClientRect').mockImplementation(function (this: Element) {
        if (this === viewport) return rect(26, 186) as DOMRect
        if (this.textContent === '国家') return rect(200 - viewport.scrollLeft, 60) as DOMRect
        return rect(0, 0) as DOMRect
      })
      await userEvent.setup().click(screen.getByRole('tab', { name: '国家' }))
      expect(viewport.scrollLeft).toBe(48)
    } finally {
      window.ResizeObserver = originalObserver
    }
  })

  it('names the ranking section by the caller title and defaults to the admin 30-minute title', () => {
    const admin = renderWithProviders(<DashboardAnalyticsView variant="admin" mode="rankings" locale="zh-CN" analytics={{ summary, trend: [], top: [] }} />)
    expect(screen.getByRole('region', { name: 'TOP10 数据 (近30分钟)' })).toBeInTheDocument()
    admin.unmount()
    renderWithProviders(<DashboardAnalyticsView variant="admin" mode="rankings" locale="zh-CN" rankingsTitle="TOP10 数据" analytics={{ summary, trend: [], top: [] }} />)
    expect(screen.getByRole('region', { name: 'TOP10 数据' })).toBeInTheDocument()
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
