import { use as registerEChartsFeatures } from 'echarts/core'
import { SVGRenderer } from 'echarts/renderers'

import { graphic, init } from './echartsRuntime'

// SSR SVG rendering avoids jsdom Canvas; the registration under test is unchanged.
registerEChartsFeatures([SVGRenderer])

function render(option: Record<string, unknown>) {
  // ECharts reports missing registrations through error, warn and log.
  const spies = (['error', 'warn', 'log'] as const).map((level) => vi.spyOn(console, level).mockImplementation(() => undefined))
  const chart = init(null, undefined, { renderer: 'svg', ssr: true, width: 600, height: 300 })
  try {
    chart.setOption({ animation: false, ...option })
    return { svg: chart.renderToSVGString(), errors: spies.flatMap((spy) => spy.mock.calls.map((call) => String(call[0]))) }
  } finally {
    chart.dispose()
    for (const spy of spies) spy.mockRestore()
  }
}

describe('on-demand echarts runtime', () => {
  it('registers every chart feature the console uses', () => {
    const { svg, errors } = render({
      title: { text: 'Trend title', left: 16 },
      legend: { data: ['Line', 'Bar'] },
      grid: { left: 20, right: 20, top: 68, bottom: 56, containLabel: true },
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
      graphic: { type: 'text', left: 'center', top: 'middle', style: { text: 'No data overlay' } },
      xAxis: { type: 'category', boundaryGap: false, data: ['a', 'b'] },
      yAxis: { type: 'value' },
      series: [
        { name: 'Line', type: 'line', data: [1, 2], showSymbol: false, areaStyle: { color: 'rgba(45, 140, 240, 0.08)' } },
        { name: 'Bar', type: 'bar', data: [2, 1], itemStyle: { color: new graphic.LinearGradient(0, 0, 0, 1, [
          { offset: 0, color: '#2d8cf0' }, { offset: 1, color: '#ffffff' },
        ]) } },
      ],
    })
    expect(errors.filter((message) => /is used but not imported|but no `use\(/.test(message))).toEqual([])
    for (const text of ['Trend title', 'No data overlay', 'Line', 'Bar']) expect(svg).toContain(text)
  })

  it('detects unregistered features so the guard above is meaningful', () => {
    const { errors } = render({ series: [{ type: 'pie', data: [1] }] })
    expect(errors.some((message) => message.includes('Series pie is used but not imported'))).toBe(true)
  })
})
