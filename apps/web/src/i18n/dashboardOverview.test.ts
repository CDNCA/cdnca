import { dashboardOverviewMessages } from './dashboardOverview'

function flatten(value: Record<string, unknown>, prefix = ''): Record<string, string> {
  return Object.fromEntries(Object.entries(value).flatMap(([key, child]) => {
    const path = prefix ? `${prefix}.${key}` : key
    return typeof child === 'string' ? [[path, child]] : Object.entries(flatten(child as Record<string, unknown>, path))
  }))
}

describe('dashboard overview locales', () => {
  it('keeps zh-CN, en-US, and pseudo locale contracts complete', () => {
    const zh = flatten(dashboardOverviewMessages['zh-CN'])
    const keys = Object.keys(zh).sort()
    for (const locale of ['en-US', 'qps-ploc', 'qps-Ploc'] as const) {
      expect(Object.keys(flatten(dashboardOverviewMessages[locale])).sort()).toEqual(keys)
    }
    expect(dashboardOverviewMessages['qps-Ploc']).toEqual(dashboardOverviewMessages['qps-ploc'])
    expect(flatten(dashboardOverviewMessages['qps-ploc'])['actions.apply']!.length)
      .toBeGreaterThan(zh['actions.apply']!.length)
  })
})

