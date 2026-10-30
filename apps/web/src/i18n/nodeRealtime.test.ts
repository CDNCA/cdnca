import i18n from './index'
import { nodeRealtimeMessages } from './nodeRealtime'

function flatten(value: unknown, prefix = ''): Record<string, string> {
  if (typeof value === 'string') return { [prefix]: value }
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).flatMap(([key, child]) => (
    Object.entries(flatten(child, prefix ? `${prefix}.${key}` : key))
  )))
}

describe('nodeRealtimeMessages', () => {
  it('keeps every locale key-complete and registers both pseudo locale aliases', () => {
    const zh = flatten(nodeRealtimeMessages['zh-CN'])
    for (const locale of ['zh-CN', 'en-US', 'qps-ploc', 'qps-Ploc'] as const) {
      expect(i18n.hasResourceBundle(locale, 'nodeRealtime')).toBe(true)
      expect(Object.keys(flatten(nodeRealtimeMessages[locale])).sort()).toEqual(Object.keys(zh).sort())
    }
  })

  it('expands pseudo text and never exposes raw service wording', () => {
    const zh = flatten(nodeRealtimeMessages['zh-CN'])
    const pseudo = flatten(nodeRealtimeMessages['qps-ploc'])

    expect(pseudo.title?.length).toBeGreaterThan(zh.title!.length)
    expect(nodeRealtimeMessages['qps-Ploc']).toEqual(nodeRealtimeMessages['qps-ploc'])
    for (const locale of Object.values(nodeRealtimeMessages)) {
      for (const value of Object.values(flatten(locale))) {
        expect(value).not.toMatch(/raw server|internal service|private message/i)
      }
    }
  })
})
