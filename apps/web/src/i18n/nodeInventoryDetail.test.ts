import { describe, expect, it } from 'vitest'

import i18n from './index'
import { nodeInventoryDetailMessages } from './nodeInventoryDetail'

function flatten(value: unknown, prefix = ''): Record<string, string> {
  if (typeof value === 'string') return { [prefix]: value }
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).flatMap(([key, child]) => (
    Object.entries(flatten(child, prefix ? `${prefix}.${key}` : key))
  )))
}

describe('node inventory detail translations', () => {
  it('registers complete zh-CN, en-US, and pseudo-locale trees', () => {
    const zh = flatten(nodeInventoryDetailMessages['zh-CN'])
    for (const locale of ['zh-CN', 'en-US', 'qps-ploc', 'qps-Ploc'] as const) {
      expect(i18n.hasResourceBundle(locale, 'nodeInventoryDetail')).toBe(true)
      expect(Object.keys(flatten(nodeInventoryDetailMessages[locale])).sort()).toEqual(Object.keys(zh).sort())
    }
    expect(zh.title).toBe('节点详情')
    expect(zh['errors.invalidResponse']).toBe('节点详情响应无效，请重试')
    expect(flatten(nodeInventoryDetailMessages['en-US'])['errors.invalidResponse']).toBe(
      'The node detail response was invalid. Try again.',
    )
    expect(flatten(nodeInventoryDetailMessages['qps-ploc']).title!.length).toBeGreaterThan(zh.title!.length)
    expect(nodeInventoryDetailMessages['qps-Ploc']).toEqual(nodeInventoryDetailMessages['qps-ploc'])
  })

  it('keeps interpolation tokens and excludes raw backend wording', () => {
    const pseudo = flatten(nodeInventoryDetailMessages['qps-ploc'])
    expect(pseudo['telemetry.sequence']).toContain('{{epoch}}')
    expect(pseudo['telemetry.sequence']).toContain('{{sequence}}')
    expect(JSON.stringify(nodeInventoryDetailMessages)).not.toMatch(/raw server|private upstream|internal service/i)
  })
})
