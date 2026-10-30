import { describe, expect, it } from 'vitest'

import { jobSettlementMessages } from './jobSettlement'

function flatten(value: unknown, prefix = ''): Record<string, string> {
  if (typeof value === 'string') return { [prefix]: value }
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).flatMap(([key, child]) => (
    Object.entries(flatten(child, prefix ? `${prefix}.${key}` : key))
  )))
}

describe('job settlement translations', () => {
  it('keeps zh-CN, en-US, and pseudo locale resources complete', () => {
    const zh = flatten(jobSettlementMessages['zh-CN'])
    for (const locale of ['en-US', 'qps-ploc', 'qps-Ploc'] as const) {
      expect(Object.keys(flatten(jobSettlementMessages[locale])).sort(), locale)
        .toEqual(Object.keys(zh).sort())
    }
  })

  it('expands pseudo-locale text and does not expose backend details', () => {
    const zh = flatten(jobSettlementMessages['zh-CN'])
    const pseudo = flatten(jobSettlementMessages['qps-ploc'])
    expect(pseudo['receipts.title'].length).toBeGreaterThan(zh['receipts.title'].length)
    expect(JSON.stringify(jobSettlementMessages)).not.toMatch(/private|raw backend|upstream detail/i)
  })
})
