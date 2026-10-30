import { describe, expect, it } from 'vitest'

import { cachePolicyHistoryMessages } from './cachePolicyHistory'

function flatten(value: unknown, prefix = ''): Record<string, string> {
  if (typeof value === 'string') return { [prefix]: value }
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).flatMap(([key, child]) => (
    Object.entries(flatten(child, prefix ? `${prefix}.${key}` : key))
  )))
}

describe('cache policy history translations', () => {
  it('keeps zh-CN, en-US, and pseudo locale resource trees complete', () => {
    const zh = flatten(cachePolicyHistoryMessages['zh-CN'])
    for (const locale of ['en-US', 'qps-ploc', 'qps-Ploc'] as const) {
      expect(Object.keys(flatten(cachePolicyHistoryMessages[locale])).sort(), locale)
        .toEqual(Object.keys(zh).sort())
    }
  })

  it('expands pseudo-locale text and preserves interpolation variables', () => {
    const zh = flatten(cachePolicyHistoryMessages['zh-CN'])
    const pseudo = flatten(cachePolicyHistoryMessages['qps-ploc'])
    expect(pseudo.title.length).toBeGreaterThan(zh.title.length)
    expect(pseudo['table.page']).toContain('{{page}}')
    expect(cachePolicyHistoryMessages['qps-Ploc']).toEqual(cachePolicyHistoryMessages['qps-ploc'])
  })

  it('does not expose raw backend details in user-facing messages', () => {
    expect(JSON.stringify(cachePolicyHistoryMessages)).not.toMatch(/private|raw backend|upstream detail/i)
  })
})
