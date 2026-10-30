import { describe, expect, it } from 'vitest'

import { dnsReconcilePageMessages } from './dnsReconcilePage'

function leafKeys(value: unknown, prefix = ''): string[] {
  if (typeof value === 'string') return [prefix]
  return Object.entries(value as Record<string, unknown>).flatMap(([key, child]) => leafKeys(child, prefix ? `${prefix}.${key}` : key))
}

describe('dns reconcile page translations', () => {
  it('keeps zh-CN, en-US, and pseudo locale complete', () => {
    const expected = leafKeys(dnsReconcilePageMessages['zh-CN']).sort()
    for (const locale of ['en-US', 'qps-ploc', 'qps-Ploc'] as const) {
      expect(leafKeys(dnsReconcilePageMessages[locale]).sort(), locale).toEqual(expected)
    }
  })

  it('does not expose backend error details in user messages', () => {
    const source = JSON.stringify(dnsReconcilePageMessages)
    expect(source).not.toMatch(/private|upstream provider|raw backend/i)
  })
})

