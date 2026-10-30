import { describe, expect, it } from 'vitest'

import { siteCapturePolicyMessages } from './siteCapturePolicy'

function keys(value: unknown, prefix = ''): string[] {
  if (!value || typeof value !== 'object') return []
  return Object.entries(value).flatMap(([key, child]) => typeof child === 'string' ? [`${prefix}${key}`] : keys(child, `${prefix}${key}.`)).sort()
}

describe('site capture policy locale', () => {
  it('keeps locale keys in parity and provides expanded pseudo text', () => {
    expect(keys(siteCapturePolicyMessages['en-US'])).toEqual(keys(siteCapturePolicyMessages['zh-CN']))
    expect(keys(siteCapturePolicyMessages['qps-ploc'])).toEqual(keys(siteCapturePolicyMessages['zh-CN']))
    expect(String((siteCapturePolicyMessages['qps-ploc'].actions as Record<string, string>).save)).toContain('~')
  })
})
