import i18n from './index'
import { nodeIsolationResources } from './nodeIsolation'

function leaves(value: unknown, prefix = ''): string[] {
  if (typeof value === 'string') return [prefix]
  if (!value || typeof value !== 'object') return []
  return Object.entries(value).flatMap(([key, child]) => leaves(child, prefix ? `${prefix}.${key}` : key))
}

describe('node isolation locale contract', () => {
  it('keeps zh-CN, en-US and pseudo locale key parity', () => {
    const baseline = leaves(nodeIsolationResources['zh-CN']).sort()
    expect(leaves(nodeIsolationResources['en-US']).sort()).toEqual(baseline)
    expect(leaves(nodeIsolationResources['qps-ploc']).sort()).toEqual(baseline)
    expect(i18n.hasResourceBundle('zh-CN', 'nodeIsolation')).toBe(true)
  })

  it('expands every pseudo-locale leaf', () => {
    const pseudo = nodeIsolationResources['qps-ploc']
    for (const key of leaves(nodeIsolationResources['en-US'])) {
      const parts = key.split('.')
      let value: unknown = pseudo
      for (const part of parts) value = (value as Record<string, unknown>)[part]
      expect(String(value)).toMatch(/^\[!! .* !!]$/)
    }
  })
})
