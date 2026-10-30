import { describe, expect, it } from 'vitest'

import i18n from './index'
import { pluginWebhooksMessages, type PluginWebhooksMessageTree } from './pluginWebhooks'

function leaves(tree: PluginWebhooksMessageTree, prefix = ''): Map<string, string> {
  const result = new Map<string, string>()
  for (const [key, value] of Object.entries(tree)) {
    const path = prefix ? `${prefix}.${key}` : key
    if (typeof value === 'string') result.set(path, value)
    else for (const [childPath, child] of leaves(value, path)) result.set(childPath, child)
  }
  return result
}

describe('plugin webhook locale bundle', () => {
  it('keeps en-US and both pseudo locale aliases complete with zh-CN', () => {
    const zh = leaves(pluginWebhooksMessages['zh-CN'])
    const en = leaves(pluginWebhooksMessages['en-US'])
    const pseudo = leaves(pluginWebhooksMessages['qps-ploc'])
    const pseudoAlias = leaves(pluginWebhooksMessages['qps-Ploc'])

    expect([...en.keys()]).toEqual([...zh.keys()])
    expect([...pseudo.keys()]).toEqual([...zh.keys()])
    expect(pseudoAlias).toEqual(pseudo)
    expect(i18n.getResourceBundle('zh-CN', 'pluginWebhooks')).toEqual(pluginWebhooksMessages['zh-CN'])
    expect(i18n.getResourceBundle('en-US', 'pluginWebhooks')).toEqual(pluginWebhooksMessages['en-US'])
  })

  it('expands every pseudo message without changing interpolation tokens', () => {
    const zh = leaves(pluginWebhooksMessages['zh-CN'])
    const pseudo = leaves(pluginWebhooksMessages['qps-ploc'])

    for (const [key, source] of zh) {
      const translated = pseudo.get(key)
      expect(translated, key).toBeDefined()
      expect(translated!.length, key).toBeGreaterThan(source.length)
      expect(translated!.match(/{{[^}]+}}/g) ?? [], key).toEqual(source.match(/{{[^}]+}}/g) ?? [])
    }
  })
})
