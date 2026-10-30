import { describe, expect, it } from 'vitest'

import i18n from './index'
import { pluginInstallationsMessages, type PluginInstallationsMessageTree } from './pluginInstallations'

function leaves(tree: PluginInstallationsMessageTree, prefix = ''): Record<string, string> {
  return Object.fromEntries(Object.entries(tree).flatMap(([key, value]) => {
    const path = prefix ? `${prefix}.${key}` : key
    return typeof value === 'string' ? [[path, value]] : Object.entries(leaves(value, path))
  }))
}

describe('plugin installation translations', () => {
  it('keeps zh-CN, English and pseudo locales structurally complete', () => {
    const zh = leaves(pluginInstallationsMessages['zh-CN'])
    const en = leaves(pluginInstallationsMessages['en-US'])
    const pseudo = leaves(pluginInstallationsMessages['qps-ploc'])
    expect(Object.keys(en)).toEqual(Object.keys(zh))
    expect(Object.keys(pseudo)).toEqual(Object.keys(zh))
    expect(pluginInstallationsMessages['qps-Ploc']).toEqual(pluginInstallationsMessages['qps-ploc'])
    expect(i18n.getResourceBundle('zh-CN', 'pluginInstallations')).toEqual(pluginInstallationsMessages['zh-CN'])
  })

  it('expands visible pseudo copy while preserving interpolation placeholders', () => {
    const zh = leaves(pluginInstallationsMessages['zh-CN'])
    const pseudo = leaves(pluginInstallationsMessages['qps-ploc'])
    for (const key of Object.keys(zh)) {
      expect(pseudo[key]?.startsWith('［')).toBe(true)
      expect(pseudo[key]?.endsWith('］')).toBe(true)
      expect(pseudo[key]!.length).toBeGreaterThan(zh[key]!.length)
    }
    expect(pseudo['pagination.page']).toContain('{{page}}')
  })
})
