import { describe, expect, it } from 'vitest'

import type { MarketPlugin } from '../../api/market'
import { idBatches, pluginDescription, pluginName, pluginSummary, pluginTitle } from './usePluginCatalog'

describe('usePluginCatalog helpers', () => {
  it('dedupes and batches ids within 200 per lookup and the 1024-byte proxy value cap', () => {
    expect(idBatches([])).toEqual([])
    expect(idBatches(['b.x', 'a.x', 'b.x'])).toEqual([['a.x', 'b.x']])
    const many = Array.from({ length: 450 }, (_, i) => `p${String(i).padStart(3, '0')}.x`)
    const batches = idBatches(many)
    expect(batches.flat()).toEqual([...many].sort())
    for (const batch of batches) {
      expect(batch.length).toBeLessThanOrEqual(200)
      expect(batch.join(',').length).toBeLessThanOrEqual(1000)
    }
    const long = Array.from({ length: 30 }, (_, i) => `io.cdnca.${'x'.repeat(80)}${i}`)
    expect(idBatches(long).every((b) => b.join(',').length <= 1000)).toBe(true)
  })

  it('picks the English name and summary in en-US and falls back to Chinese, then to the plugin id', () => {
    const plugin = { plugin_id: 'io.cdnca.crs', title: 'OWASP CRS 档位', title_en: 'OWASP CRS Levels', summary: '中文简介', summary_en: '' }
    expect(pluginTitle(plugin, 'en-US')).toBe('OWASP CRS Levels')
    expect(pluginTitle(plugin, 'zh-CN')).toBe('OWASP CRS 档位')
    expect(pluginTitle({ ...plugin, title_en: '' }, 'en-US')).toBe('OWASP CRS 档位')
    expect(pluginSummary(plugin, 'en-US')).toBe('中文简介')
    expect(pluginSummary({ ...plugin, summary_en: 'English' }, 'en-US')).toBe('English')
    const catalog = new Map([[plugin.plugin_id, plugin as unknown as MarketPlugin]])
    expect(pluginName(catalog, 'io.cdnca.crs', 'en-US')).toBe('OWASP CRS Levels')
    expect(pluginName(catalog, 'gone.plugin', 'en-US')).toBe('gone.plugin')
  })

  it('picks the English description in en-US (market 073) and falls back to the Chinese one', () => {
    const plugin = { description_md: '## 智能自动防御', description_md_en: '## Automatic defense' }
    expect(pluginDescription(plugin, 'en-US')).toBe('## Automatic defense')
    expect(pluginDescription(plugin, 'zh-CN')).toBe('## 智能自动防御')
    expect(pluginDescription({ ...plugin, description_md_en: '' }, 'en-US')).toBe('## 智能自动防御')
    expect(pluginDescription({}, 'en-US')).toBe('')
  })
})
