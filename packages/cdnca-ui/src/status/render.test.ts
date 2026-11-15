import { describe, expect, it } from 'vitest'

import { CONTROL_SCHEMA, type Incident, type View } from './model'
import { renderView, type RenderOptions } from './render'

const resolved = (n: number): Incident => ({
  id: `r${n}`, kind: 'incident', title: { zh: `事件${n}`, en: `Incident ${n}` }, impact: 'degraded', status: 'resolved',
  component_keys: [], started_at: '2026-11-11T09:00:00Z', resolved_at: '2026-11-11T10:00:00Z', updates: [],
})
const view = (recent: Incident[]): View => ({
  schema: CONTROL_SCHEMA, status: 'operational', generated_at: '2026-11-12T10:00:00Z', components: [], active: [], upcoming: [], recent,
})
const opts = (): RenderOptions => ({ stale: false, failed: false, expanded: new Map() })
const paint = (v: View, lang: 'zh' | 'en' = 'zh') => {
  const root = document.createElement('main')
  renderView(root, v, lang, opts())
  return root
}

describe('状态页历史事件', () => {
  it('只显示最近 5 条，其余翻页；刷新后停在当前页', () => {
    const recent = Array.from({ length: 12 }, (_, i) => resolved(i + 1))
    const root = paint(view(recent))
    const titles = () => Array.from(root.querySelectorAll('.st-recent-list details.st-incident')).map((node) => node.querySelector('summary')?.textContent ?? '')
    expect(titles()).toHaveLength(5)
    expect(titles()[0]).toContain('事件1')
    expect(root.querySelector('.st-page-label')?.textContent).toBe('第 1 / 3 页')
    const [prev, next] = Array.from(root.querySelectorAll<HTMLButtonElement>('.st-pager button'))
    expect(prev.disabled).toBe(true)
    next.click(); next.click()
    expect(titles()).toHaveLength(2)
    expect(titles()[0]).toContain('事件11')
    expect(next.disabled).toBe(true)
    expect(paint(view(recent)).querySelector('.st-page-label')?.textContent).toBe('第 3 / 3 页')
    expect(paint(view(recent.slice(0, 5))).querySelector('.st-pager')).toBeNull()
    expect(paint(view(recent), 'en').querySelector('.st-page-label')?.textContent).toBe('Page 1 of 3')
  })
})
