import { readdirSync, readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'

import i18n from './index'
import { enUS, zhCN } from './adminMessageQuery'
import { adminMessageTypeKey } from '../pages/AdminMessageQueryPage.adapter'

// Every event type the control plane seeds into notification_event_policies
// (the type filter's catalog), read from the control-api migrations.
function seededEventTypes(): string[] {
  const migrations = resolve(__dirname, '../../../../services/control-api/migrations')
  const types = new Set<string>()
  for (const file of readdirSync(migrations).filter((name) => name.endsWith('.up.sql'))) {
    const sql = readFileSync(join(migrations, file), 'utf8')
    for (const insert of sql.matchAll(/INSERT INTO notification_event_policies\b([\s\S]*?);/g)) {
      for (const row of insert[1].matchAll(/'([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)'/g)) types.add(row[1])
    }
  }
  return [...types].sort()
}

describe('admin message query translations', () => {
  it.each([
    ['zh-CN', '消息查询', '用户', '消息详情'],
    ['en-US', 'Message Query', 'User', 'Message details'],
  ])('provides the current message query fields in %s', (locale, title, userLabel, detailsTitle) => {
    const t = i18n.getFixedT(locale, 'adminMessageQuery')
    expect(t('title')).toBe(title)
    expect(t('filters.userId')).toBe(userLabel)
    expect(t('details.title')).toBe(detailsTitle)
    expect(t('types.trafficRecovered')).not.toContain('types.')
    expect(t('errors.load')).not.toContain('errors.')
  })

  it('provides visibly expanded pseudo-locale strings', () => {
    const t = i18n.getFixedT('qps-ploc', 'adminMessageQuery')
    expect(t('title')).toMatch(/^［.+］$/)
    expect(t('title').length).toBeGreaterThan(zhCN.title.length)
    expect(t('pagination.total', { total: 2 })).toContain('2')
    expect(t('pagination.pageSize', { count: 20 })).toContain('20')
  })

  it('keeps every message query key available in English and the pseudo locale', () => {
    const leaves = (value: object, prefix = ''): string[] => Object.entries(value).flatMap(([key, child]) => {
      const path = prefix ? `${prefix}.${key}` : key
      return typeof child === 'string' ? [path] : leaves(child, path)
    })
    expect(leaves(enUS).sort()).toEqual(leaves(zhCN).sort())
    for (const key of leaves(zhCN)) {
      expect(i18n.getFixedT('en-US', 'adminMessageQuery')(key)).not.toBe(key)
      expect(i18n.getFixedT('qps-ploc', 'adminMessageQuery')(key)).toMatch(/^［.+］$/)
    }
  })

  // fix-msgquery: every catalog event type has a Chinese name, so the type
  // filter never falls back to the raw English event key.
  it('names every seeded notification event type in Chinese', () => {
    const types = seededEventTypes()
    expect(types.length).toBeGreaterThanOrEqual(80)
    expect(types).toContain('security.escalate.blackhole')
    const t = i18n.getFixedT('zh-CN', 'adminMessageQuery')
    expect(types.filter((type) => !adminMessageTypeKey(type))).toEqual([])
    for (const type of types) expect(t(`types.${adminMessageTypeKey(type)}`)).toMatch(/[\u4e00-\u9fff]/u)
  })
})
