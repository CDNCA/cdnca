import { describe, expect, it } from 'vitest'

import i18n, { changeLocale } from './index'
import { enUS, zhCN } from './streamGuard'
import { streamGuardTags } from '../pages/streamForm'

function keys(value: unknown, prefix = ''): string[] {
  if (typeof value !== 'object' || value === null) return [prefix]
  return Object.entries(value).flatMap(([key, child]) => keys(child, prefix ? `${prefix}.${key}` : key))
}

describe('stream guard translations', () => {
  it('has the same keys in Chinese and English and a label for every tag', async () => {
    expect(keys(enUS).sort()).toEqual(keys(zhCN).sort())
    await changeLocale('zh-CN')
    for (const tag of streamGuardTags) {
      expect(i18n.t(`tagNames.${tag.replace(/[:-]/gu, '_')}`, { ns: 'streamGuard' })).not.toMatch(/tagNames/u)
    }
    expect(i18n.t('title', { ns: 'streamGuard' })).toBe('防护规则')
    await changeLocale('qps-ploc')
    expect(i18n.t('title', { ns: 'streamGuard' })).toBe('［防护规则］')
  })
})
