import { describe, expect, it } from 'vitest'

import i18n, { changeLocale } from './index'
import './l4Realtime'

describe('l4 realtime translations', () => {
  it('ships Chinese and pseudo-locale keys without English fallback', async () => {
    await changeLocale('zh-CN')
    expect(i18n.t('title', { ns: 'l4Realtime' })).toBe('四层实时监控')
    await changeLocale('qps-ploc')
    expect(i18n.t('title', { ns: 'l4Realtime' })).toBe('［四层实时监控］')
    expect(i18n.t('filters.tenantRequired', { ns: 'l4Realtime' })).not.toBe('filters.tenantRequired')
  })
})
