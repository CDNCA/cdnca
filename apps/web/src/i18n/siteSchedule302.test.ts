import { describe, expect, it } from 'vitest'

import i18n from './index'
import { siteSchedule302Messages } from './siteSchedule302'

describe('siteSchedule302Messages', () => {
  it('registers the pseudo locale so the 302 schedule card renders under qps-ploc', () => {
    expect(Object.keys(siteSchedule302Messages['qps-ploc']).sort())
      .toEqual(Object.keys(siteSchedule302Messages['zh-CN']).sort())
    const t = i18n.getFixedT('qps-ploc', 'siteSchedule302')
    expect(t('loadFailed')).toMatch(/^［.+］$/)
    expect(t('errors.unknown', { code: 'E1' })).toContain('E1')
  })
})
