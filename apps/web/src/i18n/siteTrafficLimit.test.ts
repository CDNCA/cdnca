import { describe, expect, it } from 'vitest'

import i18n from './index'
import { siteTrafficLimitMessages } from './siteTrafficLimit'

describe('siteTrafficLimitMessages', () => {
  it('registers the pseudo locale so the traffic limit card renders under qps-ploc', () => {
    expect(Object.keys(siteTrafficLimitMessages['qps-ploc']).sort())
      .toEqual(Object.keys(siteTrafficLimitMessages['zh-CN']).sort())
    const t = i18n.getFixedT('qps-ploc', 'siteTrafficLimit')
    expect(t('title')).toBe('［网~站~流~量~上~限~］')
    expect(t('errors.unknown', { code: 'E1' })).toContain('E1')
  })
})
