import { describe, expect, it } from 'vitest'

import {
  compatibilityCodeForSiteStatus,
  siteStatusFromCompatibilityCode,
} from '../api/sites'

describe('SITE-14 compatibility status adapter', () => {
  it.each([
    [200, 'normal'],
    [512, 'package_expired'],
    [513, 'traffic_exceeded'],
    [514, 'locked'],
  ] as const)('maps %i to %s in both directions', (code, state) => {
    expect(siteStatusFromCompatibilityCode(code)).toBe(state)
    expect(compatibilityCodeForSiteStatus(state)).toBe(code)
  })

  it('rejects unknown compatibility codes without leaking magic numbers into UI logic', () => {
    expect(siteStatusFromCompatibilityCode(500)).toBeNull()
  })
})
