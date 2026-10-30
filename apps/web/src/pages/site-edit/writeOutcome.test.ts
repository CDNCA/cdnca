import { describe, expect, it } from 'vitest'

import { ApiError } from '../../api/auth'
import { writeOutcomeUnknown } from './writeOutcome'

describe('writeOutcomeUnknown (TECH-01)', () => {
  it('treats a lost answer as unknown', () => {
    for (const error of [new TypeError('fetch failed'), new ApiError('x', 0, 'network_error'), new ApiError('x', 408, 'timeout'),
      new ApiError('x', 429, 'rate_limited'), new ApiError('x', 500, 'internal'), new ApiError('x', 503, 'service_unavailable'),
      new ApiError('x', 200, 'invalid_response')]) {
      expect(writeOutcomeUnknown(error)).toBe(true)
    }
  })

  it('treats a definite refusal as known', () => {
    for (const status of [400, 401, 403, 404, 409, 412, 422]) {
      expect(writeOutcomeUnknown(new ApiError('x', status, 'refused'))).toBe(false)
    }
  })
})
