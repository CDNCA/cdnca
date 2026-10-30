import { describe, expect, it } from 'vitest'

import { slaProblem } from './slaModel'

describe('slaProblem mirrors market sla.Policy.Validate', () => {
  const ok = { target: 99.9, tiers: [{ below: 99.9, credit: 10 }, { below: 99, credit: 25 }], maxCredit: 100, terminateAfter: 0 }
  it('accepts a valid policy', () => expect(slaProblem(ok)).toBeNull())
  it.each([
    [{ ...ok, target: 0 }, 'target'],
    [{ ...ok, target: 100.1 }, 'target'],
    [{ ...ok, tiers: [{ below: 99.95, credit: 10 }] }, 'tier'],
    [{ ...ok, tiers: [{ below: 99, credit: 10 }, { below: 99, credit: 20 }] }, 'tier'],
    [{ ...ok, tiers: [{ below: 99, credit: 0 }] }, 'tier'],
    [{ ...ok, tiers: [{ below: 99.9, credit: 30 }, { below: 99, credit: 10 }] }, 'monotonic'],
    [{ ...ok, tiers: Array.from({ length: 11 }, (_, i) => ({ below: 90 + i * 0.1, credit: 50 - i })) }, 'tooMany'],
    [{ ...ok, maxCredit: 101 }, 'range'],
    [{ ...ok, terminateAfter: 366 }, 'range'],
  ])('rejects %j as %s', (input, problem) => expect(slaProblem(input)).toBe(problem))
})
