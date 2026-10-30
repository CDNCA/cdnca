import { describe, expect, it } from 'vitest'

import { streamOriginShares, weightShares } from './originWeightShare'

const up = (weight: number, level = 0) => ({ weight, enabled: true, level })

describe('weightShares', () => {
  it('splits by weight over the enabled origins of a level; the total need not be 100', () => {
    // 用户例子 A50 B10 C5 D20（合计 85）：58.8 / 11.8 / 5.9 / 23.5，取整后合计仍为 100
    expect(weightShares([up(50), up(10), up(5), up(20)])).toEqual([59, 12, 6, 23])
  })

  it('rounds to integers that always add up to 100', () => {
    expect(weightShares([up(1), up(1), up(1)])).toEqual([34, 33, 33])
    const shares = weightShares([up(7), up(13), up(29), up(3), up(100)])
    expect(shares.reduce<number>((sum, share) => sum + (share ?? 0), 0)).toBe(100)
  })

  it('gives a disabled origin no share and leaves it out of the total', () => {
    expect(weightShares([up(50), { weight: 50, enabled: false }, up(25)])).toEqual([67, null, 33])
    expect(weightShares([{ weight: 5, enabled: false }])).toEqual([null])
  })

  it('computes each level on its own (backups only serve when the levels before them are down)', () => {
    expect(weightShares([up(30), up(10), up(1, 1), up(3, 2), up(1, 2)])).toEqual([75, 25, 100, 75, 25])
  })

  it('treats a missing level as the primary and a single origin as all of it', () => {
    expect(weightShares([{ weight: 9, enabled: true }])).toEqual([100])
    expect(weightShares([{ weight: 1, enabled: true }, up(3)])).toEqual([25, 75])
  })
})

describe('streamOriginShares', () => {
  it('splits over the origins not marked down; an unfinished row counts as no weight', () => {
    expect(streamOriginShares([{ weight: 3 }, { weight: 1, down: true }, { weight: 1 }])).toEqual([75, null, 25])
    expect(streamOriginShares([{ weight: 2 }, undefined, { weight: undefined }])).toEqual([100, null, null])
  })
})
