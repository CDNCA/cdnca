import { describe, expect, it } from 'vitest'

import { formatYuan, minorToYuan, yuanToMinor } from './offerTerms'

// 报价价格按元输入（最多 2 位小数），提交换算为分，不得静默改值。
describe('offer money', () => {
  it('converts yuan with up to 2 decimals to exact minor units', () => {
    expect(yuanToMinor(1)).toBe(100)
    expect(yuanToMinor(0)).toBe(0)
    expect(yuanToMinor(0.01)).toBe(1)
    expect(yuanToMinor(0.1)).toBe(10)
    expect(yuanToMinor(1.1)).toBe(110)
    // Binary floats: 0.29 * 100 = 28.999999999999996, 1.005 has 3 decimals.
    expect(yuanToMinor(0.29)).toBe(29)
    expect(yuanToMinor(19.99)).toBe(1999)
    expect(yuanToMinor(4.35)).toBe(435)
    expect(yuanToMinor(1234567.89)).toBe(123456789)
    expect(yuanToMinor('2.50')).toBe(250)
  })

  it('refuses more than 2 decimals, negatives and non-numbers instead of rounding them', () => {
    for (const bad of [1.005, 0.001, 12.345, -1, -0.01, Number.NaN, Number.POSITIVE_INFINITY, '1.234', 'abc', '', null, undefined]) {
      expect(yuanToMinor(bad as number)).toBeNull()
    }
  })

  it('shows minor units as yuan', () => {
    expect(minorToYuan(100)).toBe(1)
    expect(minorToYuan(29)).toBe(0.29)
    expect(minorToYuan(123456789)).toBe(1234567.89)
    expect(formatYuan(100)).toBe('1.00')
    expect(formatYuan(5)).toBe('0.05')
    expect(formatYuan(-250)).toBe('-2.50')
    expect(formatYuan(123456789)).toBe('1234567.89')
  })
})
