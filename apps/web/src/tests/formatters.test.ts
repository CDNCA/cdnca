import {
  businessTimeZone,
  formatBandwidth,
  formatBytes,
  formatCurrencyCNY,
  formatDateTime,
  formatNumber,
  formatPercent,
  formatQuota,
  isUnlimitedQuota,
  formatRelativeTime,
} from '../i18n/formatters'

describe('locale-aware formatters', () => {
  const instant = new Date('2026-07-22T00:30:00.000Z')
  const now = new Date('2026-07-22T01:30:00.000Z')

  it('uses the explicit Asia/Shanghai business time zone', () => {
    expect(businessTimeZone).toBe('Asia/Shanghai')
    expect(formatDateTime(instant, 'zh-CN')).toBe('2026/07/22 08:30:00')
    expect(formatDateTime(instant, 'en-US')).toBe('07/22/2026, 08:30:00')
    expect(formatDateTime(instant, 'qps-ploc')).toBe('2026/07/22 08:30:00')
  })

  it('formats relative time from a fixed clock', () => {
    expect(formatRelativeTime(instant, now, 'zh-CN')).toBe('1小时前')
    expect(formatRelativeTime(instant, now, 'en-US')).toBe('1 hour ago')
  })

  it('formats numbers, bytes, bandwidth, percentages, and CNY consistently', () => {
    expect(formatNumber(1234567.5, 'en-US')).toBe('1,234,567.5')
    expect(formatBytes(1536, 'en-US')).toBe('1.5 KB')
    expect(formatBandwidth(125_000_000, 'en-US')).toBe('125 Mbps')
    expect(formatPercent(0.125, 'en-US')).toBe('12.5%')
    expect(formatCurrencyCNY(123456, 'zh-CN')).toBe('¥1,234.56')
    expect(formatCurrencyCNY(123456, 'en-US')).toBe('CN¥1,234.56')
  })

  it('shows unlimited quota markers as 不限 instead of a huge number (W1)', () => {
    for (const value of [9007199254740991, '9007199254740991', '9223372036854775807', -1, '-1', 'unlimited', '无限', Infinity]) {
      expect(isUnlimitedQuota(value)).toBe(true)
      expect(formatQuota(value, 'zh-CN')).toBe('不限')
    }
    expect(formatQuota(9007199254740991, 'en-US')).toBe('Unlimited')
    expect(formatQuota(30, 'zh-CN')).toBe('30')
    expect(formatQuota('1200', 'en-US')).toBe('1,200')
    expect(isUnlimitedQuota(0)).toBe(false)
    expect(isUnlimitedQuota(null)).toBe(false)
  })
})
