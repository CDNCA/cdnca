import { formatAnalyticsBandwidth, formatAnalyticsBytes } from '../i18n/analyticsUnits'

describe('analytics unit formatters', () => {
  it.each(['zh-CN', 'en-US', 'qps-ploc', undefined])('keeps Kbps and KB as the minimum units for %s', (locale) => {
    expect(formatAnalyticsBandwidth(0, locale)).toBe('0 Kbps')
    expect(formatAnalyticsBandwidth(500, locale)).toBe('0.5 Kbps')
    expect(formatAnalyticsBandwidth(999, locale)).toBe('1 Kbps')
    expect(formatAnalyticsBandwidth(1000, locale)).toBe('1 Kbps')
    expect(formatAnalyticsBytes(0, locale)).toBe('0 KB')
    expect(formatAnalyticsBytes(512, locale)).toBe('0.5 KB')
    expect(formatAnalyticsBytes(1023, locale)).toBe('1 KB')
    expect(formatAnalyticsBytes(1024, locale)).toBe('1 KB')
  })

  it('retains decimal bandwidth and binary byte scaling for larger values', () => {
    expect(formatAnalyticsBandwidth(1_500_000)).toBe('1.5 Mbps')
    expect(formatAnalyticsBandwidth(1_500_000_000)).toBe('1.5 Gbps')
    expect(formatAnalyticsBandwidth(1_500_000_000_000)).toBe('1.5 Tbps')
    expect(formatAnalyticsBytes(1.5 * 1024 ** 2)).toBe('1.5 MB')
    expect(formatAnalyticsBytes(1.5 * 1024 ** 3)).toBe('1.5 GB')
    expect(formatAnalyticsBytes(1.5 * 1024 ** 5)).toBe('1.5 PB')
  })

  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY])('does not display non-finite input %s', (value) => {
    expect(formatAnalyticsBandwidth(value)).toBe('')
    expect(formatAnalyticsBytes(value)).toBe('')
  })

  it('retains the shared formatter non-negative display boundary', () => {
    expect(formatAnalyticsBandwidth(-100)).toBe('0 Kbps')
    expect(formatAnalyticsBytes(-100)).toBe('0 KB')
  })
})
