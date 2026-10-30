import { formatBandwidth, formatBytes, formatNumber } from './formatters'

export function formatAnalyticsBandwidth(value: number, locale?: string): string {
  if (!Number.isFinite(value)) return ''
  return value < 1000
    ? `${formatNumber(Math.max(0, value) / 1000, locale)} Kbps`
    : formatBandwidth(value, locale)
}

export function formatAnalyticsBytes(value: number, locale?: string): string {
  if (!Number.isFinite(value)) return ''
  return value < 1024
    ? `${formatNumber(Math.max(0, value) / 1024, locale)} KB`
    : formatBytes(value, locale)
}
