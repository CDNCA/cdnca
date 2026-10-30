import type { UserLocale } from './index'

export const businessTimeZone = 'Asia/Shanghai'

type Locale = UserLocale | string | undefined

function intlLocale(locale: Locale): 'zh-CN' | 'en-US' {
  return locale === 'en-US' ? 'en-US' : 'zh-CN'
}

export function formatDateTime(value: Date | string, locale?: Locale): string {
  const date = value instanceof Date ? value : new Date(value)
  if (Number.isNaN(date.getTime())) return ''
  return new Intl.DateTimeFormat(intlLocale(locale), {
    timeZone: businessTimeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
  }).format(date)
}

export function formatRelativeTime(value: Date | string, now: Date, locale?: Locale): string {
  const date = value instanceof Date ? value : new Date(value)
  if (Number.isNaN(date.getTime()) || Number.isNaN(now.getTime())) return ''
  const seconds = Math.round((date.getTime() - now.getTime()) / 1000)
  const ranges: Array<[Intl.RelativeTimeFormatUnit, number]> = [
    ['year', 31_536_000],
    ['month', 2_592_000],
    ['day', 86_400],
    ['hour', 3_600],
    ['minute', 60],
  ]
  const [unit, divisor] = ranges.find(([, size]) => Math.abs(seconds) >= size) ?? ['second', 1]
  return new Intl.RelativeTimeFormat(intlLocale(locale), { numeric: 'always' })
    .format(Math.round(seconds / divisor), unit)
}

export function formatNumber(value: number, locale?: Locale): string {
  return new Intl.NumberFormat(intlLocale(locale), { maximumFractionDigits: 2 }).format(value)
}

// isUnlimitedQuota recognises every way the API spells "no limit": -1 (number
// or string), the int64/uint64 and JS max sentinels, and explicit markers.
export function isUnlimitedQuota(value: number | string | null | undefined): boolean {
  if (typeof value === 'number') return value === -1 || value >= Number.MAX_SAFE_INTEGER || value === Infinity
  if (typeof value !== 'string') return false
  const text = value.trim().toLowerCase()
  if (['-1', 'unlimited', 'infinite', 'infinity', '无限', '不限'].includes(text)) return true
  return /^\d+$/.test(text) && BigInt(text) >= BigInt(Number.MAX_SAFE_INTEGER)
}

// formatQuota renders a quota count, showing 不限/Unlimited for the
// unlimited markers instead of formatting 9,007,199,254,740,991.
export function formatQuota(value: number | string, locale?: Locale): string {
  if (isUnlimitedQuota(value)) return intlLocale(locale) === 'en-US' ? 'Unlimited' : '不限'
  const number = typeof value === 'number' ? value : Number(value)
  return Number.isFinite(number) ? formatNumber(number, locale) : String(value)
}

function scaledUnit(value: number, step: number, units: readonly string[], locale?: Locale): string {
  if (!Number.isFinite(value)) return ''
  let scaled = Math.max(0, value)
  let index = 0
  while (scaled >= step && index < units.length - 1) {
    scaled /= step
    index += 1
  }
  const number = new Intl.NumberFormat(intlLocale(locale), { maximumFractionDigits: 2 }).format(scaled)
  return `${number} ${units[index]}`
}

export function formatBytes(value: number, locale?: Locale): string {
  return scaledUnit(value, 1024, ['B', 'KB', 'MB', 'GB', 'TB', 'PB'], locale)
}

export function formatBandwidth(bitsPerSecond: number, locale?: Locale): string {
  return scaledUnit(bitsPerSecond, 1000, ['bps', 'Kbps', 'Mbps', 'Gbps', 'Tbps'], locale)
}

export function formatPercent(value: number, locale?: Locale): string {
  return new Intl.NumberFormat(intlLocale(locale), {
    style: 'percent',
    maximumFractionDigits: 2,
  }).format(value)
}

export function formatCurrencyCNY(minorUnits: number, locale?: Locale): string {
  return new Intl.NumberFormat(intlLocale(locale), {
    style: 'currency',
    currency: 'CNY',
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  }).format(minorUnits / 100)
}

/** An IPv4-mapped IPv6 address (::ffff:a.b.c.d) as its IPv4 form; any other value as is (ui-errmsg-1024). */
export function displayIP(value: string): string {
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(value)
  return mapped ? mapped[1]! : value
}
