const byteUnits = [
  ['t', 2 ** 40],
  ['g', 2 ** 30],
  ['m', 2 ** 20],
  ['k', 2 ** 10],
] as const

const durationUnits = [
  ['d', 86_400_000],
  ['h', 3_600_000],
  ['m', 60_000],
  ['s', 1_000],
] as const

function parseIntegerWithUnit(value: string, units: ReadonlyArray<readonly [string, number]>): number | null {
  const match = value.trim().match(/^(\d+)([a-z]+)?$/iu)
  if (!match) return null
  const unit = (match[2] ?? '').toLowerCase()
  const multiplier = unit ? units.find(([name]) => name === unit)?.[1] : 1
  if (!multiplier) return null
  const parsed = Number(match[1]) * multiplier
  return Number.isSafeInteger(parsed) ? parsed : null
}

function inRange(value: number | null, minimum: number, maximum: number): value is number {
  return value !== null && value >= minimum && value <= maximum
}

export function formatByteSize(value: number): string {
  if (value === 0) return '0'
  for (const [unit, multiplier] of byteUnits) {
    if (value % multiplier === 0) return `${value / multiplier}${unit}`
  }
  return String(value)
}

export function parseByteSize(value: string, minimum = 0, maximum = Number.MAX_SAFE_INTEGER): number | null {
  const parsed = parseIntegerWithUnit(value, byteUnits)
  return inRange(parsed, minimum, maximum) ? parsed : null
}

export function formatDuration(value: number): string {
  if (value === 0) return '0'
  for (const [unit, multiplier] of durationUnits) {
    if (value % multiplier === 0) return `${value / multiplier}${unit}`
  }
  return `${value}ms`
}

export function parseDuration(value: string, minimum = 0, maximum = Number.MAX_SAFE_INTEGER): number | null {
  const normalized = value.trim().toLowerCase()
  const parsed = normalized.endsWith('ms')
    ? parseIntegerWithUnit(normalized.slice(0, -2), [])
    : parseIntegerWithUnit(normalized, durationUnits)
  return inRange(parsed, minimum, maximum) ? parsed : null
}

export function formatHeaderBuffers(value: { count: number; size_bytes: number }): string {
  return `${value.count} ${formatByteSize(value.size_bytes)}`
}

export function parseHeaderBuffers(value: string): { count: number; size_bytes: number } | null {
  const [countText, sizeText, ...rest] = value.trim().split(/\s+/u)
  if (!countText || !sizeText || rest.length > 0) return null
  const count = Number(countText)
  const sizeBytes = parseByteSize(sizeText, 1, 2 ** 20)
  if (!Number.isInteger(count) || count < 1 || count > 128 || sizeBytes === null) return null
  return { count, size_bytes: sizeBytes }
}
