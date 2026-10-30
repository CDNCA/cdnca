import type { Dayjs } from 'dayjs'

/**
 * The competitor submits the history window as Unix seconds (`strToTimestamp`), inclusive on both ends.
 * `null` on either side leaves that bound open.
 */
export function blockWindow(from: Dayjs | null, to: Dayjs | null): { start?: number; end?: number } {
  const window: { start?: number; end?: number } = {}
  if (from) window.start = Math.floor(from.valueOf() / 1000)
  if (to) window.end = Math.floor(to.valueOf() / 1000)
  return window
}
