import { stringSetLimits, type StringSetMatchMode } from '../../api/securityStringSets'

// Client-side check of a string set's members, the same rules the server
// applies (edgeconfig.CanonicalStringSetMembers): the page shows them while
// typing; the server's answer still decides.

export interface MemberProblem {
  /** 1-based line in the textarea. */
  line: number
  reason: 'too_long' | 'control_character' | 'wildcard_too_many_stars' | 'wildcard_only_wildcards'
}

export interface MemberSummary {
  /** Distinct members after trimming (and lower-casing A-Z when case-insensitive). */
  count: number
  /** UTF-8 bytes of the distinct members together. */
  bytes: number
  problems: MemberProblem[]
  overCount: boolean
  overBytes: boolean
}

const encoder = new TextEncoder()
// eslint-disable-next-line no-control-regex
const controlPattern = /[\u0000-\u001f\u007f-\u009f]/

function asciiLower(value: string): string {
  return value.replace(/[A-Z]/g, (letter) => letter.toLowerCase())
}

export function memberLimit(mode: StringSetMatchMode): number {
  return mode === 'wildcard' ? stringSetLimits.maxWildcardEntries : stringSetLimits.maxEntries
}

/** Checks the textarea text line by line; blank lines are dropped (parseStringSetEntries). */
export function summarizeMembers(text: string, mode: StringSetMatchMode, caseSensitive: boolean): MemberSummary {
  const problems: MemberProblem[] = []
  const seen = new Set<string>()
  let bytes = 0
  text.split('\n').forEach((raw, index) => {
    const member = raw.trim()
    if (!member) return
    const size = encoder.encode(member).length
    let reason: MemberProblem['reason'] | null = null
    if (size > stringSetLimits.maxEntryBytes) reason = 'too_long'
    else if (controlPattern.test(member)) reason = 'control_character'
    else if (mode === 'wildcard' && (member.match(/\*/g)?.length ?? 0) > stringSetLimits.maxWildcardStars) reason = 'wildcard_too_many_stars'
    else if (mode === 'wildcard' && member.replace(/[*?]/g, '') === '') reason = 'wildcard_only_wildcards'
    if (reason) {
      problems.push({ line: index + 1, reason })
      return
    }
    const key = caseSensitive ? member : asciiLower(member)
    if (seen.has(key)) return
    seen.add(key)
    bytes += encoder.encode(key).length
  })
  return { count: seen.size, bytes, problems, overCount: seen.size > memberLimit(mode), overBytes: bytes > stringSetLimits.maxTotalBytes }
}

/**
 * The textarea line of a server entries[i] refusal: entries are the
 * non-blank lines in order (parseStringSetEntries), so i counts those.
 */
export function lineOfEntry(text: string, entryIndex: number): number | null {
  let seen = -1
  const lines = text.split('\n')
  for (let line = 0; line < lines.length; line += 1) {
    if (!lines[line].trim()) continue
    seen += 1
    if (seen === entryIndex) return line + 1
  }
  return null
}

/** "38 KiB" style size for the counter. */
export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  return `${(bytes / 1024).toFixed(bytes < 10 * 1024 ? 1 : 0)} KiB`
}
