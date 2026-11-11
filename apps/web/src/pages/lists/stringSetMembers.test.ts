import { describe, expect, it } from 'vitest'

import { lineOfEntry, summarizeMembers } from './stringSetMembers'

describe('string set members (edgeconfig.CanonicalStringSetMembers rules)', () => {
  it('counts distinct trimmed members, folding A-Z when case-insensitive', () => {
    expect(summarizeMembers(' SQLMap\nsqlmap \n\nnikto', 'contains', false)).toMatchObject({ count: 2, problems: [] })
    expect(summarizeMembers('SQLMap\nsqlmap', 'contains', true).count).toBe(2)
  })

  it('names the line of each refused member', () => {
    const text = `ok\n${'x'.repeat(513)}\n\na\u0007b`
    expect(summarizeMembers(text, 'exact', true).problems).toEqual([
      { line: 2, reason: 'too_long' }, { line: 4, reason: 'control_character' },
    ])
    expect(summarizeMembers('*a*b*c*\n*?', 'wildcard', true).problems).toEqual([
      { line: 1, reason: 'wildcard_too_many_stars' }, { line: 2, reason: 'wildcard_only_wildcards' },
    ])
  })

  it('maps a server entries[i] to the textarea line (blank lines skipped)', () => {
    expect(lineOfEntry('a\n\n  \nb\nc', 1)).toBe(4)
    expect(lineOfEntry('a', 3)).toBeNull()
  })
})
