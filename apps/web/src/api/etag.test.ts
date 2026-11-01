import { describe, expect, it } from 'vitest'
import { responseETag } from './etag'

const withETag = (value?: string) => new Response(null, value === undefined ? {} : { headers: { ETag: value } })

describe('responseETag', () => {
  it('keeps a strong ETag and drops the weak prefix a compressing gateway adds', () => {
    expect(responseETag(withETag('"7"'))).toBe('"7"')
    expect(responseETag(withETag('W/"7"'))).toBe('"7"')
    expect(responseETag(withETag('W/"sha256-abc"'))).toBe('"sha256-abc"')
  })

  it('returns null without an ETag and leaves other values for the caller to refuse', () => {
    expect(responseETag(withETag())).toBeNull()
    expect(responseETag(withETag('7'))).toBe('7')
  })
})
