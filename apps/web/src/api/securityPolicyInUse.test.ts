import { describe, expect, it } from 'vitest'

import { responseApiError } from './auth'

// sec-ui-polish D3: a refused delete names the sites still running the
// policy in error.details.sites; the page lists and links them.
describe('security_policy_in_use sites', () => {
  const refusal = (details: unknown) => new Response(JSON.stringify({ error: {
    code: 'security_policy_in_use', message: 'security policy is in use by a site: a.example.com', request_id: 'req-1', details,
  } }), { status: 409, headers: { 'Content-Type': 'application/json' } })

  it('keeps the named sites', async () => {
    const error = await responseApiError(refusal({ sites: [{ id: '11111111-1111-4111-8111-111111111111', domain: 'a.example.com' }] }))
    expect(error.code).toBe('security_policy_in_use')
    expect(error.inUseSites).toEqual([{ id: '11111111-1111-4111-8111-111111111111', domain: 'a.example.com' }])
  })

  it('drops malformed entries and caps at five', async () => {
    const valid = Array.from({ length: 7 }, (_, index) => ({ id: `1111111${index}-1111-4111-8111-111111111111`, domain: `s${index}.example.com` }))
    const error = await responseApiError(refusal({ sites: [{ id: 'not-a-uuid', domain: 'x.example.com' }, { id: valid[0].id, domain: '' }, ...valid] }))
    expect(error.inUseSites).toEqual(valid.slice(0, 3))
    expect((await responseApiError(refusal(undefined))).inUseSites).toBeUndefined()
  })
})
