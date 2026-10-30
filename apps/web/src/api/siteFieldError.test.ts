import { describe, expect, it } from 'vitest'

import { responseApiError } from './auth'

// site-edit-parity2: 73 PATCH /v1/sites/01a163c0… (ikvm.asia) answered 400;
// the server now names the refused field and the editor shows it.
describe('site field validation error', () => {
  it('keeps error.details.field of a validation_error', async () => {
    const response = new Response(JSON.stringify({ error: {
      code: 'validation_error', message: 'site field cname_domain is invalid', request_id: 'req-1',
      details: { field: 'cname_domain', reason: 'follows the package subscription (cdn.cdnca.com)' },
    } }), { status: 400, headers: { 'Content-Type': 'application/json' } })
    const error = await responseApiError(response)
    expect(error.code).toBe('validation_error')
    expect(error.field).toBe('cname_domain')
  })

  it('ignores a malformed field', async () => {
    const response = new Response(JSON.stringify({ error: {
      code: 'validation_error', message: 'x', request_id: 'req-2', details: { field: '<script>' },
    } }), { status: 400 })
    expect((await responseApiError(response)).field).toBeUndefined()
  })

  // fix-fielderr-be: nested paths, and the resource codes that carry the same details.
  it.each([
    ['validation_error', 'spec.limits.domains', 'out_of_range'],
    ['node_scheduling_invalid_request', 'endpoints[1].port', 'out_of_range'],
    ['system_settings_validation_error', 'value.system_name', 'required'],
  ])('keeps a %s field path %s', async (code, field, reason) => {
    const response = new Response(JSON.stringify({ error: {
      code, message: 'm', request_id: 'req-3', details: { field, reason },
    } }), { status: 400 })
    const error = await responseApiError(response)
    expect(error.field).toBe(field)
    expect(error.reason).toBe(reason)
  })

  it('ignores field details on a non-validation error', async () => {
    const response = new Response(JSON.stringify({ error: {
      code: 'version_conflict', message: 'm', request_id: 'req-4', details: { field: 'name', reason: 'required' },
    } }), { status: 409 })
    expect((await responseApiError(response)).field).toBeUndefined()
  })
})
