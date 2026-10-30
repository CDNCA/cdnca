import { vi } from 'vitest'

import { SecurityPolicyImportApiError, securityPoliciesApi, type SecurityPolicyFields } from '../api/securityPolicies'

const fields: SecurityPolicyFields = {
  kind: 'cc', name: 'API CC', description: '', enabled: true, default_action: 'allow',
  rules: [{
    id: '33333333-3333-4333-8333-333333333333', name: 'block', priority: 100, enabled: true,
    conditions: [{ field: 'client_ip', operator: 'ip_in_cidr', values: ['192.0.2.0/24'] }],
    action: 'block', flow: 'stop', action_config: {},
  }],
}

function response(value: unknown, status = 200) {
  return Promise.resolve(new Response(status === 204 ? null : JSON.stringify(value), {
    status, headers: { 'Content-Type': 'application/json' },
  }))
}

describe('securityPoliciesApi', () => {
  it('sends filters and optimistic/idempotent write headers', async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      calls.push({ url: String(input), init })
      return response(init?.method === 'DELETE' ? undefined : { ...fields, id: 'policy', version: 2 }, init?.method === 'DELETE' ? 204 : 200)
    })

    await securityPoliciesApi.list('token', { page: 2, limit: 50, kind: 'waf', status: 'enabled', name: 'api', owner: 'tenant' })
    await securityPoliciesApi.update('token', 'policy/id', 1, fields, 'update-key')
    await securityPoliciesApi.remove('token', 'policy/id', 2, 'delete-key')

    expect(calls[0].url).toContain('page=2&limit=50&kind=waf&status=enabled&name=api&owner=tenant')
    expect(calls[1].url).toContain('/v1/security-policies/policy%2Fid')
    expect(calls[1].init?.method).toBe('PATCH')
    expect(new Headers(calls[1].init?.headers).get('If-Match')).toBe('"1"')
    expect(new Headers(calls[1].init?.headers).get('Idempotency-Key')).toBe('update-key')
    expect(new Headers(calls[2].init?.headers).get('If-Match')).toBe('"2"')
    expect(new Headers(calls[2].init?.headers).get('Idempotency-Key')).toBe('delete-key')
  })

  it('evaluates with a revision but no idempotency key', async () => {
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(() => response({
      policy_id: 'policy', policy_version: 3, action: 'allow', matched_rule_ids: [], used_default: true,
    }))
    await securityPoliciesApi.evaluate('token', 'policy', 3, {
      client_ip: '2001:db8::1', host: '', path: '/', method: 'GET', headers: {}, country: '', asn: 0, ja4: '', port: 443,
		distinct_user_agents: 0, status_404_count: 0,
    })
    const headers = new Headers(fetcher.mock.calls[0][1]?.headers)
    expect(headers.get('If-Match')).toBe('"3"')
    expect(headers.get('Idempotency-Key')).toBeNull()
  })

	  it('preserves structured ACL import line errors without exposing server text', async () => {
	    vi.spyOn(globalThis, 'fetch').mockImplementation(() => response({
	      error: {
	        code: 'acl_import_invalid', message: 'private parser details', request_id: 'request-1',
	        line_errors: [{ line: 2, code: 'invalid_cidr' }, { line: 4, code: 'invalid_expiry' }],
	      },
	    }, 422))
	    const input: SecurityPolicyFields = {
	      kind: 'acl', name: 'Imported ACL', description: '', enabled: true, default_action: 'allow', rules: [],
	      acl_import: 'block invalid',
	    }
	    const error = await securityPoliciesApi.create('token', input, 'acl-import').catch((value) => value)
	    expect(error).toBeInstanceOf(SecurityPolicyImportApiError)
	    expect(error).toMatchObject({
	      code: 'acl_import_invalid', requestId: 'request-1',
	      lineErrors: [{ line: 2, code: 'invalid_cidr' }, { line: 4, code: 'invalid_expiry' }],
	    })
	    expect(error.message).not.toContain('private parser details')
	  })

  it('loads activation status by site and kind and sends complete write metadata', async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      calls.push({ url: String(input), init })
      if (!init?.method) return response({ binding: null, latest_candidate: null, operation: null })
      return response({ candidate: { id: 'candidate' } }, 201)
    })

    await securityPoliciesApi.getActivationStatus(
      'token', '33333333-3333-4333-8333-333333333333', 'waf',
    )
    await securityPoliciesApi.publishActivation('token', {
      site_id: '33333333-3333-4333-8333-333333333333',
      policy_id: '44444444-4444-4444-8444-444444444444',
      policy_version: 3,
      expected_binding_revision: 0,
      expected_active_policy_version: 0,
      target_node_ids: ['55555555-5555-4555-8555-555555555555'],
      canary_size: 1,
      expires_at: '2026-08-04T12:00:00Z',
    }, {
      requestId: '66666666-6666-4666-8666-666666666666',
      idempotencyKey: 'security-activation-publish-1',
      traceparent: '00-0123456789abcdef0123456789abcdef-0123456789abcdef-01',
      correlationId: '77777777-7777-4777-8777-777777777777',
      taskId: 'security-task:1',
    })

    expect(calls[0].url).toContain('/v1/site-publications/security-activations?')
    const statusURL = new URL(calls[0].url, 'https://example.test')
    expect(statusURL.searchParams.get('site_id')).toBe('33333333-3333-4333-8333-333333333333')
    expect(statusURL.searchParams.get('policy_kind')).toBe('waf')
    const headers = new Headers(calls[1].init?.headers)
    expect(calls[1].url).toContain('/v1/site-publications/security-activations')
    expect(calls[1].init?.method).toBe('POST')
    expect(headers.get('Idempotency-Key')).toBe('security-activation-publish-1')
    expect(headers.get('X-Request-ID')).toBe('66666666-6666-4666-8666-666666666666')
    expect(headers.get('Traceparent')).toBe('00-0123456789abcdef0123456789abcdef-0123456789abcdef-01')
    expect(headers.get('X-Correlation-ID')).toBe('77777777-7777-4777-8777-777777777777')
    expect(headers.get('X-Task-ID')).toBe('security-task:1')
  })
})
