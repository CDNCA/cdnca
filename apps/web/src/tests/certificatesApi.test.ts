import { vi } from 'vitest'
import { ApiError } from '../api/auth'

import {
  certificatesApi,
	  type BindCertificateAssetInput,
  type CreateCertificateOrderInput,
  type ImportCertificateAssetInput,
} from '../api/certificates'

function response(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status, headers: { 'Content-Type': 'application/json' },
  })
}

describe('certificatesApi', () => {
  it('reads immutable binding publication revisions and cross-checks rollout routes without inventing owner permissions', async () => {
    const scope = '22222222-2222-4222-8222-222222222222'
    const site = '33333333-3333-4333-8333-333333333333'
    const rolloutID = '44444444-4444-4444-8444-444444444444'
    const current = {
      tenant_scope_id: scope, site_id: site, asset_id: site, version_id: site, binding_revision: 3, operation: 'publish', default: true,
      state_sequence: 1, state: 'succeeded', attempt: 1, occurred_at: '2026-10-12T00:00:00Z',
      publication_id: site, publication_revision: 1, config_version_id: site, rollout_id: rolloutID, rollout_revision: 1,
    }
    const receipt = { current, history: [{ sequence: 1, state: current.state, attempt: 1, occurred_at: current.occurred_at }] }
    const rollout = { id: rolloutID, config_version_id: site, revision: 1, action: 'apply', state: 'succeeded',
      progress: { total: 1, pending: 0, running: 0, succeeded: 1, failed: 0, cancelled: 0, superseded: 0, frozen: 0 } }
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(response(receipt)).mockResolvedValueOnce(response(receipt))
      .mockResolvedValueOnce(response(rollout)).mockResolvedValueOnce(response({ ...rollout, configuration_scope_id: scope }))
    await certificatesApi.getPublicationStatus('token', site, 3)
    await certificatesApi.getPublicationStatus('token', site, 3, scope)
    await certificatesApi.getPublicationRollout('token', rolloutID)
    await certificatesApi.getPublicationRollout('token', rolloutID, scope)
    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      `/v1/certificate-publications/${site}/revisions/3`, `/v1/certificate-publications/${site}/revisions/3?target_scope_id=${scope}`,
      `/v1/site-rollouts/${rolloutID}`, `/v1/admin/site-rollouts/${rolloutID}?scope_id=${scope}`,
    ])
    fetchMock.mockResolvedValueOnce(response({ ...receipt, current: { ...current, binding_revision: 2 } }))
      .mockResolvedValueOnce(response(rollout))
    await expect(certificatesApi.getPublicationStatus('token', site, 3, scope)).rejects.toMatchObject({ code: 'invalid_response' })
    await expect(certificatesApi.getPublicationRollout('token', rolloutID, scope)).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('preserves factual tenant and owner projections and explicit upload ownership', async () => {
    const asset = {
      id: 'asset', display_id: '1', tenant_scope_id: 'scope',
      tenant: { id: 'tenant', display_id: '9', name: 'Tenant' },
      owner: { id: 'owner', display_id: '17', username: 'member', display_name: 'Member' }, owner_status: 'recorded',
      name: 'Certificate', source: 'uploaded', revision: 1,
      created_by: 'platform-actor', updated_by: 'platform-actor', created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z',
    }
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(response({ items: [asset], total: 1, counts: { all: 1, normal: 0, expiring: 1, expired: 0, auto_renew: 0, manual_renew: 1 } }))
      .mockResolvedValueOnce(response({ asset, versions: [] }, 201))
    expect(await certificatesApi.listAssets('token')).toEqual({ items: [asset], total: 1, counts: { all: 1, normal: 0, expiring: 1, expired: 0, auto_renew: 0, manual_renew: 1 } })
    const input = { name: 'Certificate', certificate_pem: 'PUBLIC', private_key_pem: 'PRIVATE', owner_user_id: 'owner' }
    await certificatesApi.uploadAsset('token', input, 'key', 'request', 'scope')
    expect(fetchMock.mock.calls[0][0]).toBe('/v1/certificate-assets')
    expect(fetchMock.mock.calls[1][0]).toBe('/v1/certificate-assets?target_scope_id=scope')
    expect(JSON.parse(fetchMock.mock.calls[1][1]!.body as string)).toEqual(input)
  })

  it.each([
    { owner_status: 'recorded', owner: null },
    { owner_status: 'legacy_unknown', owner: { id: 'creator' } },
    { owner_status: 'inferred', owner: null },
    { tenant: null },
    { tenant: { id: 'tenant', display_id: '0', name: 'Tenant' } },
    { display_id: 'asset-uuid' },
  ])('rejects invalid ownership and tenant projections %#', async (patch) => {
    const asset = {
      id: 'asset', display_id: '1', tenant_scope_id: 'scope', tenant: { id: 'tenant', display_id: '9', name: 'Tenant' },
      owner: null, owner_status: 'legacy_unknown', name: 'Certificate', source: 'uploaded', revision: 1,
      created_by: 'creator', updated_by: 'creator', created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z', ...patch,
    }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response({ items: [asset], total: 1, counts: { all: 1, normal: 0, expiring: 1, expired: 0, auto_renew: 0, manual_renew: 1 } }))
    await expect(certificatesApi.listAssets('token')).rejects.toMatchObject({ status: 502, code: 'invalid_response' })
  })

  it('lists and creates only through the tenant certificate-order route', async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      calls.push({ url: String(input), init })
      return Promise.resolve(response(init?.method === 'POST' ? { id: 'order', status: 'pending' } : { items: [] }, init?.method === 'POST' ? 202 : 200))
    })
    const input: CreateCertificateOrderInput = {
      domains: ['example.com', '*.example.com'], challenge_type: 'dns-01',
      dns_provider_id: 'provider', auto_renew: true,
    }

    await certificatesApi.list('token')
    await certificatesApi.create('token', input, 'certificate-key')

    expect(calls.map((call) => call.url)).toEqual(['/v1/certificate-orders', '/v1/certificate-orders'])
    expect(calls.every((call) => !call.url.includes('/v1/admin/'))).toBe(true)
    expect(calls[1].init?.method).toBe('POST')
    expect(calls[1].init?.body).toBe(JSON.stringify(input))
    expect(new Headers(calls[1].init?.headers).get('Idempotency-Key')).toBe('certificate-key')
  })

  it('uses only canonical tenant certificate-asset routes and stable write metadata', async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      calls.push({ url: String(input), init })
      const url = String(input)
      const method = init?.method ?? 'GET'
      const asset = {
        display_id: '1', tenant: { id: 'tenant', display_id: '1', name: 'Tenant' }, owner: null, owner_status: 'legacy_unknown',
        id: assetID, tenant_scope_id: '22222222-2222-4222-8222-222222222222', name: 'edge certificate', source: 'uploaded', revision: 3,
        created_by: '11111111-1111-4111-8111-111111111111', updated_by: '11111111-1111-4111-8111-111111111111', created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z',
      }
      const version = {
        id: versionID, asset_id: assetID, tenant_scope_id: asset.tenant_scope_id, version: 1, status: 'active', fingerprint_sha256: 'ab'.repeat(32), certificate_pem: 'PUBLIC-PEM', sans: ['example.com'], subject: 'CN=example.com', serial_number: '1', public_key_algorithm: 'RSA', public_key_bits: 2048, signature_algorithm: 'SHA256-RSA', not_before: '2026-01-01T00:00:00Z', not_after: '2027-01-01T00:00:00Z', renewal_due: false, imported_by: asset.created_by, imported_at: asset.created_at,
      }
      if (method === 'GET' && url.endsWith('/bindings')) return Promise.resolve(response({ items: [] }))
      if (method === 'GET' && url.includes('/certificate-binding')) {
        return Promise.resolve(response({
          binding: { tenant_scope_id: asset.tenant_scope_id, site_id: binding.site_id, asset_id: assetID, version_id: versionID, revision: 1, default: true, bound: true, changed_by: asset.created_by, changed_at: asset.created_at },
          version,
        }))
      }
      if (method === 'GET' && url.includes(`/${assetID}`)) return Promise.resolve(response({ asset, versions: [version] }))
      if (method === 'POST' && (url.endsWith('/activate') || url.endsWith('/revoke'))) return Promise.resolve(response(version, 200))
      if (method === 'POST' && url.endsWith('/bindings')) return Promise.resolve(response({ tenant_scope_id: asset.tenant_scope_id, site_id: binding.site_id, asset_id: assetID, version_id: versionID, revision: 1, default: true, bound: true, changed_by: asset.created_by, changed_at: asset.created_at }, 200))
      if (method === 'DELETE' && url.includes('/bindings/')) return Promise.resolve(response({ tenant_scope_id: asset.tenant_scope_id, site_id: binding.site_id, asset_id: assetID, version_id: versionID, revision: 1, default: true, bound: false, changed_by: asset.created_by, changed_at: asset.created_at }, 200))
      if (method === 'DELETE') return Promise.resolve(response({ ...asset, deleted_at: '2026-01-02T00:00:00Z' }, 200))
      if (method === 'POST') return Promise.resolve(response({ asset, versions: [version] }, 201))
      return Promise.resolve(response({ items: [asset], total: 1, counts: { all: 1, normal: 0, expiring: 1, expired: 0, auto_renew: 0, manual_renew: 1 } }, 200))
    })
    const assetID = '33333333-3333-4333-8333-333333333333'
    const versionID = '44444444-4444-4444-8444-444444444444'
		const upload: ImportCertificateAssetInput = {
      name: 'edge certificate', certificate_pem: 'PUBLIC-PEM', private_key_pem: 'PRIVATE-PEM',
		}
		const binding: BindCertificateAssetInput = {
			site_id: '55555555-5555-4555-8555-555555555555', version_id: versionID,
			expected_revision: 0, default: true,
		}

    await certificatesApi.listAssets('token')
    await certificatesApi.getAsset('token', assetID)
		await certificatesApi.uploadAsset('token', upload, 'upload-key', 'upload-request')
		await certificatesApi.activateAssetVersion('token', assetID, versionID, {
			expected_revision: 3,
		}, 'activate-key', 'activate-request')
		await certificatesApi.listAssetBindings('token', assetID)
    await certificatesApi.getSiteBinding('token', binding.site_id)
		await certificatesApi.bindAsset('token', assetID, binding, 'bind-key', 'bind-request')
		await certificatesApi.unbindAsset('token', assetID, binding.site_id, {
			expected_revision: 1,
		}, 'unbind-key', 'unbind-request')
    await certificatesApi.deleteAsset('token', assetID, { expected_revision: 5 }, 'delete-key', 'delete-request')

    expect(calls.map((call) => call.url)).toEqual([
      '/v1/certificate-assets',
      `/v1/certificate-assets/${assetID}`,
		  '/v1/certificate-assets',
		  `/v1/certificate-assets/${assetID}/versions/${versionID}/activate`,
		  `/v1/certificate-assets/${assetID}/bindings`,
      `/v1/sites/${binding.site_id}/certificate-binding`,
		  `/v1/certificate-assets/${assetID}/bindings`,
		  `/v1/certificate-assets/${assetID}/bindings/${binding.site_id}`,
      `/v1/certificate-assets/${assetID}`,
    ])
		expect(calls.map((call) => call.init?.method ?? 'GET')).toEqual([
		  'GET', 'GET', 'POST', 'POST', 'GET', 'GET', 'POST', 'DELETE', 'DELETE',
		])
		const writes = calls.filter((call) => (call.init?.method ?? 'GET') !== 'GET')
		expect(writes.map((call) => new Headers(call.init?.headers).get('Idempotency-Key')))
		  .toEqual(['upload-key', 'activate-key', 'bind-key', 'unbind-key', 'delete-key'])
		expect(writes.map((call) => new Headers(call.init?.headers).get('X-Request-ID')))
		  .toEqual(['upload-request', 'activate-request', 'bind-request', 'unbind-request', 'delete-request'])
    expect(calls.every((call) => !call.url.includes('/v1/admin/'))).toBe(true)
    // fix-certmenu：资产吊销已下线（只改本地状态、与禁用重叠），客户端不再提供。
    expect('revokeAssetVersion' in certificatesApi).toBe(false)
  })

  it('requires a canonical tenant scope for reads and strictly validates asset responses', async () => {
    const scopeID = '22222222-2222-4222-8222-222222222222'
    const calls: Array<{ url: string; init?: RequestInit }> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      calls.push({ url: String(input), init })
      return Promise.resolve(response({ items: [{ id: 'asset-without-required-fields' }] }))
    })

    await expect(certificatesApi.listAssets('token', scopeID)).rejects.toMatchObject({
      status: 502, code: 'invalid_response',
    })
    expect(calls[0]?.url).toBe(`/v1/certificate-assets?target_scope_id=${scopeID}`)
  })

  it('rejects a site binding whose version identity or state is inconsistent', async () => {
    const binding = {
      tenant_scope_id: 'scope', site_id: 'site', asset_id: 'asset', version_id: 'version',
      revision: 1, default: true, bound: true, changed_by: 'user', changed_at: '2026-01-01T00:00:00Z',
    }
    const version = {
      id: 'other-version', asset_id: 'asset', tenant_scope_id: 'scope', version: 1, status: 'active',
      fingerprint_sha256: 'ab'.repeat(32), certificate_pem: 'PUBLIC', sans: ['example.com'], subject: 'CN=example.com',
      serial_number: '1', public_key_algorithm: 'RSA', public_key_bits: 2048, signature_algorithm: 'SHA256-RSA',
      not_before: '2026-01-01T00:00:00Z', not_after: '2027-01-01T00:00:00Z', renewal_due: false,
      imported_by: 'user', imported_at: '2026-01-01T00:00:00Z',
    }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response({ binding, version }))

    await expect(certificatesApi.getSiteBinding('token', 'site')).rejects.toMatchObject({
      status: 502, code: 'invalid_response',
    })
  })

  it.each([403, 404, 409, 412, 422, 429, 500, 503])('preserves stable API errors for asset status %s', async (status) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response({ error: { code: 'certificate_asset_failure', message: 'private server detail' } }, status))

    const error = await certificatesApi.getAsset('token', 'asset').catch((value: unknown) => value)
    expect(error).toBeInstanceOf(ApiError)
    expect(error).toMatchObject({ status, code: 'certificate_asset_failure' })
    expect((error as ApiError).message).toBe('API request failed')
  })

  it('never accepts private-key material in any asset response', async () => {
    const value = {
      asset: {
        display_id: '1', tenant: { id: 'tenant', display_id: '1', name: 'Tenant' }, owner: null, owner_status: 'legacy_unknown',
        id: 'asset', tenant_scope_id: 'scope', name: 'name', source: 'uploaded', revision: 1,
        created_by: 'user', updated_by: 'user', created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z',
      },
      versions: [{
        id: 'version', asset_id: 'asset', tenant_scope_id: 'scope', version: 1, status: 'active',
        fingerprint_sha256: 'ab'.repeat(32), certificate_pem: 'PUBLIC', sans: ['example.com'], subject: 'CN=example.com',
        serial_number: '1', public_key_algorithm: 'RSA', public_key_bits: 2048, signature_algorithm: 'SHA256-RSA',
        not_before: '2026-01-01T00:00:00Z', not_after: '2027-01-01T00:00:00Z', renewal_due: false,
        imported_by: 'user', imported_at: '2026-01-01T00:00:00Z', private_key_pem: 'PRIVATE',
      }],
    }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(value))

    await expect(certificatesApi.getAsset('token', 'asset')).rejects.toMatchObject({ code: 'invalid_response' })
  })
})
