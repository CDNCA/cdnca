import { ApiError } from './auth'
import { certificateOrderStatusApi, type CertificateOrderStatusItem } from './certificateOrderStatus'

const order: CertificateOrderStatusItem = {
  id: '33333333-3333-4333-8333-333333333333',
  scope_id: '22222222-2222-4222-8222-222222222222',
  dns_provider_id: '44444444-4444-4444-8444-444444444444',
  domains: ['example.com', 'www.example.com'],
  challenge_type: 'dns-01',
  status: 'active',
  auto_renew: true,
  renewal_of_order_id: '55555555-5555-4555-8555-555555555555',
  not_after: '2027-08-07T10:00:00Z',
  failure_code: 'dns_propagation_timeout',
  issued_asset_id: '66666666-6666-4666-8666-666666666666',
  issued_version_id: '77777777-7777-4777-8777-777777777777',
  issued_at: '2026-08-07T10:00:00Z',
  version: 3,
  created_at: '2026-08-07T09:00:00Z',
  updated_at: '2026-08-07T10:00:00Z',
}

function response(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('certificateOrderStatusApi', () => {
  it('uses the mounted read-only endpoint and strictly accepts the complete order shape', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(response({ items: [order] }))

    await expect(certificateOrderStatusApi.list('status-token')).resolves.toEqual({ items: [order] })

    expect(fetchSpy).toHaveBeenCalledTimes(1)
    const [input, init] = fetchSpy.mock.calls[0]!
    expect(String(input)).toBe('/v1/certificate-orders')
    expect(init?.method ?? 'GET').toBe('GET')
    expect(new Headers(init?.headers).get('Authorization')).toBe('Bearer status-token')
    expect(init?.body).toBeUndefined()
  })

  it.each([
    ['missing id', { id: undefined }],
    ['invalid id', { id: 'order-1' }],
    ['invalid scope', { scope_id: 'tenant-a' }],
    ['empty domains', { domains: [] }],
    ['invalid domain member', { domains: ['example.com', 7] }],
    ['invalid challenge', { challenge_type: 'tls-alpn-01' }],
    ['invalid status', { status: 'renewing' }],
    ['invalid auto renew', { auto_renew: 'yes' }],
    ['invalid renewal parent', { renewal_of_order_id: 'parent' }],
    ['invalid expiry', { not_after: 'tomorrow' }],
    ['invalid failure code', { failure_code: 'Raw failure detail' }],
    ['invalid asset id', { issued_asset_id: 'asset' }],
    ['invalid asset version id', { issued_version_id: 'version' }],
    ['invalid issued time', { issued_at: 'soon' }],
    ['invalid version', { version: 0 }],
    ['invalid created time', { created_at: 'today' }],
    ['invalid updated time', { updated_at: 123 }],
  ])('rejects %s as invalid_response', async (_label, patch) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response({ items: [{ ...order, ...patch }] }))

    await expect(certificateOrderStatusApi.list('token')).rejects.toMatchObject({
      status: 502,
      code: 'invalid_response',
    })
  })

  it('rejects malformed JSON and non-list envelopes', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response('{', { status: 200 }))
      .mockResolvedValueOnce(response({ orders: [order] }))

    await expect(certificateOrderStatusApi.list('token')).rejects.toMatchObject({ code: 'invalid_response' })
    await expect(certificateOrderStatusApi.list('token')).rejects.toMatchObject({ code: 'invalid_response' })
    expect(fetchSpy).toHaveBeenCalledTimes(2)
  })

  it.each([401, 403, 404, 409, 412, 429, 500, 503])('preserves stable status/code without raw messages for %s', async (status) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response({
      error: { code: 'certificate_order_unavailable', message: 'private acme host and account detail' },
    }, status))

    const error = await certificateOrderStatusApi.list('token').catch((value: unknown) => value)
    expect(error).toBeInstanceOf(ApiError)
    expect(error).toMatchObject({ status, code: 'certificate_order_unavailable', message: 'API request failed' })
  })
})
