import { canonicalSiteDomains, sitesApi } from './sites'

const snapshotID = '01999999-9999-7999-8999-999999999999'

describe('site domain contract and export client', () => {
  it('canonicalizes IDNA, wildcard, duplicate, and deterministic multi-domain inputs', () => {
    expect(canonicalSiteDomains([
      ' BÜCHER.example. ',
      '*.Edge.Example.com',
      'api.example.com',
      'API.EXAMPLE.COM',
    ])).toEqual(['*.edge.example.com', 'api.example.com', 'xn--bcher-kva.example'])
    expect(canonicalSiteDomains(['example'])).toBeNull()
    expect(canonicalSiteDomains(['api.*.example.com'])).toBeNull()
    expect(canonicalSiteDomains(Array.from({ length: 101 }, (_, index) => `host-${index}.example.com`)))
      .toBeNull()
  })

  it('downloads the exact tenant domain snapshot through the strict GET contract', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('site_id,domain\n', {
      status: 200,
      headers: {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': 'attachment; filename="site-domains.csv"',
        'X-Site-Domain-Export-Snapshot-ID': snapshotID,
      },
    }))

    const result = await sitesApi.exportDomains('token', { domain: ' Example.COM. ' })

    expect(fetchSpy).toHaveBeenCalledWith('/v1/sites/export?domain=example.com', expect.objectContaining({
      credentials: 'include',
      headers: expect.objectContaining({ Authorization: 'Bearer token' }),
    }))
    expect(result.filename).toBe('site-domains.csv')
    expect(result.snapshotID).toBe(snapshotID)
    expect(result.blob.type).toBe('text/csv;charset=utf-8')
  })

  it.each([
    ['content type', { 'Content-Type': 'text/plain', 'Content-Disposition': 'attachment; filename="site-domains.csv"', 'X-Site-Domain-Export-Snapshot-ID': snapshotID }],
    ['filename', { 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'inline', 'X-Site-Domain-Export-Snapshot-ID': snapshotID }],
    ['snapshot identity', { 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'attachment; filename="site-domains.csv"', 'X-Site-Domain-Export-Snapshot-ID': 'not-a-uuid' }],
  ])('rejects an invalid successful export %s response', async (_name, headers) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('private body', { status: 200, headers }))
    await expect(sitesApi.exportDomains('token', {})).rejects.toMatchObject({
      status: 502,
      code: 'invalid_response',
    })
  })
})
