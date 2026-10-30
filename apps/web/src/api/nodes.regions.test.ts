import { afterEach, describe, expect, it, vi } from 'vitest'

import { regionsApi, type RegionRecord } from './nodes'

const region: RegionRecord = {
  id: '7',
  name: '华东',
  code: 'region-7',
  country_code: 'CN',
  province_code: '310000',
  description: '主区域',
  l2_check_port: 80,
  sort: 100,
  revision: 3,
  created_at: '2026-09-15T08:00:00Z',
  updated_at: '2026-09-15T09:00:00Z',
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

afterEach(() => vi.restoreAllMocks())

describe('regionsApi', () => {
  it('lists a strict paginated catalog without accepting tenant scope input', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ count: 1, data: [region] }))

    await expect(regionsApi.list('region-token', { page: 2, page_size: 30, search: ' 华东 ' }))
      .resolves.toEqual({ count: 1, data: [region] })
    expect(fetchSpy).toHaveBeenCalledWith('/v1/regions?page=2&page_size=30&search=%E5%8D%8E%E4%B8%9C', expect.objectContaining({
      credentials: 'include', headers: expect.objectContaining({ Authorization: 'Bearer region-token' }),
    }))
    expect(String(fetchSpy.mock.calls[0]?.[0])).not.toContain('tenant')
  })

  it('sends exact create, update and delete concurrency headers', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ ...region, id: '8', revision: 1 }, 201))
      .mockResolvedValueOnce(json({ ...region, revision: 4 }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
    const input = { name: '华东', country_code: 'CN', province_code: '310000', description: '主区域', l2_check_port: 80, sort: 100 }

    await regionsApi.create('token', input, 'create-region-1')
    await regionsApi.update('token', region, input, 'update-region-1')
    await regionsApi.delete('token', region, 'delete-region-1')

    expect(fetchSpy.mock.calls[0]).toEqual(['/v1/regions', expect.objectContaining({
      method: 'POST', body: JSON.stringify(input),
      headers: expect.objectContaining({ Authorization: 'Bearer token', 'Content-Type': 'application/json', 'Idempotency-Key': 'create-region-1' }),
    })])
    expect(fetchSpy.mock.calls[1]).toEqual(['/v1/regions/7', expect.objectContaining({
      method: 'PATCH', body: JSON.stringify(input),
      headers: expect.objectContaining({ 'Idempotency-Key': 'update-region-1', 'If-Match': '"3"' }),
    })])
    expect(fetchSpy.mock.calls[2]).toEqual(['/v1/regions/7', expect.objectContaining({
      method: 'DELETE', headers: expect.objectContaining({ Authorization: 'Bearer token', 'Idempotency-Key': 'delete-region-1', 'If-Match': '"3"' }),
    })])
  })

  it('rejects malformed, unsorted and stale update responses', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ count: 1, data: [{ ...region, private_field: true }] }))
      .mockResolvedValueOnce(json({ count: 2, data: [{ ...region, id: '9', sort: 101 }, { ...region, id: '8', sort: 100 }] }))
      .mockResolvedValueOnce(json({ count: 1, data: [{ ...region, country_code: 'US', province_code: '310000' }] }))
      .mockResolvedValueOnce(json(region))
      .mockResolvedValueOnce(json({ unexpected: true }))

    await expect(regionsApi.list('token', { page: 1, page_size: 10 })).rejects.toMatchObject({ code: 'invalid_response' })
    await expect(regionsApi.list('token', { page: 1, page_size: 10 })).rejects.toMatchObject({ code: 'invalid_response' })
    // a province outside CN
    await expect(regionsApi.list('token', { page: 1, page_size: 10 })).rejects.toMatchObject({ code: 'invalid_response' })
    await expect(regionsApi.update('token', region, {
      name: region.name, country_code: '', province_code: '', description: region.description, l2_check_port: region.l2_check_port, sort: region.sort,
    }, 'update-stale')).rejects.toMatchObject({ code: 'invalid_response' })
    await expect(regionsApi.delete('token', region, 'delete-body')).rejects.toMatchObject({ code: 'invalid_response' })
    expect(fetchSpy).toHaveBeenCalledTimes(5)
  })

  it('preserves stable API error status and code', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      error: { code: 'regions_revision_conflict', message: 'private revision detail', request_id: 'request-1' },
    }, 412))

    await expect(regionsApi.update('token', region, {
      name: region.name, country_code: '', province_code: '', description: region.description, l2_check_port: region.l2_check_port, sort: region.sort,
    }, 'update-conflict')).rejects.toMatchObject({ status: 412, code: 'regions_revision_conflict' })
  })
})
