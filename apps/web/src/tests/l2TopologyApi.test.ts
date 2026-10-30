import { l2TopologyApi, type L2ConfigInput, type L2ConditionInput } from '../api/nodeScheduling'

const id = '11111111-1111-4111-8111-111111111111'
const metadata = { expectedRevision: 7, idempotencyKey: 'l2-write-key', requestId: 'l2-write-request' }
const createMetadata = { ...metadata, expectedRevision: 0 }
const config: L2ConfigInput = { name: 'L2 East', region: 'cn-east', remark: '', mode: 'cache', load_method: 'rr' }
const condition: L2ConditionInput = { name: 'Cached URLs', remark: '', rules: [{ field: 'uri', operator: 'prefix', value: '/cache/' }] }
const node = { condition_id: id, enabled: true, weight: 80, sort: 10 }
const add = { config_id: id, node_ids: ['22222222-2222-4222-8222-222222222222'], condition_id: null }

describe('L2 API contract', () => {
  it.each([
    ['/v1/l2-configs', () => l2TopologyApi.configs('access-token')],
    [`/v1/l2-configs/${id}`, () => l2TopologyApi.config('access-token', id)],
    ['/v1/l2-conds', () => l2TopologyApi.conditions('access-token')],
    [`/v1/l2-nodes?config_id=${id}`, () => l2TopologyApi.nodes('access-token', id)],
    [`/v1/l2-nodes?config_id=${id}&available=true`, () => l2TopologyApi.availableNodes('access-token', id)],
  ] as const)('reads the real scoped resource at %s', async (path, read) => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ items: [] })))
    await read()
    expect(fetchSpy).toHaveBeenCalledWith(path, expect.objectContaining({
      credentials: 'include', headers: expect.objectContaining({ Authorization: 'Bearer access-token' }),
    }))
    const headers = new Headers(fetchSpy.mock.calls[0]![1]?.headers)
    expect(headers.get('CdncaKey')).toBeNull()
    expect(headers.get('If-Match')).toBeNull()
    expect(path).not.toContain('target_scope_id')
  })

  it.each([
    ['/v1/l2-configs', 'POST', config, 0, () => l2TopologyApi.saveConfig('access-token', null, config, createMetadata)],
    [`/v1/l2-configs/${id}`, 'PUT', config, 7, () => l2TopologyApi.saveConfig('access-token', id, config, metadata)],
    [`/v1/l2-configs/${id}`, 'DELETE', undefined, 7, () => l2TopologyApi.removeConfig('access-token', id, metadata)],
    ['/v1/l2-conds', 'POST', condition, 0, () => l2TopologyApi.saveCondition('access-token', null, condition, createMetadata)],
    [`/v1/l2-conds/${id}`, 'PUT', condition, 7, () => l2TopologyApi.saveCondition('access-token', id, condition, metadata)],
    [`/v1/l2-conds/${id}`, 'DELETE', undefined, 7, () => l2TopologyApi.removeCondition('access-token', id, metadata)],
    ['/v1/l2-nodes', 'POST', add, 0, () => l2TopologyApi.addNodes('access-token', add, createMetadata)],
    [`/v1/l2-nodes/${id}`, 'PUT', node, 7, () => l2TopologyApi.saveNode('access-token', id, node, metadata)],
    [`/v1/l2-nodes/${id}`, 'DELETE', undefined, 7, () => l2TopologyApi.removeNode('access-token', id, metadata)],
  ] as const)('preserves the %s %s write contract', async (path, method, body, revision, write) => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(method === 'DELETE'
      ? new Response(null, { status: 204 }) : new Response(JSON.stringify({ id })))
    await write()
    expect(fetchSpy).toHaveBeenCalledWith(path, expect.objectContaining({
      method,
      headers: expect.objectContaining({
        Authorization: 'Bearer access-token',
        'If-Match': `"${revision}"`,
        'Idempotency-Key': metadata.idempotencyKey,
        'X-Request-ID': metadata.requestId,
      }),
    }))
    expect(fetchSpy.mock.calls[0]![1]?.body).toBe(body === undefined ? undefined : JSON.stringify(body))
  })
})
