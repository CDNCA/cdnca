import { nodesApi, type BatchNodeAdminStateRequest, type NodeInventoryItem } from '../api/nodes'
import { nodeManagementSettingsFixture } from '../test/fixtures'

const node: NodeInventoryItem = {
  id: '018f0000-0000-7000-8000-000000000001',
  display_id: '1',
  name: 'Edge Shanghai',
  description: 'primary edge',
  region: 'CN-East',
  ipv4: '192.0.2.10',
  admin_state: 'active',
  management_settings: nodeManagementSettingsFixture(),
  revision: 4,
  created_at: '2026-07-22T08:00:00Z',
  updated_at: '2026-07-22T09:00:00Z',
  presence: {
    status: 'online',
    last_heartbeat_at: '2026-07-22T08:59:55Z',
    agent_version: '2.4.1',
    session_epoch: 7,
    heartbeat_sequence: 11,
    projection_freshness: 'fresh',
    lease_signal: 'present',
  },
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('nodes API', () => {
  it('serializes only the contracted cursor, limit, administrative, and presence filters', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [node] }))

    await nodesApi.list('token', { limit: 50, status: 'disabled', presence: 'offline', cursor: node.id })

    expect(fetchSpy).toHaveBeenCalledWith(
      `/v1/nodes?limit=50&status=disabled&presence=offline&cursor=${node.id}`,
      expect.objectContaining({
        credentials: 'include',
        headers: expect.objectContaining({ Authorization: 'Bearer token' }),
      }),
    )
  })

  it('sends the exact update precondition, body, and idempotency key', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({
      ...node,
      presence: undefined,
      revision: 5,
    }))
    const input = {
      description: 'updated',
      ipv4: '',
      management_settings: { ...node.management_settings, sort: 90, node_type: 'L2' as const },
    }

    await nodesApi.update('token', node, input, 'node-update-key')

    expect(fetchSpy).toHaveBeenCalledWith(
      `/v1/nodes/${node.id}`,
      expect.objectContaining({
        method: 'PATCH',
        body: JSON.stringify(input),
        headers: expect.objectContaining({
          Authorization: 'Bearer token',
          'Idempotency-Key': 'node-update-key',
          'If-Match': '"4"',
        }),
      }),
    )
  })

  it('preserves ordered batch revisions and one idempotency key', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [] }))
    const input: BatchNodeAdminStateRequest = {
      admin_state: 'disabled',
      items: [
        { id: node.id, expected_revision: 4 },
        { id: '018f0000-0000-7000-8000-000000000002', expected_revision: 2 },
      ],
    }

    await nodesApi.batchAdminState('token', input, 'node-batch-key')

    expect(fetchSpy).toHaveBeenCalledWith(
      '/v1/nodes/batch-admin-state',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify(input),
        headers: expect.objectContaining({ 'Idempotency-Key': 'node-batch-key' }),
      }),
    )
  })

  it('uses the one-time token contracts without inventing idempotency headers', async () => {
    const token = {
      id: '018f0000-0000-7000-8000-000000000010',
      node_id: node.id,
      purpose: 're_enrollment' as const,
      created_at: '2026-07-22T09:00:00Z',
      expires_at: '2026-07-22T09:10:00Z',
      token: 'a'.repeat(43),
    }
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation((input) => Promise.resolve(
      json(String(input).endsWith('/enrollment-tokens') ? token : { node, enrollment_token: token }, 201),
    ))

    await nodesApi.create('token', {
      name: node.name,
      issue_enrollment_token: true,
      enrollment_purpose: 'initial_enrollment',
      enrollment_token_ttl_seconds: 600,
    }, 'node-create-key')
    await nodesApi.issueEnrollmentToken('token', node.id, { purpose: 're_enrollment', ttl_seconds: 600 })

    const createHeaders = new Headers(fetchSpy.mock.calls[0]?.[1]?.headers)
    expect(createHeaders.get('Idempotency-Key')).toBe('node-create-key')
    const tokenHeaders = new Headers(fetchSpy.mock.calls[1]?.[1]?.headers)
    expect(tokenHeaders.get('Idempotency-Key')).toBeNull()
  })
})
