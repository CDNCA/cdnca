import { afterEach, describe, expect, it, vi } from 'vitest'

import {
  createGatewayAddressStepUp, gatewayAddressChangeComplete, nodeGatewayAddressApi, nodeGatewayAddressStepUpAction,
  nodeGatewayAddressStepUpAudience, validGatewayAddress, validServerName,
} from './nodeGatewayAddress'

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

afterEach(() => vi.restoreAllMocks())

describe('nodeGatewayAddress', () => {
  it('validates host:port and the optional SNI name', () => {
    expect(validGatewayAddress('gateway.cdnca.com:443')).toBe(true)
    expect(validGatewayAddress('203.0.113.9:9443')).toBe(true)
    expect(validGatewayAddress('[2001:db8::1]:443')).toBe(true)
    expect(validGatewayAddress('gateway.cdnca.com')).toBe(false)
    expect(validGatewayAddress('gateway.cdnca.com:0')).toBe(false)
    expect(validGatewayAddress('gateway.cdnca.com:65536')).toBe(false)
    expect(validGatewayAddress('gateway.cdnca.com:0443')).toBe(false)
    expect(validServerName('')).toBe(true)
    expect(validServerName('gateway.cdnca.com')).toBe(true)
    expect(validServerName('gate way')).toBe(false)
  })

  it('treats a change as complete only when nothing waits, probes or failed', () => {
    expect(gatewayAddressChangeComplete({ pending: 0, probing: 0, switched: 3, failed: 0, superseded: 1 })).toBe(true)
    expect(gatewayAddressChangeComplete({ pending: 0, probing: 1, switched: 2, failed: 0, superseded: 0 })).toBe(false)
    expect(gatewayAddressChangeComplete({ pending: 0, probing: 0, switched: 2, failed: 1, superseded: 0 })).toBe(false)
  })

  it('requests a platform step-up proof with the gateway address audience and an idempotency key', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ token: 'p'.repeat(43) }))
    await expect(createGatewayAddressStepUp('session', '123456')).resolves.toBe('p'.repeat(43))
    const [url, init] = fetchSpy.mock.calls[0]
    expect(String(url)).toContain('/v1/account/mfa/step-up-proofs')
    expect(JSON.parse(String(init!.body))).toMatchObject({ audience: nodeGatewayAddressStepUpAudience,
      action: nodeGatewayAddressStepUpAction, authentication: { method: 'totp', code: '123456' }, max_uses: 1 })
    expect((init!.headers as Record<string, string>)['Idempotency-Key']).toMatch(/^ngw-step-up-/)
  })

  it('sends create and retry with the step-up token and surfaces API error codes', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ id: 'c1', node_count: 2 }, 201))
      .mockResolvedValueOnce(json({ error: { code: 'gateway_address_nothing_to_retry' } }, 409))
    await nodeGatewayAddressApi.create('session', { address: 'g.cdnca.com:443', server_name: '', target_kind: 'all' }, 'proof')
    expect(JSON.parse(String(fetchSpy.mock.calls[0][1]!.body))).toEqual({ address: 'g.cdnca.com:443', server_name: '',
      target_kind: 'all', step_up_token: 'proof' })
    await expect(nodeGatewayAddressApi.retry('session', 'c1', 'proof')).rejects.toMatchObject({ status: 409, code: 'gateway_address_nothing_to_retry' })
    expect(String(fetchSpy.mock.calls[1][0])).toContain('/v1/admin/node-gateway-address-changes/c1/retry')
  })
})
