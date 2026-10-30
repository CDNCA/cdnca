import { beforeEach, describe, expect, it, vi } from 'vitest'

import openApiContract from '../../../../api/control-plugin-webhooks.openapi.yaml?raw'

import { ApiError } from './auth'
import {
  pluginWebhookEventType,
  pluginWebhooksApi,
  type PluginWebhookCreateInput,
  type PluginWebhookSubscription,
} from './pluginWebhooks'

const scopeID = '018cc251-f400-7def-8000-000000000020'
const subscriptionID = '018cc251-f400-7def-8000-000000000010'
const secretID = '018cc251-f400-7def-8000-000000000011'
const authorizationID = '018cc251-f400-7def-8000-000000000012'
const installationID = '018cc251-f400-7def-8000-000000000013'
const token = 'token'

function response(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function subscription(overrides: Partial<PluginWebhookSubscription> = {}): PluginWebhookSubscription {
  return {
    id: subscriptionID,
    tenant_scope_id: scopeID,
    name: 'Billing events',
    target_url: 'https://hooks.example.com/cdnca',
    event_types: [pluginWebhookEventType],
    status: 'active',
    revision: 1,
    active_secret_version_id: secretID,
    created_at: '2026-07-29T08:00:00Z',
    updated_at: '2026-07-29T08:00:00Z',
    ...overrides,
  }
}

describe('pluginWebhooksApi', () => {
  beforeEach(() => vi.restoreAllMocks())

  it('uses tenant-scoped list query and rejects malformed response shapes', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(response({ items: [subscription()] }))
    const page = await pluginWebhooksApi.listSubscriptions(token, scopeID, { limit: 20, cursor: 'next' })
    expect(page.items[0]?.id).toBe(subscriptionID)
    expect(String(fetchSpy.mock.calls[0]?.[0])).toBe(`/v1/tenant-scopes/${scopeID}/plugin-webhook-subscriptions?limit=20&cursor=next`)

    fetchSpy.mockResolvedValueOnce(response({ items: [{ id: 'not-a-subscription' }] }))
    await expect(pluginWebhooksApi.listSubscriptions(token, scopeID)).rejects.toMatchObject({ code: 'invalid_response', status: 502 })
  })

  it('sends strict create and lifecycle headers with canonical empty bodies', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
      if (init?.method === 'POST' && String(_input).endsWith('/plugin-webhook-subscriptions')) {
        return response({ subscription: subscription(), secret: 'A'.repeat(43) }, 201)
      }
      return response({ subscription: subscription({ revision: 2 }) })
    })
    await pluginWebhooksApi.createSubscription(token, scopeID, {
      name: 'Billing events', target_url: 'https://hooks.example.com/cdnca', event_types: [pluginWebhookEventType],
    }, 'plugin-webhook-create-1')
    const createInit = fetchSpy.mock.calls[0]?.[1]
    expect((createInit?.headers as Record<string, string>)['Idempotency-Key']).toBe('plugin-webhook-create-1')
    expect(createInit?.body).toContain('event_types')

    await pluginWebhooksApi.revokeSubscription(token, scopeID, subscriptionID, 1, 'plugin-webhook-revoke-1')
    const revokeInit = fetchSpy.mock.calls[1]?.[1]
    expect((revokeInit?.headers as Record<string, string>)['If-Match']).toBe('"1"')
    expect(revokeInit?.body).toBe('{}')
  })

  it('sends an optional installation authorization and accepts bound subscription fields', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(response({
      subscription: subscription({
        event_types: ['io.cdnca.deployment.v1.status_changed'],
        installation_authorization_id: authorizationID,
        installation_id: installationID,
        plugin_id: 'plugin.example',
      }),
      secret: 'A'.repeat(43),
    }, 201))
    const result = await pluginWebhooksApi.createSubscription(token, scopeID, {
      name: 'Deployments', target_url: 'https://hooks.example.com/cdnca', event_types: ['io.cdnca.deployment.v1.status_changed'],
      installation_authorization_id: authorizationID,
    }, 'plugin-webhook-bound-create-1')
    const body = JSON.parse(String(fetchSpy.mock.calls[0]?.[1]?.body)) as { installation_authorization_id?: string }
    expect(body.installation_authorization_id).toBe(authorizationID)
    expect(result.subscription.installation_id).toBe(installationID)
    expect(result.subscription.plugin_id).toBe('plugin.example')
  })

  it('rejects idempotency keys with an illegal suffix or more than 128 bytes before fetch', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    const input: PluginWebhookCreateInput = {
      name: 'Billing events', target_url: 'https://hooks.example.com/cdnca', event_types: [pluginWebhookEventType],
    }
    for (const key of ['plugin-webhook-create-1!', 'a'.repeat(129)]) {
      await expect(pluginWebhooksApi.createSubscription(token, scopeID, input, key)).rejects.toMatchObject({
        code: 'invalid_request', status: 400,
      })
    }
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('rejects targets outside the strict public HTTPS authority before fetch', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    const invalidTargets = [
      'http://hooks.example.com/cdnca',
      'https://127.0.0.1/cdnca',
      'https://[2001:db8::1]/cdnca',
      'https://localhost/cdnca',
      'https://xn--bcher-kva.example/cdnca',
      'https://user@hooks.example.com/cdnca',
      'https://hooks.example.com:8443/cdnca',
      'https://hooks.example.com/cdnca?secret=value',
      'https://hooks.example.com/cdnca#fragment',
      ' https://hooks.example.com/cdnca',
    ]

    for (const target_url of invalidTargets) {
      await expect(pluginWebhooksApi.createSubscription(token, scopeID, {
        name: 'Billing events', target_url, event_types: [pluginWebhookEventType],
      }, 'plugin-webhook-create-target')).rejects.toMatchObject({ code: 'invalid_request', status: 400 })
    }
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('rejects non-canonical one-time secrets even when they have 43 base64url characters', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    fetchSpy.mockResolvedValueOnce(response({ subscription: subscription(), secret: 'a'.repeat(43) }, 201))
    await expect(pluginWebhooksApi.createSubscription(token, scopeID, {
      name: 'Billing events', target_url: 'https://hooks.example.com/cdnca', event_types: [pluginWebhookEventType],
    }, 'plugin-webhook-create-secret')).rejects.toMatchObject({ code: 'invalid_response', status: 502 })

    fetchSpy.mockResolvedValueOnce(response({
      rotation_id: secretID,
      key_id: secretID,
      status: 'pending',
      expires_at: '2026-07-30T08:00:00Z',
      secret: 'a'.repeat(43),
      subscription_revision: 1,
    }, 201))
    await expect(pluginWebhooksApi.rotateSecret(token, scopeID, subscriptionID, 1, 'plugin-webhook-rotate-secret'))
      .rejects.toMatchObject({ code: 'invalid_response', status: 502 })
  })

  it('maps stable forbidden errors without exposing server message', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response({ error: { code: 'permission_denied', params: {}, message: 'internal detail' } }, 403))
    const error = await pluginWebhooksApi.listSubscriptions(token, scopeID).catch((value: unknown) => value)
    expect(error).toBeInstanceOf(ApiError)
    expect((error as ApiError).code).toBe('permission_denied')
    expect((error as ApiError).message).not.toContain('internal detail')
  })

  it('rejects the legacy top-level error shape', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response({ code: 'permission_denied', params: {}, message: 'internal detail' }, 403))
    const error = await pluginWebhooksApi.listSubscriptions(token, scopeID).catch((value: unknown) => value)
    expect(error).toMatchObject({ code: 'request_failed', status: 403 })
  })

  it('freezes entitlement responses and the nested error and retry-after contracts', () => {
    const operation = (operationID: string) => {
      const start = openApiContract.indexOf(`operationId: ${operationID}`)
      expect(start).toBeGreaterThan(-1)
      const end = openApiContract.indexOf('\n  /v1/', start)
      return openApiContract.slice(start, end === -1 ? undefined : end)
    }
    const unprocessable = "'422': { $ref: '#/components/responses/Unprocessable' }"
    for (const operationID of ['createPluginWebhookTestDelivery', 'replayPluginWebhookDelivery', 'rotatePluginWebhookSecret']) {
      expect(operation(operationID)).toContain(unprocessable)
    }
    expect(operation('activatePluginWebhookSecret')).not.toContain("'422':")
    expect(operation('revokePluginWebhookSubscription')).not.toContain("'422':")
    expect(openApiContract).toContain('required: [code, message, request_id, params]')
    expect(openApiContract).toContain('installation_authorization_id')
    expect(openApiContract).toContain('installation_id')
    expect(openApiContract).toContain('plugin_id')
    expect(openApiContract).toContain('Retry-After: { schema: { type: integer, minimum: 1, maximum: 3600 } }')
    expect(openApiContract.match(/pattern: '\^\[A-Za-z0-9_-\]\{42\}\[AEIMQUYcgkosw048\]\$'/g)).toHaveLength(2)
    expect(openApiContract).not.toContain("pattern: '^[A-Za-z0-9_-]{43}$'")
  })
})
