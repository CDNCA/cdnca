import { afterEach, describe, expect, it, vi } from 'vitest'

import notificationsOpenApi from '../../../../api/control-notifications.openapi.yaml?raw'
import { maxNotificationPolicyEvents, notificationsApi, type NotificationDeliveryLog } from './notifications'

const delivery: NotificationDeliveryLog = {
  scope_id: '11111111-1111-4111-8111-111111111111',
  outbox_id: '22222222-2222-4222-8222-222222222222',
  event_type: 'announcement.published',
  channel: 'email',
  template_id: 'announcement_published',
  template_version: 2,
  generation: 1,
  state: 'retry_wait',
  revision: 2,
  attempt_count: 1,
  failure_code: 'smtp_temporary_failure',
  retry_at: '2026-08-08T10:01:00Z',
  created_at: '2026-08-08T10:00:00Z',
  updated_at: '2026-08-08T10:00:05Z',
}

function json(value: unknown, status = 200) {
  return Promise.resolve(new Response(JSON.stringify(value), {
    status, headers: { 'Content-Type': 'application/json' },
  }))
}

afterEach(() => vi.restoreAllMocks())

describe('notifications delivery log API', () => {
  it('accepts package monitor subscription events backed by the tenant notification queue', async () => {
    const subscription = {
      event_type: 'package.monitor.traffic.triggered',
      sms_enabled: false, email_enabled: true,
      sms_supported: true, email_supported: true, revision: 2, changed: false,
    }
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(() => json(subscription))

    await expect(notificationsApi.getSubscription('token', 'package.monitor.traffic.triggered')).resolves.toEqual(subscription)
    expect(fetchMock).toHaveBeenCalledWith(
      '/v1/account/notification-subscriptions/package.monitor.traffic.triggered',
      expect.objectContaining({ credentials: 'include' }),
    )

    fetchMock.mockImplementationOnce(() => json({ ...subscription, event_type: 'package.monitor.traffic.recovered' }))
    await expect(notificationsApi.getSubscription('token', 'package.monitor.traffic.triggered')).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('accepts runtime health telemetry extensions from the control API', async () => {
    const health = {
      enabled: true, state: 'ready', ready: true, worker_running: true, enabled_channels: 1,
      consecutive_failures: 0, last_error_class: 'smtp_temporary_failure',
    }
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => json(health))
    await expect(notificationsApi.getRuntimeHealth('token')).resolves.toEqual(health)
  })

  it('keeps the server request ID when a successful response violates the contract', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => Promise.resolve(new Response(JSON.stringify({ enabled: true }), {
      status: 200, headers: { 'Content-Type': 'application/json', 'X-Request-ID': 'notification-contract-1' },
    })))
    await expect(notificationsApi.getRuntimeHealth('token')).rejects.toMatchObject({
      code: 'invalid_response', requestId: 'notification-contract-1',
    })
  })

  it('serializes bounded filters and validates redacted delivery and attempt pages', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockImplementationOnce(() => json({ items: [delivery], next_cursor: delivery.outbox_id }))
      .mockImplementationOnce(() => json({
        outbox_id: delivery.outbox_id,
        items: [{
          attempt_number: 1, outcome: 'temporary_failure', failure_code: 'smtp_temporary_failure',
          next_attempt_at: '2026-08-08T10:01:00Z', claimed_at: '2026-08-08T10:00:01Z',
          lease_expires_at: '2026-08-08T10:00:31Z',
          completed_at: '2026-08-08T10:00:05Z',
        }],
      }))

    await expect(notificationsApi.listDeliveries('token', {
      scopeID: delivery.scope_id, channel: 'email', state: 'retry_wait', limit: 25, cursor: delivery.outbox_id,
    })).resolves.toEqual({ items: [delivery], next_cursor: delivery.outbox_id })
    expect(new URL(fetchMock.mock.calls[0]![0] as string, 'https://example.test').pathname +
      new URL(fetchMock.mock.calls[0]![0] as string, 'https://example.test').search).toBe(
      `/v1/admin/notifications/deliveries?scope_id=${delivery.scope_id}&channel=email&state=retry_wait&limit=25&cursor=${delivery.outbox_id}`,
    )

    await expect(notificationsApi.listDeliveryAttempts('token', delivery.outbox_id)).resolves.toEqual({
      outbox_id: delivery.outbox_id,
      items: [{
        attempt_number: 1, outcome: 'temporary_failure', failure_code: 'smtp_temporary_failure',
        next_attempt_at: '2026-08-08T10:01:00Z', claimed_at: '2026-08-08T10:00:01Z',
        lease_expires_at: '2026-08-08T10:00:31Z',
        completed_at: '2026-08-08T10:00:05Z',
      }],
    })
  })

  it.each([
    ['delivery secret field', { items: [{ ...delivery, subject: 'private' }] }],
    ['unknown state', { items: [{ ...delivery, state: 'provider_private_state' }] }],
    ['attempt lease token', { outbox_id: delivery.outbox_id, items: [{
      attempt_number: 1, outcome: 'leased', claimed_at: '2026-08-08T10:00:01Z', lease_token: 'private',
      lease_expires_at: '2026-08-08T10:00:31Z',
    }] }],
  ])('rejects %s in a supposedly public response', async (_name, response) => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => json(response))
    const request = Object.hasOwn(response, 'outbox_id')
      ? notificationsApi.listDeliveryAttempts('token', delivery.outbox_id)
      : notificationsApi.listDeliveries('token', {})
    await expect(request).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('rejects malformed filters and outbox IDs before network access', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch')
    await expect(notificationsApi.listDeliveries('token', { limit: 0 })).rejects.toMatchObject({ code: 'validation_error' })
    await expect(notificationsApi.listDeliveries('token', { cursor: 'not-a-cursor' })).rejects.toMatchObject({ code: 'validation_error' })
    await expect(notificationsApi.listDeliveryAttempts('token', 'not-an-outbox')).rejects.toMatchObject({ code: 'validation_error' })
    expect(fetchMock).not.toHaveBeenCalled()
  })
})

describe('notification policy API', () => {
  const policy = {
    schema: 'cdnca.notification-delivery-policy/v1' as const,
    window_mode: 'custom' as const,
    window_start: '08:00',
    window_end: '22:00',
    timezone: 'Asia/Shanghai',
    revision: 4,
    changed: false,
    events: [{
      event_type: 'announcement.published', enabled: true, sms_enabled: false, email_enabled: true,
      repeat_count: 2, interval_hours: 6, supported: true,
    }],
  }

  it('reads and writes the delivery policy with CAS and request identity headers', async () => {
    const next = {
      window_mode: 'custom' as const,
      window_start: '09:00',
      window_end: '21:00',
      timezone: 'Asia/Shanghai',
      events: [{ ...policy.events[0], email_enabled: false }],
    }
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockImplementationOnce(() => json(policy))
      .mockImplementationOnce(() => json({ schema: policy.schema, ...next, revision: 5, changed: true }))

    await expect(notificationsApi.getDeliveryPolicy('token')).resolves.toEqual(policy)
    await expect(notificationsApi.putDeliveryPolicy('token', next, 4, 'notification-policy-1')).resolves.toMatchObject({
      ...next, revision: 5, changed: true,
    })
    expect(fetchMock.mock.calls[0]![0]).toBe('/v1/admin/notifications/policy')
    expect(fetchMock.mock.calls[1]![0]).toBe('/v1/admin/notifications/policy')
    expect(fetchMock.mock.calls[1]![1]).toEqual(expect.objectContaining({
      method: 'PUT',
      headers: expect.objectContaining({ 'If-Match': '"4"', 'X-Request-ID': 'notification-policy-1' }),
      body: JSON.stringify(next),
    }))
  })

  it('rejects a policy response with an invalid time even when HTTP succeeds', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => json({ ...policy, window_start: '25:00' }))
    await expect(notificationsApi.getDeliveryPolicy('token')).rejects.toMatchObject({ code: 'invalid_response' })
  })

  const eventsOf = (count: number) => Array.from({ length: count }, (_, index) => ({
    ...policy.events[0], event_type: `test.event_${index}`,
  }))

  // live-click-B E1: 主控事件目录已有 75 条，旧前端 64 上限把整个响应判为非法。
  it('accepts a policy whose event catalog exceeds the old 64 limit', async () => {
    const large = { ...policy, events: eventsOf(75) }
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => json(large))
    await expect(notificationsApi.getDeliveryPolicy('token')).resolves.toEqual(large)
  })

  it('rejects a policy with more events than the shared upper bound', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => json({ ...policy, events: eventsOf(maxNotificationPolicyEvents + 1) }))
    await expect(notificationsApi.getDeliveryPolicy('token')).rejects.toMatchObject({ code: 'invalid_response' })
  })

  it('keeps the event upper bound equal to the OpenAPI contract', () => {
    const write = notificationsOpenApi.slice(notificationsOpenApi.indexOf('    DeliveryPolicyWrite:'))
    const events = /\n {8}events: \{[^\n]*maxItems: (\d+)/.exec(write)
    expect(Number(events?.[1])).toBe(maxNotificationPolicyEvents)
  })
})
