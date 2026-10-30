import { notificationHistoryApi, type NotificationHistoryFact, type NotificationHistoryFilters } from '../api/notificationHistory'

const outboxID = '11111111-1111-4111-8111-111111111111'
const scopeID = '22222222-2222-4222-8222-222222222222'
const messageID = '33333333-3333-4333-8333-333333333333'
const fact: NotificationHistoryFact = {
  id: `${outboxID}:2`, outbox_id: outboxID, scope_id: scopeID, message_id: messageID, sequence: 2,
  attempt_number: 1, failure_count: 1, generation: 1, fact_kind: 'retry_scheduled', state: 'retry_wait',
  failure_code: 'dispatch_unavailable', observed_at: '2026-09-28T01:02:03.123456789Z', event_type: 'announcement.published',
  recipient_user_id: scopeID, recipient_user_display_id: '15', recipient_kind: 'member', channel: 'email',
  replay_of_outbox_id: null, recipient_address: null, recipient_address_state: 'unavailable',
}
const page = (items: unknown[] = [fact]) => ({ schema: 'cdnca.notification-delivery-history/v1', items, total_count: items.length })
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } })

it('queries the immutable history endpoint with exact filters and bearer ownership', async () => {
  const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ ...page(), total_count: 2, next_cursor: `${outboxID}:1` }))
  const signal = new AbortController().signal
  const filters: NotificationHistoryFilters = {
    scopeID, userID: '15', messageID, channel: 'email', eventType: 'announcement.published', result: 'failure', state: 'retry_wait',
    from: '2026-09-27T01:00:00Z', to: '2026-09-28T01:00:00Z', limit: 300, cursor: `${outboxID}:3`,
  }
  const result = await notificationHistoryApi.list('token', filters, signal)
  const [url, init] = fetchSpy.mock.calls[0]
  const parsed = new URL(String(url), 'https://example.test')
  expect(parsed.pathname).toBe('/v1/admin/notifications/delivery-history')
  expect(Object.fromEntries(parsed.searchParams)).toEqual({
    scope_id: scopeID, user_id: '15', message_id: messageID, channel: 'email', event_type: 'announcement.published', result: 'failure', state: 'retry_wait',
    from: filters.from, to: filters.to, limit: '300', cursor: `${outboxID}:3`,
  })
  expect(new Headers(init?.headers).get('Authorization')).toBe('Bearer token')
  expect(init).toMatchObject({ credentials: 'include', signal })
  expect(result.items[0].failure_count).toBe(1)
  expect(result.next_cursor).toBe(`${outboxID}:1`)
})

it('keeps default history unbounded and accepts anonymous facts without historical addresses', async () => {
  const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(page([{
    ...fact, recipient_user_id: null, recipient_user_display_id: null, recipient_kind: 'anonymous',
    attempt_number: 0, failure_count: 0, fact_kind: 'replay_created', failure_code: null, state: 'pending',
  }])))
  const result = await notificationHistoryApi.list('token', {})
  expect(String(fetchSpy.mock.calls[0][0])).not.toContain('?')
  expect(result.items[0].recipient_address).toBeNull()
  expect(result.items[0].recipient_user_id).toBeNull()
})

it('accepts the largest backend display ID without rounding it', async () => {
  const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(page([{ ...fact, recipient_user_display_id: '9223372036854775807' }])))
  const result = await notificationHistoryApi.list('token', { userID: '9223372036854775807' })
  expect(new URL(String(fetchSpy.mock.calls[0][0]), 'https://test').searchParams.get('user_id')).toBe('9223372036854775807')
  expect(result.items[0].recipient_user_display_id).toBe('9223372036854775807')
})

it.each([
  { subject: 'unapproved content' }, { recipient_address: 'current@example.test' }, { failure_count: -1 }, { attempt_number: -1 },
  { sequence: 3 }, { state: 'success' }, { failure_code: 'raw provider error with secret' }, { fact_kind: 'current_state' },
  { observed_at: 'yesterday' }, { recipient_user_display_id: '0' }, { recipient_user_display_id: '9223372036854775808' }, { message_id: 'not-a-message-id' },
])('rejects invalid or unapproved response fields: %j', async (changes) => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(page([{ ...fact, ...changes }])))
  await expect(notificationHistoryApi.list('token', {})).rejects.toMatchObject({ code: 'invalid_response' })
})

it.each([
  { limit: 301 }, { limit: 0 }, { cursor: '' }, { userID: '0' }, { userID: 15 }, { userID: '9223372036854775808' }, { messageID: '15' },
  { state: 'success' }, { result: 'accepted' }, { eventType: 'legacy type' }, { channel: 'webhook' }, { unknown: 'value' },
  { from: '2026-09-01T00:00:00Z', to: '2026-09-01T00:00:00Z' },
  { from: '2026-08-01T00:00:00Z', to: '2026-09-02T00:00:00Z' },
])('rejects invalid filters before requesting: %j', async (filters) => {
  const fetchSpy = vi.spyOn(globalThis, 'fetch')
  await expect(notificationHistoryApi.list('token', filters as NotificationHistoryFilters)).rejects.toMatchObject({ code: 'validation_error' })
  expect(fetchSpy).not.toHaveBeenCalled()
})

it('preserves API error codes without exposing raw server messages and maps network failure', async () => {
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(json({ error: { code: 'permission_denied', message: 'sensitive server detail' } }, 403))
    .mockRejectedValueOnce(new Error('network provider data'))
  await expect(notificationHistoryApi.list('token', {})).rejects.toMatchObject({ code: 'permission_denied', status: 403, message: 'API request failed' })
  await expect(notificationHistoryApi.list('token', {})).rejects.toMatchObject({ code: 'network_error' })
})

it('does not reinterpret cancellation as a network error', async () => {
  const controller = new AbortController()
  controller.abort()
  const aborted = new DOMException('Aborted', 'AbortError')
  vi.spyOn(globalThis, 'fetch').mockRejectedValueOnce(aborted)
  await expect(notificationHistoryApi.list('token', {}, controller.signal)).rejects.toBe(aborted)
})


it.each(['m***@example.test', '***@example.test', '***1234'])('accepts a recorded masked address and provider call time: %s', async (address) => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(page([{ ...fact, recipient_address: address, recipient_address_state: 'masked', provider_call_started_at: '2026-09-28T01:02:01.123456Z' }])))
  const result = await notificationHistoryApi.list('token', {})
  expect(result.items[0]).toMatchObject({ recipient_address: address, provider_call_started_at: '2026-09-28T01:02:01.123456Z' })
})

it.each([
  { recipient_address: 'unmasked@example.test', recipient_address_state: 'masked' },
  { recipient_address: null, recipient_address_state: 'masked' },
  { provider_call_started_at: 'yesterday' },
])('rejects inconsistent observation fields: %j', async (changes) => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(page([{ ...fact, ...changes }])))
  await expect(notificationHistoryApi.list('token', {})).rejects.toMatchObject({ code: 'invalid_response' })
})
