import { announcementsApi, globalAnnouncementsApi, newAnnouncementIdempotencyKey } from '../api/announcements'
import { vi } from 'vitest'

const announcementID = '11111111-1111-4111-8111-111111111111'
const eventID = '22222222-2222-4222-8222-222222222222'
const input = {
  title: 'Maintenance',
  body: 'Window',
  all: true,
  user_ids: [],
  group_ids: [],
  withdrawal_visibility: 'retain' as const,
}

function ok(value: unknown = {}) {
  return Promise.resolve(new Response(JSON.stringify(value), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  }))
}

describe('announcementsApi', () => {
  it('calls every owned route with exact paths, bodies, and preconditions', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => ok({ items: [] }))

    await announcementsApi.list('token', { status: 'draft', limit: 10, cursor: 'admin-cursor' })
    await announcementsApi.get('token', announcementID)
    await announcementsApi.create('token', input, 'create-key')
    await announcementsApi.update('token', announcementID, { ...input, version: 1, expected_revision: 2 }, 'update-key')
    await announcementsApi.schedule('token', announcementID, { version: 1, expected_revision: 3, publish_at: '2026-07-24T02:00:00.000Z' }, 'schedule-key')
    await announcementsApi.publish('token', announcementID, { version: 1, expected_revision: 4 }, 'publish-key')
    await announcementsApi.revise('token', announcementID, { ...input, expected_head_version: 1 }, 'revise-key')
    await announcementsApi.withdraw('token', announcementID, { version: 2, expected_revision: 5 }, 'withdraw-key')
    await announcementsApi.archive('token', announcementID, 1, 'archive-key')
    await announcementsApi.restore('token', announcementID, 2, 'restore-key')
    await announcementsApi.inbox('token', { filter: 'unread', limit: 10, cursor: 'inbox-cursor' })
    await announcementsApi.inbox('token', { limit: 10, offset: 20 })
    await announcementsApi.state('token', eventID, 'delivered', 6, 'delivered-key')
    await announcementsApi.state('token', eventID, 'read', 7, 'read-key')

    const calls = fetchSpy.mock.calls.map(([url, init]) => ({
      url: String(url),
      method: init?.method ?? 'GET',
      credentials: init?.credentials,
      headers: new Headers(init?.headers),
      body: init?.body ? JSON.parse(String(init.body)) as unknown : undefined,
    }))
    expect(calls).toHaveLength(14)
    expect(calls.map(({ url, method }) => [method, url])).toEqual([
      ['GET', '/v1/admin/announcements?status=draft&limit=10&cursor=admin-cursor'],
      ['GET', `/v1/admin/announcements/${announcementID}`],
      ['POST', '/v1/admin/announcements'],
      ['PATCH', `/v1/admin/announcements/${announcementID}`],
      ['POST', `/v1/admin/announcements/${announcementID}/schedule`],
      ['POST', `/v1/admin/announcements/${announcementID}/publish`],
      ['POST', `/v1/admin/announcements/${announcementID}/revise`],
      ['POST', `/v1/admin/announcements/${announcementID}/withdraw`],
      ['POST', `/v1/admin/announcements/${announcementID}/archive`],
      ['POST', `/v1/admin/announcements/${announcementID}/restore`],
      ['GET', '/v1/account/messages?filter=unread&limit=10&cursor=inbox-cursor'],
      ['GET', '/v1/account/messages?limit=10&offset=20'],
      ['POST', `/v1/account/messages/${eventID}/delivered`],
      ['POST', `/v1/account/messages/${eventID}/read`],
    ])
    for (const call of calls) expect(call.headers.get('Authorization')).toBe('Bearer token')
    for (const call of calls) expect(call.credentials).toBe('include')
    expect(calls[3].headers.get('Idempotency-Key')).toBe('update-key')
    expect(calls[3].headers.get('If-Match')).toBe('"2"')
    expect(calls[6].headers.get('If-Match')).toBe('"1"')
    expect(calls[8].body).toEqual({ expected_lifecycle_revision: 1 })
    expect(calls[9].headers.get('If-Match')).toBe('"2"')
    expect(calls[12].body).toEqual({ expected_revision: 6 })
    expect(calls[13].headers.get('Idempotency-Key')).toBe('read-key')
  })

  it('generates contract-safe operation-scoped idempotency keys', () => {
    expect(newAnnouncementIdempotencyKey('announcement-create')).toMatch(/^announcement-create-[A-Za-z0-9._:-]+$/)
  })

  it('maps conflicts to a stable error without exposing the server message', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      error: { code: 'version_conflict', message: 'raw database revision detail', request_id: 'request-1' },
    }), { status: 409, headers: { 'Content-Type': 'application/json' } }))

    await expect(announcementsApi.publish(
      'token', announcementID, { version: 1, expected_revision: 2 }, 'publish-key',
    )).rejects.toMatchObject({ status: 409, code: 'version_conflict', message: 'API request failed' })
  })

  it('calls global lifecycle routes with explicit cross-tenant targets', async () => {
	const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => ok({ items: [] }))
	const target = {
	  title: 'Global maintenance', body: 'Maintenance window', all_tenants: false,
	  tenant_scope_ids: ['33333333-3333-4333-8333-333333333333'],
	  role_targets: [{ scope_id: '33333333-3333-4333-8333-333333333333', role_id: '44444444-4444-4444-8444-444444444444' }],
	  user_targets: [{ scope_id: '55555555-5555-4555-8555-555555555555', user_id: '66666666-6666-4666-8666-666666666666' }],
	  withdrawal_visibility: 'hide' as const,
	}

	await globalAnnouncementsApi.list('token', { status: 'draft', limit: 20, cursor: 'global-cursor' })
	await globalAnnouncementsApi.get('token', announcementID)
	await globalAnnouncementsApi.create('token', target, 'global-create-key')
	await globalAnnouncementsApi.update('token', announcementID, { ...target, expected_revision: 2 }, 'global-update-key')
	await globalAnnouncementsApi.publish('token', announcementID, 3, 'global-publish-key')
	await globalAnnouncementsApi.withdraw('token', announcementID, 4, 'global-withdraw-key')

	const calls = fetchSpy.mock.calls.map(([url, init]) => ({
	  url: String(url), method: init?.method ?? 'GET', headers: new Headers(init?.headers),
	  body: init?.body ? JSON.parse(String(init.body)) as unknown : undefined,
	}))
	expect(calls.map(({ method, url }) => [method, url])).toEqual([
	  ['GET', '/v1/admin/announcements/global?status=draft&limit=20&cursor=global-cursor'],
	  ['GET', `/v1/admin/announcements/global/${announcementID}`],
	  ['POST', '/v1/admin/announcements/global'],
	  ['PATCH', `/v1/admin/announcements/global/${announcementID}`],
	  ['POST', `/v1/admin/announcements/global/${announcementID}/publish`],
	  ['POST', `/v1/admin/announcements/global/${announcementID}/withdraw`],
	])
	expect(calls[2].body).toEqual(target)
	expect(calls[3].headers.get('If-Match')).toBe('"2"')
	expect(calls[4].body).toEqual({ expected_revision: 3 })
	expect(calls[5].headers.get('Idempotency-Key')).toBe('global-withdraw-key')
  })
})
