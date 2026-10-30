import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { vi } from 'vitest'

import { useSessionStore } from '../auth/session'
import AnnouncementManagementPage from '../pages/AnnouncementManagementPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

function fixture() {
  const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['announcements.manage'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
  return [1, 2].map((index) => ({
    id: `77777777-7777-4777-8777-77777777777${index}`, platform_scope_id: actor.scope_id,
    version: 1, revision: 4, status: 'published' as const, title: `已发布公告${index}`, body: '正文',
    format: 'content' as const, sort_order: 100, visible: true, popup: false, red: false, bold: false,
    audience: { all_tenants: true, tenant_scope_ids: [], role_targets: [], user_targets: [] },
    withdrawal_visibility: 'retain' as const, recipient_count: 2, archived: false, lifecycle_revision: 1,
    created_at: '2026-09-25T00:00:00Z', state_changed_at: '2026-09-25T00:00:00Z',
  }))
}

function json(value: unknown, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } })
}

async function confirmBatch(items: ReturnType<typeof fixture>) {
  await screen.findByText(items[0].title)
  items.forEach((item) => fireEvent.click(within(screen.getByText(item.title).closest('tr')!).getByRole('checkbox')))
  expect(screen.getByRole('button', { name: '显示' })).toBeDisabled()
  fireEvent.click(screen.getByRole('button', { name: '批量删除' }))
  fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: '确认' }))
}

it('deletes a published management record and restores it using lifecycle revisions', async () => {
  let item = fixture()[0]
  const requests: { url: string; revision: string | null; body: unknown }[] = []
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const url = String(input)
    if (init?.method === 'POST') {
      requests.push({ url, revision: new Headers(init.headers).get('If-Match'), body: JSON.parse(String(init.body)) })
      item = { ...item, archived: url.endsWith('/archive'), lifecycle_revision: item.lifecycle_revision + 1 }
      return json(item)
    }
    return json({ items: item.archived === url.includes('status=archived') ? [item] : [] })
  })
  renderWithProviders(<AnnouncementManagementPage />, ['/sys/anno'])
  const row = (await screen.findByText(item.title)).closest('tr')!
  expect(within(row).getByRole('checkbox')).toBeEnabled()
  fireEvent.click(within(row).getByRole('button', { name: '删除' }))
  const dialog = within(await screen.findByRole('dialog'))
  expect(dialog.getByText(/已发布消息及已读历史仍保留/)).toBeInTheDocument()
  fireEvent.click(dialog.getByRole('button', { name: '确认' }))
  await waitFor(() => expect(screen.queryByText(item.title)).not.toBeInTheDocument())
  expect(requests[0]).toMatchObject({ revision: '"1"', body: { expected_lifecycle_revision: 1 } })
  fireEvent.mouseDown(screen.getByRole('combobox', { name: '公告状态' }))
  fireEvent.click(screen.getByText('已归档'))
  const archivedRow = (await screen.findByText(item.title)).closest('tr')!
  expect(within(archivedRow).getByRole('checkbox')).toBeDisabled()
  fireEvent.click(within(archivedRow).getByRole('button', { name: '恢复' }))
  fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: '确认' }))
  await waitFor(() => expect(requests).toHaveLength(2))
  expect(requests[1]).toMatchObject({ revision: '"2"', body: { expected_lifecycle_revision: 2 } })
  expect(requests[1].url).toMatch(/\/restore$/)
  expect(item.status).toBe('published')
})

it.each([[400, 'validation_error'], [409, 'version_conflict']])('refreshes a partially deleted batch after %s and reports confirmed progress', async (status, code) => {
  const items = fixture()
  let completed = false
  let reads = 0
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    if (init?.method === 'POST') {
      if (String(input).includes(items[0].id)) {
        completed = true
        return json({ ...items[0], archived: true, lifecycle_revision: 2 })
      }
      return json({ error: { code, message: 'raw internal error' } }, Number(status))
    }
    reads += 1
    return json({ items: completed ? [items[1]] : items })
  })
  renderWithProviders(<AnnouncementManagementPage />, ['/sys/anno'])
  await confirmBatch(items)
  expect(await screen.findByText('已完成 1 / 2 条')).toBeInTheDocument()
  await waitFor(() => expect(screen.queryByText(items[0].title)).not.toBeInTheDocument())
  expect(reads).toBeGreaterThanOrEqual(2)
  expect(screen.queryByText('raw internal error')).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: '关闭并刷新' }))
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
  expect(screen.getByRole('button', { name: '新增公告' })).toBeEnabled()
})

it('retries only the unconfirmed deletion with its exact key after response loss', async () => {
  const items = fixture()
  const committed = new Set<string>()
  const requests: { id: string; key: string | null; body: unknown }[] = []
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    if (init?.method === 'POST') {
      const id = String(input).split('/').at(-2)!
      requests.push({ id, key: new Headers(init.headers).get('Idempotency-Key'), body: JSON.parse(String(init.body)) })
      const replayed = committed.has(id)
      committed.add(id)
      if (id === items[1].id && !replayed) throw new Error('response lost after commit')
      return json({ ...items.find((item) => item.id === id)!, archived: true, lifecycle_revision: 2, replayed })
    }
    return json({ items: items.filter((item) => !committed.has(item.id)) })
  })
  renderWithProviders(<AnnouncementManagementPage />, ['/sys/anno'])
  await confirmBatch(items)
  expect(await screen.findByText('已完成 1 / 2 条')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: '使用同一请求重试' }))
  expect(await screen.findByText('公告已删除，可从已归档列表恢复')).toBeInTheDocument()
  expect(requests.map(({ id }) => id)).toEqual([items[0].id, items[1].id, items[1].id])
  expect(requests[2]).toEqual(requests[1])
})
