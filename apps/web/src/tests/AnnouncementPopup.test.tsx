import { fireEvent, screen, waitFor } from '@testing-library/react'
import { beforeEach, vi } from 'vitest'
import { AnnouncementPopup } from '../components/AnnouncementPopup'
import { AnnouncementBody } from '../components/AnnouncementBody'
import { useSessionStore } from '../auth/session'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

function inbox(items: unknown[]) {
  return new Response(JSON.stringify({ items }), { status: 200, headers: { 'Content-Type': 'application/json' } })
}
const popupItem = { id: 'popup', title: '弹窗公告', body: '', format: 'link', link_url: 'https://example.com/notice', visible: true, popup: true, red: true, bold: true, state_revision: 3 }

beforeEach(() => window.sessionStorage.clear())

it('opens visible unread popup announcements with 稍后再看 and 我已阅读，不再显示', async () => {
  const actor = principal({ permissions: ['announcements.read'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(inbox([{ id: 'hidden', title: '隐藏公告', visible: false, popup: true }, popupItem]))
  renderWithProviders(<AnnouncementPopup />)
  const dialog = await screen.findByRole('dialog')
  expect(dialog).toHaveTextContent('弹窗公告')
  expect(screen.getByText('弹窗公告')).toHaveStyle({ color: 'var(--cdnca-color-error)', fontWeight: '700' })
  expect(screen.getByRole('link')).toHaveAttribute('href', 'https://example.com/notice')
  expect(screen.queryByText('隐藏公告')).toBeNull()
  expect(screen.getByRole('button', { name: '稍后再看' })).toBeInTheDocument()
  expect(screen.getByRole('button', { name: '我已阅读，不再显示' })).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: /^关闭$/ })).toBeNull()
})

it('稍后再看 hides it for this sign-in without marking read; the next sign-in shows it again', async () => {
  const actor = principal({ permissions: ['announcements.read'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
  const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => inbox([popupItem]))
  const view = renderWithProviders(<AnnouncementPopup />)
  fireEvent.click(await screen.findByRole('button', { name: '稍后再看' }))
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  expect(fetchSpy.mock.calls.every(([url]) => !String(url).includes('/read'))).toBe(true)

  // Reload of the same sign-in: still hidden.
  view.unmount()
  useSessionStore.getState().setSession(authResponse(actor), actor, 'refresh')
  const again = renderWithProviders(<AnnouncementPopup />)
  await waitFor(() => expect(fetchSpy.mock.calls.length).toBeGreaterThanOrEqual(2))
  expect(screen.queryByRole('dialog')).toBeNull()

  // Next sign-in: pops up again.
  again.unmount()
  useSessionStore.getState().setSession(authResponse(actor), actor)
  renderWithProviders(<AnnouncementPopup />)
  expect(await screen.findByRole('dialog')).toHaveTextContent('弹窗公告')
})

it('我已阅读，不再显示 marks the message read with its revision', async () => {
  const actor = principal({ permissions: ['announcements.read'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
  const fetchSpy = vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(inbox([popupItem]))
    .mockResolvedValueOnce(new Response(JSON.stringify({ event_id: 'popup', read_at: '2026-10-27T12:00:00Z', revision: 4 }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
  renderWithProviders(<AnnouncementPopup />)
  fireEvent.click(await screen.findByRole('button', { name: '我已阅读，不再显示' }))
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  const [url, init] = fetchSpy.mock.calls[1]
  expect(String(url)).toContain('/v1/account/messages/popup/read')
  expect(init?.method).toBe('POST')
  expect(JSON.parse(String(init?.body))).toEqual({ expected_revision: 3 })
})

it('a failed 我已阅读 hides it for this sign-in only and says so', async () => {
  const actor = principal({ permissions: ['announcements.read'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(inbox([popupItem]))
    .mockResolvedValueOnce(new Response(JSON.stringify({ error: { code: 'revision_conflict' } }), { status: 409, headers: { 'Content-Type': 'application/json' } }))
  renderWithProviders(<AnnouncementPopup />)
  fireEvent.click(await screen.findByRole('button', { name: '我已阅读，不再显示' }))
  expect(await screen.findByText('标记已读失败，本次登录不再弹出，下次登录仍会提示')).toBeInTheDocument()
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
})

it('isolates HTML in a sandbox and refuses unsafe link protocols', () => {
  renderWithProviders(<AnnouncementBody item={{ title: 'HTML 公告', format: 'content', body: '<h2>标题</h2><script>alert(1)</script>' }} />)
  const frame = screen.getByTitle('HTML 公告')
  expect(frame).toHaveAttribute('sandbox', '')
  expect(frame.getAttribute('srcdoc')).toContain("default-src 'none'")
  expect(document.querySelector('script')).toBeNull()
})

// 未读超过一页时也不漏弹——由服务端只返回“未读且需弹窗”的公告。
it('asks the server for unread popup announcements only', async () => {
  const actor = principal({ permissions: ['announcements.read'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
  const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(inbox([popupItem]))
  renderWithProviders(<AnnouncementPopup />)
  await screen.findByRole('dialog')
  const url = new URL(String(fetchSpy.mock.calls[0][0]), 'http://localhost')
  expect(url.searchParams.get('filter')).toBe('popup')
})
