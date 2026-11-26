import { act, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { authApi } from '../api/auth'
import { useSessionStore } from '../auth/session'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import shellStyles from '../styles.css?raw'
import { ImpersonationStatusBanner } from './ImpersonationStatusBanner'
import { InstallationLockBanner } from './InstallationLockBanner'
import { PinnedBanners } from './PinnedBanners'

// scrolled down a long page (plugin deep link) the
// banners went under the fixed header and their buttons took no clicks.

const revoke = vi.hoisted(() => vi.fn())
vi.mock('../api/impersonation', async () => {
  const actual = await vi.importActual<typeof import('../api/impersonation')>('../api/impersonation')
  return { ...actual, impersonationApi: { ...actual.impersonationApi, revoke } }
})

const grantID = '44444444-4444-4444-8444-444444444444'
const tenantID = '11111111-1111-4111-8111-111111111111'
const scopeID = '22222222-2222-4222-8222-222222222222'
const actor = principal({ scope_kind: 'platform', tenant_id: null, permissions: ['identity.impersonation.manage'] })
const impersonated = {
  user_id: '33333333-3333-4333-8333-333333333333', scope_id: scopeID, scope_kind: 'tenant' as const, tenant_id: tenantID,
  username: 'tenant-user', display_name: 'Tenant User', roles: ['tenant_viewer'], permissions: ['sites.read'],
  impersonation: {
    grant_id: grantID, actor_user_id: actor.user_id, actor_display_name: 'Support Admin',
    subject_user_id: '33333333-3333-4333-8333-333333333333', subject_display_name: 'Tenant User',
    tenant_id: tenantID, expires_at: '2099-08-07T08:15:00Z',
  },
}
const banned = { locked: true, reason: 'installation_banned', ban_id: '0b0b0b0b-0b0b-40b0-80b0-0b0b0b0b0b0b', reason_code: 'abuse',
  reason_text: '违规转售', until: '2026-12-01T00:00:00Z' }

// jsdom has no layout: the impersonation banner is 40px, the lock banner 120px
// (466px with its narrow-screen details open), the container as tall as its banners stacked.
const heights = { status: 40, alert: 120, alertOpen: 466 }
const own = (element: Element) => element.matches('[role="status"]') ? heights.status
  : element.matches('[role="alert"]') ? (element.querySelector('[aria-expanded="true"]') ? heights.alertOpen : heights.alert) : 0
const observers: ResizeObserverCallback[] = []
const resize = () => act(() => { for (const callback of [...observers]) callback([], {} as ResizeObserver) })
const ResizeObserverBefore = window.ResizeObserver
const root = document.documentElement
const reserved = () => root.style.getPropertyValue('--app-banners-height')

function rule(selector: string): string {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  return shellStyles.match(new RegExp(`(?:^|\\n)${escaped} \\{([^}]*)\\}`))?.[1] ?? ''
}

function renderShell(lock: { locked: boolean }) {
  vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify(lock), { status: 200, headers: { 'Content-Type': 'application/json' } })))
  return renderWithProviders(
    <main className="app-main">
      <PinnedBanners>
        <ImpersonationStatusBanner />
        <InstallationLockBanner />
      </PinnedBanners>
    </main>,
  )
}

describe('PinnedBanners', () => {
  beforeEach(() => {
    revoke.mockReset()
    observers.length = 0
    useSessionStore.getState().setSession(authResponse(actor), actor)
    vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockImplementation(function (this: HTMLElement) {
      const height = this.classList.contains('app-pinned-banners') ? [...this.children].reduce((sum, child) => sum + own(child), 0) : own(this)
      return { x: 0, y: 0, top: 0, left: 0, right: 0, bottom: height, width: 0, height, toJSON: () => ({}) } as DOMRect
    })
    window.ResizeObserver = class {
      private readonly callback: ResizeObserverCallback
      constructor(callback: ResizeObserverCallback) { this.callback = callback }
      observe() { observers.push(this.callback) }
      unobserve() {}
      disconnect() { observers.splice(observers.indexOf(this.callback), 1) }
    }
  })
  afterEach(() => {
    window.ResizeObserver = ResizeObserverBefore
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
  })

  it('pins the banners under the fixed header and reserves their height only while one shows', () => {
    const pinned = rule('.app-main > .app-pinned-banners')
    expect(pinned).toMatch(/position: fixed;/)
    expect(pinned).toMatch(/top: 64px;/)
    expect(pinned).toMatch(/left: var\(--sidebar-width\);/)
    expect(pinned).toMatch(/margin: 0;/)
    const headerZ = Number(rule('.app-header').match(/z-index: (\d+);/)?.[1])
    const pinnedZ = Number(pinned.match(/z-index: (\d+);/)?.[1])
    expect(pinnedZ).toBeGreaterThan(0)
    expect(pinnedZ).toBeLessThan(headerZ)
    expect(rule('html[data-app-banners] .app-main')).toMatch(/padding-top: calc\(64px \+ var\(--app-banners-height, 0px\)\);/)
    // In-page scrolling clears the header, plus the banners when shown.
    expect(rule('html:has(.app-header)')).toMatch(/scroll-padding-top: calc\(64px \+ var\(--app-banners-height, 0px\)\);/)
    // The shell without banners is unchanged.
    expect(rule('.app-main')).toMatch(/padding-top: 64px;/)
  })

  it('reserves nothing with no banner shown', async () => {
    const { container } = renderShell({ locked: false })
    await waitFor(() => expect(fetch).toHaveBeenCalled())
    resize()
    expect(container.querySelector('.app-main > .app-pinned-banners')).toBeEmptyDOMElement()
    expect(root.hasAttribute('data-app-banners')).toBe(false)
    expect(reserved()).toBe('')
  })

  it('reserves the impersonation banner alone, following its wrapped height', async () => {
    useSessionStore.setState({ principal: impersonated })
    const { container } = renderShell({ locked: false })
    expect(container.querySelector('.app-pinned-banners > [role="status"]')).toBeInTheDocument()
    expect(root.hasAttribute('data-app-banners')).toBe(true)
    expect(reserved()).toBe('40px')
    heights.status = 87.5
    resize()
    expect(reserved()).toBe('88px')
    heights.status = 40
  })

  it('reserves the installation lock banner alone', async () => {
    const { container } = renderShell(banned)
    expect(await screen.findByText('本主控授权已被锁定，后台处于只读状态')).toBeInTheDocument()
    resize()
    expect(container.querySelector('.app-pinned-banners > [role="alert"]')).toBeInTheDocument()
    expect(reserved()).toBe('120px')
  })

  it('stacks both banners (impersonation first), reserves their sum and gives it back on exit', async () => {
    revoke.mockResolvedValue({})
    vi.spyOn(authApi, 'me').mockResolvedValue(actor)
    useSessionStore.setState({ principal: impersonated })
    const view = renderShell(banned)
    await screen.findByText('本主控授权已被锁定，后台处于只读状态')
    resize()
    const container = view.container.querySelector('.app-main > .app-pinned-banners')!
    expect([...container.children].map((child) => child.getAttribute('role'))).toEqual(['status', 'alert'])
    expect(reserved()).toBe('160px')

    await userEvent.click(screen.getByRole('button', { name: '退出代登录' }))
    await waitFor(() => expect(screen.queryByRole('status')).not.toBeInTheDocument())
    expect(revoke).toHaveBeenCalledTimes(1)
    resize()
    expect(reserved()).toBe('120px')

    view.unmount()
    expect(root.hasAttribute('data-app-banners')).toBe(false)
    expect(reserved()).toBe('')
    expect(observers).toEqual([])
  })

  it('on a narrow screen follows the lock banner as its details open and fold', async () => {
    const matchMediaBefore = window.matchMedia
    window.matchMedia = (query: string) => ({ ...matchMediaBefore(query), matches: query === '(max-width: 767px)' })
    try {
      useSessionStore.setState({ principal: impersonated })
      renderShell(banned)
      await screen.findByText('本主控授权已被锁定，后台处于只读状态')
      resize()
      const toggle = screen.getByRole('button', { name: '展开锁定详情' })
      expect(toggle).toHaveAttribute('aria-expanded', 'false')
      expect(reserved()).toBe('160px')
      await userEvent.click(toggle)
      resize()
      expect(toggle).toHaveAttribute('aria-expanded', 'true')
      expect(reserved()).toBe('506px')
      await userEvent.click(screen.getByRole('button', { name: '收起锁定详情' }))
      resize()
      expect(reserved()).toBe('160px')
    } finally {
      window.matchMedia = matchMediaBefore
    }
  })
})
