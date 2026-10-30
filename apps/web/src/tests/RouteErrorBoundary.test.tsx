import { lazy, Suspense, useState } from 'react'
import { fireEvent, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { useLocation, useNavigate } from 'react-router-dom'

vi.mock('../pages/SiteListPage', async () => {
  const { useEffect } = await import('react')
  function FailingSiteListPage() {
    useEffect(() => {
      throw new Error('route render failed')
    }, [])
    return null
  }
  return { default: FailingSiteListPage }
})

import { AppRoutes } from '../App'
import { observabilityLogsApi } from '../api/observabilityLogs'
import { useSessionStore } from '../auth/session'
import {
  RouteErrorBoundary,
  RouteStatusPage,
  installStaleChunkReload,
  isLazyRouteError,
  reloadForStaleChunk,
  resetStaleChunkReloadForTest,
} from '../components/RouteErrorBoundary'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

function ThrowingRoute(): never {
  throw new Error('raw server response: secret-token')
}

function ChunkThrowingRoute(): never {
  throw new Error('Loading chunk 42 failed')
}

function LocationProbe() {
  const location = useLocation()
  return <output data-testid="route-location">{location.pathname}</output>
}

let hashRouteMounts = 0

function HashScrubbingStatefulRoute() {
  const location = useLocation()
  const navigate = useNavigate()
  const [mount] = useState(() => ++hashRouteMounts)
  const [draft, setDraft] = useState('')

  return (
    <>
      <input aria-label="route draft" value={draft} onChange={(event) => setDraft(event.target.value)} />
      <output data-testid="route-hash">{location.hash}</output>
      <button
        type="button"
        onClick={() => void navigate({
          pathname: location.pathname,
          search: location.search,
          hash: '',
        }, { replace: true })}
      >
        clear hash
      </button>
      <output data-testid="route-mount">{mount}</output>
    </>
  )
}

describe('RouteErrorBoundary', () => {
  beforeEach(() => {
    sessionStorage.clear()
    resetStaleChunkReloadForTest()
    vi.spyOn(console, 'error').mockImplementation(() => undefined)
  })

  it('recognizes lazy chunk failures without exposing the error message', () => {
    expect(isLazyRouteError(new Error('Loading chunk 42 failed'))).toBe(true)
    expect(isLazyRouteError(new Error('dynamically imported module failed'))).toBe(true)
    expect(isLazyRouteError(new Error('request failed'))).toBe(false)

    renderWithProviders(
      <RouteErrorBoundary>
        <ThrowingRoute />
      </RouteErrorBoundary>,
    )

    expect(screen.getByText('服务异常')).toBeInTheDocument()
    expect(screen.queryByText(/secret-token/)).not.toBeInTheDocument()
  })

  it('reports only bounded stable route facts and keeps the fallback on reporting failure', async () => {
    const user = principal()
    useSessionStore.getState().setSession(authResponse(user), user)
    const report = vi.spyOn(observabilityLogsApi, 'recordFrontend').mockRejectedValue(new Error('offline secret-token'))

    renderWithProviders(
      <RouteErrorBoundary>
        <ThrowingRoute />
      </RouteErrorBoundary>,
      ['/sites?token=private#secret'],
    )

    expect(screen.getByText('服务异常')).toBeInTheDocument()
    await waitFor(() => expect(report).toHaveBeenCalledWith('memory-only-access-token', {
      event_code:'render_error',
      route:'/sites',
      reason_code:'route_render_failed',
      result_code:'failure',
      release:expect.stringMatching(/^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/),
    }, undefined))  // 第三个参数是平台代查的 target_scope_id；租户会话没有该参数。
    expect(JSON.stringify(report.mock.calls)).not.toContain('raw server response')
  })

  it('renders the guarded reload action for a rejected lazy import', async () => {
    const RejectedRoute = lazy(async () => {
      throw new Error('Failed to fetch dynamically imported module')
    })
    const reload = vi.fn()

    renderWithProviders(
      <RouteErrorBoundary reload={reload}>
        <Suspense fallback={<div>loading</div>}>
          <RejectedRoute />
        </Suspense>
      </RouteErrorBoundary>,
    )

    // fix-ui1026b：旧分块 404 自动整页刷新一次，刷新期间只显示加载中，不显示 500。
    expect(await screen.findByText('页面加载中')).toBeInTheDocument()
    expect(reload).toHaveBeenCalledOnce()
    expect(screen.queryByText('服务异常')).not.toBeInTheDocument()
    expect(screen.queryByText(/dynamically imported module/)).not.toBeInTheDocument()
  })

  it('reloads once on vite:preloadError and not again in the same page life', () => {
    const reload = vi.fn()
    expect(reloadForStaleChunk(reload)).toBe(true)
    expect(reloadForStaleChunk(reload)).toBe(true)
    expect(reload).toHaveBeenCalledOnce()

    const windowReload = vi.fn()
    resetStaleChunkReloadForTest()
    sessionStorage.clear()
    const original = window.location
    Object.defineProperty(window, 'location', { configurable: true, value: { ...original, reload: windowReload } })
    try {
      installStaleChunkReload()
      window.dispatchEvent(new Event('vite:preloadError', { cancelable: true }))
      window.dispatchEvent(new Event('vite:preloadError', { cancelable: true }))
      expect(windowReload).toHaveBeenCalledOnce()
    } finally {
      Object.defineProperty(window, 'location', { configurable: true, value: original })
    }
  })

  it('retries the failed route and remounts the lazy child', () => {
    let shouldThrow = true
    function RecoverableRoute() {
      if (shouldThrow) throw new Error('Loading chunk 42 failed')
      return <div>loaded</div>
    }
    // 已自动刷新过一次（30 秒内）：不再刷新，显示错误页供手动重试。
    sessionStorage.setItem(`cdnca:route-reload:${window.location.pathname}${window.location.search}${window.location.hash}`, String(Date.now()))

    renderWithProviders(
      <RouteErrorBoundary>
        <RecoverableRoute />
      </RouteErrorBoundary>,
    )
    expect(screen.getByText('服务异常')).toBeInTheDocument()

    shouldThrow = false
    fireEvent.click(screen.getByRole('button', { name: '重试' }))

    expect(screen.getByText('loaded')).toBeInTheDocument()
  })

  it('preserves child state when only the route hash is scrubbed', async () => {
    hashRouteMounts = 0
    renderWithProviders(
      <RouteErrorBoundary>
        <HashScrubbingStatefulRoute />
      </RouteErrorBoundary>,
      ['/reset-password?flow=confirm#one-time-secret'],
    )

    fireEvent.change(screen.getByLabelText('route draft'), { target: { value: 'keep me' } })
    fireEvent.click(screen.getByRole('button', { name: 'clear hash' }))

    await waitFor(() => expect(screen.getByTestId('route-hash')).toBeEmptyDOMElement())
    expect(screen.getByLabelText('route draft')).toHaveValue('keep me')
    expect(screen.getByTestId('route-mount')).toHaveTextContent('1')
  })

  it('allows one controlled hard reload and then blocks repeated reloads', () => {
    const reload = vi.fn()
    const first = renderWithProviders(
      <RouteErrorBoundary reload={reload}>
        <ChunkThrowingRoute />
      </RouteErrorBoundary>,
    )
    expect(reload).toHaveBeenCalledOnce()
    expect(screen.getByText('页面加载中')).toBeInTheDocument()
    first.unmount()

    // 刷新后的新页面 30 秒内又失败：不再自动刷新，给出错误页，刷新按钮不可再点。
    resetStaleChunkReloadForTest()
    renderWithProviders(
      <RouteErrorBoundary reload={reload}>
        <ChunkThrowingRoute />
      </RouteErrorBoundary>,
    )
    const reloadButton = screen.getByRole('button', { name: '刷新会话' })
    fireEvent.click(reloadButton)
    expect(reload).toHaveBeenCalledOnce()
    expect(reloadButton).toBeDisabled()
  })

  it.each([
    ['404', '页面不存在'],
    ['403', '无权访问'],
    ['500', '服务异常'],
  ] as const)('renders recoverable %s status with overview navigation', (status, message) => {
    renderWithProviders(
      <>
        <RouteStatusPage status={status} />
        <LocationProbe />
      </>,
      ['/broken'],
    )

    expect(screen.getByText(message)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '返回服务概览' }))
    expect(screen.getByTestId('route-location')).toHaveTextContent('/')
  })

  it('clears the AppRoutes fallback before navigating to the overview', async () => {
    // /site/list 由 PermissionRoute(sites.read) 保护；没有该权限时根本不会挂载会抛错的页面。
    const user = principal({ permissions: ['identity.self.read', 'sites.read'] })
    useSessionStore.getState().setSession(authResponse(user), user)

    renderWithProviders(<><AppRoutes /><LocationProbe /></>, ['/site/list'])

    expect(await screen.findByText('服务异常')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '返回服务概览' }))

    await waitFor(() => expect(screen.getByTestId('route-location')).toHaveTextContent('/home'))
    expect(screen.queryByText('服务异常')).not.toBeInTheDocument()
  })
})
