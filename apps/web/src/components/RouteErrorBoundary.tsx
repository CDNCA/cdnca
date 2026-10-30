import { Component, Fragment, useCallback, type ReactNode } from 'react'
import { Button, Result, Space, Spin } from 'antd'
import { useLocation, useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'

import { useSessionStore } from '../auth/session'
import { reportFrontendRouteError } from '../observability/frontendReporter'

const routeReloadStoragePrefix = 'cdnca:route-reload:'

export type RouteStatus = '403' | '404' | '500'

// eslint-disable-next-line react-refresh/only-export-components
export function isLazyRouteError(error: unknown): boolean {
  const message = error instanceof Error ? `${error.name} ${error.message}` : String(error)
  return /ChunkLoadError|Loading (?:chunk|CSS chunk)|dynamically imported module|failed to fetch dynamically imported module|importing a module script failed|unable to preload CSS/i.test(message)
}

function routeReloadStorageKey(): string | null {
  if (typeof window === 'undefined') return null
  return `${routeReloadStoragePrefix}${window.location.pathname}${window.location.search}${window.location.hash}`
}

// fix-ui1026b：标记只在 30 秒内有效。刷新后新页面马上又失败（新版本也缺分块）才拦住，
// 防止无限刷新；同一标签页以后再遇到发版换分块，仍会自动刷新一次。
const routeReloadLoopWindowMs = 30_000

function markRouteReloadAttempt(): boolean {
  const key = routeReloadStorageKey()
  if (!key) return false
  try {
    const last = Number(window.sessionStorage.getItem(key))
    if (last && Date.now() - last < routeReloadLoopWindowMs) return false
    window.sessionStorage.setItem(key, String(Date.now()))
    return true
  } catch {
    return false
  }
}

// 发版后已打开的页面拿旧分块 404 时（vite:preloadError），整页刷新一次拿新版本，不显示 500。
// 同一页面生命周期只刷新一次；错误随后仍会到路由错误边界，边界看到正在刷新就只显示加载中。
let staleChunkReloading = false

// eslint-disable-next-line react-refresh/only-export-components
export function reloadForStaleChunk(reload: () => void = () => window.location.reload()): boolean {
  if (staleChunkReloading) return true
  if (!markRouteReloadAttempt()) return false
  staleChunkReloading = true
  reload()
  return true
}

// eslint-disable-next-line react-refresh/only-export-components
export function installStaleChunkReload(): void {
  window.addEventListener('vite:preloadError', () => {
    reloadForStaleChunk()
  })
}

// 仅测试用：模拟新的一次整页加载。
// eslint-disable-next-line react-refresh/only-export-components
export function resetStaleChunkReloadForTest(): void {
  staleChunkReloading = false
}

interface RouteErrorBoundaryProps {
  children: ReactNode
  reload?: () => void
}

interface RouteErrorBoundaryState {
  error: Error | null
  locationKey: string
  retryKey: number
  reloadBlocked: boolean
  reloading: boolean
}

interface StatefulRouteErrorBoundaryProps extends RouteErrorBoundaryProps {
  locationKey: string
  onRouteError: (lazyRouteError: boolean) => void
}

interface RouteErrorFallbackProps {
  error: Error
  reloadBlocked: boolean
  onReload: () => void
  onRetry: () => void
}

function RouteErrorFallback({ error, reloadBlocked, onReload, onRetry }: RouteErrorFallbackProps) {
  const { t } = useTranslation('common')
  const navigate = useNavigate()
  const chunkFailure = isLazyRouteError(error)

  return (
    <Result
      status="500"
      title="500"
      subTitle={t('serviceError')}
      extra={(
        <Space wrap>
          <Button type="primary" onClick={onRetry}>
            {t('retry')}
          </Button>
          {chunkFailure ? (
            <Button onClick={onReload} disabled={reloadBlocked}>
              {t('refreshSession')}
            </Button>
          ) : null}
          <Button onClick={() => navigate('/')}>
            {t('returnOverview')}
          </Button>
        </Space>
      )}
    />
  )
}

function RouteReloading() {
  const { t } = useTranslation('common')
  return <Spin className="route-reloading" tip={t('pageLoading')}><div style={{ minHeight: 200 }} /></Spin>
}

class StatefulRouteErrorBoundary extends Component<StatefulRouteErrorBoundaryProps, RouteErrorBoundaryState> {
  state: RouteErrorBoundaryState = {
    error: null,
    locationKey: this.props.locationKey,
    retryKey: 0,
    reloadBlocked: false,
    reloading: false,
  }

  static getDerivedStateFromProps(
    props: StatefulRouteErrorBoundaryProps,
    state: RouteErrorBoundaryState,
  ): Partial<RouteErrorBoundaryState> | null {
    if (props.locationKey === state.locationKey) return null
    // 只有处于错误态时才重挂载子树来清掉错误；正常导航（如只改 ?tab=）不得重挂载，
    // 否则整个控制台壳和页面状态都会被重建（站点编辑页切标签卡死，site-tab-stuck）。
    if (!state.error) return { locationKey: props.locationKey }
    return {
      error: null,
      locationKey: props.locationKey,
      retryKey: state.retryKey + 1,
      reloadBlocked: false,
      reloading: false,
    }
  }

  static getDerivedStateFromError(error: Error): Partial<RouteErrorBoundaryState> {
    return { error }
  }

  componentDidCatch(error: Error) {
    const lazyRouteError = isLazyRouteError(error)
    this.props.onRouteError(lazyRouteError)
    if (lazyRouteError) this.reload()
  }

  private retry = () => {
    this.setState((state) => ({
      error: null,
      retryKey: state.retryKey + 1,
    }))
  }

  private reload = () => {
    const reloading = reloadForStaleChunk(this.props.reload)
    this.setState({ reloadBlocked: true, reloading })
  }

  render() {
    const { error, retryKey, reloadBlocked, reloading } = this.state
    if (error && reloading) return <RouteReloading />
    if (error) {
      return (
        <RouteErrorFallback
          error={error}
          reloadBlocked={reloadBlocked}
          onReload={this.reload}
          onRetry={this.retry}
        />
      )
    }

    return <Fragment key={retryKey}>{this.props.children}</Fragment>
  }
}

export function RouteErrorBoundary(props: RouteErrorBoundaryProps) {
  const location = useLocation()
  const accessToken = useSessionStore((state) => state.accessToken)
  const reportError = useCallback((lazyRouteError: boolean) => {
    if (accessToken) reportFrontendRouteError(accessToken, location.pathname, lazyRouteError)
  }, [accessToken, location.pathname])
  return <StatefulRouteErrorBoundary {...props} locationKey={`${location.pathname}${location.search}`} onRouteError={reportError} />
}

interface RouteStatusPageProps {
  status: RouteStatus
}

export function RouteStatusPage({ status }: RouteStatusPageProps) {
  const { t } = useTranslation('common')
  const navigate = useNavigate()
  const message = status === '404' ? t('notFound') : status === '403' ? t('forbidden') : t('serviceError')

  return (
    <Result
      status={status}
      title={status}
      subTitle={message}
      extra={(
        <Button type="primary" onClick={() => navigate('/')}>
          {t('returnOverview')}
        </Button>
      )}
    />
  )
}
