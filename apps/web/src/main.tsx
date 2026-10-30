import '@ant-design/v5-patch-for-react-19'

import { StrictMode, useMemo } from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClientProvider } from '@tanstack/react-query'
import { createBrowserRouter, RouterProvider, ScrollRestoration } from 'react-router-dom'
import { useTranslation } from 'react-i18next'

import { AppRoutes } from './App'
import { ApprovalPromptHost } from './approval/ApprovalPromptHost'
import { setApiErrorObserver } from './api/auth'
import { SessionQueryBoundary } from './auth/SessionQueryBoundary'
import { SessionBootstrap, SessionRefreshTimer } from './auth/SessionBootstrap'
import { MigrationHoldGate } from './components/MigrationHoldGate'
import { createSessionQueryClient } from './auth/sessionQueryClient'
import { PasswordChangeGate } from './components/PasswordChangeGate'
import { installStaleChunkReload } from './components/RouteErrorBoundary'
import { SessionRegionGate } from './components/SessionRegionGate'
import { useSessionStore } from './auth/session'
import './i18n'
import { antdLocaleFor } from './i18n/antdLocale'
import { createGlobalApiErrorReporter } from './observability/apiErrorBootstrap'
import '@cdnca/ui/styles.css'
import './styles.css'
import './styles/compact-toolbar.css'
import './styles/tech-look.css'
import { ThemeProvider } from './theme/ThemeProvider'

setApiErrorObserver(createGlobalApiErrorReporter({
  getAccessToken:()=>useSessionStore.getState().accessToken,
  getPathname:()=>window.location.pathname,
}))

installStaleChunkReload()

const queryClient = createSessionQueryClient()

// C05：路由切换滚动恢复用 react-router 自带的 ScrollRestoration（新页面回顶部、后退恢复原位置）；
// 它只在 data router 下工作，所以用 createBrowserRouter，原来的 <Routes> 原样挂在唯一的 * 路由下。
// 位置按 pathname 记（getKey）：同一路径只改查询参数（筛选、分页、页签）时保持滚动位置，不回顶部。
const scrollKey = (location: { pathname: string }) => location.pathname
function RoutedApplication() {
  return (
    <SessionQueryBoundary>
      <ScrollRestoration getKey={scrollKey} />
      <MigrationHoldGate>
        <SessionBootstrap>
          <SessionRefreshTimer />
          <SessionRegionGate />
          <PasswordChangeGate />
          <ApprovalPromptHost />
          <AppRoutes />
        </SessionBootstrap>
      </MigrationHoldGate>
    </SessionQueryBoundary>
  )
}

export function RootApplication() {
  const { i18n } = useTranslation()
  const antdLocale = antdLocaleFor(i18n.resolvedLanguage)
  const router = useMemo(() => createBrowserRouter([{ path: '*', element: <RoutedApplication /> }], { basename: '/dashboard' }), [])

  return (
    <ThemeProvider locale={antdLocale}>
      <QueryClientProvider client={queryClient}>
        <RouterProvider router={router} />
      </QueryClientProvider>
    </ThemeProvider>
  )
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <RootApplication />
  </StrictMode>,
)
