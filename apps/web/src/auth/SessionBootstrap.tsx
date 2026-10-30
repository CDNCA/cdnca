import { useEffect, type PropsWithChildren } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Spin } from 'antd'
import { useTranslation } from 'react-i18next'
import { matchPath, useLocation } from 'react-router-dom'

import { isTransientRefreshError, refreshSession, useSessionStore } from './session'

const bootstrapRetries = 3
const transientRetryMilliseconds = 15_000

function isAccountRecoveryPath(pathname: string): boolean {
  return ['/forget-password', '/forgot-password', '/reset-password'].some((path) =>
    matchPath({ path, caseSensitive: false, end: true }, pathname) !== null)
}

// 登录/注册页不需要先恢复会话，否则刷新请求慢时整页转圈、看不到表单。
function isPublicAuthenticationPath(pathname: string): boolean {
  // /sso/bridge 凭票据直接换新会话（ADR 0019 BB-05），不必先恢复旧会话。
  return isAccountRecoveryPath(pathname) || ['/login', '/register', '/sso/bridge'].some((path) =>
    matchPath({ path, caseSensitive: false, end: true }, pathname) !== null)
}

export function SessionBootstrap({ children }: PropsWithChildren) {
  const status = useSessionStore((state) => state.status)
  const location = useLocation()
  const { t } = useTranslation('common')
  const isPublicAuthentication = isPublicAuthenticationPath(location.pathname)

  const bootstrap = useQuery({
    queryKey: ['auth', 'bootstrap'],
    queryFn: refreshSession,
    // A transient failure (network, 5xx) is retried; a refusal is final.
    retry: (failures, error) => failures < bootstrapRetries && isTransientRefreshError(error),
    retryDelay: (failures) => Math.min(1_000 * 2 ** failures, 8_000),
    staleTime: Infinity,
    enabled: status === 'bootstrapping' && !isPublicAuthentication,
  })

  useEffect(() => {
    // Retries exhausted on a transient error: show the login page rather than
    // spinning forever (the refresh cookie is still there for the next load).
    if (bootstrap.isError && useSessionStore.getState().status === 'bootstrapping') {
      useSessionStore.getState().clearSession()
    }
  }, [bootstrap.isError])

  if (status === 'bootstrapping' && !isPublicAuthentication) {
    return (
      <div className="session-loading" aria-label={t('sessionRestoring')}>
        <Spin size="large" />
      </div>
    )
  }

  return children
}

export function SessionRefreshTimer() {
  const expiresAt = useSessionStore((state) => state.expiresAt)
  const status = useSessionStore((state) => state.status)
  const location = useLocation()
  const isAccountRecovery = isAccountRecoveryPath(location.pathname)

  useEffect(() => {
    if (status !== 'authenticated' || expiresAt === null || isAccountRecovery) {
      return
    }

    let timer = 0
    const schedule = (delay: number) => {
      timer = window.setTimeout(() => {
        // A transient failure keeps the session (refreshSession); try again
        // shortly so the access token is renewed before requests need it.
        refreshSession().catch((error: unknown) => {
          if (isTransientRefreshError(error)) schedule(transientRetryMilliseconds)
        })
      }, delay)
    }
    schedule(Math.max(5_000, expiresAt - Date.now() - 30_000))

    // Timers are throttled in background tabs and frozen while the machine
    // sleeps: renew as soon as the page is visible again if the token is due.
    const onVisible = () => {
      if (document.visibilityState === 'visible' && expiresAt - Date.now() < 30_000) {
        window.clearTimeout(timer)
        schedule(0)
      }
    }
    document.addEventListener('visibilitychange', onVisible)

    return () => {
      window.clearTimeout(timer)
      document.removeEventListener('visibilitychange', onVisible)
    }
  }, [expiresAt, isAccountRecovery, status])

  return null
}
