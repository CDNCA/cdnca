import { observabilityLogsApi } from '../api/observabilityLogs'
import type { ApiErrorSignal } from '../api/auth'
import { useSessionStore } from '../auth/session'

const releasePattern = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/
const uuidPattern = /^(?!00000000-0000-0000-0000-000000000000$)[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const configuredRelease: unknown = import.meta.env.VITE_RELEASE
const release = typeof configuredRelease === 'string' && releasePattern.test(configuredRelease)
  ? configuredRelease
  : 'web-unknown'

let reportInFlight = false

export function boundedFrontendPathname(value: string): string {
  const pathname = value.split(/[?#]/, 1)[0]
  if (!pathname.startsWith('/')) return '/'
  let bounded = ''
  for (const character of pathname) {
    if (new TextEncoder().encode(bounded + character).byteLength > 256) break
    bounded += character
  }
  return bounded || '/'
}

function currentPlatformTargetScopeId(): string | null | undefined {
  if (useSessionStore.getState().principal?.scope_kind !== 'platform') return undefined
  if (typeof window === 'undefined') return null
  const targetScopeId = new URLSearchParams(window.location.search).get('target_scope_id')
  return targetScopeId && uuidPattern.test(targetScopeId) ? targetScopeId : null
}

function sendFrontendEvent(accessToken: string, input: Parameters<typeof observabilityLogsApi.recordFrontend>[1]): void {
  const targetScopeId = currentPlatformTargetScopeId()
  if (targetScopeId === null || reportInFlight) return
  reportInFlight = true
  void observabilityLogsApi.recordFrontend(accessToken, input, targetScopeId).catch(() => undefined).finally(() => { reportInFlight = false })
}

export function reportFrontendRouteError(accessToken: string, pathname: string, lazyRouteError: boolean): void {
  sendFrontendEvent(accessToken, {
    event_code:lazyRouteError ? 'route_error' : 'render_error',
    route:boundedFrontendPathname(pathname),
    reason_code:lazyRouteError ? 'lazy_route_load_failed' : 'route_render_failed',
    result_code:'failure',
    release,
  })
}

export function reportFrontendApiError(accessToken: string, pathname: string, signal: ApiErrorSignal): void {
  if (!Number.isInteger(signal.status) || signal.status < 0 || signal.status > 599 ||
    !/^[a-z][a-z0-9_]{0,63}$/.test(signal.code)) return
  sendFrontendEvent(accessToken, {
    event_code:'api_error',
    route:boundedFrontendPathname(pathname),
    reason_code:`api_${signal.status}_${signal.code}`,
    result_code:'failure',
    release,
  })
}
