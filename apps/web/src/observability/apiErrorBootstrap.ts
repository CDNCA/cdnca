import type { ApiErrorSignal } from '../api/auth'
import { boundedFrontendPathname, reportFrontendApiError } from './frontendReporter'

const dedupeWindowMilliseconds = 30_000
const maximumDedupeEntries = 64
const stableCodePattern = /^[a-z][a-z0-9_]{0,63}$/

interface GlobalApiErrorReporterConfig {
  getAccessToken: () => string | null | undefined
  getPathname: () => string
  now?: () => number
  report?: (accessToken: string, pathname: string, signal: ApiErrorSignal) => void
}

function expectedFailure(signal: ApiErrorSignal): boolean {
  return signal.status === 401 || signal.code === 'stale_session' || signal.code === 'session_expired' ||
    /(?:request_)?cancel(?:led|ed)$/.test(signal.code)
}

export function createGlobalApiErrorReporter(config: GlobalApiErrorReporterConfig): (signal: ApiErrorSignal) => void {
  const now = config.now ?? Date.now
  const report = config.report ?? reportFrontendApiError
  const seen = new Map<string, number>()

  return (signal) => {
    if (!Number.isInteger(signal.status) || signal.status < 0 || signal.status > 599 ||
      !stableCodePattern.test(signal.code) || expectedFailure(signal)) return
    const accessToken = config.getAccessToken()
    if (!accessToken || /\s/.test(accessToken)) return
    const pathname = boundedFrontendPathname(config.getPathname())
    const observedAt = now()
    const key = `${pathname}\n${signal.status}\n${signal.code}`
    const previous = seen.get(key)
    if (previous !== undefined && observedAt-previous <= dedupeWindowMilliseconds) return
    if (previous !== undefined) seen.delete(key)
    while (seen.size >= maximumDedupeEntries) seen.delete(seen.keys().next().value!)
    seen.set(key, observedAt)
    try { report(accessToken, pathname, signal) } catch { /* Reporting cannot change request outcomes. */ }
  }
}
