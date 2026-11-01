// The admin overview's own dashboard read, shared by AdminHomePage and the
// entry: main.tsx starts it as soon as the session is
// restored, so /v1/admin/dashboard runs while the console shell and the page
// chunk download instead of after them. Same key and read as the page, so the
// page picks up the in-flight query.
import type { QueryClient } from '@tanstack/react-query'

import type { Principal } from '../api/auth'
import { dashboardApi, type AdminDashboardRange } from '../api/dashboard'
import { useSessionStore } from '../auth/session'
import { businessTimeZone } from '../i18n/formatters'

export type AdminDashboardOwner = readonly ['platform', string, null, string, number]

export const staleAdminDashboardRead = new Error('stale admin dashboard read')
export const defaultAdminDashboardRange: AdminDashboardRange = 'seven_days'

export function adminDashboardOwner(principal: Principal, sessionEpoch: number): AdminDashboardOwner | null {
  if (
    principal.scope_kind !== 'platform' ||
    !principal.scope_id ||
    principal.tenant_id !== null ||
    !principal.user_id ||
    !sessionEpoch
  ) return null
  return ['platform', principal.scope_id, null, principal.user_id, sessionEpoch]
}

export function currentAdminDashboardAccess(ownerKey: string): string | null {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (!accessToken || !principal || !principal.permissions.includes('platform.admin')) return null
  const owner = adminDashboardOwner(principal, sessionEpoch)
  return owner && JSON.stringify(owner) === ownerKey ? accessToken : null
}

export const adminDashboardQueryPrefix = (owner: AdminDashboardOwner) => ['dashboard', 'admin', ...owner] as const

export function adminDashboardQuery(owner: AdminDashboardOwner, range: AdminDashboardRange, canRead: () => boolean) {
  const ownerKey = JSON.stringify(owner)
  return {
    queryKey: [...adminDashboardQueryPrefix(owner), range, businessTimeZone] as const,
    queryFn: async ({ signal }: { signal: AbortSignal }) => {
      const token = currentAdminDashboardAccess(ownerKey)
      if (!token) throw staleAdminDashboardRead
      try {
        const result = await dashboardApi.admin(token, range, businessTimeZone, signal)
        if (!canRead()) throw staleAdminDashboardRead
        return result
      } catch (error) {
        if (!canRead()) throw staleAdminDashboardRead
        throw error
      }
    },
    staleTime: 30_000,
  }
}

/** Start the overview's first read when the restored session is a platform administrator. */
export function prefetchAdminDashboard(queryClient: QueryClient) {
  const { principal, sessionEpoch } = useSessionStore.getState()
  if (!principal || !principal.permissions.includes('platform.admin')) return
  const owner = adminDashboardOwner(principal, sessionEpoch)
  if (!owner) return
  const ownerKey = JSON.stringify(owner)
  void queryClient.prefetchQuery(adminDashboardQuery(owner, defaultAdminDashboardRange, () => Boolean(currentAdminDashboardAccess(ownerKey))))
}
