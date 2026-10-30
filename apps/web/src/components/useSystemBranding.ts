import { useEffect } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'

import type { Principal } from '../api/auth'
import { publicBranding } from '../api/publicBranding'
import { systemSettingsApi } from '../api/systemSettings'

export const systemBrandingQueryKey = ['system-settings', 'branding'] as const
/** Fired by the system settings page after a save, so the shell re-reads the name and titles. */
export const systemSettingsChangedEvent = 'cdnca:system-settings-changed'

export interface SystemBranding {
  systemName: string
  userTitle: string
  adminTitle: string
}

/**
 * System name and console titles from the system settings (fix-ui1026 #4).
 * Platform sessions that may read the system settings use
 * GET /v1/admin/system-settings; every other session (tenant users, L6) reads
 * the anonymous public whitelist GET /v1/system-settings/public. A failed read
 * gets null and the shell falls back to the theme or the built-in name.
 */
export function useSystemBranding(principal: Principal | null, accessToken: string | null): SystemBranding | null {
  const queryClient = useQueryClient()
  const enabled = Boolean(accessToken && principal)
  const admin = Boolean(principal?.scope_kind === 'platform' &&
    (principal.permissions.includes('system_configuration.read') || principal.permissions.includes('platform.admin')))
  const query = useQuery({
    queryKey: [...systemBrandingQueryKey, admin ? 'admin' : 'public', principal?.user_id ?? ''],
    queryFn: async ({ signal }) => {
      if (!admin) return publicBranding(signal)
      const { value } = await systemSettingsApi.get(accessToken ?? '')
      return { systemName: value.system_name, userTitle: value.user_title, adminTitle: value.admin_title }
    },
    enabled, retry: false, staleTime: 5 * 60_000,
  })
  useEffect(() => {
    if (!enabled) return
    const refetch = () => { void queryClient.invalidateQueries({ queryKey: systemBrandingQueryKey }) }
    window.addEventListener(systemSettingsChangedEvent, refetch)
    return () => window.removeEventListener(systemSettingsChangedEvent, refetch)
  }, [enabled, queryClient])
  return enabled ? query.data ?? null : null
}
