import { useQuery } from '@tanstack/react-query'

import { ticketsApi, ticketsManagePermission, ticketsReadPermission } from '../api/tickets'
import type { Principal } from '../api/auth'

export const ticketMenuKey = '/sys/tickets'
export const ticketBadgePollMs = 60_000

// useTicketMenuBadge returns the open-ticket count for the admin sidebar. It
// reuses GET /v1/admin/tickets/summary (same query key as the tickets page,
// so working a ticket refreshes it) and polls once a minute while visible.
export function useTicketMenuBadge(principal: Principal, accessToken: string | null): number {
  const permissions = principal.permissions
  const enabled = principal.scope_kind === 'platform' && Boolean(accessToken) &&
    [ticketsReadPermission, ticketsManagePermission, 'platform.admin'].some((permission) => permissions.includes(permission))
  const summary = useQuery({
    queryKey: ['tickets', 'admin', 'summary'],
    queryFn: () => ticketsApi.summary(accessToken ?? '', 'admin'),
    enabled,
    refetchInterval: ticketBadgePollMs,
    refetchIntervalInBackground: false,
    retry: false,
  })
  return enabled ? summary.data?.pending ?? 0 : 0
}
