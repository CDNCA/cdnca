import { useQuery } from '@tanstack/react-query'

import { fetchGrantedModules } from '../api/modules'

export const grantedModulesQueryKey = ['entitlement', 'modules'] as const
export const grantedModulesPollMs = 5 * 60_000

const noModules: readonly string[] = []

// useGrantedModules returns the module codes the local lease grants. Until
// GET /v1/modules answers (or when it fails) it returns none, so menu items
// with requiredModule stay hidden rather than flash in and out.
export function useGrantedModules(accessToken: string | null): readonly string[] {
  const modules = useQuery({
    queryKey: grantedModulesQueryKey,
    queryFn: () => fetchGrantedModules(accessToken ?? ''),
    enabled: Boolean(accessToken),
    refetchInterval: grantedModulesPollMs,
    refetchIntervalInBackground: false,
    retry: false,
  })
  return modules.data?.modules ?? noModules
}
