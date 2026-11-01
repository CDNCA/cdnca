import { useQuery } from '@tanstack/react-query'

import { fetchRuntimeFeatures, type RuntimeFeature } from '../api/runtimeFeatures'

export const runtimeFeaturesQueryKey = ['runtime', 'features'] as const

const noFeatures: readonly RuntimeFeature[] = []

// useRuntimeFeatures returns the optional runtimes this control plane mounted.
// Until GET /v1/runtime-features answers (or when it fails) it returns none,
// so menu items with requiredRuntime stay hidden rather than lead to a 404.
export function useRuntimeFeatures(accessToken: string | null): readonly RuntimeFeature[] {
  const features = useQuery({
    queryKey: runtimeFeaturesQueryKey,
    queryFn: () => fetchRuntimeFeatures(accessToken ?? ''),
    enabled: Boolean(accessToken),
    staleTime: Infinity,
    retry: false,
  })
  return features.data ?? noFeatures
}

// useRuntimeFeatureOff reports true only once the shell's GET
// /v1/runtime-features answered without feature. It never fetches: in-page
// links to a runtime are dropped when it is known to be off, and kept while
// unknown (the page route itself is still gated by the menu and the API).
export function useRuntimeFeatureOff(feature: RuntimeFeature, accessToken: string | null): boolean {
  const features = useQuery({
    queryKey: runtimeFeaturesQueryKey,
    queryFn: () => fetchRuntimeFeatures(accessToken ?? ''),
    enabled: false,
    staleTime: Infinity,
    retry: false,
  }).data
  return features !== undefined && !features.includes(feature)
}

// useDemoLocked: the signed-in account is a locked demo account; account
// settings (password, contacts, MFA, API keys) are shown disabled and the API
// refuses them with 403 demo_account_locked. Like useRuntimeFeatureOff it
// never fetches: it reads the shell's GET /v1/runtime-features answer.
export function useDemoLocked(accessToken: string | null): boolean {
  const features = useQuery({
    queryKey: runtimeFeaturesQueryKey,
    queryFn: () => fetchRuntimeFeatures(accessToken ?? ''),
    enabled: false,
    staleTime: Infinity,
    retry: false,
  }).data
  return features?.includes('demo_locked') ?? false
}
