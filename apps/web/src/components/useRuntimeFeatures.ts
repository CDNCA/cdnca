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
