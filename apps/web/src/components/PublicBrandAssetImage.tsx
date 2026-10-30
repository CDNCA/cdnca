import { useEffect, useMemo, useState } from 'react'

import type { ThemeDocument } from '../api/theme'
import { brandCandidates, useThemeRuntime } from '../theme/runtime'

export const publicBrandAssetUpdatedEvent = 'cdnca:brand-asset-updated'

// usePublicBrandFavicon points <link rel="icon"> (favicon) and
// <link rel="apple-touch-icon"> (app_icon) at the first image that loads
// among the slot's candidates: the platform upload (only a slot listed in
// brand_assets, never for a tenant's own theme), the theme's image, the
// fallback slot, the bundled logo.
export function usePublicBrandFavicon() {
  const { document: themeDocument, scope, brandAssets } = useThemeRuntime()
  const uploaded = scope === 'tenant' ? noUploads : brandAssets
  useBrandIconLink('icon', brandCandidates('favicon', themeDocument, uploaded), themeDocument)
  useBrandIconLink('apple-touch-icon', brandCandidates('app_icon', themeDocument, uploaded), themeDocument)
}

const noUploads = {}

function useBrandIconLink(rel: string, candidates: string[], themeDocument: ThemeDocument | null) {
  // Keyed by the candidate URLs and their types, not by the theme object: a
  // reloaded but identical theme does not probe again.
  const typeOf = (src: string) => Object.values(themeDocument?.brand ?? {}).find((asset) => asset && src.startsWith(asset.url))?.mime_type ?? 'image/png'
  const key = candidates.map((src) => `${src} ${typeOf(src)}`).join('\n')
  useEffect(() => {
    const entries = key.split('\n').map((line) => line.split(' '))
    const sources = entries.map(([src]) => src)
    const types = new Map(entries.map(([src, type]) => [src, type]))
    const existingLink = document.head.querySelector<HTMLLinkElement>(`link[rel~="${rel}"]`)
    const link = existingLink ?? document.createElement('link')
    const originalHref = link.getAttribute('href')
    const originalType = link.getAttribute('type')
    let created = false

    if (!existingLink) {
      created = true
      link.rel = rel
      document.head.append(link)
    }

    // The last candidate is the slot's bundled file (brandCandidates).
    const fallback = () => {
      link.href = sources[sources.length - 1]
      link.type = 'image/png'
    }
    let index = 0
    let current = sources[0]
    const onLoad = () => {
      link.href = current
      link.type = types.get(current) ?? 'image/png'
    }
    const onError = () => {
      fallback()
      if (index + 1 < sources.length) {
        index += 1
        load(sources[index])
      }
    }

    const probe = document.createElement('img')
    probe.alt = ''
    probe.setAttribute('aria-hidden', 'true')
    if (rel === 'icon') probe.dataset.cdncaFaviconProbe = 'true'
    probe.style.display = 'none'
    probe.addEventListener('load', onLoad)
    probe.addEventListener('error', onError)
    document.body.append(probe)
    const load = (src: string) => {
      current = src
      probe.src = src
    }
    // An upload (publicBrandAssetUpdatedEvent) makes ThemeProvider reload
    // brand_assets; the new ?v=<revision> changes the key and probes again.
    fallback()
    load(sources[0])

    return () => {
      probe.removeEventListener('load', onLoad)
      probe.removeEventListener('error', onError)
      probe.remove()
      if (created) {
        link.remove()
      } else {
        if (originalHref === null) link.removeAttribute('href')
        else link.href = originalHref
        if (originalType === null) link.removeAttribute('type')
        else link.type = originalType
      }
    }
  }, [rel, key])
}

export function PublicBrandFavicon() {
  usePublicBrandFavicon()
  return null
}

// The platform upload (a slot listed in brand_assets) wins, then the active
// theme's image (PA-17), then the built-in file; each failed load moves to the
// next candidate. A tenant's own theme (PA-26) skips the platform upload.
export function PublicBrandAssetImage({ alt, slot = 'logo', className }: {
  alt: string
  slot?: 'logo' | 'logo_dark' | 'login_ad' | 'login_background'
  className?: string
}) {
  const { document, scope, brandAssets } = useThemeRuntime()
  // Keyed by content: an identical reloaded theme keeps the image (and the
  // candidate it fell back to) instead of requesting the first one again.
  const key = brandCandidates(slot, document, scope === 'tenant' ? noUploads : brandAssets).join('\n')
  const candidates = useMemo(() => key.split('\n'), [key])
  const [index, setIndex] = useState(0)
  useEffect(() => setIndex(0), [key])
  const src = candidates[Math.min(index, candidates.length - 1)]
  return <img className={className} src={src} alt={alt} onError={() => setIndex((current) => Math.min(current + 1, candidates.length - 1))} />
}
