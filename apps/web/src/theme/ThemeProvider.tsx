import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { CdncaProvider, type CdncaProviderProps } from '@cdnca/ui'

import { themeApi, themeStylesheetPath, type ThemeBrandAssets, type ThemeDocument, type ThemeScope } from '../api/theme'
import { publicBrandAssetUpdatedEvent } from '../components/PublicBrandAssetImage'
import { roleForPrincipal, useSessionStore } from '../auth/session'
import { defaultThemeLayout, ThemeRuntimeContext, themeChangedEvent } from './runtime'

const stylesheetID = 'cdnca-theme-stylesheet'

// ThemeProvider loads the caller's theme (GET /v1/theme/current, then its
// immutable theme.<sha>.json and theme.<sha>.css, all same-origin) and feeds
// the tokens to the shared CdncaProvider, so a white-label theme overrides the
// common cdnca look. Until it loads, or if it fails, the default tokens apply. A theme is data: no script, no inline style, no CSP change.
// The theme follows the session (PA-26): a tenant user sees the tenant's own
// theme, the sign-in page the theme of the tenant its hostname is bound to,
// so it reloads whenever the signed-in scope changes.
export function ThemeProvider({ children, ...config }: Omit<CdncaProviderProps, 'tokens'> & { children: ReactNode }) {
  const [document, setDocument] = useState<ThemeDocument | null>(null)
  const [scope, setScope] = useState<ThemeScope>('platform')
  const [brandAssets, setBrandAssets] = useState<ThemeBrandAssets>({})
  const scopeID = useSessionStore((state) => state.principal?.scope_id ?? null)
  // admin / user from the session, public on the sign-in pages: a theme's
  // tokens_by_role block and the console-only rules key off it.
  const role = useSessionStore((state) => (state.principal ? roleForPrincipal(state.principal) : 'public'))

  useEffect(() => {
    let cancelled = false
    const load = async () => {
      try {
        const current = await themeApi.current(useSessionStore.getState().accessToken)
        const loaded = await themeApi.document(current)
        if (cancelled) return
        applyStylesheet(themeStylesheetPath(current), loaded.package_sha256)
        setDocument(loaded)
        setScope(current.scope)
        setBrandAssets(current.brand_assets ?? {})
      } catch {
        // Keep whatever theme is showing; the default tokens are built in.
      }
    }
    void load()
    const reload = () => { void load() }
    window.addEventListener(themeChangedEvent, reload)
    // An upload changes the slot's revision in brand_assets, which the images
    // put in ?v=, so the new file shows at once.
    window.addEventListener(publicBrandAssetUpdatedEvent, reload)
    return () => {
      cancelled = true
      window.removeEventListener(themeChangedEvent, reload)
      window.removeEventListener(publicBrandAssetUpdatedEvent, reload)
    }
  }, [scopeID])

  const shown = document
  const runtime = useMemo(() => ({ document: shown, layout: shown?.layout ?? defaultThemeLayout, scope, brandAssets }), [shown, scope, brandAssets])
  const look = shown?.layout.look ?? 'classic'
  const motion = shown?.layout.motion ?? 'off'
  const tokens = useMemo(() => {
    if (!document) return undefined
    const overrides = role === 'public' ? undefined : document.antd_tokens_by_role?.[role]
    return overrides ? { ...document.antd_tokens, ...overrides } : document.antd_tokens
  }, [document, role])

  useEffect(() => {
    const root = window.document.documentElement.dataset
    root.cdncaRole = role
    if (shown) {
      root.cdncaThemeId = shown.id
      root.cdncaLook = look
      root.cdncaMotion = motion
    } else {
      delete root.cdncaThemeId
      delete root.cdncaLook
      delete root.cdncaMotion
    }
  }, [shown, look, motion, role])

  return (
    <ThemeRuntimeContext.Provider value={runtime}>
      <CdncaProvider {...config} tokens={tokens} look={look === 'tech' ? 'console' : 'classic'}>
        {children}
      </CdncaProvider>
    </ThemeRuntimeContext.Provider>
  )
}

function applyStylesheet(path: string | null, packageSHA256: string) {
  const root = window.document.documentElement
  let link = window.document.getElementById(stylesheetID) as HTMLLinkElement | null
  if (!path) {
    link?.remove()
    delete root.dataset.cdncaTheme
    return
  }
  if (!link) {
    link = window.document.createElement('link')
    link.id = stylesheetID
    link.rel = 'stylesheet'
    window.document.head.append(link)
  }
  if (link.getAttribute('href') !== path) link.setAttribute('href', path)
  root.dataset.cdncaTheme = packageSHA256
}

