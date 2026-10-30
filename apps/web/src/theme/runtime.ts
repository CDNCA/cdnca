import { createContext, useContext } from 'react'
import type { ThemeConfig } from 'antd'
import { cdncaTheme, defaultAntdTokens as sharedDefaultTokens } from '@cdnca/ui'

import { localizedText, type ThemeAntdTokens, type ThemeBrandAssets, type ThemeBrandSlot, type ThemeDocument, type ThemeScope } from '../api/theme'

// Default tokens come from the shared package (= libs/themepack/tokens.go
// defaults), so the first paint before /v1/theme/current answers and a failed
// fetch both look like the default theme in every front end.
export const defaultAntdTokens: ThemeAntdTokens = sharedDefaultTokens

export const defaultThemeLayout: ThemeDocument['layout'] = {
  login_layout: 'split',
  sidebar: 'light',
  header_links: [],
  footer_text: {},
  user_home_blocks: ['profile', 'network', 'monitoring', 'top', 'notices', 'package_traffic', 'usage'],
}

export interface ThemeRuntime {
  document: ThemeDocument | null
  layout: ThemeDocument['layout']
  /** tenant: the tenant's own theme (PA-26), whose images replace the platform uploads. */
  scope?: ThemeScope
  /** Slots the platform uploaded, with their revisions (/v1/theme/current brand_assets). */
  brandAssets?: ThemeBrandAssets
}

export const ThemeRuntimeContext = createContext<ThemeRuntime>({ document: null, layout: defaultThemeLayout, scope: 'platform', brandAssets: {} })

export function useThemeRuntime(): ThemeRuntime {
  return useContext(ThemeRuntimeContext)
}

/** Product name shown when the active theme names none (cdnca naming rule). */
export const defaultBrandName = 'cdnca'

/** The product name the active theme sets for locale; '' when it sets none. */
export function useThemeBrandName(locale: string): string {
  const { layout } = useThemeRuntime()
  return localizedText(layout.brand_name, locale)
}

/**
 * The active theme's product name for locale, else fallback (the system
 * settings name when the caller has it), else defaultBrandName (fix-e1 #6,
 * fix-ui1026 #4: the theme wins over the system settings).
 */
export function useBrandName(locale: string, fallback?: string): string {
  return useThemeBrandName(locale) || fallback?.trim() || defaultBrandName
}

/** Event the theme admin page fires after an activation. */
export const themeChangedEvent = 'cdnca:theme-changed'

// antdThemeConfig maps a theme document onto ConfigProvider.theme: the shared
// cdnca theme driven by the theme's whitelisted tokens.
export function antdThemeConfig(tokens: ThemeAntdTokens, reducedMotion: boolean): ThemeConfig {
  return cdncaTheme(tokens, reducedMotion)
}

const brandFallbacks: Partial<Record<ThemeBrandSlot, ThemeBrandSlot>> = {
  logo_dark: 'logo',
  login_background: 'login_ad',
  app_icon: 'favicon',
}

const builtInBrand: Record<ThemeBrandSlot, string> = {
  logo: '/dashboard/logo.png',
  logo_dark: '/dashboard/logo-dark.png',
  login_ad: '/dashboard/ad.jpeg',
  login_background: '/dashboard/login-background.jpeg',
  favicon: '/dashboard/favicon.png',
  app_icon: '/dashboard/app-icon-180.png',
}

/** The bundled cdnca default for a brand slot (assets/brand/cdnca, scripts/brand/export.sh). */
export function builtInBrandAsset(slot: ThemeBrandSlot): string {
  return builtInBrand[slot]
}

/**
 * Image sources to try in order for a brand slot: the platform's own upload
 * (brandasset), then the active theme's image, then the slot it falls back to,
 * then the built-in file. Duplicates are dropped. Only slots listed in
 * uploaded (current.brand_assets) are requested, with ?v=<revision> so a new
 * upload busts the cache; a slot never uploaded costs no 404. A tenant's own
 * theme passes no uploads: a white-label tenant never shows the platform's logo.
 */
export function brandCandidates(slot: ThemeBrandSlot, document: ThemeDocument | null, uploaded: ThemeBrandAssets = {}): string[] {
  const result: string[] = []
  const add = (value: string | undefined) => {
    if (value && !result.includes(value)) result.push(value)
  }
  let current: ThemeBrandSlot | undefined = slot
  while (current) {
    const revision = uploaded[current]
    if (revision) add(`/v1/brand-assets/${current}?v=${revision}`)
    add(document?.brand[current]?.url)
    current = brandFallbacks[current]
  }
  add(builtInBrand[slot])
  return result
}
