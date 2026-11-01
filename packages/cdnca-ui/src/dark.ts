import { useEffect, useState } from 'react'
import { theme as antdTheme, type ThemeConfig } from 'antd'

import tokens from './tokens.json'

// the dark palette shared by dark.css (CSS variables) and the
// antd dark theme. A theme only sets the nine *-dark seeds; everything else
// is derived the same way dark.css derives it (color-mix in sRGB).

export interface CdncaDarkSeeds {
  colorBgDark: string
  colorChromeDark: string
  colorSurfaceDark: string
  colorSurfaceMutedDark: string
  colorBorderDark: string
  colorBorderSoftDark: string
  colorTextDark: string
  colorTextSecondaryDark: string
  colorPrimaryDark: string
}

const seedNames: (keyof CdncaDarkSeeds)[] = [
  'colorBgDark', 'colorChromeDark', 'colorSurfaceDark', 'colorSurfaceMutedDark', 'colorBorderDark',
  'colorBorderSoftDark', 'colorTextDark', 'colorTextSecondaryDark', 'colorPrimaryDark',
]

export const defaultDarkSeeds: CdncaDarkSeeds = Object.fromEntries(
  seedNames.map((name) => [name, tokens.css[name]]),
) as unknown as CdncaDarkSeeds

/** Status colors in dark mode (dark.css): lighter tones that keep AA on the dark card. */
export const darkStatusColors = { success: '#4ade80', warning: '#fbbf24', error: '#f87171' } as const

/** The seeds from a rendered theme's css_variables (--cdnca-color-bg-dark ...); missing ones use the defaults. */
export function darkSeedsFromCSSVariables(variables: Record<string, string> | undefined): CdncaDarkSeeds {
  const seeds = { ...defaultDarkSeeds }
  for (const name of seedNames) {
    const value = variables?.[`--cdnca-${name.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`)}`]
    if (value && /^#[0-9a-f]{6}$/i.test(value)) seeds[name] = value
  }
  return seeds
}

function rgb(hex: string): number[] {
  return [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16))
}

/** color-mix(in srgb, a p%, b) as #rrggbb. */
export function mixHex(a: string, percent: number, b: string): string {
  const x = rgb(a)
  const y = rgb(b)
  return `#${x.map((v, i) => Math.round(v * percent / 100 + y[i] * (1 - percent / 100)).toString(16).padStart(2, '0')).join('')}`
}

function luminance(hex: string): number {
  const [r, g, b] = rgb(hex).map((v) => {
    const c = v / 255
    return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4
  })
  return 0.2126 * r + 0.7152 * g + 0.0722 * b
}

/** WCAG 2 contrast ratio of two #rrggbb colors. */
export function contrastRatio(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x)
  return (hi + 0.05) / (lo + 0.05)
}

export interface CdncaDarkPalette {
  page: string
  chrome: string
  card: string
  cardMuted: string
  elevated: string
  input: string
  border: string
  borderSoft: string
  borderInput: string
  title: string
  text: string
  textSecondary: string
  textWeak: string
  textDisabled: string
  primary: string
  link: string
  linkHover: string
  onPrimary: string
  success: string
  warning: string
  error: string
  info: string
  tableHeader: string
  rowHover: string
  rowSelected: string
}

/** Every dark color, derived from the seeds exactly as dark.css does. */
export function darkPalette(seeds: CdncaDarkSeeds = defaultDarkSeeds): CdncaDarkPalette {
  const s = seeds
  return {
    page: s.colorBgDark,
    chrome: s.colorChromeDark,
    card: s.colorSurfaceDark,
    cardMuted: s.colorSurfaceMutedDark,
    elevated: mixHex(s.colorSurfaceDark, 94, '#ffffff'),
    input: s.colorSurfaceMutedDark,
    border: s.colorBorderDark,
    borderSoft: s.colorBorderSoftDark,
    borderInput: mixHex(s.colorTextSecondaryDark, 62, s.colorSurfaceDark),
    title: mixHex(s.colorTextDark, 50, '#ffffff'),
    text: s.colorTextDark,
    textSecondary: s.colorTextSecondaryDark,
    textWeak: mixHex(s.colorTextSecondaryDark, 90, s.colorSurfaceDark),
    textDisabled: mixHex(s.colorTextSecondaryDark, 55, s.colorSurfaceDark),
    primary: s.colorPrimaryDark,
    link: s.colorPrimaryDark,
    linkHover: mixHex(s.colorPrimaryDark, 75, '#ffffff'),
    // Light primaries carry dark text (white on #60a5fa is 2.5:1).
    onPrimary: s.colorBgDark,
    ...darkStatusColors,
    info: s.colorPrimaryDark,
    tableHeader: s.colorSurfaceMutedDark,
    rowHover: mixHex(s.colorPrimaryDark, 8, s.colorSurfaceDark),
    rowSelected: mixHex(s.colorPrimaryDark, 12, s.colorSurfaceDark),
  }
}

/** antd's dark algorithm fed with the same palette, layered over a light cdnca theme. */
export function darkThemeConfig(base: ThemeConfig, seeds: CdncaDarkSeeds = defaultDarkSeeds): ThemeConfig {
  const p = darkPalette(seeds)
  const components = base.components ?? {}
  return {
    ...base,
    // darkAlgorithm darkens the seed primary/status colors; the second pass pins
    // them back to the palette so antd and the CSS show the same color.
    algorithm: [antdTheme.darkAlgorithm, (_seed, map) => ({
      ...map!, colorPrimary: p.primary, colorInfo: p.info, colorSuccess: p.success, colorWarning: p.warning, colorError: p.error,
      colorLink: p.link, colorLinkHover: p.linkHover, colorTextLightSolid: p.onPrimary,
    })],
    token: {
      ...base.token,
      colorPrimary: p.primary,
      colorInfo: p.info,
      colorSuccess: p.success,
      colorWarning: p.warning,
      colorError: p.error,
      colorLink: p.link,
      colorLinkHover: p.linkHover,
      colorTextBase: p.text,
      colorText: p.text,
      colorTextHeading: p.title,
      colorTextSecondary: p.textSecondary,
      colorTextTertiary: p.textWeak,
      colorTextQuaternary: p.textDisabled,
      colorTextDisabled: p.textDisabled,
      colorTextPlaceholder: p.textWeak,
      colorTextLightSolid: p.onPrimary,
      colorBgBase: p.page,
      colorBgLayout: p.page,
      colorBgContainer: p.card,
      colorBgElevated: p.elevated,
      colorBgSpotlight: p.elevated,
      colorBgContainerDisabled: p.cardMuted,
      colorFillAlter: p.cardMuted,
      colorBorder: p.borderInput,
      colorBorderSecondary: p.border,
      colorSplit: p.border,
      controlItemBgHover: p.rowHover,
      controlItemBgActive: p.rowSelected,
      boxShadowTertiary: 'inset 0 1px 0 rgb(255 255 255 / 4%), 0 8px 24px rgb(0 0 0 / 32%)',
    },
    components: {
      ...components,
      Table: {
        ...components.Table,
        headerBg: p.tableHeader, headerColor: p.text, borderColor: p.border, rowHoverBg: p.rowHover,
        rowSelectedBg: p.rowSelected, rowSelectedHoverBg: p.rowSelected, headerSortActiveBg: p.cardMuted,
      },
      Select: { ...components.Select, optionSelectedBg: p.rowSelected, optionSelectedColor: p.text },
      Menu: { ...components.Menu, itemBg: p.chrome, subMenuItemBg: p.chrome, itemColor: p.textSecondary, itemSelectedBg: p.rowSelected, itemSelectedColor: p.primary },
      Segmented: { ...components.Segmented, itemSelectedColor: p.primary, itemSelectedBg: p.elevated, trackBg: p.cardMuted },
      Layout: { ...components.Layout, headerBg: p.chrome, bodyBg: p.page, siderBg: p.chrome },
      Tooltip: { colorBgSpotlight: p.elevated, colorTextLightSolid: p.text },
    },
  }
}

/**
 * The page's color mode: <html data-theme="dark"> (web AppShell's switch)
 * means dark. It is read from the document, so every front end and every
 * provider follows the same switch without a shared store.
 */
export function useColorMode(): 'light' | 'dark' {
  const read = (): 'light' | 'dark' => (typeof document !== 'undefined' && document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light')
  const [mode, setMode] = useState<'light' | 'dark'>(read)
  useEffect(() => {
    const update = () => setMode(read())
    update()
    const observer = new MutationObserver(update)
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] })
    return () => observer.disconnect()
  }, [])
  return mode
}
