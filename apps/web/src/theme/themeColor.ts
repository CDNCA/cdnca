import { useEffect, useState } from 'react'

// Colors drawn in script (echarts options, inline SVG strokes) read the same
// --cdnca-* variables the stylesheets use, so a theme recolors charts too.
// The fallback is the default theme's value (the default-look lock test checks
// it): with no theme stylesheet, or in jsdom, the chart looks as before.
export function themeColor(variable: string, fallback: string): string {
  if (typeof window === 'undefined' || !window.document.body) return fallback
  const value = window.getComputedStyle(window.document.body).getPropertyValue(variable).trim()
  return value || fallback
}

/** themeColor at an opacity, as "rgba(r, g, b, alpha)"; alpha keeps the default's exact spelling. */
export function themeColorAlpha(variable: string, fallback: string, alpha: string): string {
  const hex = /^#([0-9a-f]{6})$/i.exec(themeColor(variable, fallback))?.[1] ?? fallback.slice(1)
  const [r, g, b] = [0, 2, 4].map((at) => parseInt(hex.slice(at, at + 2), 16))
  return `rgba(${r}, ${g}, ${b}, ${alpha})`
}

/**
 * A counter that changes when the theme variables may have changed: the theme
 * stylesheet finished loading, the active theme or role switched, or dark mode
 * toggled. Charts list it in their effect dependencies to redraw.
 */
export function useThemeRevision(): number {
  const [revision, setRevision] = useState(0)
  useEffect(() => {
    const bump = () => setRevision((value) => value + 1)
    const root = window.document.documentElement
    const body = window.document.body
    const observer = new MutationObserver(bump)
    observer.observe(root, { attributes: true, attributeFilter: ['data-cdnca-theme', 'data-cdnca-role'] })
    // body also gets antd's own classes (modals); only the dark switch counts.
    let dark = body.classList.contains('i-theme-dark')
    const darkObserver = new MutationObserver(() => {
      if (body.classList.contains('i-theme-dark') === dark) return
      dark = !dark
      bump()
    })
    darkObserver.observe(body, { attributes: true, attributeFilter: ['class'] })
    const loaded = (event: Event) => { if ((event.target as Element | null)?.id === 'cdnca-theme-stylesheet') bump() }
    window.document.addEventListener('load', loaded, true)
    return () => {
      observer.disconnect()
      darkObserver.disconnect()
      window.document.removeEventListener('load', loaded, true)
    }
  }, [])
  return revision
}
