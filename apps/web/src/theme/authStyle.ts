import { useEffect } from 'react'

import { authStylePathPattern } from '../api/theme'
import { useThemeRuntime } from './runtime'

// Theme plugin C auth_style: the user console plugin may restyle the
// platform's sign-in, sign-up and recovery pages. Only CSS is taken, into a
// <style> of its own; the forms stay the platform's. control-api validates
// the CSS on install; it is checked again here and dropped whole on any sign
// of markup, script or remote loading (the page CSP still applies).

export const authStyleAttribute = 'data-cdnca-auth-style'
const maxBytes = 256 << 10

export interface AuthStyle { css: string; images: Record<string, string> }

// Markup or script in a stylesheet: closing the <style>, a script tag, legacy
// IE script hooks, javascript: URLs, @import and @charset (an import could
// reach anywhere; a charset could change how the rest is read), HTML comments,
// the admin console role selector and any backslash (CSS escapes could spell
// the rest; libs/sitetheme refuses them on install too).
const forbidden = [/<\s*\/?\s*script/i, /<\s*\/\s*style/i, /<!--/, /-->/, /@import/i, /@charset/i, /expression\s*\(/i, /javascript\s*:/i,
  /vbscript\s*:/i, /behavio(u)?r\s*:/i, /-moz-binding/i, /data-cdnca-role\s*=\s*['"]?admin/i, /\\/]
// url() is allowed only for the plugin's own images on this origin, or an
// inline image (libs/sitetheme auth_style accepts the same data: types).
const urlPattern = /url\(\s*(['"]?)(.*?)\1\s*\)/gi
const allowedURL = /^\/v1\/theme\/(?:auth-style\/)?assets\/[0-9a-f]{64}$/
const inlineImage = /^data:image\/(?:png|jpeg|webp|gif|svg\+xml)(?:;base64)?,[A-Za-z0-9+/=%._-]*$/

/** The CSS to inject, or "" when any part of it is unsafe. */
export function sanitizeAuthCSS(css: unknown): string {
  if (typeof css !== 'string' || css.length === 0 || css.length > maxBytes) return ''
  if (forbidden.some((pattern) => pattern.test(css))) return ''
  for (const match of css.matchAll(urlPattern)) {
    const url = match[2].trim()
    if (!allowedURL.test(url) && !inlineImage.test(url)) return ''
  }
  // Any "url(" left that the pattern above did not read as a whole is refused too.
  if ((css.match(/url\(/gi) ?? []).length !== [...css.matchAll(urlPattern)].length) return ''
  return css
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/** The user console plugin's sign-in page style at path (the theme document's auth_style_url); null on any failure. */
export async function loadAuthStyle(path: string, fetcher: typeof fetch = fetch): Promise<AuthStyle | null> {
  if (!authStylePathPattern.test(path)) return null
  const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
  try {
    const response = await fetcher(`${apiRoot}${path}`, { credentials: 'omit', cache: 'no-store', headers: { Accept: 'application/json' } })
    if (response.status !== 200) return null
    const body: unknown = await response.json()
    if (!isRecord(body) || typeof body.css !== 'string') return null
    const images = isRecord(body.images)
      ? Object.fromEntries(Object.entries(body.images).filter(([slot, url]) => /^[a-z0-9_-]{1,32}$/.test(slot) && typeof url === 'string' && allowedURL.test(url)))
      : {}
    return { css: body.css, images: images as Record<string, string> }
  } catch {
    return null
  }
}

/** Puts the CSS in the document's own auth style element (or removes it for ""). Returns the cleanup. */
export function applyAuthStyle(css: string, doc: Document = document): () => void {
  doc.head.querySelectorAll(`style[${authStyleAttribute}]`).forEach((node) => node.remove())
  const safe = sanitizeAuthCSS(css)
  if (!safe) return () => undefined
  const style = doc.createElement('style')
  style.setAttribute(authStyleAttribute, '')
  // textContent: the text is never parsed as markup.
  style.textContent = safe
  doc.head.appendChild(style)
  return () => style.remove()
}

/**
 * Applies the user console plugin's auth_style while a sign-in page is shown.
 * The theme document names it (auth_style_url); without one nothing is
 * requested.
 */
export function useAuthStyle() {
  const path = useThemeRuntime().document?.auth_style_url
  useEffect(() => {
    if (!path) return
    let cleanup: () => void = () => undefined
    let live = true
    void loadAuthStyle(path).then((style) => {
      if (live && style) cleanup = applyAuthStyle(style.css)
    })
    return () => { live = false; cleanup() }
  }, [path])
}
