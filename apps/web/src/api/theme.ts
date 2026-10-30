import { ApiError, networkApiError, responseApiError } from './auth'

// PA-17 theme packages (ADR 0007 §7): the control plane renders the active
// theme into same-origin theme.<sha>.css + theme.<sha>.json; the SPA only
// reads them. Nothing here executes theme-supplied code.

export type I18nText = Partial<Record<'zh-CN' | 'zh-TW' | 'en-US', string>>
export type LoginLayout = 'split' | 'centered' | 'background'
export type SidebarMode = 'light' | 'dark'
/** Structural style set (html[data-cdnca-look]): classic = today's look, tech = the licensing console look. */
export type ThemeLook = 'classic' | 'tech'
/** Animation level (html[data-cdnca-motion]); prefers-reduced-motion always turns it off. */
export type ThemeMotion = 'off' | 'subtle' | 'rich'
export type ThemeRole = 'admin' | 'user'
export type UserHomeBlock = 'profile' | 'network' | 'monitoring' | 'top' | 'notices' | 'package_traffic' | 'usage'
export type ThemeBrandSlot = 'favicon' | 'logo' | 'login_ad' | 'logo_dark' | 'login_background' | 'app_icon'

export interface ThemeAntdTokens {
  colorPrimary: string
  colorLink: string
  colorLinkHover: string
  colorText: string
  colorTextSecondary: string
  colorBorder: string
  colorBgLayout: string
  colorBgContainer: string
  borderRadius: number
  controlHeight: number
  fontSize: number
  lineHeight: number
  fontFamily: string
}

export interface ThemeDocument {
  schema: 'cdnca.theme.rendered/v1'
  id: string
  version: string
  package_sha256: string
  name: I18nText
  antd_tokens: ThemeAntdTokens
  /** Only the antd tokens one console overrides (package tokens_by_role). */
  antd_tokens_by_role?: Partial<Record<ThemeRole, Partial<ThemeAntdTokens>>>
  css_variables: Record<string, string>
  layout: {
    login_layout: LoginLayout
    sidebar: SidebarMode
    header_links: { label: I18nText; url: string }[]
    footer_text: I18nText
    /** Product name for the consoles and sign-in page (PA-26 white label); absent: "cdnca". */
    brand_name?: I18nText
    user_home_blocks: UserHomeBlock[]
    /** Absent in documents rendered before 1.0.35: classic / off. */
    look?: ThemeLook
    motion?: ThemeMotion
  }
  brand: Partial<Record<ThemeBrandSlot, { url: string; mime_type: string; sha256: string }>>
  /** Theme plugin C: the user console plugin's sign-in page style (GET, JSON {css, images}); absent without one. */
  auth_style_url?: string
}

export interface ThemeCurrent {
  schema: 'cdnca.theme.current/v1'
  revision: number
  theme_id: string
  version: string
  package_sha256: string
  tokens_url: string
  stylesheet_url: string
  /** tenant: a tenant's own theme (PA-26); platform-uploaded brand images do not apply. */
  scope: ThemeScope
  /** Slots the platform uploaded and their revisions; empty for a tenant's own theme. */
  brand_assets?: ThemeBrandAssets
}

export type ThemeBrandAssets = Partial<Record<ThemeBrandSlot, number>>
export type ThemeScope = 'platform' | 'tenant'
export interface ThemePackage {
  package_sha256: string
  theme_id: string
  version: string
  name: I18nText
  description?: I18nText
  source: 'builtin' | 'upload' | 'market'
  requires_feature?: string
  downloaded_at: string
  active: boolean
  tokens_url: string
  stylesheet_url: string
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const sha256Pattern = /^[0-9a-f]{64}$/
const colorPattern = /^#[0-9a-f]{6}$/
const tokenPathPattern = /^\/v1\/theme\/theme\.[0-9a-f]{64}\.json$/
const stylesheetPathPattern = /^\/v1\/theme\/theme\.[0-9a-f]{64}\.css$/
const assetPathPattern = /^\/v1\/theme\/assets\/[0-9a-f]{64}$/
export const authStylePathPattern = /^\/v1\/theme\/auth-style(?:\.[0-9a-f]{64}\.json)?$/
const cssVariablePattern = /^--[a-z][a-z0-9-]{0,63}$/
const cssValuePattern = /^[^;{}<>\\]{1,256}$/
const loginLayouts = new Set<LoginLayout>(['split', 'centered', 'background'])
const homeBlocks = new Set<UserHomeBlock>(['profile', 'network', 'monitoring', 'top', 'notices', 'package_traffic', 'usage'])
const brandSlots = new Set<ThemeBrandSlot>(['favicon', 'logo', 'login_ad', 'logo_dark', 'login_background', 'app_icon'])

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isI18n(value: unknown): value is I18nText {
  return isRecord(value) && Object.entries(value).every(([key, text]) => ['zh-CN', 'zh-TW', 'en-US'].includes(key) && typeof text === 'string')
}

const colorTokenKeys = ['colorPrimary', 'colorLink', 'colorLinkHover', 'colorText', 'colorTextSecondary', 'colorBorder', 'colorBgLayout', 'colorBgContainer']
const numberTokenKeys = ['borderRadius', 'controlHeight', 'fontSize', 'lineHeight']

function validToken(key: string, value: unknown): boolean {
  if (colorTokenKeys.includes(key)) return typeof value === 'string' && colorPattern.test(value)
  if (numberTokenKeys.includes(key)) return typeof value === 'number' && Number.isFinite(value)
  if (key === 'fontFamily') return typeof value === 'string' && !/[;{}<>()\\]/.test(value)
  return false
}

function isTokens(value: unknown): value is ThemeAntdTokens {
  if (!isRecord(value)) return false
  return [...colorTokenKeys, ...numberTokenKeys, 'fontFamily'].every((key) => validToken(key, value[key]))
}

function isRoleTokens(value: unknown): boolean {
  if (value === undefined) return true
  return isRecord(value) && Object.entries(value).every(([role, tokens]) => (role === 'admin' || role === 'user') && isRecord(tokens) &&
    Object.entries(tokens).every(([key, token]) => validToken(key, token)))
}

export function isThemeDocument(value: unknown): value is ThemeDocument {
  if (!isRecord(value) || value.schema !== 'cdnca.theme.rendered/v1' || typeof value.id !== 'string' ||
    typeof value.version !== 'string' || typeof value.package_sha256 !== 'string' || !sha256Pattern.test(value.package_sha256) ||
    !isI18n(value.name) || !isTokens(value.antd_tokens) || !isRoleTokens(value.antd_tokens_by_role) || !isRecord(value.css_variables) || !isRecord(value.layout) || !isRecord(value.brand)) return false
  if (value.auth_style_url !== undefined && !(typeof value.auth_style_url === 'string' && authStylePathPattern.test(value.auth_style_url))) return false
  if (!Object.entries(value.css_variables).every(([name, text]) => cssVariablePattern.test(name) && typeof text === 'string' && cssValuePattern.test(text))) return false
  const layout = value.layout
  if (!loginLayouts.has(layout.login_layout as LoginLayout) || (layout.sidebar !== 'light' && layout.sidebar !== 'dark') ||
    (layout.look !== undefined && layout.look !== 'classic' && layout.look !== 'tech') ||
    (layout.motion !== undefined && layout.motion !== 'off' && layout.motion !== 'subtle' && layout.motion !== 'rich') ||
    !isI18n(layout.footer_text) || (layout.brand_name !== undefined && !isI18n(layout.brand_name)) ||
    !Array.isArray(layout.user_home_blocks) ||
    !layout.user_home_blocks.every((block) => homeBlocks.has(block as UserHomeBlock)) || !Array.isArray(layout.header_links) ||
    layout.header_links.length > 8 || !layout.header_links.every((link) => isRecord(link) && isI18n(link.label) &&
      typeof link.url === 'string' && link.url.startsWith('https://'))) return false
  return Object.entries(value.brand).every(([slot, asset]) => brandSlots.has(slot as ThemeBrandSlot) && isRecord(asset) &&
    typeof asset.url === 'string' && assetPathPattern.test(asset.url) && typeof asset.mime_type === 'string' &&
    typeof asset.sha256 === 'string' && sha256Pattern.test(asset.sha256))
}

function isBrandAssets(value: unknown): boolean {
  return value === undefined || isRecord(value) && Object.entries(value).every(([slot, revision]) =>
    brandSlots.has(slot as ThemeBrandSlot) && Number.isSafeInteger(revision) && (revision as number) > 0)
}

function isCurrent(value: unknown): value is ThemeCurrent {
  return isRecord(value) && value.schema === 'cdnca.theme.current/v1' && Number.isSafeInteger(value.revision) &&
    (value.scope === 'platform' || value.scope === 'tenant') && isBrandAssets(value.brand_assets) &&
    (value.revision as number) >= 0 && typeof value.theme_id === 'string' && typeof value.version === 'string' &&
    typeof value.package_sha256 === 'string' && sha256Pattern.test(value.package_sha256) &&
    typeof value.tokens_url === 'string' && tokenPathPattern.test(value.tokens_url) &&
    typeof value.stylesheet_url === 'string' && stylesheetPathPattern.test(value.stylesheet_url)
}

async function parse<T>(response: Response, validate: (value: unknown) => value is T): Promise<T> {
  if (!response.ok) throw await responseApiError(response)
  let body: unknown
  try { body = await response.json() } catch { throw new ApiError('Invalid API response', 0, 'invalid_response') }
  if (!validate(body)) throw new ApiError('Invalid API response', 0, 'invalid_response')
  return body
}

async function request(path: string, init: RequestInit = {}) {
  try {
    return await fetch(`${apiRoot}${path}`, { credentials: 'include', ...init })
  } catch { throw networkApiError() }
}

export const themeApi = {
  /** The caller's theme: the tenant's own for a tenant session, else by Host, else the platform's. */
  async current(accessToken?: string | null) {
    const headers: Record<string, string> = accessToken ? { Authorization: `Bearer ${accessToken}` } : {}
    return parse(await request('/v1/theme/current', { cache: 'no-store', headers }), isCurrent)
  },
  async document(current: ThemeCurrent) {
    if (!tokenPathPattern.test(current.tokens_url)) throw new ApiError('Invalid API response', 0, 'invalid_response')
    return parse(await request(current.tokens_url), isThemeDocument)
  },
}

/** Picks the text for locale, falling back to zh-CN. */
export function localizedText(text: I18nText | undefined, locale: string): string {
  if (!text) return ''
  return text[locale as keyof I18nText] ?? text['zh-CN'] ?? ''
}

export function themeStylesheetPath(current: ThemeCurrent): string | null {
  return stylesheetPathPattern.test(current.stylesheet_url) ? current.stylesheet_url : null
}
