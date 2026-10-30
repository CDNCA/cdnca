// 官网可编辑内容（更新日志、使用文档、联系我们、品牌）的唯一来源。
// 运营在授权端运营后台「官网内容」编辑并发布（license-service 迁移 110，GET /public/v1/site-content）；
// 门户机 nginx 把同源 /public/v1/site-content 反代到授权端（scripts/install-site.sh），CSP 不放宽。
// 预渲染与接口不可用时用种子 site-content-seed.json（与迁移 110 的种子逐字一致，授权端集成测试核对）。
// 浏览器水合后取一次接口内容替换；失败（网络、非 2xx、格式不对）静默保留当前内容。
import { useSyncExternalStore } from 'react'
import type { L } from '../i18n'
import seedJson from './site-content-seed.json'

export const SITE_CONTENT_PATH = '/public/v1/site-content'

export type ContactKind = 'telegram' | 'email' | 'group' | 'other'

export interface Release { version: string; date: string; notes: { zh: string[]; en: string[] } }
/** body 是受限 Markdown（content/markdown.ts） */
export interface DocContent { slug: string; title: L; description: L; body: L }
export interface ContactItem { kind: ContactKind; label: L; value: string; href: string }
export interface Contact { title: L; subtitle: L; items: ContactItem[] }
/** logo/favicon 是同源资源路径（/public/v1/site-content/assets/<sha256>），没有时用默认 */
export interface Brand { site_name: string; logo: string | null; favicon: string | null }
export interface SiteContent { releases: Release[]; docs: DocContent[]; contact: Contact; brand: Brand }

const str = (v: unknown, max: number): v is string => typeof v === 'string' && v.length > 0 && v.length <= max
const lang = (v: unknown, max: number): v is L => !!v && typeof v === 'object' && str((v as L).zh, max) && str((v as L).en, max)
const list = (v: unknown, max: number): v is string[] => Array.isArray(v) && v.length > 0 && v.every((x) => str(x, max))
const ASSET = /^\/public\/v1\/site-content\/assets\/[0-9a-f]{64}$/
const KINDS: ContactKind[] = ['telegram', 'email', 'group', 'other']

/** 只放行 https 与 mailto 链接（授权端同样校验，这里是纵深防御）。 */
export function safeHref(href: string): string | undefined {
  return /^https:\/\/[^\s/]+/i.test(href) || /^mailto:[^\s]+@[^\s]+$/i.test(href) ? href : undefined
}

function releases(v: unknown): Release[] | null {
  if (!Array.isArray(v)) return null
  const ok = v.every((r) => r && str(r.version, 32) && typeof r.date === 'string' && r.notes && list(r.notes.zh, 2000) && list(r.notes.en, 2000))
  return ok ? v.map((r) => ({ version: r.version, date: r.date, notes: { zh: r.notes.zh, en: r.notes.en } })) : null
}

function docs(v: unknown): DocContent[] | null {
  if (!Array.isArray(v)) return null
  const ok = v.every((d) => d && /^[a-z0-9][a-z0-9-]{0,63}$/.test(d.slug) && lang(d.title, 200) && lang(d.description, 500) && lang(d.body, 100000))
  return ok ? v.map((d) => ({ slug: d.slug, title: d.title, description: d.description, body: d.body })) : null
}

function contact(v: unknown): Contact | null {
  const c = v as Contact | null
  if (!c || !lang(c.title, 200) || !lang(c.subtitle, 500) || !Array.isArray(c.items)) return null
  const items = c.items.filter((i) => i && KINDS.includes(i.kind) && lang(i.label, 100) && str(i.value, 500) && typeof i.href === 'string')
  return items.length === c.items.length ? { title: c.title, subtitle: c.subtitle, items: items.map((i) => ({ kind: i.kind, label: i.label, value: i.value, href: i.href })) } : null
}

function brand(v: unknown): Brand | null {
  const b = v as Brand | null
  const asset = (x: unknown) => x === null || (typeof x === 'string' && ASSET.test(x))
  if (!b || !str(b.site_name, 100) || !asset(b.logo) || !asset(b.favicon)) return null
  return { site_name: b.site_name, logo: b.logo, favicon: b.favicon }
}

/**
 * 接口内容 → SiteContent。整体格式不对返回 null；某一部分缺失（如联系我们未发布为 null）
 * 时该部分沿用 fallback。
 */
export function normalize(raw: unknown, fallback: SiteContent): SiteContent | null {
  if (!raw || typeof raw !== 'object' || (raw as { schema?: unknown }).schema !== 'cdnca.site-content/v1') return null
  const r = raw as Record<string, unknown>
  const rel = releases(r.releases)
  const doc = docs(r.docs)
  if (!rel || !doc) return null
  return { releases: rel, docs: doc, contact: contact(r.contact) ?? fallback.contact, brand: brand(r.brand) ?? fallback.brand }
}

export const SEED: SiteContent = normalize(seedJson, null as unknown as SiteContent)!

let current = SEED
const listeners = new Set<() => void>()

export function getSiteContent(): SiteContent { return current }

export function setSiteContent(next: SiteContent) {
  current = next
  for (const l of listeners) l()
}

function subscribe(l: () => void) {
  listeners.add(l)
  return () => { listeners.delete(l) }
}

/** 组件读取当前内容；服务端与水合首帧固定用种子，保证与预渲染一致。 */
export function useSiteContent(): SiteContent {
  return useSyncExternalStore(subscribe, getSiteContent, () => SEED)
}

/** 读取已发布内容并替换；任何失败返回 false 并保留当前内容。 */
export async function loadSiteContent(timeoutMs = 5000): Promise<boolean> {
  const ctrl = new AbortController()
  const timer = setTimeout(() => ctrl.abort(), timeoutMs)
  try {
    const res = await fetch(SITE_CONTENT_PATH, { credentials: 'omit', signal: ctrl.signal, headers: { Accept: 'application/json' } })
    if (!res.ok) return false
    const next = normalize(await res.json(), current)
    if (!next) return false
    setSiteContent(next)
    return true
  } catch {
    return false
  } finally {
    clearTimeout(timer)
  }
}
