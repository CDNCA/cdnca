// 中英双语：中文无前缀（默认），英文 /en 前缀。每页两份内容对象，按路径选。
export type Lang = 'zh' | 'en'
export type L<T = string> = Record<Lang, T>

export const LANGS: Lang[] = ['zh', 'en']

/** '/en/docs' -> { lang: 'en', path: '/docs' }；'/' -> { lang: 'zh', path: '/' } */
export function splitPath(pathname: string): { lang: Lang; path: string } {
  let p = pathname.replace(/\/index\.html$/, '').replace(/\/+$/, '') || '/'
  let lang: Lang = 'zh'
  if (p === '/en' || p.startsWith('/en/')) {
    lang = 'en'
    p = p.slice(3) || '/'
  }
  return { lang, path: p }
}

/** 语言无关路径 -> 该语言的站内 URL */
export function href(lang: Lang, path: string): string {
  if (lang === 'zh') return path
  return path === '/' ? '/en/' : `/en${path}`
}

export const htmlLang: L = { zh: 'zh-CN', en: 'en' }
