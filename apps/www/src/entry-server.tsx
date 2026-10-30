import { renderToString } from 'react-dom/server'
import { App } from './App'
import { href, htmlLang, LANGS, splitPath, type Lang } from './i18n'
import { allPages, findPage } from './routes'
import { SITE_ORIGIN } from './site'
import { setCatalog, setGroupDetails, type ApiCatalog, type ApiGroupDetail } from './content/apiCatalog'
import catalog from './generated/api-catalog.json'

// 预渲染时同步提供接口目录与全部分组详情（只进 SSR 包）。
setCatalog(catalog as ApiCatalog)
setGroupDetails(Object.values(import.meta.glob<ApiGroupDetail>('./generated/api-operations/*.json', { eager: true, import: 'default' })))

export interface Rendered {
  lang: string
  html: string
  head: string
}

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

/** 预渲染一个 URL：正文 HTML + <head> 元信息（title、description、canonical、hreflang、OG）。 */
export function render(url: string): Rendered {
  const { lang, path } = splitPath(url)
  const page = findPage(path)
  const html = renderToString(<App pathname={url} />)
  if (!page) {
    return {
      lang: 'zh-CN',
      html,
      head: '<title>页面不存在 · cdnca</title>\n<meta name="robots" content="noindex" />',
    }
  }
  const title = path === '/' ? page.title[lang] : `${page.title[lang]} · cdnca`
  const desc = page.description[lang]
  const alt = LANGS.map(
    (l) => `<link rel="alternate" hreflang="${htmlLang[l]}" href="${SITE_ORIGIN}${href(l, path)}" />`,
  )
  alt.push(`<link rel="alternate" hreflang="x-default" href="${SITE_ORIGIN}${href('zh', path)}" />`)
  const head = [
    `<title>${esc(title)}</title>`,
    `<meta name="description" content="${esc(desc)}" />`,
    `<link rel="canonical" href="${SITE_ORIGIN}${href(lang, path)}" />`,
    ...alt,
    `<meta property="og:type" content="website" />`,
    `<meta property="og:title" content="${esc(title)}" />`,
    `<meta property="og:description" content="${esc(desc)}" />`,
    `<meta property="og:url" content="${SITE_ORIGIN}${href(lang, path)}" />`,
  ].join('\n')
  return { lang: htmlLang[lang], html, head }
}

/** 需要预渲染的全部 URL（每页中英各一份）。 */
export function urls(): string[] {
  const out: string[] = []
  for (const p of allPages()) for (const l of LANGS) out.push(href(l as Lang, p.path))
  return out
}

export { SITE_ORIGIN }
