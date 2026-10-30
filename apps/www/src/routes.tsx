// 路由表单一来源：预渲染（scripts/prerender.mjs）、sitemap.xml、导航与测试都读这里。
// 路径语言无关；每条路由在 / 与 /en 下各出一页。
import type { ReactElement } from 'react'
import type { L, Lang } from './i18n'
import { dynamicPage, dynamicPaths, pages } from './pages'

export interface PageDef {
  path: string
  title: L
  description: L
  render: (lang: Lang) => ReactElement
}

const byPath = new Map<string, PageDef>(pages.map((p) => [p.path, p]))

/** 静态页 + 接口分组页（分组页依赖已加载的接口目录）。 */
export function allPages(): PageDef[] {
  return [...pages, ...dynamicPaths().map((p) => dynamicPage(p)!)]
}

export function findPage(path: string): PageDef | undefined {
  return byPath.get(path) ?? dynamicPage(path)
}

/** 顶部导航（语言无关路径）。登录/注册是外链，单独放在 Layout。 */
export const NAV: { path: string; label: L }[] = [
  { path: '/features', label: { zh: '功能与优势', en: 'Features' } },
  { path: '/market', label: { zh: '市场', en: 'Market' } },
  { path: '/developers', label: { zh: '开发者平台', en: 'Developers' } },
  { path: '/docs', label: { zh: '使用文档', en: 'Docs' } },
  { path: '/changelog', label: { zh: '更新日志', en: 'Changelog' } },
  { path: '/about', label: { zh: '联系我们', en: 'Contact' } },
]
