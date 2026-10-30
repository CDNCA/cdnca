import { StrictMode } from 'react'
import { hydrateRoot } from 'react-dom/client'
import '@cdnca/ui/styles.css'
import './styles.css'
import { App } from './App'
import { loadCatalog, loadGroupDetail } from './content/apiCatalog'
import { getSiteContent, loadSiteContent } from './content/siteContent'
import { splitPath } from './i18n'
import { findPage } from './routes'

// 预渲染的 HTML 已含完整正文；水合后才有交互（菜单、FAQ、复制、市场数据）。
// 接口目录约 300 KB，只有 /developers/api* 页先按需加载再水合，其他页不带；
// 分组页另外加载该分组的接口详情（generated/api-operations/<分组>.json）。
async function start() {
  const { path } = splitPath(window.location.pathname)
  if (path === '/developers/api' || path.startsWith('/developers/api/')) {
    try {
      await loadCatalog()
      const group = /^\/developers\/api\/([a-z0-9-]+)$/.exec(path)
      if (group && !(await loadGroupDetail(group[1]))) return
    } catch {
      // 加载失败：保留预渲染的静态内容，不水合（页面仍可阅读）。
      return
    }
  }
  hydrateRoot(
    document.getElementById('root')!,
    <StrictMode>
      <App pathname={window.location.pathname} />
    </StrictMode>,
  )
  // 水合后取运营发布的官网内容替换种子；失败保留预渲染内容（content/siteContent.ts）。
  if (await loadSiteContent()) applyHead(path)
}

/** 内容替换后同步 favicon 与标题（新增文档页的预渲染标题是 404）。 */
function applyHead(path: string) {
  const { brand } = getSiteContent()
  if (brand.favicon) document.querySelector<HTMLLinkElement>('link[rel="icon"]')?.setAttribute('href', brand.favicon)
  const page = findPage(path)
  if (page && path !== '/') document.title = `${page.title[document.documentElement.lang === 'en' ? 'en' : 'zh']} · ${brand.site_name}`
}
void start()
