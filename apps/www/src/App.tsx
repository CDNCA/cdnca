import { Layout } from './components/Layout'
import { useSiteContent } from './content/siteContent'
import { splitPath } from './i18n'
import { findPage } from './routes'
import { NotFoundPage } from './pages/NotFound'

/** 整站只有一层：按 pathname 选页。站内跳转都是普通 <a>（静态站整页导航）。 */
export function App({ pathname }: { pathname: string }) {
  // 订阅官网内容：接口内容到达后重新选页（运营新增的文档页没有预渲染文件，经 404.html 水合后在这里出现）。
  useSiteContent()
  const { lang, path } = splitPath(pathname)
  const page = findPage(path)
  if (!page) {
    // 404.html 只预渲染一份（中文布局 + 双语正文），客户端水合时保持一致。
    return <Layout lang="zh" path="/"><NotFoundPage /></Layout>
  }
  return <Layout lang={lang} path={path}>{page.render(lang)}</Layout>
}
