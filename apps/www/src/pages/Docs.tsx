import { BookOpen } from 'lucide-react'
import { CodeBlock, PageHero } from '../components/Blocks'
import { DOC_GROUPS, DOCS_HOME, docGroupOf } from '../content/docsIndex'
import type { Block, DocBlock, Rich } from '../content/docs'
import { parseMarkdown, parseInline } from '../content/markdown'
import { useSiteContent, type DocContent } from '../content/siteContent'
import { href, type Lang } from '../i18n'

const T = {
  title: { zh: '使用文档', en: 'Documentation' },
  lead: { zh: '按你的角色或要做的事找到操作步骤：安装主控与节点、接入网站、授权与门户、节点市场和插件。', en: 'Find the steps by your role or by the task: installing the control plane and nodes, onboarding sites, licences and the portal, the node market and plugins.' },
  nav: { zh: '文档目录', en: 'Docs' },
  home: { zh: '文档首页', en: 'Docs home' },
  other: { zh: '其他', en: 'More' },
  jump: { zh: '查看文档目录', en: 'Browse all docs' },
}

/** 窄屏时侧栏排在正文之后，正文顶部给一个跳到目录的链接。 */
const Jump = ({ lang }: { lang: Lang }) => <a className="docs-jump" href="#docs-nav">{T.jump[lang]}</a>

/** 站内链接：/docs/... 按当前语言加前缀；#锚点 原样。href 已由 markdown.ts 限定为这两类。 */
function linkHref(lang: Lang, target: string): string {
  return target.startsWith('#') ? target : href(lang, target)
}

/** 行内内容：文字走 React 文本节点；链接是受控 <a>，目标只可能是站内文档或本页锚点。 */
function renderRich(rich: Rich, lang: Lang) {
  if (typeof rich === 'string') return rich
  return rich.map((x, i) => (typeof x === 'string' ? x : <a key={i} href={linkHref(lang, x.href)}>{x.text}</a>))
}

/** 表格首列文字（作 key 与行标题）；纯文字或去掉链接语法后的文字。 */
const keyOf = (r: Rich) => (typeof r === 'string' ? r : r.map((x) => (typeof x === 'string' ? x : x.text)).join(''))

/** 渲染一个块。手写内容（Block）只有纯文字；文档正文（DocBlock）可含站内链接、标题带层级与锚点。 */
export function renderBlock(b: Block | DocBlock, lang: Lang, i: number) {
  if ('p' in b) return <p key={i}>{renderRich(b.p[lang], lang)}</p>
  if ('h' in b) return 'level' in b && b.level === 3 ? <h3 key={i} id={b.id}>{b.h[lang]}</h3> : <h2 key={i} id={'id' in b ? b.id : undefined}>{b.h[lang]}</h2>
  if ('note' in b) return <p key={i} className="callout" role="note">{renderRich(b.note[lang], lang)}</p>
  if ('cmd' in b) return <CodeBlock key={i} code={b.cmd} lang={lang} label={b.label?.[lang]} />
  if ('list' in b) {
    const items = b.list.map((x, j) => <li key={j}>{renderRich(x[lang], lang)}</li>)
    return b.ordered ? <ol key={i}>{items}</ol> : <ul key={i}>{items}</ul>
  }
  return (
    <div className="table-wrap" key={i}>
      <table className="table">
        <thead><tr>{b.table.head.map((h, j) => <th scope="col" key={j}>{h[lang]}</th>)}</tr></thead>
        <tbody>{b.table.rows.map((r, j) => <tr key={`${j}-${keyOf(r[0][lang])}`}>{r.map((c, k) => (k === 0 ? <th scope="row" key={k}>{renderRich(c[lang], lang)}</th> : <td key={k}>{renderRich(c[lang], lang)}</td>))}</tr>)}</tbody>
      </table>
    </div>
  )
}

/** 侧栏：按分组列出文档；运营新增、未登记分组的文档放在“其他”。 */
function DocsNav({ lang, current }: { lang: Lang; current: string }) {
  const { docs } = useSiteContent()
  const groups = DOC_GROUPS.map((g) => ({ id: g.id, title: g.title[lang], docs: docs.filter((d) => docGroupOf(d.slug) === g.id) }))
  const rest = docs.filter((d) => !docGroupOf(d.slug))
  if (rest.length) groups.push({ id: 'other', title: T.other[lang], docs: rest })
  return (
    <nav className="docs-nav" id="docs-nav" aria-label={T.nav[lang]}>
      <div className="docs-nav-inner">
        <a className="docs-nav-home" href={href(lang, '/docs')} aria-current={current === '' ? 'page' : undefined}>{T.home[lang]}</a>
        {groups.filter((g) => g.docs.length).map((g) => (
          <div className="docs-nav-group" key={g.id}>
            <p className="docs-nav-title" id={`docs-nav-${g.id}`}>{g.title}</p>
            <ul aria-labelledby={`docs-nav-${g.id}`}>
              {g.docs.map((d) => (
                <li key={d.slug}><a href={href(lang, `/docs/${d.slug}`)} aria-current={current === d.slug ? 'page' : undefined}>{d.title[lang]}</a></li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </nav>
  )
}

export function DocsIndexPage({ lang }: { lang: Lang }) {
  const { docs } = useSiteContent()
  const known = new Set(docs.map((d) => d.slug))
  // 入口表只列当前存在的文档（运营删掉某篇时对应行自动消失）。
  const rows = (list: typeof DOCS_HOME.roles) => list.filter((r) => known.has(r.target.split('#')[0].replace('/docs/', '')))
  return (
    <>
      <PageHero title={T.title[lang]} lead={T.lead[lang]} />
      <section className="section">
        <div className="container docs-layout">
          <DocsNav lang={lang} current="" />
          <div className="prose docs-home">
            <Jump lang={lang} />
            <h2 id="by-role">{DOCS_HOME.rolesTitle[lang]}</h2>
            <div className="table-wrap">
              <table className="table">
                <thead><tr>{DOCS_HOME.rolesHead.map((h) => <th scope="col" key={h.en}>{h[lang]}</th>)}</tr></thead>
                <tbody>
                  {rows(DOCS_HOME.roles).map((r) => (
                    <tr key={r.target}><th scope="row">{r.who[lang]}</th><td>{r.what[lang]}</td><td><a href={href(lang, r.target)}>{r.link[lang]}</a></td></tr>
                  ))}
                </tbody>
              </table>
            </div>
            <h2 id="by-task">{DOCS_HOME.tasksTitle[lang]}</h2>
            <div className="table-wrap">
              <table className="table">
                <thead><tr>{DOCS_HOME.tasksHead.map((h) => <th scope="col" key={h.en}>{h[lang]}</th>)}</tr></thead>
                <tbody>
                  {rows(DOCS_HOME.tasks).map((r) => (
                    <tr key={r.target}><th scope="row">{r.who[lang]}</th><td>{r.what[lang]}</td><td><a href={href(lang, r.target)}>{r.link[lang]}</a></td></tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="muted">{renderRich(parseInline(DOCS_HOME.footer[lang]), lang)}</p>
            <h2 id="all-docs">{DOCS_HOME.allTitle[lang]}</h2>
            <div className="grid grid-2">
              {docs.map((d) => (
                <a className="card api-group" key={d.slug} href={href(lang, `/docs/${d.slug}`)}>
                  <span className="card-icon"><BookOpen aria-hidden="true" size={22} /></span>
                  <strong>{d.title[lang]}</strong>
                  <span className="muted">{d.description[lang]}</span>
                </a>
              ))}
            </div>
          </div>
        </div>
      </section>
    </>
  )
}

/** 正文是受限 Markdown：解析成 Block 后按文本节点渲染（React 转义），只有站内链接是 <a>，不会出现 HTML。 */
export function DocPageView({ lang, doc }: { lang: Lang; doc: DocContent }) {
  const blocks = parseMarkdown(doc.body[lang])
  const toc = blocks.flatMap((b) => ('h' in b && b.level === 2 ? [{ id: b.id, text: b.h[lang] }] : []))
  return (
    <section className="section">
      <div className="container docs-layout">
        <DocsNav lang={lang} current={doc.slug} />
        <article className="prose">
          <Jump lang={lang} />
          <h1>{doc.title[lang]}</h1>
          <p className="lead">{doc.description[lang]}</p>
          {toc.length >= 4 ? (
            <nav className="docs-toc" aria-label={lang === 'zh' ? '本页目录' : 'On this page'}>
              <ul>{toc.map((x) => <li key={x.id}><a href={`#${x.id}`}>{x.text}</a></li>)}</ul>
            </nav>
          ) : null}
          {blocks.map((b, i) => renderBlock(b, lang, i))}
        </article>
      </div>
    </section>
  )
}
