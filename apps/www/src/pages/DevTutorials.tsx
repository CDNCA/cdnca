import { PageHero, Section } from '../components/Blocks'
import { GUIDES, GUIDES_PATH, REVIEW_RULES_PATH, UI_SDK_PATH } from '../content/devGuides'
import { TUTORIALS, TUTORIALS_PATH, type Tutorial } from '../content/devTutorials'
import { PLUGIN_SIGNING_PATH } from '../content/pluginSigning'
import { href, type Lang } from '../i18n'
import { LINKS } from '../site'
import { renderBlock } from './Docs'

const T = {
  eyebrow: { zh: '开发者平台', en: 'Developer platform' },
  title: { zh: '开发教程：从入驻到卸载', en: 'Developer tutorials: from onboarding to uninstall' },
  lead: { zh: '按你要做的事一步步走：入驻、签名、制作、联调、审核、发布、安装授权、调用接口、升级卸载。每类插件的字段与规则见按类型开发指南。', en: 'Step by step through what you need to do: onboarding, signing, building, integrating, review, publishing, installation, calling the API, upgrading and uninstalling. Each kind’s fields and rules are in the guides by kind.' },
  enter: { zh: '进入开发者平台', en: 'Open the developer platform' },
  steps: { zh: '教程目录', en: 'Tutorials' },
  toc: { zh: '本页目录', en: 'On this page' },
  all: { zh: '全部教程', en: 'All tutorials' },
  prev: { zh: '上一篇', en: 'Previous' },
  next: { zh: '下一篇', en: 'Next' },
  byKind: { zh: '按类型开发指南', en: 'Guides by plugin kind' },
  related: { zh: '相关参考', en: 'Related reference' },
  signing: { zh: '插件签名工具', en: 'Plugin signing tool' },
  rules: { zh: '审核规则清单', en: 'Review rules' },
  sdk: { zh: 'ui_page 开发者 SDK', en: 'ui_page developer SDK' },
  api: { zh: '开放接口目录', en: 'API reference' },
  earn: { zh: '收入与结算方式', en: 'Income and settlement' },
}

/** 每篇额外挂的参考页（类型指南之外）。 */
const EXTRA: Record<string, { path: string; label: keyof typeof T }[]> = {
  signing: [{ path: PLUGIN_SIGNING_PATH, label: 'signing' }],
  integrate: [{ path: UI_SDK_PATH, label: 'sdk' }],
  review: [{ path: REVIEW_RULES_PATH, label: 'rules' }],
  publish: [{ path: '/developers/earn', label: 'earn' }],
  api: [{ path: '/developers/api', label: 'api' }],
}

/** 教程目录（索引页与每篇侧栏共用）。 */
function TutorialNav({ lang, current }: { lang: Lang; current?: string }) {
  return (
    <nav className="docs-nav" aria-label={T.steps[lang]}>
      <ol className="tutorial-steps">
        {TUTORIALS.map((t) => (
          <li key={t.slug}>
            <a href={href(lang, `${TUTORIALS_PATH}/${t.slug}`)} aria-current={t.slug === current ? 'page' : undefined}>{t.nav[lang]}</a>
          </li>
        ))}
      </ol>
    </nav>
  )
}

export function TutorialsIndexPage({ lang }: { lang: Lang }) {
  return (
    <>
      <PageHero eyebrow={T.eyebrow[lang]} title={T.title[lang]} lead={T.lead[lang]}>
        <div className="btn-row">
          <a className="btn btn-primary" href={href(lang, `${TUTORIALS_PATH}/${TUTORIALS[0].slug}`)}>{TUTORIALS[0].nav[lang]} →</a>
          <a className="btn btn-ghost" href={href(lang, GUIDES_PATH)}>{T.byKind[lang]}</a>
          <a className="btn btn-ghost" href={LINKS.developerLogin}>{T.enter[lang]}</a>
        </div>
      </PageHero>
      <Section id="tutorials">
        <ol className="grid grid-3 api-groups tutorial-cards">
          {TUTORIALS.map((t, i) => (
            <li key={t.slug}>
              <a className="card api-group" href={href(lang, `${TUTORIALS_PATH}/${t.slug}`)}>
                <span className="muted">{i + 1}</span>
                <strong>{t.nav[lang]}</strong>
                <span className="muted">{t.lead[lang]}</span>
              </a>
            </li>
          ))}
        </ol>
      </Section>
    </>
  )
}

export function TutorialPage({ lang, tutorial }: { lang: Lang; tutorial: Tutorial }) {
  const i = TUTORIALS.indexOf(tutorial)
  const prev = TUTORIALS[i - 1]
  const next = TUTORIALS[i + 1]
  const guides = tutorial.guides.map((slug) => GUIDES.find((g) => g.slug === slug)!)
  const extra = EXTRA[tutorial.slug] ?? []
  return (
    <>
      <PageHero eyebrow={`${T.eyebrow[lang]} · ${i + 1} / ${TUTORIALS.length}`} title={tutorial.title[lang]} lead={tutorial.lead[lang]}>
        <p><a href={href(lang, TUTORIALS_PATH)}>← {T.all[lang]}</a></p>
      </PageHero>
      <section className="section">
        <div className="container docs-layout tutorial-layout">
          <TutorialNav lang={lang} current={tutorial.slug} />
          <div>
            <nav aria-label={T.toc[lang]}>
              <ol className="guide-toc">
                {tutorial.sections.map((sec) => <li key={sec.id}><a href={`#${sec.id}`}>{sec.title[lang]}</a></li>)}
              </ol>
            </nav>
            {tutorial.sections.map((sec) => (
              <article className="prose tutorial-section" key={sec.id} id={sec.id} aria-labelledby={`${sec.id}-title`}>
                <h2 id={`${sec.id}-title`}>{sec.title[lang]}</h2>
                {sec.blocks.map((b, j) => renderBlock(b, lang, j))}
              </article>
            ))}
            {guides.length || extra.length ? (
              <aside className="card tutorial-related" aria-labelledby="related-title">
                <h2 id="related-title" className="h3">{T.related[lang]}</h2>
                <ul>
                  {guides.map((g) => <li key={g.slug}><a href={href(lang, `${GUIDES_PATH}/${g.slug}`)}>{g.title[lang]}</a></li>)}
                  {extra.map((x) => <li key={x.path}><a href={href(lang, x.path)}>{T[x.label][lang]}</a></li>)}
                </ul>
              </aside>
            ) : null}
            <nav className="tutorial-pager" aria-label={`${T.prev[lang]} / ${T.next[lang]}`}>
              {prev ? <a href={href(lang, `${TUTORIALS_PATH}/${prev.slug}`)}>← {T.prev[lang]}：{prev.nav[lang]}</a> : <span />}
              {next ? <a href={href(lang, `${TUTORIALS_PATH}/${next.slug}`)}>{T.next[lang]}：{next.nav[lang]} →</a> : null}
            </nav>
          </div>
        </div>
      </section>
    </>
  )
}
