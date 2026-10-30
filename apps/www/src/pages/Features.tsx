import { CheckCircle2 } from 'lucide-react'
import { Figure, PageHero, Section } from '../components/Blocks'
import { FeatureFigure, FeatureIcon } from '../components/FeatureFigure'
import { FREE_CLAIM, NEUTRAL_CTA } from '../content/claims'
import { CAPABILITY_GROUPS, FEATURES, type Feature } from '../content/features'
import { href, type Lang } from '../i18n'
import { LINKS } from '../site'

const T = {
  title: { zh: '功能与优势', en: 'Features' },
  lead: { zh: '一个主控，统一调度自有节点、订阅节点与云 CDN；防护、计费、插件都在里面。', en: 'One control plane schedules your nodes, subscribed nodes and cloud CDNs — with protection, billing and plugins built in.' },
  core: { zh: '六项核心能力', en: 'Six core capabilities' },
  all: { zh: '全部能力', en: 'Everything included' },
  arch: { zh: '整体架构', en: 'Architecture' },
  more: { zh: '了解更多', en: 'Learn more' },
  how: { zh: '怎么用', en: 'How to use it' },
  limits: { zh: '状态与限制', en: 'Status and limits' },
  back: { zh: '返回功能总览', en: 'All features' },
}

export function FeaturesPage({ lang }: { lang: Lang }) {
  return (
    <>
      <PageHero eyebrow={FREE_CLAIM?.[lang].badge} title={T.title[lang]} lead={T.lead[lang]}>
        <div className="btn-row">
          <a className="btn btn-primary" href={LINKS.register}>{FREE_CLAIM ? FREE_CLAIM[lang].cta : NEUTRAL_CTA[lang]}</a>
          <a className="btn btn-ghost" href={href(lang, '/docs')}>{lang === 'zh' ? '使用文档' : 'Docs'}</a>
        </div>
      </PageHero>
      <Section id="arch" title={T.arch[lang]}>
        <div className="narrow center"><Figure><FeatureFigure k="A" lang={lang} /></Figure></div>
      </Section>
      <Section id="core" title={T.core[lang]} alt>
        <div className="grid grid-3">
          {FEATURES.map((f) => (
            <article className="card" key={f.slug}>
              <FeatureIcon name={f.icon} />
              <h3>{f.name[lang]}</h3>
              <p><strong>{f.tagline[lang]}</strong></p>
              <p>{f.card[lang]}</p>
              <a className="card-more" href={href(lang, `/features/${f.slug}`)} aria-label={`${T.more[lang]}：${f.name[lang]}`}>{T.more[lang]} →</a>
            </article>
          ))}
        </div>
      </Section>
      <Section id="all" title={T.all[lang]}>
        <div className="grid grid-3">
          {CAPABILITY_GROUPS.map((g) => (
            <div className="card" key={g.title.en}>
              <h3>{g.title[lang]}</h3>
              <ul className="check-list">
                {g.items.map((it) => <li key={it.en}><CheckCircle2 aria-hidden="true" size={16} color="#0b6b3a" /> {it[lang]}</li>)}
              </ul>
            </div>
          ))}
        </div>
      </Section>
    </>
  )
}

export function FeatureDetailPage({ f, lang }: { f: Feature; lang: Lang }) {
  return (
    <>
      <PageHero eyebrow={f.name[lang]} title={f.tagline[lang]} lead={f.lead[lang]}>
        <div className="btn-row">
          <a className="btn btn-primary" href={LINKS.register}>{FREE_CLAIM ? FREE_CLAIM[lang].cta : NEUTRAL_CTA[lang]}</a>
          <a className="btn btn-ghost" href={href(lang, f.docs.path)}>{f.docs.label[lang]}</a>
        </div>
      </PageHero>
      <Section id="figure">
        <div className="narrow center"><Figure><FeatureFigure k={f.figure} lang={lang} /></Figure></div>
      </Section>
      <Section id="points" alt>
        <div className="grid grid-2">
          {f.points.map((p) => (
            <article className="card" key={p.title.en}>
              <h2 className="h3">{p.title[lang]}</h2>
              <p>{p.body[lang]}</p>
            </article>
          ))}
        </div>
      </Section>
      <Section id="limits" title={T.limits[lang]}>
        <p>{f.limits[lang]}</p>
        <p><a href={href(lang, f.docs.path)}>{T.how[lang]}：{f.docs.label[lang]} →</a></p>
        <p><a href={href(lang, '/features')}>← {T.back[lang]}</a></p>
      </Section>
    </>
  )
}
