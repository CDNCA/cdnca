import { PageHero, Section } from '../components/Blocks'
import { ContactList } from '../components/Contact'
import { useSiteContent } from '../content/siteContent'
import { href, type Lang } from '../i18n'
import { LINKS } from '../site'

// 更新日志与联系我们的内容由运营在授权端「官网内容」编辑（content/siteContent.ts）。
export function ChangelogPage({ lang }: { lang: Lang }) {
  const { releases } = useSiteContent()
  return (
    <>
      <PageHero title={lang === 'zh' ? '更新日志' : 'Changelog'} lead={lang === 'zh' ? '每个版本的主要变化。升级请在主控后台“维护操作”中进行。' : 'What changed in each release. Upgrade from Maintenance in your control plane.'} />
      {releases.map((r) => (
        <Section key={r.version} id={`v${r.version.replace(/[^A-Za-z0-9]+/g, '-')}`} title={r.version} lead={r.date ? <time dateTime={r.date}>{r.date}</time> : undefined}>
          <ul>{r.notes[lang].map((n, i) => <li key={i}>{n}</li>)}</ul>
          <p><a href={href(lang, '/docs/operations')}>{lang === 'zh' ? '如何升级' : 'How to upgrade'} →</a></p>
        </Section>
      ))}
    </>
  )
}

export function AboutPage({ lang }: { lang: Lang }) {
  const { contact } = useSiteContent()
  return (
    <>
      <PageHero title={contact.title[lang]} lead={contact.subtitle[lang]} />
      <Section id="contact">
        <div className="contact-page">
          <ContactList lang={lang} />
        </div>
        <p className="muted">{lang === 'zh' ? 'cdnca 是自建 CDN 系统：我们不卖 CDN 节点，只做让你自己当 CDN 老板的系统。' : 'cdnca is a self-hosted CDN system. We don’t sell CDN nodes — we build the system that lets you run your own CDN business.'}</p>
        <div className="btn-row">
          <a className="btn btn-primary" href={LINKS.licenses}>{lang === 'zh' ? '授权中心' : 'Licence centre'}</a>
          <a className="btn btn-ghost" href={href(lang, '/docs/troubleshooting')}>{lang === 'zh' ? '问题处理' : 'Troubleshooting'}</a>
        </div>
      </Section>
    </>
  )
}
