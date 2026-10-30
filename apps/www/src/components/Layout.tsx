import { useState, type ReactNode } from 'react'
import { Menu, X } from 'lucide-react'
import { href, type Lang } from '../i18n'
import { NAV } from '../routes'
import { LINKS } from '../site'
import { ContactEntry } from './Contact'
import { Logo } from './Logo'

const T = {
  skip: { zh: '跳到正文', en: 'Skip to content' },
  login: { zh: '登录', en: 'Sign in' },
  register: { zh: '注册', en: 'Sign up' },
  menu: { zh: '菜单', en: 'Menu' },
  nav: { zh: '主导航', en: 'Main' },
  switchTo: { zh: 'English', en: '中文' },
  switchLabel: { zh: 'Switch to English', en: '切换到中文' },
  home: { zh: 'cdnca 首页', en: 'cdnca home' },
  footNav: { zh: '页脚导航', en: 'Footer' },
  product: { zh: '产品', en: 'Product' },
  dev: { zh: '开发者', en: 'Developers' },
  docs: { zh: '文档', en: 'Docs' },
  account: { zh: '账号', en: 'Account' },
  licenses: { zh: '授权中心', en: 'Licence centre' },
  devLogin: { zh: '开发者平台登录', en: 'Developer sign-in' },
  slogan: { zh: '自建 CDN 系统：一个主控，管理自有节点、订阅节点与云 CDN。', en: 'Self-hosted CDN: one control plane for your nodes, subscribed nodes and cloud CDNs.' },
}

export function Layout({ lang, path, children }: { lang: Lang; path: string; children: ReactNode }) {
  const [open, setOpen] = useState(false)
  const other: Lang = lang === 'zh' ? 'en' : 'zh'
  const current = (p: string) => path === p || path.startsWith(`${p}/`)
  const year = 2026
  return (
    <>
      <a className="skip-link" href="#main">{T.skip[lang]}</a>
      <header className="site-header">
        <div className="container header-row">
          <a className="brand" href={href(lang, '/')} aria-label={T.home[lang]}>
            <Logo /> <span>cdnca</span>
          </a>
          <button
            type="button"
            className="menu-toggle"
            aria-expanded={open}
            aria-controls="site-nav"
            onClick={() => setOpen((v) => !v)}
          >
            {open ? <X aria-hidden="true" size={20} /> : <Menu aria-hidden="true" size={20} />}
            <span className="sr-only">{T.menu[lang]}</span>
          </button>
          <nav id="site-nav" className={open ? 'site-nav open' : 'site-nav'} aria-label={T.nav[lang]}>
            <ul>
              {NAV.map((n) => (
                <li key={n.path}>
                  <a href={href(lang, n.path)} aria-current={current(n.path) ? 'page' : undefined}>{n.label[lang]}</a>
                </li>
              ))}
            </ul>
            <div className="nav-actions">
              <a className="lang-switch" href={href(other, path)} hrefLang={other === 'zh' ? 'zh-CN' : 'en'} lang={other === 'zh' ? 'zh-CN' : 'en'} aria-label={T.switchLabel[lang]}>
                {T.switchTo[lang]}
              </a>
              <a className="btn btn-ghost" href={LINKS.login}>{T.login[lang]}</a>
              <a className="btn btn-primary" href={LINKS.register}>{T.register[lang]}</a>
            </div>
          </nav>
        </div>
      </header>
      <main id="main" tabIndex={-1}>{children}</main>
      <footer className="site-footer">
        <div className="container footer-grid">
          <div>
            <p className="brand"><Logo /> <span>cdnca</span></p>
            <p className="muted">{T.slogan[lang]}</p>
          </div>
          <nav aria-label={T.footNav[lang]} className="footer-cols">
            <FooterCol title={T.product[lang]} links={[
              [href(lang, '/features'), NAV[0].label[lang]],
              [href(lang, '/market'), NAV[1].label[lang]],
              [href(lang, '/changelog'), NAV[4].label[lang]],
            ]} />
            <FooterCol title={T.dev[lang]} links={[
              [href(lang, '/developers'), NAV[2].label[lang]],
              [href(lang, '/developers/api'), lang === 'zh' ? '开放接口' : 'API reference'],
              [LINKS.developerLogin, T.devLogin[lang]],
            ]} />
            <FooterCol title={T.docs[lang]} links={[
              [href(lang, '/docs/install-control'), lang === 'zh' ? '主控安装' : 'Install control plane'],
              [href(lang, '/docs/install-node'), lang === 'zh' ? '节点安装' : 'Install a node'],
              [href(lang, '/docs/troubleshooting'), lang === 'zh' ? '问题处理' : 'Troubleshooting'],
            ]} />
            <FooterCol title={T.account[lang]} links={[
              [LINKS.login, T.login[lang]],
              [LINKS.register, T.register[lang]],
              [LINKS.licenses, T.licenses[lang]],
            ]} />
          </nav>
        </div>
        <div className="container footer-bottom muted">
          <span>© {year} cdnca</span>
          <ContactEntry lang={lang} label={NAV[5].label[lang]} />
        </div>
      </footer>
    </>
  )
}

function FooterCol({ title, links }: { title: string; links: [string, string][] }) {
  return (
    <div>
      <h2 className="footer-title">{title}</h2>
      <ul>
        {links.map(([to, label]) => (
          <li key={to}><a href={to}>{label}</a></li>
        ))}
      </ul>
    </div>
  )
}
