import type { ReactNode } from 'react'
import { Check } from 'lucide-react'
import { CodeBlock, Faq, Figure, Section } from '../components/Blocks'
import { FeatureFigure, FeatureIcon } from '../components/FeatureFigure'
import { FigArchitecture } from '../components/Figures'
import { FREE_CLAIM, NEUTRAL_CTA } from '../content/claims'
import { FEATURES } from '../content/features'
import { href, type L, type Lang } from '../i18n'
import { ADMIN_RECOVERY_LOCAL_PATH, CONTROL_INSTALL_COMMAND, LINKS } from '../site'

const T = {
  banner: { zh: '1.0.35 发布：动态路由、自动防御、插件市场', en: '1.0.35: dynamic routing, automatic defense, plugin market' },
  bannerLink: { zh: '查看更新日志', en: 'Read the changelog' },
  eyebrow: { zh: '自建 CDN 系统 · 主控 + 节点 · OpenResty', en: 'Self-hosted CDN · control plane + edge · OpenResty' },
  h1: { zh: '一个主控，就能当 CDN 老板', en: 'One control plane. Your own CDN business.' },
  sub: { zh: '自己的节点、订阅来的节点、Cloudflare 等云 CDN，统一在一个主控里调度、防护和计费。', en: 'Run your nodes, subscribed nodes and cloud CDNs like Cloudflare from one control plane — routing, protection and billing included.' },
  docs: { zh: '查看安装文档', en: 'Read the install guide' },
  coreTitle: { zh: '核心能力', en: 'What sets cdnca apart' },
  more: { zh: '了解更多', en: 'Learn more' },
  statsTitle: { zh: '实测，不是口号', en: 'Measured, not promised' },
  flowTitle: { zh: '节点订阅：没有机房也能开 CDN', en: 'Node subscriptions: a CDN without a data centre' },
  flowLead: { zh: '供给方上架节点 → 订阅方预付订阅 → 站点下发到供给节点 → 按用量逐级结算，层级不限。', en: 'Supplier lists nodes → subscriber prepays → sites are delivered → usage settles hop by hop, at any depth.' },
  loopTitle: { zh: '防护闭环：攻击来了自动挡，走了自动撤', en: 'A protection loop that switches itself on and off' },
  loopLead: { zh: '学习基线 → 判定可疑 → 生成规则（影子观察）→ 分级处置 → 自动撤销；跨节点只广播已确认的签名。', en: 'Learn → detect → mine rules (shadow) → mitigate by level → revoke automatically. Only confirmed signatures are shared between nodes.' },
  cmpTitle: { zh: '与常见自建 CDN 系统相比', en: 'Compared with typical self-hosted CDN systems' },
  cmpCap: { zh: '能力', en: 'Capability' },
  cmpUs: { zh: 'cdnca', en: 'cdnca' },
  cmpTypical: { zh: '常见自建 CDN 系统', en: 'Typical self-hosted CDN' },
  cmpHas: { zh: '已具备', en: 'Included' },
  stepsTitle: { zh: '三步上手', en: 'Up and running in three steps' },
  devTitle: { zh: '开发者：写插件，在每一个 cdnca 主控里售卖', en: 'Developers: build plugins, sell them in every cdnca control plane' },
  devLead: { zh: '开放 API、事件 Webhook、插件市场托管结算。', en: 'Open API, event webhooks and escrow-settled plugin sales.' },
  devCta: { zh: '了解开发者平台', en: 'Developer platform' },
  faqTitle: { zh: '常见问题', en: 'FAQ' },
  endTitle: { zh: '现在就搭建你的 CDN', en: 'Build your CDN today' },
}

const STATS: { v: L; k: L }[] = [
  { v: { zh: '1.5 秒', en: '1.5 s' }, k: { zh: '10 万站时改一个站点到生效，不 reload', en: 'to apply one change with 100,000 sites — no reload' } },
  { v: { zh: '四层 + 七层', en: 'L4 + L7' }, k: { zh: 'TCP/UDP 转发、HTTP/2、HTTP/3', en: 'TCP/UDP forwarding, HTTP/2, HTTP/3' } },
  { v: { zh: 'x86_64', en: 'x86_64' }, k: { zh: 'Ubuntu / Debian / Rocky / Alma / RHEL', en: 'Ubuntu / Debian / Rocky / Alma / RHEL' } },
]

// 对比表：只写我们有什么；右列只写“通常需要…”，不打勾不打叉，不点名其他产品（§3.1 规则 4）。
const COMPARE: { cap: L; typical: L }[] = [
  { cap: { zh: '站点增删改不 reload', en: 'Site changes without reloads' }, typical: { zh: '通常每次改配置都要 reload', en: 'Usually reload on every config change' } },
  { cap: { zh: '节点订阅与转售', en: 'Node subscription and resale' }, typical: { zh: '通常需要自购全部节点', en: 'Usually you buy every node yourself' } },
  { cap: { zh: '云 CDN 聚合调度', en: 'Cloud CDN aggregation' }, typical: { zh: '通常需要另行对接', en: 'Usually integrated separately' } },
  { cap: { zh: '按站点自适应 WAF', en: 'Per-site adaptive WAF' }, typical: { zh: '通常需要手动调规则与白名单', en: 'Usually tuned by hand' } },
  { cap: { zh: '智能自动防御', en: 'Automatic defense' }, typical: { zh: '通常需要人工看日志处置', en: 'Usually handled manually from logs' } },
  { cap: { zh: '插件市场与开发者分成', en: 'Plugin market with developer revenue' }, typical: { zh: '通常只有官方扩展', en: 'Usually vendor-only extensions' } },
  { cap: { zh: '主控备份恢复与一键迁移', en: 'Control-plane backup and one-click migration' }, typical: { zh: '通常需要手工搬数据库', en: 'Usually a manual database move' } },
  { cap: { zh: '签名制品与签名者吊销', en: 'Signed artifacts and signer revocation' }, typical: { zh: '通常不校验下发内容', en: 'Usually unsigned delivery' } },
]

function faqItems(lang: Lang) {
  const items: { q: string; a: ReactNode }[] = [
    { q: lang === 'zh' ? '需要什么服务器？' : 'What servers do I need?', a: lang === 'zh' ? '主控与节点都只支持 x86_64。主控最低 4G 内存（建议 8G），节点最低 1G 内存加 2G Swap。支持 Ubuntu、Debian、Rocky、AlmaLinux、RHEL，详见系统要求。' : 'Both control plane and nodes are x86_64 only. The control plane needs at least 4 GB RAM (8 GB recommended); nodes need 1 GB RAM plus 2 GB swap. Ubuntu, Debian, Rocky, AlmaLinux and RHEL are supported — see Requirements.' },
  ]
  if (FREE_CLAIM) items.push({ q: FREE_CLAIM[lang].faqQ, a: FREE_CLAIM[lang].faqA })
  items.push(
    { q: lang === 'zh' ? '节点能用自己的服务器吗？' : 'Can I use my own servers as nodes?', a: lang === 'zh' ? '可以。在主控“节点”页复制安装命令到你的服务器上执行即可；也可以同时订阅节点市场里别人的节点。' : 'Yes. Copy the install command from the Nodes page of your control plane and run it on your server. You can also subscribe to other suppliers’ nodes at the same time.' },
    { q: lang === 'zh' ? '能接 Cloudflare 吗？' : 'Does it work with Cloudflare?', a: lang === 'zh' ? '能。聚合边缘支持 Cloudflare、CloudFront、EdgeOne、阿里云 ESA，用你自己的账号，凭据只存在你的主控里。' : 'Yes. Aggregated edge supports Cloudflare, CloudFront, EdgeOne and Alibaba Cloud ESA using your own accounts; credentials stay in your control plane.' },
    { q: lang === 'zh' ? '插件怎么买？' : 'How do I buy plugins?', a: lang === 'zh' ? '在主控的“插件市场”页购买、下载并启用。一份购买绑定一个主控，换机器时可在授权中心改绑。' : 'Buy, download and enable them on the Plugin market page of your control plane. Each purchase is bound to one control plane and can be rebound in the licence centre.' },
    {
      q: lang === 'zh' ? '忘记管理员密码怎么办？' : 'I forgot the administrator password. What now?',
      a: lang === 'zh'
        ? <>还有其他管理员时，请他在“系统管理 → 用户列表”为你重置密码。唯一的平台管理员也登录不了时，按<a href={LINKS.adminRecovery}>主控 root 恢复手册</a>在主控服务器上以 root 执行恢复命令；同版本手册也随安装包装在本机 <code>{ADMIN_RECOVERY_LOCAL_PATH}</code>。恢复会撤销该账号全部会话，不移除 MFA，也不吊销 API Key。</>
        : <>If another administrator can sign in, ask them to reset your password under System → Users. If the only platform administrator is locked out, follow the <a href={LINKS.adminRecovery}>control-plane root recovery runbook</a> as root on the control-plane server; the same version of the runbook ships with the package at <code>{ADMIN_RECOVERY_LOCAL_PATH}</code>. Recovery revokes all of the account’s sessions but keeps MFA and API keys.</>,
    },
  )
  return items
}

export function HomePage({ lang }: { lang: Lang }) {
  const cta = FREE_CLAIM ? FREE_CLAIM[lang].cta : NEUTRAL_CTA[lang]
  const steps: { t: L; d: L; code?: string }[] = [
    { t: { zh: '注册并复制主控安装命令', en: 'Sign up and copy the install command' }, d: { zh: '在授权中心登记主控服务器 IP，复制一行安装命令到服务器执行。', en: 'Register your server IP in the licence centre, then run the one-line installer on it.' }, code: CONTROL_INSTALL_COMMAND },
    { t: { zh: '添加节点', en: 'Add nodes' }, d: { zh: '在主控“节点”页复制节点安装命令（带注册密钥），到节点服务器执行。', en: 'Copy the node command (with its registration key) from the Nodes page and run it on each node.' } },
    { t: { zh: '添加网站', en: 'Add a site' }, d: { zh: '在主控添加网站，把域名 CNAME 指向分配的地址即可生效。', en: 'Add the site in the control plane and point its CNAME to the assigned target.' } },
  ]
  return (
    <>
      <p className="banner">{T.banner[lang]} · <a href={href(lang, '/changelog')}>{T.bannerLink[lang]}</a></p>
      <section className="hero">
        <div className="container hero-grid">
          <div>
            <p className="eyebrow">{T.eyebrow[lang]}</p>
            <h1>{T.h1[lang]}</h1>
            {FREE_CLAIM ? <p className="badge-free" data-claim="free"><Check aria-hidden="true" size={20} />{FREE_CLAIM[lang].badge}</p> : null}
            <p className="lead">{T.sub[lang]}</p>
            <div className="btn-row">
              <a className="btn btn-primary" href={LINKS.register}>{cta}</a>
              <a className="btn btn-ghost" href={href(lang, '/docs/install-control')}>{T.docs[lang]}</a>
            </div>
          </div>
          <Figure><FigArchitecture lang={lang} animated /></Figure>
        </div>
      </section>

      <Section id="core" title={T.coreTitle[lang]}>
        <div className="grid grid-3">
          {FEATURES.map((f) => (
            <article className="card" key={f.slug}>
              <FeatureIcon name={f.icon} />
              <h3>{f.name[lang]}</h3>
              <p>{f.card[lang]}</p>
              <a className="card-more" href={href(lang, `/features/${f.slug}`)} aria-label={`${T.more[lang]}：${f.name[lang]}`}>{T.more[lang]} →</a>
            </article>
          ))}
        </div>
      </Section>

      <Section id="stats" title={T.statsTitle[lang]} dark>
        <div className="grid grid-3">
          {STATS.map((s) => (
            <div className="stat" key={s.v.en}><strong>{s.v[lang]}</strong><span>{s.k[lang]}</span></div>
          ))}
        </div>
        <p className="footnote">{lang === 'zh' ? '测试条件：单机 OpenResty 2 worker，10 万站点对象，改 1 站从下发到生效；仓库 tests/dynroute-scale/RESULTS.md。' : 'Test conditions: single host, OpenResty with 2 workers, 100,000 site objects, one site changed end to end; see tests/dynroute-scale/RESULTS.md in the repository.'}</p>
      </Section>

      <Section id="resale" title={T.flowTitle[lang]} lead={T.flowLead[lang]}>
        <Figure><FeatureFigure k="B" lang={lang} /></Figure>
      </Section>

      <Section id="loop" title={T.loopTitle[lang]} lead={T.loopLead[lang]} alt>
        <div className="narrow center"><Figure><FeatureFigure k="C" lang={lang} /></Figure></div>
      </Section>

      <Section id="compare" title={T.cmpTitle[lang]}>
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th scope="col">{T.cmpCap[lang]}</th><th scope="col">{T.cmpUs[lang]}</th><th scope="col">{T.cmpTypical[lang]}</th></tr></thead>
            <tbody>
              {COMPARE.map((r) => (
                <tr key={r.cap.en}>
                  <th scope="row">{r.cap[lang]}</th>
                  <td><Check aria-hidden="true" size={18} color="#0b6b3a" /> {T.cmpHas[lang]}</td>
                  <td className="muted">{r.typical[lang]}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Section>

      <Section id="steps" title={T.stepsTitle[lang]} alt>
        <ol className="steps grid grid-3">
          {steps.map((s) => (
            <li key={s.t.en} className="card">
              <h3>{s.t[lang]}</h3>
              <p>{s.d[lang]}</p>
              {s.code ? <CodeBlock code={s.code} lang={lang} /> : null}
            </li>
          ))}
        </ol>
      </Section>

      <Section id="dev">
        <div className="grid grid-2 align-center">
          <div>
            <h2>{T.devTitle[lang]}</h2>
            <p className="lead">{T.devLead[lang]}</p>
            <a className="btn btn-primary" href={href(lang, '/developers')}>{T.devCta[lang]}</a>
          </div>
          <Figure><FeatureFigure k="G" lang={lang} /></Figure>
        </div>
      </Section>

      <Section id="faq" title={T.faqTitle[lang]} alt>
        <div className="narrow"><Faq items={faqItems(lang)} /></div>
      </Section>

      <Section id="end">
        <div className="cta-band">
          <h2>{T.endTitle[lang]}</h2>
          <div className="btn-row">
            <a className="btn btn-primary" href={LINKS.register}>{cta}</a>
            <a className="btn btn-ghost" href={href(lang, '/docs')}>{T.docs[lang]}</a>
          </div>
        </div>
      </Section>
    </>
  )
}
