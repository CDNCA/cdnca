// 全部页面登记处（routes.tsx 读这里）。新页面在此登记，预渲染与 sitemap 自动包含。
import type { PageDef } from '../routes'
import { FEATURES } from '../content/features'
import { FeatureDetailPage, FeaturesPage } from './Features'
import { HomePage } from './Home'
import { getCatalog } from '../content/apiCatalog'
import { getSiteContent, SEED } from '../content/siteContent'
import { DocPageView, DocsIndexPage } from './Docs'
import { AboutPage, ChangelogPage } from './Misc'
import { MarketPage } from './Market'
import { ApiGroupPage, ApiIndexPage, CategoriesPage, DevelopersPage, EarnPage, PluginSigningPage } from './Developers'
import { PLUGIN_SIGNING_PATH } from '../content/pluginSigning'
import { GUIDES, GUIDES_PATH, REVIEW_RULES_PATH, UI_SDK_PATH } from '../content/devGuides'
import { GuidePage, GuidesIndexPage, ReviewRulesPage, UISdkPage } from './DevGuides'
import { TUTORIALS, TUTORIALS_PATH } from '../content/devTutorials'
import { TutorialPage, TutorialsIndexPage } from './DevTutorials'

export const pages: PageDef[] = [
  {
    path: '/',
    title: { zh: 'cdnca · 自建 CDN 系统：一个主控，就能当 CDN 老板', en: 'cdnca · Self-hosted CDN system: one control plane, your own CDN business' },
    description: { zh: 'cdnca 自建 CDN 系统：一个主控统一调度自有节点、订阅节点与 Cloudflare 等云 CDN，内置动态路由、自适应 WAF、智能自动防御与插件市场。', en: 'cdnca is a self-hosted CDN system: one control plane schedules your nodes, subscribed nodes and cloud CDNs, with dynamic routing, adaptive WAF, automatic defense and a plugin market.' },
    render: (lang) => <HomePage lang={lang} />,
  },
  {
    path: '/features',
    title: { zh: '功能与优势', en: 'Features' },
    description: { zh: 'cdnca 功能总览：节点订阅、动态路由、自适应 WAF、智能自动防御、聚合边缘、插件市场，以及接入、加速、安全、运营、运维全量能力。', en: 'cdnca features: node subscriptions, dynamic routing, adaptive WAF, automatic defense, aggregated edge and plugin market, plus the full capability list.' },
    render: (lang) => <FeaturesPage lang={lang} />,
  },
  ...FEATURES.map((f): PageDef => ({
    path: `/features/${f.slug}`,
    title: { zh: `${f.name.zh}：${f.tagline.zh}`, en: `${f.name.en}: ${f.tagline.en}` },
    description: { zh: `${f.name.zh} · ${f.lead.zh}`, en: `${f.name.en} · ${f.lead.en}` },
    render: (lang) => <FeatureDetailPage f={f} lang={lang} />,
  })),
  {
    path: '/market',
    title: { zh: '市场：节点报价与插件条目', en: 'Market: node offers and plugins' },
    description: { zh: 'cdnca 市场公开页：节点市场供货方报价（价格由供货方自定）与插件市场条目；订阅与购买在授权门户与主控内完成。', en: 'cdnca market: node offers from suppliers (prices set by each supplier) and plugin listings; subscribe and buy from the licence portal and your control plane.' },
    render: (lang) => <MarketPage lang={lang} />,
  },
  {
    path: '/developers',
    title: { zh: '开发者平台：写插件，在每一个 cdnca 主控里售卖', en: 'Developer platform: build and sell cdnca plugins' },
    description: { zh: 'cdnca 开发者平台：开放 API、事件 Webhook、插件市场；可开发主题、防护规则包、支付/DNS/短信/通知/备案接口、外部服务与带页面的插件。', en: 'cdnca developer platform: open API, event webhooks and a plugin market for themes, rule packs, payment/DNS/SMS/notification/ICP providers, external services and plugins with pages.' },
    render: (lang) => <DevelopersPage lang={lang} />,
  },
  {
    path: '/developers/categories',
    title: { zh: '可开发类目', en: 'Plugin categories' },
    description: { zh: 'cdnca 插件市场可开发类目全表：每类对应的插件类型、谁可以发布、能做什么；标明官方专属项。', en: 'Every plugin category in the cdnca market: its kind, who may publish it and what it does, with official-only items marked.' },
    render: (lang) => <CategoriesPage lang={lang} />,
  },
  {
    path: '/developers/earn',
    title: { zh: '开发者收入与结算方式', en: 'Developer income and settlement' },
    description: { zh: 'cdnca 开发者怎么收钱：插件自己定价（免费、一次性、订阅、试用），买家付款托管，许可证生效后进入待结算并打款。', en: 'How cdnca developers get paid: set your own plugin price (free, one-off, subscription, trial); buyer payments are held in escrow and paid out once the licence is active.' },
    render: (lang) => <EarnPage lang={lang} />,
  },
  {
    path: PLUGIN_SIGNING_PATH,
    title: { zh: '插件签名工具 cdnca-plugin：下载与使用', en: 'Plugin signing tool cdnca-plugin: download and usage' },
    description: { zh: 'cdnca 插件发布者签名工具 cdnca-plugin：Linux/macOS/Windows 下载与 SHA-256 校验，生成 Ed25519 密钥、登记发布者公钥、给 manifest 签名。', en: 'cdnca-plugin, the publisher signing tool: Linux/macOS/Windows downloads with SHA-256 checks, creating an Ed25519 key, registering it and signing manifests.' },
    render: (lang) => <PluginSigningPage lang={lang} />,
  },
  {
    path: TUTORIALS_PATH,
    title: { zh: '开发教程：从入驻、签名、审核到安装授权与接口调用', en: 'Developer tutorials: onboarding, signing, review, installation and API calls' },
    description: { zh: 'cdnca 插件开发任务式教程：开发者入驻、签名工具与发布密钥、制作插件、本地联调、提交审核、发布与定价、客户安装授权、调用开放接口、升级与卸载。', en: 'Task-based cdnca plugin tutorials: onboarding, the signing tool and publisher key, building, local integration, review, publishing and pricing, customer installation, calling the open API, upgrading and uninstalling.' },
    render: (lang) => <TutorialsIndexPage lang={lang} />,
  },
  ...TUTORIALS.map((t): PageDef => ({
    path: `${TUTORIALS_PATH}/${t.slug}`,
    title: t.title,
    description: { zh: `${t.title.zh}：${t.lead.zh}`, en: `${t.title.en}: ${t.lead.en}` },
    render: (lang) => <TutorialPage lang={lang} tutorial={t} />,
  })),
  {
    path: GUIDES_PATH,
    title: { zh: '按类型开发指南：规则包、主题、服务商接口、外部服务与页面', en: 'Plugin guides by kind: rule packs, themes, providers, external services and pages' },
    description: { zh: 'cdnca 插件按类型开发指南：rule_pack、theme、provider、external_service 与 ui_page 的快速开始、manifest 字段、协议、上传字段、审核规则与本地调试。', en: 'cdnca plugin guides by kind: quick start, manifest fields, protocol, upload fields, review rules and local debugging for rule_pack, theme, provider, external_service and ui_page.' },
    render: (lang) => <GuidesIndexPage lang={lang} />,
  },
  ...GUIDES.map((g): PageDef => ({
    path: `${GUIDES_PATH}/${g.slug}`,
    title: g.title,
    description: { zh: `${g.title.zh}：${g.lead.zh}`, en: `${g.title.en}: ${g.lead.en}` },
    render: (lang) => <GuidePage lang={lang} guide={g} />,
  })),
  {
    path: REVIEW_RULES_PATH,
    title: { zh: '插件审核规则清单', en: 'Plugin review rules' },
    description: { zh: 'cdnca 插件市场审核 worker 的全部规则：规则 ID、级别、拒绝或隔离、是否试运行，以及必须人工审核的情况；由审核引擎代码自动导出。', en: 'Every rule of the cdnca plugin market review worker: rule ID, severity, reject or quarantine, evaluation mode, and when human review is required; exported from the review engine code.' },
    render: (lang) => <ReviewRulesPage lang={lang} />,
  },
  {
    path: UI_SDK_PATH,
    title: { zh: 'ui_page 开发者 SDK：带页面插件的协议与验签', en: 'ui_page developer SDK: page plugin protocol and verification' },
    description: { zh: 'cdnca 带页面插件（ui_page）开发者 SDK：沙箱 iframe、postMessage 协议 cdnca.plugin-ui/v1、主控代理受限 API、后端 Ed25519 验签与 SDK 源码。', en: 'cdnca ui_page developer SDK: sandboxed iframe, the cdnca.plugin-ui/v1 postMessage protocol, the control plane proxy, backend Ed25519 verification and SDK source.' },
    render: (lang) => <UISdkPage lang={lang} />,
  },
  {
    path: '/developers/api',
    title: { zh: '开放接口目录', en: 'API reference' },
    description: { zh: 'cdnca 主控开放接口目录：从 OpenAPI 契约生成，按分组列出接口，并给出每个接口的认证方式、所需权限、参数、请求与响应字段和状态码。', en: 'cdnca control-plane API reference generated from the OpenAPI contracts: operations by group, each with auth, required permissions, parameters, request and response fields and status codes.' },
    render: (lang) => <ApiIndexPage lang={lang} />,
  },
  {
    path: '/docs',
    title: { zh: '使用文档', en: 'Documentation' },
    description: { zh: 'cdnca 使用文档：系统要求、主控安装、节点安装、插件安装、重启升级卸载与迁移、问题处理。', en: 'cdnca documentation: requirements, installing the control plane, nodes and plugins, operations and troubleshooting.' },
    render: (lang) => <DocsIndexPage lang={lang} />,
  },
  {
    path: '/changelog',
    title: { zh: '更新日志', en: 'Changelog' },
    description: { zh: 'cdnca 更新日志：每个版本的主要变化与升级方式。1.0.35 为首个公开版本。', en: 'cdnca changelog: what changed in each release and how to upgrade. 1.0.35 is the first public release.' },
    render: (lang) => <ChangelogPage lang={lang} />,
  },
  {
    path: '/about',
    title: { zh: '联系我们', en: 'Contact' },
    description: { zh: '联系 cdnca：自建 CDN 系统，主控统一调度自有节点、订阅节点与云 CDN。', en: 'Contact cdnca, the self-hosted CDN system that schedules your nodes, subscribed nodes and cloud CDNs.' },
    render: (lang) => <AboutPage lang={lang} />,
  },
]

const API_GROUP = /^\/developers\/api\/([a-z0-9-]+)$/
const DOC = /^\/docs\/([a-z0-9][a-z0-9-]*)$/

/**
 * 动态页：文档页 /docs/<slug>（当前官网内容，运营可增删）与接口分组页 /developers/api/<分组 id>
 * （生成的接口目录）。
 */
export function dynamicPage(path: string): PageDef | undefined {
  const d = DOC.exec(path)
  if (d) {
    const doc = getSiteContent().docs.find((x) => x.slug === d[1])
    return doc && {
      path,
      title: doc.title,
      description: doc.description,
      render: (lang) => <DocPageView lang={lang} doc={doc} />,
    }
  }
  const m = API_GROUP.exec(path)
  const group = m ? getCatalog()?.groups.find((g) => g.id === m[1]) : undefined
  if (!group) return undefined
  return {
    path,
    title: { zh: `${group.prefix} 接口`, en: `${group.prefix} API` },
    description: { zh: `cdnca 开放接口 ${group.prefix}：${group.count} 个接口的认证方式、所需权限、参数、请求与响应字段和状态码。`, en: `cdnca API ${group.prefix}: auth, required permissions, parameters, request and response fields and status codes for ${group.count} operations.` },
    render: (lang) => <ApiGroupPage lang={lang} group={group} />,
  }
}

/** 预渲染用：全部动态页路径（文档按种子内容预渲染） */
export function dynamicPaths(): string[] {
  return [...SEED.docs.map((d) => `/docs/${d.slug}`), ...(getCatalog()?.groups ?? []).map((g) => `/developers/api/${g.id}`)]
}
