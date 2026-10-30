// 功能文案（www-design.md §3.2–§3.3）。只写已合入的能力；出处见每条注释。
import type { L } from '../i18n'
import type { FlowKey } from '../components/Figures'
import { AVAILABLE } from './availability'

export type FigureKey = 'A' | 'B' | 'C' | 'F' | 'G' | FlowKey

export interface Feature {
  slug: string
  icon: 'network' | 'route' | 'shield' | 'radar' | 'cloud' | 'puzzle'
  name: L
  card: L
  tagline: L
  lead: L
  figure: FigureKey
  points: { title: L; body: L }[]
  limits: L
  docs: { path: string; label: L }
}

export const FEATURES: Feature[] = [
  {
    // ADR 0012 §1；ML-01～13、15、19、26 已合入
    slug: 'node-market',
    icon: 'network',
    name: { zh: '节点订阅', en: 'Node subscriptions' },
    card: { zh: '把节点挂到市场按天、流量或 95 带宽出售；订阅来的节点还能和自有节点组合后再转售。', en: 'List nodes on the market by day, traffic or 95th percentile; combine subscribed nodes with your own and resell them.' },
    tagline: { zh: '一个主控，就能当老板', en: 'One control plane makes you the operator' },
    lead: { zh: '没有机房也能开 CDN：订阅别人的节点，与自己的节点一起调度，再按自己的价格卖给客户。', en: 'Run a CDN without your own data centre: subscribe to other suppliers’ nodes, schedule them with yours and sell at your own price.' },
    figure: 'B',
    points: [
      { title: { zh: '供货方自定价格', en: 'Suppliers set the price' }, body: { zh: '按天、按流量、按 95 带宽、按日峰值计费；订阅先预付，生效后才下发站点。', en: 'Bill per day, per GB, by 95th percentile or daily peak. Subscriptions are prepaid before any site is delivered.' } },
      { title: { zh: '限额只停一个订阅方', en: 'Limits pause one subscriber only' }, body: { zh: '供货方自选限额项（域名数、带宽峰值、月流量、连接数等），到限只暂停该订阅方的调度，不影响别人，也不下架节点。', en: 'Suppliers pick limits (domains, peak bandwidth, monthly traffic, connections…). Hitting one pauses scheduling for that subscriber only — nobody else is affected and the node stays listed.' } },
      { title: { zh: '可组合、可转售', en: 'Combine and resell' }, body: { zh: '订阅来的节点可与自有节点组成线路再卖出；供货方可以禁止二次分销。', en: 'Subscribed nodes can join your own in a line group and be resold; suppliers may forbid onward resale.' } },
      { title: { zh: '访客直连物理节点', en: 'Visitors hit the real node' }, body: { zh: '站点直接下发到供给节点，访客流量不绕行中间商。', en: 'Sites are delivered straight to the supplying node; visitor traffic never detours through a middleman.' } },
    ],
    limits: { zh: '订阅、计费与限额在主控内完成，用量按 5 分钟扣费，余额不足先透支后暂停。', en: 'Subscriptions, billing and limits run in the control plane; usage is charged every 5 minutes, with overdraft before pausing.' },
    docs: { path: '/docs/install-control', label: { zh: '先装一个主控', en: 'Install a control plane first' } },
  },
  {
    // docs/adr/0009-edge-runtime-routing.md §1；tests/dynroute-scale/RESULTS.md:12-35,116-120
    slug: 'dynamic-routing',
    icon: 'route',
    name: { zh: '动态路由', en: 'Dynamic routing' },
    card: { zh: '站点是数据，不是配置文件：增删改不 reload，为百万站设计。', en: 'Sites are data, not config files: add, change or remove without reloads. Designed for a million sites.' },
    tagline: { zh: '站点是数据，不是配置文件', en: 'Sites are data, not config files' },
    lead: { zh: '节点按 Host/SNI 在共享字典里查到签名站点对象，站点增删改只更新数据，nginx 不 reload。', en: 'Nodes look up the signed site object by Host/SNI in a shared dictionary. Adding, changing or removing a site updates data only — nginx does not reload.' },
    figure: 'D',
    points: [
      { title: { zh: '不 reload', en: 'No reloads' }, body: { zh: '站点变更不触发 reload，长连接与 HTTP/3 会话不受影响；只有新增监听端口才 reload。', en: 'Site changes never reload nginx, so long-lived connections and HTTP/3 sessions survive. Only new listening ports trigger a reload.' } },
      { title: { zh: '签名站点对象', en: 'Signed site objects' }, body: { zh: '主控签发站点对象下发到节点，节点校验后才生效。', en: 'The control plane signs every site object; nodes verify before activating it.' } },
      { title: { zh: '10 万站实测', en: '100k sites measured' }, body: { zh: '10 万站时改 1 个站点从下发到生效 1.50 秒；热请求 p50 约 0.2 毫秒。', en: 'With 100,000 sites, one change goes live in 1.50 s; warm requests run at about 0.2 ms p50.' } },
    ],
    limits: { zh: '百万站为设计目标，目前实测到 10 万站（单机 2 worker）。', en: 'One million sites is the design target; measured so far up to 100,000 sites (single host, 2 workers).' },
    docs: { path: '/docs/install-node', label: { zh: '节点安装', en: 'Install a node' } },
  },
  {
    // ADR 0011 状态行
    slug: 'waf',
    icon: 'shield',
    name: { zh: '自适应 WAF', en: 'Adaptive WAF' },
    card: { zh: '按站点真实流量自动调整误报排除，官方规则库免费更新。', en: 'Tunes exclusions to each site’s real traffic; the official rule library updates for free.' },
    tagline: { zh: '越用越准的 WAF', en: 'A WAF that gets sharper with use' },
    lead: { zh: '节点为每个站点建画像、自动排除误报；各主控汇总的情报去重合并成官方规则库，再下发给所有主控。', en: 'Nodes profile each site and exclude false positives automatically; intelligence from every control plane is merged into the official rule library and delivered back.' },
    figure: 'E',
    points: [
      { title: { zh: '按站点自适应', en: 'Per-site adaptation' }, body: { zh: '同一条规则在不同站点上有不同的排除项，不需要手动调参。', en: 'The same rule carries different exclusions per site — no manual tuning.' } },
      { title: { zh: '学习与建议免费', en: 'Learning and advice are free' }, body: { zh: '学习、观察、建议模式免费使用。', en: 'Learning, observation and suggestion modes are free.' } },
      { title: { zh: '官方规则库免费下发', en: 'Official rules for free' }, body: { zh: '规则库更新经签名下发，主控自动应用。', en: 'Rule updates are signed and applied by the control plane automatically.' } },
      // 官方包 system/waf-php-vpatch（默认开，站点可关）
      { title: { zh: 'PHP 高危漏洞虚拟补丁', en: 'Virtual patches for critical PHP flaws' }, body: { zh: '已内置 PHP2Shell（CVE-2026-109618/109619）等 PHP 高危漏洞的边缘虚拟补丁，默认开启，可按站点关闭或调整阈值。边缘拦截是缓解措施，仍需升级 PHP。', en: 'Edge virtual patches for PHP2Shell (CVE-2026-109618/109619) and other critical PHP flaws are built in and on by default; switch them off or tune thresholds per site. Edge blocking mitigates; upgrading PHP is still required.' } },
    ],
    limits: { zh: '让建议自动生效属于收费模块“自动处置”。', en: 'Applying suggestions automatically is part of the paid “automatic mitigation” module.' },
    docs: { path: '/docs/plugins', label: { zh: '插件与模块', en: 'Plugins and modules' } },
  },
  {
    // ADR 0010 §1；libs/entitlement/module.go:192-198
    slug: 'auto-defense',
    icon: 'radar',
    name: { zh: '智能自动防御', en: 'Automatic defense' },
    card: { zh: '节点本地学习基线，攻击开始后秒级自动处置，结束后自动撤销。', en: 'Nodes learn a local baseline, mitigate within seconds when an attack starts and revoke when it ends.' },
    tagline: { zh: '不用盯日志也能挡住新变种', en: 'Stop new attack variants without watching logs' },
    lead: { zh: '每个节点独立学习每个站点的正常流量，判定带原因，处置分级，攻击结束自动撤销。', en: 'Each node learns normal traffic for every site on its own; verdicts carry reasons, mitigation is graded, and everything is revoked when the attack ends.' },
    figure: 'C',
    points: [
      { title: { zh: '节点自治', en: 'Node autonomy' }, body: { zh: '主控断开时节点照常学习与判定，不依赖中心。', en: 'Nodes keep learning and deciding even when the control plane is unreachable.' } },
      { title: { zh: '每站基线 ≤ 2 KB', en: '≤ 2 KB per site' }, body: { zh: '基线小，百万站也放得下。', en: 'Baselines are small enough for very large site counts.' } },
      { title: { zh: '判定可解释', en: 'Explainable verdicts' }, body: { zh: '每次处置都带触发原因，可在主控查看与撤销。', en: 'Every mitigation records why it fired; view or revoke it in the control plane.' } },
    ],
    limits: { zh: '学习、观察、告警免费；自动处置为收费模块（module.autodefense.auto）。', en: 'Learning, observation and alerting are free; automatic mitigation is a paid module (module.autodefense.auto).' },
    docs: { path: '/docs/plugins', label: { zh: '插件与模块', en: 'Plugins and modules' } },
  },
  {
    // ADR 0008 §1；services/control-api/internal/cdnprovider/{cloudflare,cloudfront,edgeone,esa}；module.go:190
    slug: 'aggregated-edge',
    icon: 'cloud',
    name: { zh: '聚合边缘', en: 'Aggregated edge' },
    card: { zh: '绑定自己的 Cloudflare / CloudFront / EdgeOne / ESA，与自有节点一起调度。', en: 'Bring your own Cloudflare, CloudFront, EdgeOne or ESA account and schedule it alongside your nodes.' },
    tagline: { zh: '自有节点 + 云 CDN，一起调度', en: 'Your nodes and cloud CDNs, scheduled together' },
    lead: { zh: '在主控里绑定云 CDN 账号，站点配置自动同步到云端，与自有节点统一调度。', en: 'Link cloud CDN accounts in the control plane; site settings sync to the cloud and are scheduled together with your nodes.' },
    figure: 'F',
    points: [
      { title: { zh: '账号归你', en: 'Your accounts' }, body: { zh: '云账号与费用都在你自己名下，凭据只存在你的主控。', en: 'Cloud accounts and bills stay in your name; credentials are stored only in your control plane.' } },
      { title: { zh: '四家适配器', en: 'Four adapters' }, body: { zh: 'Cloudflare、CloudFront、EdgeOne、阿里云 ESA。', en: 'Cloudflare, CloudFront, EdgeOne and Alibaba Cloud ESA.' } },
      { title: { zh: '官方免费模块', en: 'Free official module' }, body: { zh: '聚合边缘是官方免费模块，新装主控默认包含。', en: 'Aggregated edge is a free official module included with every new install.' } },
    ],
    limits: { zh: '各家能力差异以主控内的能力声明为准，不支持的配置项会在发布前提示。', en: 'Each provider’s capabilities are declared in the control plane; unsupported settings are flagged before publishing.' },
    docs: { path: '/docs/plugins', label: { zh: '插件与模块', en: 'Plugins and modules' } },
  },
  {
    // ADR 0007 §8.5
    slug: 'plugin-market',
    icon: 'puzzle',
    name: { zh: '插件市场', en: 'Plugin market' },
    card: { zh: '在主控里一键购买、下载、启用插件；开发者可以上架赚钱。', en: 'Buy, download and enable plugins inside the control plane; developers publish and earn.' },
    tagline: { zh: '在主控里直接买插件', en: 'Buy plugins right inside your control plane' },
    lead: { zh: '主题、规则包、支付与 DNS 接口、带页面的扩展，都能在主控的插件市场里找到。', en: 'Themes, rule packs, payment and DNS providers and extensions with pages — all in the control plane’s plugin market.' },
    figure: 'G',
    points: [
      { title: { zh: '官方与认证开发者', en: 'Official and verified' }, body: { zh: '每个条目标明发布者：官方、认证开发者或第三方。', en: 'Every listing shows the publisher: official, verified developer or third party.' } },
      { title: { zh: '多种价格方式', en: 'Flexible pricing' }, body: { zh: '免费、一次性买断、按月或按年订阅，可带试用天数。', en: 'Free, one-off, monthly or yearly subscription, with optional trial days.' } },
      { title: { zh: '下载与启用分开', en: 'Download and enable separately' }, body: { zh: '先下载校验，再按需启用或禁用。', en: 'Download and verify first, then enable or disable when you need it.' } },
      { title: { zh: '一份购买绑一个主控', en: 'One purchase, one control plane' }, body: { zh: '换机器时在授权中心解绑改绑。', en: 'Moving servers? Rebind the purchase in the licence centre.' } },
    ],
    limits: { zh: '插件不进入控制面与节点请求路径；规则包是数据，由核心引擎解释执行。', en: 'Plugins never run inside the control plane or the node request path; rule packs are data interpreted by the core engine.' },
    docs: { path: '/docs/plugins', label: { zh: '插件安装', en: 'Installing plugins' } },
  },
]

// 节点订阅的直结与保证金：未合入时不渲染（availability.ts）。
if (AVAILABLE.directPay) {
  FEATURES[0].points.push({
    title: { zh: '结算只走直结', en: 'Direct settlement only' },
    body: { zh: '供货方在自己主控配支付宝/微信等收款通道，订阅方一键充值，钱直接进供货方商户号，回调自动记余额，平台不经手资金。', en: 'Suppliers configure their own Alipay/WeChat Pay channels; subscribers top up in one click, money lands in the supplier’s merchant account and the callback credits the balance. The platform never holds funds.' },
  })
}
if (AVAILABLE.supplierDeposit) {
  FEATURES[0].points.push({
    title: { zh: '防跑路保障', en: 'Supplier deposits' },
    body: { zh: '供货方交保证金，失联时平台按比例赔付订阅方未用完的余额；订阅前可看到每家供货方的保证金与信用。', en: 'Suppliers post a deposit; if one disappears, subscribers are compensated pro rata for unused balance. Deposits and credit are visible before you subscribe.' },
  })
}

/** 功能总览页的全量能力清单（五组）。只列已合入的能力。 */
export const CAPABILITY_GROUPS: { title: L; items: L[] }[] = [
  {
    title: { zh: '接入', en: 'Onboarding' },
    items: [
      { zh: 'HTTP/HTTPS 网站、通配符与别名域名', en: 'HTTP/HTTPS sites, wildcard and alias domains' },
      { zh: '四层 TCP/UDP 转发、端口范围、跟随端口回源', en: 'L4 TCP/UDP forwarding, port ranges, follow-port origin' },
      { zh: 'DNS 服务商对接与分线路解析', en: 'DNS provider integration with per-line records' },
      { zh: 'ACME 自动证书（HTTP-01 / DNS-01）', en: 'Automatic ACME certificates (HTTP-01 / DNS-01)' },
    ],
  },
  {
    title: { zh: '加速', en: 'Performance' },
    items: [
      { zh: '缓存规则、缓存预热与清理', en: 'Cache rules, prefetch and purge' },
      { zh: 'HTTP/2 与 HTTP/3', en: 'HTTP/2 and HTTP/3' },
      { zh: '动态路由：站点变更不 reload', en: 'Dynamic routing: no reloads on site changes' },
      { zh: '聚合边缘：云 CDN 与自有节点统一调度', en: 'Aggregated edge with cloud CDNs' },
    ],
  },
  {
    title: { zh: '安全', en: 'Security' },
    items: [
      { zh: 'WAF（ModSecurity + CRS 档位）与自适应排除', en: 'WAF (ModSecurity + CRS levels) with adaptive exclusions' },
      { zh: 'CC 防护：多维度计数、JS 挑战、自动切换', en: 'CC protection: multi-dimension counting, JS challenge, auto switch' },
      { zh: '四层防护：连接速率、异形包过滤、内核拉黑', en: 'L4 protection: connection rate, malformed packet filter, kernel blocklists' },
      { zh: 'IP 情报库：国家/运营商/IDC 规则', en: 'IP intelligence: country / carrier / IDC rules' },
      { zh: '智能自动防御', en: 'Automatic defense' },
    ],
  },
  {
    title: { zh: '运营', en: 'Business' },
    items: [
      { zh: '多租户、套餐、流量包与用量计费', en: 'Multi-tenant plans, traffic packs and usage billing' },
      { zh: '节点订阅与转售', en: 'Node subscriptions and resale' },
      { zh: '工单、通知中心、短信与邮件', en: 'Tickets, notification centre, SMS and email' },
      { zh: '白标主题与租户自选主题', en: 'White-label themes, per-tenant themes' },
      { zh: '插件市场', en: 'Plugin market' },
    ],
  },
  {
    title: { zh: '运维', en: 'Operations' },
    items: [
      { zh: '一行命令安装主控与节点', en: 'One-line install for control plane and nodes' },
      { zh: '主控备份、恢复与一键迁移', en: 'Control-plane backup, restore and one-click migration' },
      { zh: '签名制品、签名者吊销', en: 'Signed artifacts and signer revocation' },
      { zh: '后台升级 runner，可指定版本', en: 'In-console upgrade runner with version pinning' },
    ],
  },
]
