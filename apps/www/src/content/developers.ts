// 开发者平台文案（www-design.md §3.5–§3.7）。只讲开发者怎么收钱，不写平台抽成。
import type { L } from '../i18n'
import { AVAILABLE } from './availability'

export interface Category {
  /** kinds.json 中的 kind */
  kind: string
  /** provider 协议（services/market-service/internal/review/pass_datapack.go ProvidesKinds） */
  provides?: string
  name: L
  body: L
  /** kinds.json official_only，或 OfficialOnlyProvides */
  officialOnly: boolean
  /**
   * 市场审核接受、但主控尚未启用的协议：libs/entitlement/pluginprovider Kinds 不含它
   * （pluginprovider.go Build 丢弃 notify）。页面标“即将开放”。developers.test.tsx 对照 Kinds。
   */
  comingSoon?: boolean
}

// 依据：libs/marketproto/pluginkind/kinds.json（8 类，official_only 3 类）、
// pass_datapack.go ProvidesKinds（payment/dns/sms/notify/cdn/icp/mail，cdn 官方专属）、ADR 0007 §8.2。
// 测试 developers.test.ts 会把本表与这两处逐项对照，缺项或多项即失败。
export const CATEGORIES: Category[] = [
  { kind: 'theme', name: { zh: '主题', en: 'Themes' }, officialOnly: false,
    body: { zh: '声明式主题包：设计令牌、品牌槽位、布局槽位、错误页模板，不带脚本。', en: 'Declarative theme packages: design tokens, brand and layout slots, error-page templates — no scripts.' } },
  { kind: 'rule_pack', name: { zh: '防护规则包', en: 'Protection rule packs' }, officialOnly: false,
    body: { zh: 'WAF / CC / ACL 规则，主控发布前做冲突检测，由核心引擎解释执行。', en: 'WAF, CC and ACL rules, conflict-checked before publishing and interpreted by the core engine.' } },
  { kind: 'provider', provides: 'payment', name: { zh: '支付接口', en: 'Payment providers' }, officialOnly: false,
    body: { zh: '对接新的支付渠道。插件只上报支付事实，主控查单确认后才入账。', en: 'Add a payment channel. The plugin reports payment facts; the control plane confirms by querying the order before crediting.' } },
  { kind: 'provider', provides: 'dns', name: { zh: 'DNS 服务商', en: 'DNS providers' }, officialOnly: false,
    body: { zh: '通过契约测试（记录增删改查、线路、权重、TXT）后可在主控里选用。', en: 'Selectable in the control plane after passing the contract suite (record CRUD, lines, weights, TXT).' } },
  { kind: 'provider', provides: 'sms', name: { zh: '短信', en: 'SMS' }, officialOnly: false,
    body: { zh: '新的短信通道，用于验证码与告警通知。', en: 'A new SMS channel for verification codes and alerts.' } },
  { kind: 'provider', provides: 'mail', name: { zh: '邮件发送', en: 'Email delivery' }, officialOnly: false,
    body: { zh: '新的邮件发送通道（邮件推送服务等），与内置 SMTP 并存，由主控选择启用。', en: 'A new email delivery channel (mail push services and more), alongside the built-in SMTP; the control plane chooses which one is active.' } },
  { kind: 'provider', provides: 'notify', name: { zh: '通知渠道', en: 'Notification channels' }, officialOnly: false, comingSoon: true,
    body: { zh: '即将开放：把通知中心的消息投递到新的渠道（IM、Webhook 等）。市场已接受此类声明，主控启用前不会调用。', en: 'Coming soon: deliver notification-centre messages to new channels (IM, webhooks and more). The market accepts the declaration; the control plane will not call it until it is enabled.' } },
  { kind: 'provider', provides: 'icp', name: { zh: '备案查询', en: 'ICP filing lookup' }, officialOnly: false,
    body: { zh: '对接备案查询数据源，用于接入域名时的备案校验。', en: 'Plug in an ICP filing data source used when domains are added.' } },
  { kind: 'external_service', name: { zh: '外部服务', en: 'External services' }, officialOnly: false,
    body: { zh: '进程外 HTTPS 服务：自动化、报表导出、对接 CRM / 工单等；订阅事件 Webhook，用租户授权的 API Key 调用开放 API。', en: 'Out-of-process HTTPS services — automation, exports, CRM or ticketing bridges — receiving event webhooks and calling the open API with an API key the tenant grants.' } },
  { kind: 'ui_page', name: { zh: '带页面的插件', en: 'Plugins with pages' }, officialOnly: false,
    body: { zh: '嵌在主控插件中心或站点“扩展”页签里的沙箱页面。', en: 'Sandboxed pages embedded in the plugin centre or a site’s “Extensions” tab.' } },
  { kind: 'provider', provides: 'cdn', name: { zh: '聚合边缘适配器', en: 'Aggregated-edge adapters' }, officialOnly: true,
    body: { zh: '第三方 CDN 适配器由官方维护（Cloudflare、CloudFront、EdgeOne、ESA）。', en: 'Third-party CDN adapters are maintained by cdnca (Cloudflare, CloudFront, EdgeOne, ESA).' } },
  { kind: 'module', name: { zh: '官方模块', en: 'Official modules' }, officialOnly: true,
    body: { zh: '聚合边缘、自动防御、支付通道等内置能力模块。', en: 'Built-in capability modules such as aggregated edge, automatic defense and payment channels.' } },
  { kind: 'dataset', name: { zh: '数据包', en: 'Datasets' }, officialOnly: true,
    body: { zh: 'IP 情报库、蜘蛛名单等签名数据。', en: 'Signed data such as IP intelligence and crawler lists.' } },
  { kind: 'engine_module', name: { zh: '引擎扩展', en: 'Engine modules' }, officialOnly: true,
    body: { zh: '节点 nginx 原生模块。', en: 'Native nginx modules on the edge.' } },
]

// ADR 0016：数据导入适配器（external_service 输出 cdnca.migrate/v1）——未合入前不列。
if (AVAILABLE.migrateImport) {
  CATEGORIES.splice(8, 0, {
    kind: 'external_service', name: { zh: '数据导入适配器', en: 'Data import adapters' }, officialOnly: false,
    body: { zh: '把其他 CDN 系统的数据转换成 cdnca.migrate/v1 中间格式，由管理员上传到官方导入模块。', en: 'Convert data from other CDN systems into the cdnca.migrate/v1 format, uploaded by an admin to the official import module.' },
  })
}

export const INTEGRATIONS: { title: L; body: L; facts: L }[] = [
  {
    // docs/developer/api-usage.md §1
    title: { zh: '开放 API', en: 'Open API' },
    body: { zh: '租户在主控创建 API Key，服务端用 Authorization: CdncaKey <key_id>.<secret> 调用标注“API Key 可调”的接口。', en: 'Tenants create API keys in the control plane; servers call operations marked “API key” with Authorization: CdncaKey <key_id>.<secret>.' },
    facts: { zh: 'API Key 只能调用标注的接口，不能登录、改密或管理 API Key。', en: 'API keys can only call marked operations — no sign-in, password changes or key management.' },
  },
  {
    // docs/developer/plugin-integration.md §8.1–8.2
    title: { zh: '事件 Webhook', en: 'Event webhooks' },
    body: { zh: '7 类领域事件：部署、站点、证书状态、证书到期、节点、用量阈值、安全事件。至少一次投递，可按站点过滤、补发与按时间重放。', en: 'Seven domain events: deployments, sites, certificate status, certificate expiry, nodes, usage thresholds and security incidents. At-least-once delivery with per-site filters, redelivery and time-based replay.' },
    facts: { zh: '事件只带变更类别，需要配置值时调开放 API 读取（当前用租户授权的 API Key）。', en: 'Events carry change categories only; read current values through the open API (today with an API key the tenant grants).' },
  },
  {
    // ADR 0007 §3
    title: { zh: '插件', en: 'Plugins' },
    body: { zh: '四种形态：进程外 HTTPS 服务、声明式规则包、主题包、沙箱页面。', en: 'Four shapes: out-of-process HTTPS services, declarative rule packs, theme packages and sandboxed pages.' },
    facts: { zh: '第三方代码不进入控制面与节点请求路径；规则包是数据，由核心引擎解释。', en: 'Third-party code never runs in the control plane or the request path; rule packs are data interpreted by the core engine.' },
  },
]

/** 开发者收入（只写怎么收钱，不写平台抽成）。 */
export const EARN: { title: L; body: L; figure: 'I' | 'J' }[] = [
  {
    // ADR 0007 §8.5
    title: { zh: '插件市场', en: 'Plugin market' },
    body: { zh: '自己定价：免费、一次性买断、按月或按年订阅，可设试用天数。买家在主控内付款给平台托管，许可证生效后进入你的待结算，按结算规则打款给你。', en: 'Set your own price: free, one-off, monthly or yearly, with optional trial days. Buyers pay into escrow from their control plane; once the licence is active the amount becomes your pending balance and is paid out under the settlement rules.' },
    figure: 'I',
  },
]
if (AVAILABLE.directPay) {
  EARN.push({
    title: { zh: '节点市场', en: 'Node market' },
    body: { zh: '供货方自己定价，按天、流量、95 带宽或日峰值计费；在自己主控配好收款通道，订阅方一键充值，钱直接进你的商户号，回调自动记余额。', en: 'Suppliers set their own price by day, traffic, 95th percentile or daily peak. Configure your payment channel; subscribers top up in one click, money lands in your merchant account and the callback credits their balance.' },
    figure: 'J',
  })
}
