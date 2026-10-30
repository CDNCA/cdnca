// 自绘插图 A–J（www-design.md §4）。全部内联 SVG：role="img" + <title>/<desc>
// 由 aria-labelledby 引用，正文说明同时作为文字等价物。颜色用 CSS 变量，不用第三方素材。
import type { ReactNode } from 'react'
import type { L, Lang } from '../i18n'

const C = {
  brand: 'var(--www-brand-strong)',
  soft: 'var(--www-brand-soft)',
  text: 'var(--cdnca-color-title)',
  muted: 'var(--www-muted)',
  line: '#8796ad',
  ok: '#0b6b3a',
  okSoft: '#e3f6ec',
  warn: '#8a4b00',
  warnSoft: '#fff4e0',
}

function Svg({ id, w, h, title, desc, children }: { id: string; w: number; h: number; title: string; desc: string; children: ReactNode }) {
  return (
    <svg viewBox={`0 0 ${w} ${h}`} role="img" aria-labelledby={`${id}-t ${id}-d`} data-figure={id}>
      <title id={`${id}-t`}>{title}</title>
      <desc id={`${id}-d`}>{desc}</desc>
      <defs>
        <marker id={`${id}-arrow`} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
          <path d="M0 0 10 5 0 10z" fill={C.line} />
        </marker>
      </defs>
      {children}
    </svg>
  )
}

function Box({ x, y, w, h, label, sub, tone = 'plain' }: { x: number; y: number; w: number; h: number; label: string; sub?: string; tone?: 'plain' | 'brand' | 'ok' | 'warn' }) {
  const fill = tone === 'brand' ? C.brand : tone === 'ok' ? C.okSoft : tone === 'warn' ? C.warnSoft : '#fff'
  const stroke = tone === 'brand' ? C.brand : tone === 'ok' ? C.ok : tone === 'warn' ? C.warn : C.line
  const color = tone === 'brand' ? '#fff' : C.text
  return (
    <g>
      <rect x={x} y={y} width={w} height={h} rx={10} fill={fill} stroke={stroke} strokeWidth={1.5} />
      <text x={x + w / 2} y={y + h / 2 + (sub ? -4 : 5)} textAnchor="middle" fontSize={15} fontWeight={700} fill={color}>{label}</text>
      {sub ? <text x={x + w / 2} y={y + h / 2 + 16} textAnchor="middle" fontSize={12} fill={tone === 'brand' ? '#fff' : C.muted}>{sub}</text> : null}
    </g>
  )
}

function Arrow({ id, d, label, lx, ly, dashed, className }: { id: string; d: string; label?: string; lx?: number; ly?: number; dashed?: boolean; className?: string }) {
  return (
    <g>
      <path d={d} fill="none" stroke={C.line} strokeWidth={2} strokeDasharray={dashed ? '6 5' : undefined} markerEnd={`url(#${id}-arrow)`} className={className} />
      {label ? <text x={lx} y={ly} textAnchor="middle" fontSize={12} fill={C.muted}>{label}</text> : null}
    </g>
  )
}

/** 通用流程图：按行排布、行内左→右，行尾折到下一行开头。 */
function Flow({ id, lang, title, desc, steps, perRow = 4, highlight }: { id: string; lang: Lang; title: L; desc: L; steps: L[]; perRow?: number; highlight?: number[] }) {
  const bw = 180, bh = 64, gx = 44, gy = 56, pad = 16
  const rows = Math.ceil(steps.length / perRow)
  const w = pad * 2 + perRow * bw + (perRow - 1) * gx
  const h = pad * 2 + rows * bh + (rows - 1) * gy
  const pos = steps.map((_, i) => ({ x: pad + (i % perRow) * (bw + gx), y: pad + Math.floor(i / perRow) * (bh + gy) }))
  return (
    <Svg id={id} w={w} h={h} title={title[lang]} desc={desc[lang]}>
      {pos.slice(1).map((p, k) => {
        const a = pos[k]
        if (p.y === a.y) return <Arrow key={k} id={id} d={`M${a.x + bw} ${a.y + bh / 2}H${p.x - 4}`} />
        const midY = a.y + bh + gy / 2
        return <Arrow key={k} id={id} d={`M${a.x + bw / 2} ${a.y + bh}V${midY}H${p.x + bw / 2}V${p.y - 4}`} />
      })}
      {steps.map((s, i) => (
        <Box key={i} x={pos[i].x} y={pos[i].y} w={bw} h={bh} label={`${i + 1}. ${s[lang]}`} tone={highlight?.includes(i) ? 'brand' : 'plain'} />
      ))}
    </Svg>
  )
}

/** 图 A：总体架构。animated（首页首屏）时叠加动效层：管理虚线流动表示配置下发，
 * 绿点 = 访客请求就近接入、缓存、回源；红点 = 攻击请求在节点被 WAF/自动防御拦下；
 * 节点角上的绿点表示在线心跳。动效全在 styles.css（.arch-*），减少动态效果时只剩静态图。 */
export function FigArchitecture({ lang, animated = false }: { lang: Lang; animated?: boolean }) {
  const t = (zh: string, en: string) => (lang === 'zh' ? zh : en)
  const flow = animated ? 'arch-flow' : undefined
  return (
    <Svg id="fig-a" w={640} h={420}
      title={t('cdnca 总体架构', 'cdnca architecture')}
      desc={t('访客请求进入三类节点：自有节点、订阅来的节点、云 CDN，再回到源站。主控经网关以 mTLS 管理节点，并连接授权端与插件市场。',
        'Visitors reach three kinds of edges: your own nodes, subscribed nodes and cloud CDNs, which fetch from the origin. The control plane manages nodes over mTLS through the gateway and talks to the licensing service and plugin market.')}>
      <Box x={170} y={16} w={300} h={66} label={t('主控', 'Control plane')} sub={t('调度 · 防护 · 计费', 'Routing · Protection · Billing')} tone="brand" />
      <Box x={500} y={16} w={124} h={30} label={t('授权端', 'Licensing')} />
      <Box x={500} y={54} w={124} h={30} label={t('插件市场', 'Plugin market')} />
      <Arrow id="fig-a" d="M470 33H496" />
      <Arrow id="fig-a" d="M470 66H496" />
      <Box x={230} y={118} w={180} h={40} label={t('网关（mTLS）', 'Gateway (mTLS)')} />
      <Arrow id="fig-a" d="M320 82V114" />
      <Box x={20} y={200} w={180} h={64} label={t('自有节点', 'Your nodes')} sub="OpenResty" tone="ok" />
      <Box x={230} y={200} w={180} h={64} label={t('订阅节点', 'Subscribed nodes')} sub={t('节点市场', 'Node market')} tone="ok" />
      <Box x={440} y={200} w={180} h={64} label={t('云 CDN', 'Cloud CDNs')} sub="CF · CloudFront · EO · ESA" tone="warn" />
      <Arrow id="fig-a" d="M280 158L120 196" dashed className={flow} />
      <Arrow id="fig-a" d="M320 158V196" dashed className={flow} />
      <Arrow id="fig-a" d="M410 82C560 120 540 160 530 196" dashed label={t('API', 'API')} lx={540} ly={140} className={flow} />
      <Box x={20} y={320} w={150} h={50} label={t('访客', 'Visitors')} />
      <Box x={470} y={320} w={150} h={50} label={t('源站', 'Origin')} />
      <Arrow id="fig-a" d="M95 320V268" />
      <Arrow id="fig-a" d="M170 345H466" label={t('就近接入 → 缓存 → 回源', 'nearest edge → cache → origin')} lx={318} ly={366} />
      <Arrow id="fig-a" d="M320 268V341" />
      <text x={320} y={404} textAnchor="middle" fontSize={12} fill={C.muted}>{t('虚线：管理与下发；实线：访客流量', 'Dashed: management & delivery · Solid: visitor traffic')}</text>
      {animated ? (
        <g aria-hidden="true">
          <rect x={170} y={16} width={300} height={66} rx={10} className="arch-pulse" />
          {[[188, 210], [398, 210], [608, 210]].map(([x, y]) => <circle key={x} cx={x} cy={y} r={4} className="arch-beat" />)}
          <circle r={5} className="arch-pkt arch-cfg arch-cfg-1" />
          <circle r={5} className="arch-pkt arch-cfg arch-cfg-2" />
          <circle r={5} className="arch-pkt arch-cfg arch-cfg-3" />
          <circle r={5} className="arch-pkt arch-ok arch-ok-1" />
          <circle r={5} className="arch-pkt arch-ok arch-ok-2" />
          <circle r={5} className="arch-pkt arch-ok arch-ok-3" />
          <circle r={5} className="arch-pkt arch-ok arch-ok-4" />
          <circle r={5} className="arch-pkt arch-bad arch-bad-1" />
          <circle r={5} className="arch-pkt arch-bad arch-bad-2" />
          <g className="arch-shield">
            <circle cx={118} cy={268} r={14} />
            <text x={150} y={292} textAnchor="middle" fontSize={11}>{t('已拦截', 'Blocked')}</text>
          </g>
        </g>
      ) : null}
    </Svg>
  )
}

/** 图 B：节点订阅转售链 */
export function FigResale({ lang }: { lang: Lang }) {
  const t = (zh: string, en: string) => (lang === 'zh' ? zh : en)
  return (
    <Svg id="fig-b" w={720} h={230}
      title={t('节点订阅与转售链', 'Node subscription and resale chain')}
      desc={t('供给方 A 把节点挂到市场；订阅方 B 把自有节点与 A 的节点组合后再卖给 C。每条边各有一本账，按用量逐级结算。',
        'Supplier A lists nodes; subscriber B combines its own nodes with A’s and resells to C. Every hop keeps its own ledger and settles by usage.')}>
      <Box x={16} y={70} w={180} h={80} label={t('供给方 A', 'Supplier A')} sub={t('自有节点上架', 'lists own nodes')} tone="ok" />
      <Box x={270} y={70} w={180} h={80} label={t('订阅方 B', 'Subscriber B')} sub={t('自有 + A 的节点', 'own + A’s nodes')} tone="brand" />
      <Box x={524} y={70} w={180} h={80} label={t('订阅方 C', 'Subscriber C')} sub={t('网站接入', 'serves sites')} tone="ok" />
      <Arrow id="fig-b" d="M196 110H266" label={t('预付订阅', 'prepaid')} lx={231} ly={100} />
      <Arrow id="fig-b" d="M450 110H520" label={t('再组合转售', 'resell')} lx={485} ly={100} />
      <Arrow id="fig-b" d="M614 160C614 210 106 210 106 156" dashed />
      <text x={360} y={222} textAnchor="middle" fontSize={12} fill={C.muted}>{t('站点下发到实际供给节点；用量逐级结算，每条边一本账', 'Sites are delivered to the supplying nodes; usage settles hop by hop')}</text>
      <text x={360} y={36} textAnchor="middle" fontSize={13} fill={C.text}>{t('按天 · 按流量 · 95 带宽 · 日峰值', 'Per day · per GB · 95th percentile · daily peak')}</text>
    </Svg>
  )
}

/** 图 C：自动防御闭环 */
export function FigDefenseLoop({ lang }: { lang: Lang }) {
  const t = (zh: string, en: string) => (lang === 'zh' ? zh : en)
  const steps: [string, string][] = [
    [t('学习基线', 'Learn baseline'), t('节点本地', 'on the node')],
    [t('判定可疑', 'Detect'), t('带原因', 'with reasons')],
    [t('挖掘规则', 'Mine rules'), t('影子观察', 'shadow mode')],
    [t('分级处置', 'Mitigate'), t('按级别', 'by level')],
    [t('自动撤销', 'Auto revoke'), t('攻击结束', 'when it ends')],
  ]
  const cx = 300, cy = 190, r = 140
  const pts = steps.map((_, i) => {
    const a = -Math.PI / 2 + (i * 2 * Math.PI) / steps.length
    return { x: cx + r * Math.cos(a), y: cy + r * Math.sin(a) }
  })
  return (
    <Svg id="fig-c" w={600} h={380}
      title={t('智能自动防御闭环', 'Automatic defense loop')}
      desc={t('五步闭环：节点本地学习基线，判定可疑并给出原因，挖掘规则先影子观察，分级处置，攻击结束后自动撤销。跨节点只广播已确认的签名。',
        'A five-step loop: learn a baseline on the node, detect with reasons, mine rules in shadow mode, mitigate by level, and revoke automatically. Only confirmed signatures are shared across nodes.')}>
      <circle cx={cx} cy={cy} r={r} fill="none" stroke={C.soft} strokeWidth={22} />
      {pts.map((p, i) => {
        const q = pts[(i + 1) % pts.length]
        const mx = (p.x + q.x) / 2, my = (p.y + q.y) / 2
        const ox = cx + (mx - cx) * 1.12, oy = cy + (my - cy) * 1.12
        return <Arrow key={i} id="fig-c" d={`M${p.x} ${p.y}Q${ox} ${oy} ${q.x} ${q.y}`} />
      })}
      {pts.map((p, i) => (
        <Box key={i} x={p.x - 70} y={p.y - 28} w={140} h={56} label={steps[i][0]} sub={steps[i][1]} tone={i === 3 ? 'brand' : 'plain'} />
      ))}
      <text x={cx} y={cy - 4} textAnchor="middle" fontSize={15} fontWeight={700} fill={C.text}>{t('每站基线 ≤ 2 KB', '≤ 2 KB per site')}</text>
      <text x={cx} y={cy + 18} textAnchor="middle" fontSize={12} fill={C.muted}>{t('跨节点只广播已确认签名', 'only confirmed signatures shared')}</text>
    </Svg>
  )
}

/** 图 F：聚合边缘调度 */
export function FigAggregated({ lang }: { lang: Lang }) {
  const t = (zh: string, en: string) => (lang === 'zh' ? zh : en)
  const targets = [t('自有节点', 'Your nodes'), 'Cloudflare', 'CloudFront', 'EdgeOne', 'ESA']
  return (
    <Svg id="fig-f" w={700} h={300}
      title={t('聚合边缘调度', 'Aggregated edge scheduling')}
      desc={t('主控的调度器按地区、运营商与可用性，在自有节点与 Cloudflare、CloudFront、EdgeOne、ESA 四家云 CDN 之间分配流量。云账号归用户，凭据只存本地主控。',
        'The scheduler in the control plane splits traffic across your nodes and four cloud CDNs (Cloudflare, CloudFront, EdgeOne, ESA) by region, carrier and availability. Cloud accounts stay yours; credentials are stored only in your control plane.')}>
      <Box x={250} y={16} w={200} h={70} label={t('调度器', 'Scheduler')} sub={t('地区 · 运营商 · 可用性', 'region · carrier · health')} tone="brand" />
      {targets.map((name, i) => {
        const x = 16 + i * 136
        return (
          <g key={name}>
            <Arrow id="fig-f" d={`M350 86C350 140 ${x + 60} 150 ${x + 60} 196`} />
            <Box x={x} y={200} w={120} h={60} label={name} tone={i === 0 ? 'ok' : 'warn'} />
          </g>
        )
      })}
      <text x={350} y={290} textAnchor="middle" fontSize={12} fill={C.muted}>{t('云账号归你，凭据只存在你的主控', 'Cloud accounts stay yours; credentials never leave your control plane')}</text>
    </Svg>
  )
}

/** 图 G：插件卡片示意（自绘，不截图） */
export function FigPluginCard({ lang }: { lang: Lang }) {
  const t = (zh: string, en: string) => (lang === 'zh' ? zh : en)
  const states = [t('购买', 'Buy'), t('下载', 'Download'), t('启用', 'Enable')]
  return (
    <Svg id="fig-g" w={520} h={250}
      title={t('插件卡片示意', 'Plugin card illustration')}
      desc={t('插件卡片：名称、官方或认证开发者角标、免费/一次性/订阅价格方式，按钮依次为购买、下载、启用。',
        'A plugin card shows the name, an official or verified-developer badge and the pricing model (free, one-off, subscription); its button moves through buy, download and enable.')}>
      <rect x={16} y={16} width={488} height={218} rx={14} fill="#fff" stroke={C.line} />
      <rect x={40} y={40} width={56} height={56} rx={12} fill={C.soft} />
      <path d="M58 68h20M68 58v20" stroke={C.brand} strokeWidth={4} strokeLinecap="round" />
      <text x={112} y={62} fontSize={18} fontWeight={700} fill={C.text}>{t('示例规则包', 'Sample rule pack')}</text>
      <rect x={112} y={74} width={84} height={24} rx={6} fill={C.warnSoft} stroke={C.warn} />
      <text x={154} y={91} textAnchor="middle" fontSize={12} fontWeight={700} fill={C.warn}>{t('官方', 'Official')}</text>
      <rect x={204} y={74} width={110} height={24} rx={6} fill={C.okSoft} stroke={C.ok} />
      <text x={259} y={91} textAnchor="middle" fontSize={12} fontWeight={700} fill={C.ok}>{t('认证开发者', 'Verified dev')}</text>
      <text x={40} y={130} fontSize={14} fill={C.muted}>{t('免费 / 一次性 / 按月或按年订阅', 'Free / one-off / monthly or yearly')}</text>
      {states.map((s, i) => (
        <g key={s}>
          <rect x={40 + i * 150} y={158} width={130} height={44} rx={8} fill={i === 0 ? C.brand : '#fff'} stroke={C.brand} strokeWidth={1.5} />
          <text x={105 + i * 150} y={186} textAnchor="middle" fontSize={15} fontWeight={700} fill={i === 0 ? '#fff' : C.brand}>{s}</text>
          {i < 2 ? <Arrow id="fig-g" d={`M${172 + i * 150} 180H${186 + i * 150}`} /> : null}
        </g>
      ))}
    </Svg>
  )
}

const FLOWS = {
  D: {
    title: { zh: '动态路由请求路径', en: 'Dynamic routing request path' },
    desc: { zh: '请求按 Host 或 SNI 在共享字典里查到站点，加载签名站点对象，依次经过安全阶段、缓存，最后回源。站点增删改只更新数据，不 reload。', en: 'A request is matched by Host or SNI in a shared dictionary, the signed site object is loaded, then security, cache and origin fetch run in order. Site changes only update data — no reload.' },
    steps: [
      { zh: 'Host / SNI', en: 'Host / SNI' },
      { zh: '共享字典查站点', en: 'Shared-dict lookup' },
      { zh: '签名站点对象', en: 'Signed site object' },
      { zh: '安全阶段', en: 'Security phase' },
      { zh: '缓存', en: 'Cache' },
      { zh: '回源', en: 'Origin' },
    ],
    perRow: 3,
  },
  E: {
    title: { zh: 'WAF 规则情报回路', en: 'WAF rule-intelligence loop' },
    desc: { zh: '节点按站点画像自动排除误报，主控汇总后提交授权端规则情报，去重合并成官方规则库，再下发给所有主控。', en: 'Nodes profile each site and auto-exclude false positives; the control plane forwards evidence to rule intelligence, which deduplicates and merges it into the official rule library delivered back to every control plane.' },
    steps: [
      { zh: '节点画像', en: 'Node profiling' },
      { zh: '自动排除误报', en: 'Auto exclusions' },
      { zh: '主控汇总', en: 'Control plane' },
      { zh: '规则情报去重合并', en: 'Rule intelligence' },
      { zh: '官方规则库', en: 'Official rules' },
      { zh: '下发所有主控', en: 'All control planes' },
    ],
    perRow: 3,
  },
  H: {
    title: { zh: '开发者上架流程', en: 'Developer publishing flow' },
    desc: { zh: '八步：实名入驻，申请命名空间与发布者密钥，上传版本，自动审核，市场签发目录，进入各主控的插件市场，买家购买，结算打款。', en: 'Eight steps: verify identity, get a namespace and publisher key, upload a version, automated review, the market signs the catalogue, it appears in every control plane, buyers purchase, payouts are settled.' },
    steps: [
      { zh: '实名入驻', en: 'Verify identity' },
      { zh: '命名空间与密钥', en: 'Namespace & key' },
      { zh: '上传版本', en: 'Upload version' },
      { zh: '自动审核', en: 'Auto review' },
      { zh: '市场签目录', en: 'Signed catalogue' },
      { zh: '主控内上架', en: 'In every console' },
      { zh: '买家购买', en: 'Buyers purchase' },
      { zh: '结算打款', en: 'Payout' },
    ],
    perRow: 4,
  },
  I: {
    title: { zh: '插件收入路径', en: 'Plugin income path' },
    desc: { zh: '买家在主控内付款给平台托管，许可证生效后进入开发者待结算，按结算规则打款给开发者。', en: 'Buyers pay into escrow from their control plane; once the licence is active the amount becomes the developer’s pending balance and is paid out under the settlement rules.' },
    steps: [
      { zh: '买家在主控付款', en: 'Buyer pays' },
      { zh: '平台托管', en: 'Escrow' },
      { zh: '开发者待结算', en: 'Pending balance' },
      { zh: '打款到开发者', en: 'Payout' },
    ],
    perRow: 4,
  },
  J: {
    title: { zh: '节点市场直结', en: 'Node market direct settlement' },
    desc: { zh: '订阅方一键充值，钱直接进供货方自己配置的收款商户号，支付回调自动给订阅方记余额，平台不经手资金。', en: 'The subscriber tops up in one click; money goes straight to the supplier’s own merchant account and the payment callback credits the balance automatically. The platform never holds the funds.' },
    steps: [
      { zh: '订阅方一键充值', en: 'Subscriber tops up' },
      { zh: '供货方商户号', en: 'Supplier merchant' },
      { zh: '回调自动记余额', en: 'Callback credits' },
    ],
    perRow: 3,
  },
} satisfies Record<string, { title: L; desc: L; steps: L[]; perRow: number }>

export type FlowKey = keyof typeof FLOWS

export function FigFlow({ k, lang }: { k: FlowKey; lang: Lang }) {
  const f = FLOWS[k]
  return <Flow id={`fig-${k.toLowerCase()}`} lang={lang} title={f.title} desc={f.desc} steps={f.steps} perRow={f.perRow} />
}
