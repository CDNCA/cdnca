import { useCallback, useEffect, useState } from 'react'
import { geoAreas } from '../../../web/src/api/geoAreas'
import { PageHero, Section } from '../components/Blocks'
import { marketApi, offerPrice, type PublicOffer, type PublicPlugin } from '../content/marketApi'
import { href, type L, type Lang } from '../i18n'
import { LINKS } from '../site'

// 市场公开页（www-design.md §3.4）：只展示“有什么”，不放套餐价、不放平台抽成。
// 价格是供货方自定，按接口原样显示。订阅节点与获取/购买插件都在客户自己的主控里办（官网不知道客户主控地址），
// 所以按钮指向对应的操作说明（C04/MARKET-01/02），不再把节点订阅指到授权门户。
// 预渲染只出骨架（加载中），数据在浏览器端拉取。

const T = {
  title: { zh: '市场', en: 'Market' },
  lead: { zh: '节点市场的供货方报价与插件市场的条目。订阅节点、获取或购买插件都在你自己的主控里操作；还没有主控请先在授权门户取得授权并安装。', en: 'Node offers from suppliers and plugin market listings. Subscribe to nodes and get or buy plugins inside your own control plane; without one, get a licence from the licence portal and install it first.' },
  nodes: { zh: '节点市场', en: 'Node market' },
  nodesLead: { zh: '价格由供货方自定，以下按供货方填写原样展示。', en: 'Suppliers set their own prices; shown exactly as listed.' },
  plugins: { zh: '插件市场', en: 'Plugin market' },
  loading: { zh: '正在加载公开数据…', en: 'Loading public listings…' },
  empty: { zh: '暂无公开数据。', en: 'No public listings yet.' },
  unavailable: { zh: '暂无公开数据（市场接口暂时不可用）。', en: 'No public listings right now (the market API is unavailable).' },
  portal: { zh: '前往授权门户', en: 'Open the licence portal' },
  subscribe: { zh: '在主控中订阅', en: 'Subscribe in your control plane' },
  buy: { zh: '在主控中购买', en: 'Buy in your control plane' },
  get: { zh: '在主控中获取', en: 'Get it in your control plane' },
  included: { zh: '新装主控已内置', en: 'Included in new control planes' },
  howTo: { zh: '查看操作说明', en: 'How to do it' },
  more: { zh: '更多条目请登录后查看。', en: 'Sign in to see more.' },
  trial: { zh: '天试用', en: '-day trial' },
  area: { zh: '节点大区', en: 'Node area' },
  areaAll: { zh: '全部大区', en: 'All areas' },
  areaWhole: { zh: '（全部）', en: ' (all)' },
  areaEmpty: { zh: '所选大区暂无供货方上架节点，可以换一个大区看看。', en: 'No supplier has listed nodes in this area yet; try another area.' },
}

// 大区来自 libs/geoarea 生成的控制台镜像（apps/web/src/api/geoAreas.ts，web_mirror_test.go 保证一致）。
// 「全球」在市场接口里等于不过滤，所以不单列；每个大洲一组：先是整个大洲，再是它下面的区域。
const CONTINENTS = geoAreas.filter((a) => a.level === 'continent')
const areaName = (a: { name_zh: string; name_en: string }, lang: Lang) => (lang === 'zh' ? a.name_zh : a.name_en)

function AreaPicker({ lang, value, onChange }: { lang: Lang; value: string; onChange: (v: string) => void }) {
  return (
    <label className="market-area">
      <span>{T.area[lang]}</span>
      <select value={value} onChange={(e) => onChange(e.target.value)}>
        <option value="">{T.areaAll[lang]}</option>
        {CONTINENTS.map((c) => (
          <optgroup key={c.code} label={areaName(c, lang)}>
            <option value={c.code}>{`${areaName(c, lang)}${T.areaWhole[lang]}`}</option>
            {geoAreas.filter((a) => a.parent === c.code).map((a) => <option key={a.code} value={a.code}>{areaName(a, lang)}</option>)}
          </optgroup>
        ))}
      </select>
    </label>
  )
}

const BILLING: Record<string, L> = {
  daily_bundle: { zh: '按天', en: 'Per day' },
  traffic: { zh: '按流量', en: 'Per GB' },
  bandwidth_95: { zh: '95 带宽', en: '95th percentile' },
  bandwidth_daily_peak: { zh: '日峰值带宽', en: 'Daily peak' },
  committed_plus_overage: { zh: '保底 + 超额', en: 'Commit + overage' },
}
const TIER: Record<string, L> = {
  high: { zh: '质量高', en: 'High quality' },
  standard: { zh: '质量标准', en: 'Standard quality' },
  low: { zh: '质量偏低', en: 'Low quality' },
  insufficient: { zh: '样本不足', en: 'Not enough data' },
}
const PUBLISHER: Record<string, L> = {
  official: { zh: '官方', en: 'Official' },
  certified: { zh: '认证开发者', en: 'Verified developer' },
  third_party: { zh: '第三方', en: 'Third party' },
}
const PRICE_MODEL: Record<string, L> = {
  free: { zh: '免费', en: 'Free' },
  one_time: { zh: '一次性', en: 'One-off' },
  subscription_month: { zh: '按月订阅', en: 'Monthly' },
  subscription_year: { zh: '按年订阅', en: 'Yearly' },
}

const SUBSCRIBE_GUIDE = '/docs/market-subscriber#browse'

/**
 * 插件按价格说清动作（C04/MARKET-02）：官方免费模块新装主控已内置；其他免费插件“获取”；收费插件“购买”。
 * 都指向插件文档里对应的段落。
 */
function PluginAction({ lang, plugin }: { lang: Lang; plugin: PublicPlugin }) {
  const free = plugin.price_models.length > 0 && plugin.price_models.every((model) => model === 'free')
  const [label, target] = free && plugin.publisher_kind === 'official' ? [T.included, '/docs/plugins#official']
    : free ? [T.get, '/docs/plugins#admin'] : [T.buy, '/docs/plugins#admin']
  const name = plugin.title || plugin.plugin_id
  return <a href={href(lang, target)} aria-label={`${label[lang]}：${name}`}>{label[lang]} →</a>
}

type State<T> = { status: 'loading' } | { status: 'ok'; items: T[]; more: boolean } | { status: 'error' }

function useListing<T>(load: (signal: AbortSignal) => Promise<{ items: T[]; has_more: boolean }>) {
  const [state, setState] = useState<State<T>>({ status: 'loading' })
  useEffect(() => {
    // 换筛选条件时先回到加载中，不把上一次的结果当成新条件的结果。
    setState({ status: 'loading' })
    const ctl = new AbortController()
    load(ctl.signal).then(
      (r) => setState({ status: 'ok', items: r.items, more: r.has_more }),
      () => { if (!ctl.signal.aborted) setState({ status: 'error' }) },
    )
    return () => ctl.abort()
  }, [load])
  return state
}

function Fallback({ lang, state, guide }: { lang: Lang; state: 'loading' | 'error' | 'empty'; guide: string }) {
  if (state === 'loading') return <p role="status" aria-live="polite">{T.loading[lang]}</p>
  return (
    <div role="status" className="card">
      <p>{state === 'error' ? T.unavailable[lang] : T.empty[lang]}</p>
      <a className="btn btn-ghost" href={href(lang, guide)}>{T.howTo[lang]}</a>
    </div>
  )
}

function NodeOffers({ lang }: { lang: Lang }) {
  const [area, setArea] = useState('')
  const load = useCallback((signal: AbortSignal) => marketApi.nodeOffers(signal, area), [area])
  const s = useListing<PublicOffer>(load)
  return (
    <>
      <AreaPicker lang={lang} value={area} onChange={setArea} />
      <NodeOfferList lang={lang} s={s} area={area} />
    </>
  )
}

function NodeOfferList({ lang, s, area }: { lang: Lang; s: State<PublicOffer>; area: string }) {
  if (s.status !== 'ok') return <Fallback lang={lang} state={s.status} guide={SUBSCRIBE_GUIDE} />
  if (!s.items.length && area) return <div role="status" className="card"><p>{T.areaEmpty[lang]}</p></div>
  if (!s.items.length) return <Fallback lang={lang} state="empty" guide={SUBSCRIBE_GUIDE} />
  return (
    <>
      <ul className="grid grid-3 api-groups" aria-label={T.nodes[lang]}>
        {s.items.map((o) => (
          <li key={o.id} className="card">
            <h3>{o.name}</h3>
            <p className="muted">{o.seller_name}</p>
            <p>
              {[...new Set([...o.regions, ...o.carriers, o.line_class, ...(o.custom ?? [])])].filter(Boolean).map((t) => <span key={t} className="tag">{t}</span>)}{' '}
              {o.quality_tier && TIER[o.quality_tier] ? <span className="tag tag-key">{TIER[o.quality_tier][lang]}</span> : null}
            </p>
            <p><strong>{offerPrice(o, lang)}</strong> · {(BILLING[o.billing_model] ?? { zh: o.billing_model, en: o.billing_model })[lang]}{o.trial_days > 0 ? ` · ${o.trial_days}${T.trial[lang]}` : ''}</p>
            <a className="btn btn-primary" href={href(lang, SUBSCRIBE_GUIDE)} aria-label={`${T.subscribe[lang]}：${o.name}`}>{T.subscribe[lang]}</a>
          </li>
        ))}
      </ul>
      {s.more ? <p className="muted">{T.more[lang]}</p> : null}
    </>
  )
}

function Plugins({ lang }: { lang: Lang }) {
  const s = useListing<PublicPlugin>(marketApi.plugins)
  if (s.status !== 'ok') return <Fallback lang={lang} state={s.status} guide="/docs/plugins#admin" />
  if (!s.items.length) return <Fallback lang={lang} state="empty" guide="/docs/plugins#admin" />
  return (
    <>
      <ul className="grid grid-3 api-groups" aria-label={T.plugins[lang]}>
        {s.items.map((p) => (
          <li key={p.id} className="card">
            <p>
              <span className={p.publisher_kind === 'official' ? 'tag tag-official' : 'tag'}>{(PUBLISHER[p.publisher_kind] ?? PUBLISHER.third_party)[lang]}</span>{' '}
              <code>{p.kind}</code>
            </p>
            <h3>{p.title || p.plugin_id}</h3>
            <p>{p.summary}</p>
            <p className="muted">{p.price_models.map((m) => (PRICE_MODEL[m] ?? { zh: m, en: m })[lang]).join(' / ')}{p.latest_version ? ` · v${p.latest_version}` : ''}</p>
            <PluginAction lang={lang} plugin={p} />
          </li>
        ))}
      </ul>
      {s.more ? <p className="muted">{T.more[lang]}</p> : null}
    </>
  )
}

export function MarketPage({ lang }: { lang: Lang }) {
  return (
    <>
      <PageHero title={T.title[lang]} lead={T.lead[lang]}>
        <div className="btn-row">
          <a className="btn btn-primary" href={LINKS.login}>{T.portal[lang]}</a>
          <a className="btn btn-ghost" href={href(lang, '/features/node-market')}>{lang === 'zh' ? '节点订阅怎么用' : 'How node subscriptions work'}</a>
        </div>
      </PageHero>
      <Section id="nodes" title={T.nodes[lang]} lead={T.nodesLead[lang]}><NodeOffers lang={lang} /></Section>
      <Section id="plugins" title={T.plugins[lang]} alt><Plugins lang={lang} /></Section>
    </>
  )
}
