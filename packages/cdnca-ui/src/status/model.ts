// 公开状态页的数据模型与纯函数。数据只来自同源接口返回的状态快照。
export type Lang = 'zh' | 'en'
/** unconfigured：没有可判断的证据（无节点、无任务、未配置拨测），不采样、不计可用率、不拉低总体状态。 */
export type Status = 'operational' | 'degraded' | 'outage' | 'maintenance' | 'unconfigured'
export type DayStatus = Status | 'no_data' | 'before_monitoring'
export interface Text { zh: string; en: string }
export interface DayEvent {
  id?: string; status?: string
  kind: 'incident' | 'maintenance'; title: Text; impact: 'degraded' | 'outage' | 'maintenance'; start: string; end?: string; minutes: number
}
export interface Day {
  day: string; status: DayStatus; uptime: number | null
  /** 仅 before_monitoring 的日子有：该组件监测开始的日期（UTC）。 */
  since?: string
  sampled?: number; degraded?: number; outage?: number; maintenance?: number
  /** 正常 / 暂无数据的分钟数（后端算好；旧数据没有时由 daySplit 推出）。 */
  operational?: number; no_data?: number
  avg_ms?: number; events?: DayEvent[]
}
export interface Component {
  key: string; name: Text; status: Status; note: Text; mode?: 'group' | 'auto' | 'manual'; parent?: string
  history?: Day[]; uptime_90d?: number | null
  /** 监测开始日（UTC，YYYY-MM-DD）：第一条真实样本的日期；分组取组内最早。序列里没有任何样本时为 undefined。 */
  monitoring_since?: string
}
export interface Update { id: string; status: string; message: Text; created_at: string }
export interface Incident {
  id: string; kind: 'incident' | 'maintenance'; title: Text; impact: 'degraded' | 'outage' | 'maintenance'; status: string
  component_keys: string[]; scheduled_start?: string; scheduled_end?: string; started_at: string; resolved_at?: string; updates: Update[]
}
export interface View {
  schema: string; status: Status
  /** 仅主控状态页有：客户自己的标题、说明和是否显示 logo。 */
  title?: string; description?: string; show_logo?: boolean; components: Component[]; active: Incident[]; upcoming: Incident[]; recent: Incident[]
  generated_at: string
}
/** 页面上的一张卡片：分组（带子组件）或没有子组件的独立组件。 */
export interface Group { item: Component; children: Component[] }

/** 同源快照地址。浏览器只读这一个地址。 */
export const SNAPSHOT_URL = '/status.json'
export const SCHEMA = 'cdnca.platform-status/v1'
/** 主控公开状态页（services/control-api statuspage）的 schema。 */
export const CONTROL_SCHEMA = 'cdnca.status-page/v2'
export const FETCH_TIMEOUT_MS = 8000
/** 快照比这更旧就带「更新稍有延迟」标记。 */
export const SNAPSHOT_FRESH_MS = 5 * 60_000
/** 日色分档（仅用于说明文字）：可用率 ≥99.9% 正常，≥99% 降级，否则中断。 */
export const UPTIME_NORMAL = 0.999
export const UPTIME_DEGRADED = 0.99

export function pickLang(search: string, languages: readonly string[]): Lang {
  const query = new URLSearchParams(search).get('lang')
  if (query === 'zh' || query === 'en') return query
  const first = languages.find((value) => /^(zh|en)\b/i.test(value))
  return first?.toLowerCase().startsWith('en') ? 'en' : 'zh'
}

/** 校验返回的形状；不是预期结构时返回 null（按取不到处理；nginx 回退页的 HTML 也走这里）。 */
export function parseView(value: unknown): View | null {
  const view = value as Partial<View> | null
  if (!view || (view.schema !== SCHEMA && view.schema !== CONTROL_SCHEMA) || !Array.isArray(view.components) || !Array.isArray(view.active)) return null
  return withMonitoring({
    ...(view as View), upcoming: Array.isArray(view.upcoming) ? view.upcoming : [],
    recent: Array.isArray(view.recent) ? view.recent : [],
  })
}

/** 快照够新直接用；比 SNAPSHOT_FRESH_MS 旧仍显示，带过期标记；取不到返回 null。 */
export interface Fetched { view: View; stale: boolean }
export function chooseView(snapshot: View | null, now: number): Fetched | null {
  if (!snapshot) return null
  return { view: snapshot, stale: now - new Date(snapshot.generated_at).getTime() > SNAPSHOT_FRESH_MS }
}

export function text(value: Text, lang: Lang): string {
  return (lang === 'en' ? value.en : value.zh) || value.zh || value.en
}

/** 按 parent 分组，保持接口给出的顺序；找不到分组的子组件按独立组件处理。 */
export function groupComponents(components: Component[]): Group[] {
  const keys = new Set(components.map((item) => item.key))
  const groups: Group[] = []
  const byKey = new Map<string, Group>()
  for (const item of components) {
    if (item.parent && keys.has(item.parent)) continue
    const group = { item, children: [] as Component[] }
    groups.push(group)
    byKey.set(item.key, group)
  }
  for (const item of components) if (item.parent) byKey.get(item.parent)?.children.push(item)
  return groups
}

/** 可用率向下取整到两位小数：有中断分钟时不会显示成 100.00%。 */
export function formatUptime(value: number, lang: Lang): string {
  const floored = Math.floor(value * 10000) / 10000
  return new Intl.NumberFormat(lang === 'en' ? 'en-US' : 'zh-CN', { style: 'percent', minimumFractionDigits: 2, maximumFractionDigits: 2 }).format(floored)
}

/** 顶部「已计划 N 次维护」：进行中和即将开始的维护个数，以及最近的一个时间（没有就取最近一次已完成的）。 */
export function maintenanceSummary(view: View): { count: number; next?: string; last?: string } {
  const open = [...view.active.filter((item) => item.kind === 'maintenance'), ...view.upcoming]
  const starts = open.map((item) => item.scheduled_start ?? item.started_at).sort()
  const done = view.recent.filter((item) => item.kind === 'maintenance' && item.resolved_at).map((item) => item.scheduled_start ?? item.started_at).sort()
  return { count: open.length, next: starts[0], last: done[done.length - 1] }
}

// ---- 路由：hash，#/incident/<id> 为事件详情，其余都是列表 ----
export type Route = { name: 'list' } | { name: 'incident'; id: string }
export function parseRoute(hash: string): Route {
  const match = /^#\/incident\/([^/?#]+)\/?$/.exec(hash)
  if (!match) return { name: 'list' }
  try {
    const id = decodeURIComponent(match[1])
    return id ? { name: 'incident', id } : { name: 'list' }
  } catch {
    return { name: 'list' }
  }
}
export function incidentHref(id: string): string { return `#/incident/${encodeURIComponent(id)}` }

/** 在 active、upcoming、recent 里按 id 找事件；只有 90 天内的查得到。 */
export function findIncident(view: View, id: string): Incident | null {
  return [...view.active, ...view.upcoming, ...view.recent].find((item) => item.id === id) ?? null
}

/** component_keys 可能是分组 key，也可能是子组件 key：都对应到组件名；子组件带上所属分组名。查不到的 key 原样保留。 */
export interface Affected { key: string; name: string; parent?: string }
export function affectedComponents(view: View, keys: string[], lang: Lang): Affected[] {
  const byKey = new Map(view.components.map((item) => [item.key, item]))
  return keys.map((key) => {
    const item = byKey.get(key)
    if (!item) return { key, name: key }
    const parent = item.parent ? byKey.get(item.parent) : undefined
    return { key, name: text(item.name, lang), parent: parent ? text(parent.name, lang) : undefined }
  })
}

// ---- 事件起止与时段轴 ----
export const DAY_MS = 86_400_000
export const impactOf = (impact: string): 'degraded' | 'outage' | 'maintenance' => (impact === 'outage' || impact === 'maintenance' ? impact : 'degraded')

/** 事件起止：维护优先取计划时段；没有结束时间表示仍在进行（end 为 undefined）。 */
export function incidentSpan(item: Incident): { start: string; end?: string } {
  if (item.kind === 'maintenance' && item.scheduled_start) return { start: item.scheduled_start, end: item.scheduled_end ?? item.resolved_at }
  return { start: item.started_at, end: item.resolved_at }
}

export interface Segment { impact: 'degraded' | 'outage' | 'maintenance'; left: number; width: number }
/** 把若干时段放到 [from, to) 窗口上，输出百分比位置；太短的至少 1.2% 宽，保证看得见；窗口外的丢弃。 */
export function segmentsIn(from: number, to: number, spans: { impact: string; start: number; end: number }[]): Segment[] {
  const total = to - from
  if (total <= 0) return []
  const out: Segment[] = []
  for (const span of spans) {
    const start = Math.max(from, span.start)
    const end = Math.min(to, span.end)
    if (end < start || (end === start && span.start !== span.end)) continue
    const left = ((start - from) / total) * 100
    const width = Math.max(1.2, ((end - start) / total) * 100)
    out.push({ impact: impactOf(span.impact), left: Math.min(left, 100 - width), width })
  }
  return out
}

export const dayStart = (day: string): number => new Date(`${day}T00:00:00Z`).getTime()

/** 相隔天数：day 与 today 都是 YYYY-MM-DD（UTC）。 */
export function daysBetween(day: string, today: string): number { return Math.round((dayStart(today) - dayStart(day)) / DAY_MS) }

// ---- 监测开始日：区分「监测开始前」和「监测中但当天缺样本」 ----
const realDay = (day: Day) => day.status !== 'no_data' && day.status !== 'before_monitoring'

/**
 * 监测开始日 = 该组件第一条真实样本的日期（分组取组内最早）；接口给了 monitoring_since 就以接口为准。
 * 开始日之前的 no_data 改成 before_monitoring；开始日之后的缺样本仍是 no_data。不生成任何样本，可用率不动。
 * 每次从原始快照重新算，重复调用结果一致。
 */
export function withMonitoring(view: View): View {
  const own = new Map(view.components.map((item) => [item.key, item.monitoring_since ?? item.history?.find(realDay)?.day]))
  const earliest = new Map<string, string | undefined>()
  for (const item of view.components) {
    const dates = [own.get(item.key), ...view.components.filter((child) => child.parent === item.key).map((child) => own.get(child.key))].filter((v): v is string => Boolean(v))
    earliest.set(item.key, dates.sort()[0])
  }
  return {
    ...view,
    components: view.components.map((item) => {
      const since = earliest.get(item.key)
      if (!item.history) return { ...item, monitoring_since: since }
      const history = item.history.map((day): Day => (since && day.status === 'no_data' && day.day < since ? { ...day, status: 'before_monitoring', since } : day))
      return { ...item, monitoring_since: since, history }
    }),
  }
}

/** 90 天可用率旁的「自 YYYY-MM-DD 起」：监测开始日晚于窗口第一天才写，满 90 天后自动消失。 */
export function uptimeSince(item: Component): string | null {
  const first = item.history?.[0]?.day
  return item.uptime_90d != null && item.monitoring_since && first && item.monitoring_since > first ? item.monitoring_since : null
}


// ---- 日竖条按当天各状态时长占比分段着色 ----
export type SplitKey = 'operational' | 'degraded' | 'outage' | 'maintenance' | 'no_data'
export type Split = Record<SplitKey, number>
/** 从下到上的顺序：正常、降级、中断、维护、暂无数据。 */
export const SPLIT_ORDER: SplitKey[] = ['operational', 'degraded', 'outage', 'maintenance', 'no_data']
const SPLIT_VAR: Record<SplitKey, string> = { operational: '--bar-ok', degraded: '--bar-warn', outage: '--bar-bad', maintenance: '--bar-maint', no_data: '--bar-none' }
/** 任何非零异常段至少占竖条高度的这个比例（约 2px），短时故障不会消失。 */
export const MIN_SEGMENT = 0.08

/**
 * 当天各状态的分钟数。后端给了 operational / no_data 就直接用；旧数据没有时，
 * 正常 = 有样本的分钟里扣掉降级、中断、维护，暂无数据记 0（旧数据没有给出已过去的时长）。
 * 没有样本的日子（no_data / before_monitoring）返回 null，竖条保持单色。
 */
export function daySplit(day: Day): Split | null {
  if (day.status === 'no_data' || day.status === 'before_monitoring' || !(day.sampled && day.sampled > 0)) return null
  const degraded = day.degraded ?? 0
  const outage = day.outage ?? 0
  const maintenance = day.maintenance ?? 0
  const operational = day.operational ?? Math.max(day.sampled - degraded - outage - maintenance, 0)
  return { operational, degraded, outage, maintenance, no_data: day.no_data ?? 0 }
}

export interface BarStop { key: SplitKey; from: number; to: number }
/**
 * 把各状态分钟数换成竖条上的占比区间（0 在底部、1 在顶部），顺序同 SPLIT_ORDER。
 * 非零的异常段（降级、中断、维护）不足 MIN_SEGMENT 的补到 MIN_SEGMENT，多出的部分从最大的一段里扣掉。
 * 全是正常、没有异常和暂无数据时返回 null：竖条用整根绿色。
 */
export function barStops(split: Split): BarStop[] | null {
  const total = SPLIT_ORDER.reduce((sum, key) => sum + split[key], 0)
  if (total <= 0) return null
  if (SPLIT_ORDER.every((key) => key === 'operational' || split[key] === 0)) return null
  const share = Object.fromEntries(SPLIT_ORDER.map((key) => [key, split[key] / total])) as Record<SplitKey, number>
  let borrowed = 0
  for (const key of ['degraded', 'outage', 'maintenance'] as const) {
    if (share[key] > 0 && share[key] < MIN_SEGMENT) { borrowed += MIN_SEGMENT - share[key]; share[key] = MIN_SEGMENT }
  }
  if (borrowed > 0) {
    const largest = SPLIT_ORDER.reduce((best, key) => (share[key] > share[best] ? key : best), 'operational' as SplitKey)
    share[largest] = Math.max(share[largest] - borrowed, 0)
  }
  const stops: BarStop[] = []
  let at = 0
  for (const key of SPLIT_ORDER) {
    if (share[key] <= 0) continue
    stops.push({ key, from: at, to: at + share[key] })
    at += share[key]
  }
  if (stops.length) stops[stops.length - 1].to = 1
  return stops
}

/** barStops 的 CSS：从下到上的硬边渐变，颜色取状态页的颜色变量（深浅色自动跟随）。 */
export function barBackground(split: Split): string | null {
  const stops = barStops(split)
  if (!stops) return null
  const parts = stops.map((stop) => `var(${SPLIT_VAR[stop.key]}) ${(stop.from * 100).toFixed(2)}% ${(stop.to * 100).toFixed(2)}%`)
  return `linear-gradient(to top, ${parts.join(', ')})`
}
