import { duration, fill, messages } from './i18n'
import { renderBody } from './body'
import { splitText } from './split'
import { attachDayCard, closeDayCard, resetCards, restoreCard, snapshotCard, type Snapshot } from './daycard'
import { around, el, icon, time, type Child } from './dom'
import { barBackground, daySplit, formatUptime, groupComponents, incidentHref, uptimeSince, maintenanceSummary, text, type Component, type Day, type Group, type Incident, type Lang, type Status, type View } from './model'

export { el }

export interface RenderOptions {
  /** 快照比预期旧（直连也失败）。 */
  stale: boolean
  /** 最近一次取数失败：有旧数据就带着旧数据显示说明，没有就只显示说明。 */
  failed: boolean
  /** 用户手动展开(true)或收起(false)过的分组；没有记录的分组按默认：有子组件降级或中断才展开。重绘（每分钟）后保持。 */
  expanded: Map<string, boolean>
  /** 从事件详情返回时要重新打开的当天卡片；不传则沿用重绘前已打开的那张（每分钟刷新不收起）。 */
  restore?: Snapshot | null
}

// ---- 悬停浮层：整页共用一个绝对定位的浮层，不占布局空间；鼠标移入、键盘聚焦、触屏点按或横向拖动都显示。 ----
let tip: HTMLElement | null = null
let tipOwner: Element | null = null
let hiddenAt = 0
/** 最近一次指针是触屏或笔：浏览器之后补发的兼容鼠标事件（mouseenter/mouseleave）会把浮层关掉或跳到别的日条，这时只由点别处关闭。 */
let touching = false
/** 刚隐藏不久又在相邻日条上显示时跳过淡入，连续划过不闪烁。 */
const INSTANT_MS = 120

function tooltip(): HTMLElement {
  if (!tip) {
    tip = el('div', { class: 'st-tip', role: 'tooltip', id: 'st-tip', hidden: '' })
    document.body.append(tip)
    document.addEventListener('click', (event) => {
      if (!(event.target instanceof Element) || !event.target.closest('.st-bars')) hideTip()
    })
    document.addEventListener('keydown', (event) => { if (event.key === 'Escape') hideTip() })
    window.addEventListener('scroll', hideTip, { passive: true })
    window.addEventListener('resize', hideTip)
  }
  return tip
}

export function hideTip(): void {
  if (!tip) return
  if (!tip.hidden) hiddenAt = performance.now()
  tip.hidden = true
  tipOwner?.removeAttribute('aria-describedby')
  tipOwner = null
}

/** 浮层内容：日期、状态、可用率、当天各状态时长、平均耗时、当天事件。 */
export function dayTip(day: Day, lang: Lang): HTMLElement {
  const m = messages(lang)
  const rows: HTMLElement[] = [
    el('div', { class: 'st-tip-head' }, el('strong', {}, day.day), el('span', { class: `st-tip-state st-${day.status}` }, m.status[day.status])),
  ]
  if (day.status === 'before_monitoring') {
    rows.push(el('p', { class: 'st-tip-line' }, fill(m.tipBefore, { since: day.since ?? '' })))
    return el('div', {}, ...rows)
  }
  if (day.status === 'no_data') {
    rows.push(el('p', { class: 'st-tip-line' }, m.tipNoData))
    return el('div', {}, ...rows)
  }
  rows.push(el('p', { class: 'st-tip-line' }, day.uptime == null ? m.tipNoUptime : fill(m.tipUptime, { value: formatUptime(day.uptime, lang) })))
  rows.push(el('p', { class: 'st-tip-line' }, splitText(day, lang) || m.tipNone))
  if (day.avg_ms != null) rows.push(el('p', { class: 'st-tip-line' }, fill(m.tipLatency, { value: String(day.avg_ms) })))
  if (day.events?.length) {
    rows.push(el('p', { class: 'st-tip-line st-tip-title' }, m.tipEvents))
    for (const event of day.events) {
      rows.push(el('p', { class: `st-tip-line st-tip-event st-impact-${event.impact}` }, fill(m.eventLine, {
        title: text(event.title, lang), kind: event.kind === 'maintenance' ? m.kindMaintenance : m.kindIncident, duration: duration(event.minutes, lang),
      })))
    }
  }
  return el('div', {}, ...rows)
}

function showTip(bar: Element, day: Day, lang: Lang): void {
  const box = tooltip()
  if (tipOwner === bar && !box.hidden) return
  const wasHidden = box.hidden
  box.replaceChildren(dayTip(day, lang))
  if (wasHidden) box.toggleAttribute('data-instant', performance.now() - hiddenAt < INSTANT_MS)
  box.hidden = false
  tipOwner?.removeAttribute('aria-describedby')
  tipOwner = bar
  bar.setAttribute('aria-describedby', 'st-tip')
  const rect = bar.getBoundingClientRect()
  const width = box.offsetWidth
  const height = box.offsetHeight
  const center = rect.left + rect.width / 2
  const left = Math.min(Math.max(8, center - width / 2), Math.max(8, document.documentElement.clientWidth - width - 8))
  const above = rect.top - height - 10
  const top = above >= 8 ? above : rect.bottom + 10
  box.dataset.side = above >= 8 ? 'top' : 'bottom'
  box.style.setProperty('--ax', `${Math.min(Math.max(12, center - left), width - 12)}px`)
  box.style.left = `${left + window.scrollX}px`
  box.style.top = `${top + window.scrollY}px`
}

function describe(day: Day, lang: Lang): string {
  const m = messages(lang)
  if (day.status === 'before_monitoring') return `${day.day}：${fill(m.tipBefore, { since: day.since ?? '' })}`
  const split = splitText(day, lang)
  const head = day.uptime == null ? `${day.day}：${m.status[day.status]}` : `${day.day}：${m.status[day.status]}，${fill(m.tipUptime, { value: formatUptime(day.uptime, lang) })}`
  return split ? `${head}，${split}` : head
}

let todayKey = ''

/** 一个组件或分组的 90 天色条：细竖条，宽度随容器；浮层绝对定位，条下面不留文字行。 */
function bars(item: Component, lang: Lang, size: 'group' | 'sub'): HTMLElement | null {
  const days = item.history
  if (!days?.length) return null
  const m = messages(lang)
  const name = text(item.name, lang)
  const list: HTMLElement[] = days.map((day, index) => {
    const bar = el('li', { class: `st-bar st-${day.status}`, 'aria-label': describe(day, lang), tabindex: index === days.length - 1 ? '0' : '-1' })
    const split = daySplit(day)
    const background = split ? barBackground(split) : null
    if (background) { bar.classList.add('is-split'); bar.style.background = background }
    const show = () => showTip(bar, day, lang)
    bar.addEventListener('mouseenter', () => { if (!touching) show() })
    bar.addEventListener('focus', show)
    bar.addEventListener('mouseleave', () => { if (!touching) hideTip() })
    bar.addEventListener('blur', hideTip)
    bar.addEventListener('keydown', (event) => {
      const target = event.key === 'ArrowLeft' ? index - 1 : event.key === 'ArrowRight' ? index + 1 : event.key === 'Home' ? 0 : event.key === 'End' ? list.length - 1 : -1
      const next = list[target]
      if (!next) return
      event.preventDefault()
      bar.setAttribute('tabindex', '-1'); next.setAttribute('tabindex', '0'); next.focus()
    })
    return bar
  })
  const row = el('ol', { class: 'st-bars', role: 'group', 'aria-label': fill(m.historyLabel, { name }) }, ...list)
  // 触屏和笔：竖条只有两三像素宽，按横向位置换算成第几天，点按和左右拖动都能准确落在某一天，间隙也不会丢。
  const pick = (event: PointerEvent) => {
    touching = event.pointerType !== 'mouse'
    if (!touching) return
    const rect = row.getBoundingClientRect()
    const index = Math.min(days.length - 1, Math.max(0, Math.floor(((event.clientX - rect.left) / rect.width) * days.length)))
    showTip(list[index], days[index], lang)
  }
  attachDayCard(row, list, days, lang, item.key, todayKey, hideTip)
  row.addEventListener('pointerdown', pick)
  row.addEventListener('pointermove', pick)
  row.addEventListener('pointerleave', (event) => { if (event.pointerType === 'mouse') touching = false })
  return el('div', { class: `st-history is-${size}` }, row)
}

function uptimeNode(item: Component, lang: Lang): HTMLElement {
  const m = messages(lang)
  const value = item.uptime_90d == null ? m.noValue : formatUptime(item.uptime_90d, lang)
  const since = uptimeSince(item)
  return el('span', { class: 'st-uptime' }, el('span', { class: 'st-uptime-label' }, m.uptimeLabel, ' '), el('strong', {}, value),
    since ? el('span', { class: 'st-uptime-since' }, ' ', fill(m.uptimeSince, { since })) : null)
}

/** 状态图标：实心圆加对勾等；文字标签只在非正常时显示，颜色之外还有图标形状和文字，不只靠颜色。 */
function stateMark(status: Status, lang: Lang): HTMLElement {
  const label = messages(lang).status[status]
  return el('span', { class: `st-state st-${status}` }, el('span', { class: 'st-dot' }, icon(status)), el('span', { class: status === 'operational' ? 'st-sr' : 'st-state-text' }, label))
}

function subRow(item: Component, lang: Lang): HTMLElement {
  const note = text(item.note, lang)
  return el('li', { class: 'st-sub' },
    el('div', { class: 'st-row' },
      el('div', { class: 'st-name' }, stateMark(item.status, lang), el('h4', {}, text(item.name, lang)), note ? el('span', { class: 'st-muted st-note' }, note) : null),
      uptimeNode(item, lang)),
    bars(item, lang, 'sub'))
}

function groupCard(group: Group, lang: Lang, opts: RenderOptions): HTMLElement {
  const m = messages(lang)
  const { item, children } = group
  const name = text(item.name, lang)
  const note = text(item.note, lang)
  const label = (count: boolean) => el('div', { class: 'st-name' }, stateMark(item.status, lang), el('h3', {}, name),
    count && children.length ? el('span', { class: 'st-count st-muted' }, fill(m.subCount, { count: String(children.length) })) : null,
    count && children.length ? icon('chevron') : null,
    note ? el('span', { class: 'st-muted st-note' }, note) : null)
  if (!children.length) return el('li', { class: 'st-card' }, el('div', { class: 'st-row' }, label(false), uptimeNode(item, lang)), bars(item, lang, 'group'))

  const open = opts.expanded.get(item.key) ?? children.some((child) => child.status === 'degraded' || child.status === 'outage')
  const panelId = `st-sub-${item.key}`
  const button = el('button', { class: 'st-head st-row', type: 'button', 'aria-expanded': String(open), 'aria-controls': panelId,
    'aria-label': fill(open ? m.collapse : m.expand, { name }) }, label(true), uptimeNode(item, lang))
  const panel = el('ul', { class: 'st-subs', id: panelId }, ...children.map((child) => subRow(child, lang)))
  panel.hidden = !open
  button.addEventListener('click', () => {
    const next = panel.hidden
    panel.hidden = !next
    button.setAttribute('aria-expanded', String(next))
    button.setAttribute('aria-label', fill(next ? m.collapse : m.expand, { name }))
    opts.expanded.set(item.key, next)
    hideTip()
    closeDayCard()
  })
  return el('li', { class: 'st-card st-group' }, button, bars(item, lang, 'group'), panel)
}

/** 卡片顶部的日期范围：取所有组件日历史里最早和最晚一天，写成「2026年8月 – 2026年11月」。 */
function dateRange(components: Component[], lang: Lang): string {
  const days = components.flatMap((item) => item.history?.map((d) => d.day) ?? []).sort()
  if (!days.length) return ''
  const fmt = new Intl.DateTimeFormat(lang === 'en' ? 'en-US' : 'zh-CN', { year: 'numeric', month: lang === 'en' ? 'short' : 'long', timeZone: 'UTC' })
  const first = fmt.format(new Date(`${days[0]}T00:00:00Z`))
  const last = fmt.format(new Date(`${days[days.length - 1]}T00:00:00Z`))
  return first === last ? first : `${first} – ${last}`
}

function windowText(start: string, end: string, lang: Lang): Child[] {
  const [before, middle, after] = messages(lang).window.split(/\{start\}|\{end\}/)
  return [before, time(start, lang), middle, time(end, lang), after].filter((part) => part !== '')
}

function incident(item: Incident, names: Map<string, string>, lang: Lang, open: boolean): HTMLElement {
  const m = messages(lang)
  const affected = item.component_keys.map((key) => names.get(key)).filter((name): name is string => Boolean(name))
  const badge = el('span', { class: `st-badge st-${item.impact}` }, m.impact[item.impact])
  const head = el('h3', {}, text(item.title, lang), ' ', badge)
  const body = [
    item.kind === 'maintenance' && item.scheduled_start && item.scheduled_end
      ? el('p', { class: 'st-muted' }, ...windowText(item.scheduled_start, item.scheduled_end, lang)) : null,
    affected.length ? el('p', { class: 'st-muted' }, fill(m.affected, { names: affected.join(m.listSeparator) })) : null,
    el('ol', { class: 'st-updates' }, ...item.updates.map((update) => el('li', {},
      el('strong', {}, m.incidentStatus[update.status] ?? update.status), ' · ', time(update.created_at, lang),
      renderBody(text(update.message, lang))))),
    el('p', { class: 'st-more' }, el('a', { class: 'st-link', href: incidentHref(item.id) }, m.detailMore)),
  ]
  if (open) return el('article', { class: `st-incident st-impact-${item.impact}` }, head, ...body)
  const summary = el('summary', {}, head, el('span', { class: 'st-muted' }, item.resolved_at ? time(item.resolved_at, lang) : ''))
  return el('details', { class: `st-incident st-impact-${item.impact}` }, summary, ...body)
}

function maintenanceLine(view: View, lang: Lang): HTMLElement {
  const m = messages(lang)
  const summary = maintenanceSummary(view)
  const parts: Child[] = [summary.count > 0 ? fill(m.maintenanceCount, { count: String(summary.count) }) : m.maintenanceNone]
  if (summary.next) parts.push(' · ', ...around(m.maintenanceNext, '{time}', time(summary.next, lang)))
  else if (summary.last) parts.push(' · ', ...around(m.maintenanceLast, '{time}', time(summary.last, lang)))
  return el('p', { class: 'st-muted st-maint' }, ...parts)
}

/**
 * 整页内容。view 为 null 表示一次数据都没取到：只显示说明，不显示任何状态。
 * 有旧数据但这次失败：照常画旧数据，横幅下加一句「稍后自动重试」。
 */
export function renderView(root: HTMLElement, view: View | null, lang: Lang, opts: RenderOptions): void {
  const m = messages(lang)
  const before = snapshotCard()
  hideTip()
  closeDayCard()
  resetCards()
  todayKey = view ? view.generated_at.slice(0, 10) : ''
  if (!view) {
    root.replaceChildren(el('section', { class: 'st-banner st-no_data', role: 'status' }, el('div', {}, el('h2', {}, m.unavailable))))
    return
  }
  const names = new Map(view.components.map((item) => [item.key, text(item.name, lang)]))
  const note = opts.failed ? m.retrying : opts.stale ? m.stale : ''
  const sections: Child[] = [
    el('section', { class: `st-banner st-${view.status}`, role: 'status' }, el('span', { class: 'st-dot st-dot-lg' }, icon(view.status)),
      el('div', {}, el('h2', {}, m.banner[view.status]),
        el('p', { class: 'st-muted' }, ...around(m.updatedAt, '{time}', time(view.generated_at, lang, false))),
        maintenanceLine(view, lang),
        note ? el('p', { class: 'st-notice' }, note) : null)),
  ]
  if (view.active.length) sections.push(el('section', {}, el('h2', {}, m.active), ...view.active.map((item) => incident(item, names, lang, true))))
  if (view.upcoming.length) sections.push(el('section', {}, el('h2', {}, m.upcoming), ...view.upcoming.map((item) => incident(item, names, lang, true))))
  const groups = groupComponents(view.components)
  const range = dateRange(view.components, lang)
  sections.push(el('section', { class: 'st-panel' },
    el('div', { class: 'st-panel-head' }, el('h2', {}, m.components), range ? el('span', { class: 'st-muted st-range' }, range) : null),
    groups.length ? el('ul', { class: 'st-components' }, ...groups.map((group) => groupCard(group, lang, opts))) : el('p', { class: 'st-muted st-empty' }, m.noComponents),
    el('p', { class: 'st-muted st-legend' }, m.legend)))
  sections.push(el('section', {}, el('h2', {}, m.recent, ' ', el('span', { class: 'st-muted st-range' }, m.recentRange)),
    ...(view.recent.length ? view.recent.map((item) => incident(item, names, lang, false)) : [el('p', { class: 'st-muted' }, m.noRecent)])))
  root.replaceChildren(...sections.filter((node): node is Node => node instanceof Node))
  const snap = opts.restore ?? before
  if (snap) restoreCard(snap, opts.restore ? 'card' : before?.focused ? 'card' : 'none')
}
