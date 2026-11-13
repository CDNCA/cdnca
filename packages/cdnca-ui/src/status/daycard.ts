import { axisTrack } from './axis'
import { el, icon, type Child } from './dom'
import { duration, fill, messages } from './i18n'
import { DAY_MS, dayStart, daysBetween, incidentHref, segmentsIn, text, type Day, type DayEvent, type Lang } from './model'
import { formatUptime } from './model'
import { splitText } from './split'

// 点按某一天弹出的当天事件卡片：整页共用一张，绝对定位在日条下方，不挤占布局。
// 非模态对话框：焦点进卡片，Esc 或点卡片外面关闭，关闭后焦点回到原来的日条；两端可切换前一天、后一天。
export interface Snapshot { key: string; day: string }
export type FocusMode = 'card' | 'none' | 'prev' | 'next'

interface Ctrl { key: string; bars: HTMLElement[]; days: Day[]; lang: Lang; today: string; onOpen: () => void }
const registry = new Map<string, Ctrl>()
let card: HTMLElement | null = null
let current: { ctrl: Ctrl; index: number } | null = null
const CARD_ID = 'st-daycard'

/** 每次重绘前清掉旧页面的登记。 */
export function resetCards(): void { registry.clear() }

export function snapshotCard(): (Snapshot & { focused: boolean }) | null {
  if (!current || !card || card.hidden) return null
  return { key: current.ctrl.key, day: current.ctrl.days[current.index].day, focused: card.contains(document.activeElement) }
}

export function restoreCard(snap: Snapshot, mode: FocusMode): void {
  const ctrl = registry.get(snap.key)
  const index = ctrl?.days.findIndex((d) => d.day === snap.day) ?? -1
  if (ctrl && index >= 0) open(ctrl, index, mode)
}

function fmtDate(day: string, lang: Lang): string {
  return new Intl.DateTimeFormat(lang === 'en' ? 'en-US' : 'zh-CN', { year: 'numeric', month: lang === 'en' ? 'short' : 'long', day: 'numeric', timeZone: 'UTC' }).format(new Date(`${day}T00:00:00Z`))
}
const hhmm = (ms: number): string => new Date(ms).toISOString().slice(11, 16)

function relative(day: string, today: string, lang: Lang): string {
  const m = messages(lang)
  const n = daysBetween(day, today)
  return n === 0 ? m.today : n > 0 ? fill(m.daysAgo, { n: String(n) }) : fill(m.dayAfter, { n: String(-n) })
}

function eventMeta(event: DayEvent, lang: Lang): string {
  const m = messages(lang)
  const value = duration(event.minutes, lang)
  if (event.kind === 'maintenance') return fill(m.eventMaintenance, { duration: value })
  return event.status === 'resolved' || event.status === 'completed' || event.end ? fill(m.eventResolved, { duration: value }) : fill(m.eventOngoing, { duration: value })
}

function eventRow(event: DayEvent, lang: Lang): HTMLElement {
  const m = messages(lang)
  const title = text(event.title, lang)
  const impact = event.impact === 'outage' ? 'outage' : event.impact === 'maintenance' ? 'maintenance' : 'degraded'
  const mark = el('span', { class: 'st-event-icon' }, icon(impact === 'maintenance' ? 'clock' : impact))
  const body: Child[] = [mark, el('span', { class: 'st-event-title' }, title), el('span', { class: 'st-event-rule', 'aria-hidden': 'true' }),
    el('span', { class: 'st-event-meta' }, eventMeta(event, lang)), el('span', { class: 'st-event-go' }, icon('right'))]
  const cls = `st-event st-impact-${impact}`
  return event.id
    ? el('a', { class: cls, href: incidentHref(event.id), 'aria-label': `${fill(m.openEvent, { title })}，${eventMeta(event, lang)}` }, ...body)
    : el('div', { class: cls }, ...body)
}

function dayAxis(day: Day, lang: Lang): HTMLElement {
  const m = messages(lang)
  const from = dayStart(day.day)
  const spans = (day.events ?? []).map((e) => {
    const start = new Date(e.start).getTime()
    return { impact: e.impact, start, end: e.end ? new Date(e.end).getTime() : start + e.minutes * 60_000 }
  })
  const parts = spans.map((s, i) => `${text(day.events![i].title, lang)} ${hhmm(Math.max(from, s.start))}–${hhmm(Math.min(from + DAY_MS, s.end))}`)
  return el('div', { class: 'st-axis-wrap' }, axisTrack(segmentsIn(from, from + DAY_MS, spans), fill(m.axisLabel, { parts: parts.join(m.listSeparator) })),
    el('div', { class: 'st-axis-ends', 'aria-hidden': 'true' }, el('span', {}, '00:00'), el('span', {}, m.axisEnds), el('span', {}, '24:00')))
}

function nav(kind: 'prev' | 'next', target: Day | undefined, ctrl: Ctrl): HTMLElement {
  const m = messages(ctrl.lang)
  const disabled = !target
  const label = target ? relative(target.day, ctrl.today, ctrl.lang) : ''
  const aria = target ? fill(kind === 'prev' ? m.prevDay : m.nextDay, { day: target.day }) : kind === 'prev' ? m.noPrevDay : m.noNextDay
  const button = el('button', { class: `st-nav st-nav-${kind}`, type: 'button', 'data-nav': kind, 'aria-label': aria, ...(disabled ? { 'aria-disabled': 'true' } : {}) },
    kind === 'prev' ? icon('left') : null, el('span', {}, label), kind === 'next' ? icon('right') : null)
  return button
}

function paint(ctrl: Ctrl, index: number): void {
  const m = messages(ctrl.lang)
  const day = ctrl.days[index]
  const box = card!
  const state = el('p', { class: `st-card-state st-${day.status}` },
    el('span', { class: 'st-dot' }, icon(day.status === 'no_data' || day.status === 'before_monitoring' ? 'no_data' : day.status)), el('strong', {}, m.status[day.status]),
    day.status !== 'no_data' && day.uptime != null ? el('span', { class: 'st-muted' }, fill(m.tipUptime, { value: formatUptime(day.uptime, ctrl.lang) })) : null)
  if (day.status === 'before_monitoring') {
    const note = el('p', { class: 'st-card-state st-before_monitoring' }, el('span', { class: 'st-muted' }, fill(m.tipBefore, { since: day.since ?? '' })))
    box.replaceChildren(el('div', { class: 'st-card-head' }, nav('prev', ctrl.days[index - 1], ctrl), el('h3', { class: 'st-card-date', id: 'st-daycard-title' }, fmtDate(day.day, ctrl.lang)), nav('next', ctrl.days[index + 1], ctrl)), note,
      el('button', { class: 'st-card-close', type: 'button' }, m.closeCard))
    box.setAttribute('aria-label', fill(m.dayCard, { day: day.day }))
    return
  }
  const events = day.events ?? []
  const heading = el('h3', { class: 'st-card-date', id: 'st-daycard-title' }, fmtDate(day.day, ctrl.lang))
  const head = el('div', { class: 'st-card-head' }, nav('prev', ctrl.days[index - 1], ctrl), heading, nav('next', ctrl.days[index + 1], ctrl))
  const breakdown = splitText(day, ctrl.lang)
  const children: Child[] = [head, state, breakdown ? el('p', { class: 'st-card-split' }, breakdown) : null]
  if (events.length) {
    children.push(el('div', { class: 'st-events' }, ...events.map((event) => eventRow(event, ctrl.lang))), dayAxis(day, ctrl.lang))
  }
  children.push(el('button', { class: 'st-card-close', type: 'button' }, m.closeCard))
  box.replaceChildren(...children.filter((c): c is Node => c instanceof Node))
  box.setAttribute('aria-label', fill(m.dayCard, { day: day.day }))
  box.removeAttribute('aria-labelledby')
}

function place(ctrl: Ctrl, index: number): void {
  const box = card!
  const bar = ctrl.bars[index]
  const rect = bar.getBoundingClientRect()
  const row = (bar.parentElement ?? bar).getBoundingClientRect()
  const width = box.offsetWidth
  const center = rect.left + rect.width / 2
  const left = Math.min(Math.max(8, center - width / 2), Math.max(8, document.documentElement.clientWidth - width - 8))
  box.style.left = `${left + window.scrollX}px`
  box.style.top = `${row.bottom + 10 + window.scrollY}px`
  box.style.setProperty('--ax', `${Math.min(Math.max(20, center - left), Math.max(20, width - 20))}px`)
}

function focusables(): HTMLElement[] {
  return [...card!.querySelectorAll<HTMLElement>('a[href], button')].filter((node) => {
    const styles = getComputedStyle(node)
    return styles.display !== 'none' && styles.visibility !== 'hidden'
  })
}

function ensureCard(): HTMLElement {
  if (card) return card
  card = el('div', { class: 'st-daycard', id: CARD_ID, role: 'dialog', tabindex: '-1', hidden: '' })
  document.body.append(card)
  card.addEventListener('click', (event) => {
    if (!current || !(event.target instanceof Element)) return
    const { ctrl, index } = current
    const button = event.target.closest<HTMLElement>('button')
    if (!button) return
    if (button.classList.contains('st-card-close')) { close(true); return }
    const kind = button.dataset.nav
    if (button.getAttribute('aria-disabled') === 'true') return
    if (kind === 'prev') open(ctrl, index - 1, 'prev')
    else if (kind === 'next') open(ctrl, index + 1, 'next')
  })
  card.addEventListener('keydown', (event) => {
    if (!current) return
    const { ctrl, index } = current
    if (event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); close(true); return }
    if (event.key === 'ArrowLeft' && index > 0) { event.preventDefault(); open(ctrl, index - 1, 'card'); return }
    if (event.key === 'ArrowRight' && index < ctrl.days.length - 1) { event.preventDefault(); open(ctrl, index + 1, 'card'); return }
    if (event.key !== 'Tab') return
    // Tab 走出卡片两端就收起卡片，焦点交还给日条，继续往下走。
    const list = focusables()
    const first = list[0]
    const last = list[list.length - 1]
    if ((event.shiftKey && (document.activeElement === first || document.activeElement === card)) || (!event.shiftKey && document.activeElement === last)) {
      event.preventDefault()
      close(true)
    }
  })
  document.addEventListener('click', (event) => {
    if (!current || !card || card.hidden || !(event.target instanceof Element)) return
    // 卡片内容重绘会把被点的按钮摘掉，此时 contains 已不成立：用事件路径判断，路径在派发时就定好了。
    if (event.composedPath().includes(card) || event.target.closest('.st-bar')) return
    close(false)
  })
  window.addEventListener('resize', () => { if (current && !card!.hidden) place(current.ctrl, current.index) })
  return card
}

function setOwner(ctrl: Ctrl, index: number, expanded: boolean): void {
  ctrl.bars.forEach((bar, i) => {
    bar.setAttribute('aria-expanded', String(expanded && i === index))
    if (expanded) bar.setAttribute('tabindex', i === index ? '0' : '-1')
  })
}

function open(ctrl: Ctrl, index: number, mode: FocusMode): void {
  const bar = ctrl.bars[index]
  if (!bar || bar.closest('[hidden]')) return
  const box = ensureCard()
  if (current && current.ctrl !== ctrl) setOwner(current.ctrl, -1, false)
  ctrl.onOpen()
  const wasHidden = box.hidden
  current = { ctrl, index }
  paint(ctrl, index)
  setOwner(ctrl, index, true)
  box.hidden = false
  if (wasHidden) { box.removeAttribute('data-swap') } else { box.setAttribute('data-swap', '') }
  box.setAttribute('aria-labelledby', 'st-daycard-title')
  place(ctrl, index)
  if (mode === 'none') return
  const target = mode === 'prev' || mode === 'next' ? box.querySelector<HTMLElement>(`[data-nav="${mode}"]`) : null
  ;(target ?? box).focus()
}

export function closeDayCard(): void { close(false) }

function close(refocus: boolean): void {
  if (!current || !card) return
  const { ctrl, index } = current
  const bar = ctrl.bars[index]
  const had = card.contains(document.activeElement)
  card.hidden = true
  current = null
  setOwner(ctrl, index, false)
  if ((refocus || had) && bar?.isConnected) { bar.focus(); ctrl.onOpen() }
}

/** 给一行日条接上点按弹出：点按（桌面和触屏都是）和 Enter/空格都打开当天卡片，再点同一天收起。 */
export function attachDayCard(row: HTMLElement, bars: HTMLElement[], days: Day[], lang: Lang, key: string, today: string, onOpen: () => void): void {
  const ctrl: Ctrl = { key, bars, days, lang, today, onOpen }
  registry.set(key, ctrl)
  bars.forEach((bar) => {
    bar.setAttribute('role', 'button')
    bar.setAttribute('aria-haspopup', 'dialog')
    bar.setAttribute('aria-expanded', 'false')
    bar.setAttribute('aria-controls', CARD_ID)
  })
  const toggle = (index: number, mode: FocusMode) => {
    if (current?.ctrl === ctrl && current.index === index && card && !card.hidden) close(true)
    else open(ctrl, index, mode)
  }
  row.addEventListener('click', (event) => {
    const hit = event.target instanceof Element ? bars.indexOf(event.target.closest<HTMLElement>('.st-bar') as HTMLElement) : -1
    // 触屏上竖条只有两三像素宽：点在间隙里按横向位置换算成第几天。
    const rect = row.getBoundingClientRect()
    const guess = rect.width > 0 ? Math.floor(((event.clientX - rect.left) / rect.width) * days.length) : -1
    const index = hit >= 0 ? hit : Math.min(days.length - 1, Math.max(0, guess))
    if (index >= 0) toggle(index, 'card')
  })
  bars.forEach((bar, index) => bar.addEventListener('keydown', (event) => {
    if (event.key !== 'Enter' && event.key !== ' ') return
    event.preventDefault()
    toggle(index, 'card')
  }))
}
