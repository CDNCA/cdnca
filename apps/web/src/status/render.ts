import { fill, messages, type Lang } from './i18n'

export type Status = 'operational' | 'degraded' | 'outage' | 'maintenance'
export interface Day { day: string; status: Status | 'no_data'; uptime: number | null }
export interface Component { id: string; name: string; description?: string; status: Status; uptime_90d: number | null; history: Day[] }
export interface Update { id: string; status: string; message: string; created_at: string }
export interface Incident {
  id: string; kind: 'incident' | 'maintenance'; title: string; impact: 'degraded' | 'outage' | 'maintenance'; status: string
  component_ids: string[]; scheduled_start?: string; scheduled_end?: string; started_at: string; resolved_at?: string; updates: Update[]
}
export interface View {
  schema: string; title: string; description?: string; show_logo: boolean; status: Status
  components: Component[]; active: Incident[]; upcoming: Incident[]; recent: Incident[]; generated_at: string
}

type Attrs = Record<string, string>
const SVG = 'http://www.w3.org/2000/svg'
// Icon paths (24x24, stroke): check, alert triangle, x, wrench.
const icons: Record<Status, string> = {
  operational: 'M20 6 9 17l-5-5',
  degraded: 'M12 9v4m0 4h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z',
  outage: 'M18 6 6 18M6 6l12 12',
  maintenance: 'M14.7 6.3a4 4 0 0 0 5 5L22 14l-8 8-2.3-2.3a4 4 0 0 0-5-5L2 10l8-8z',
}

export function el(tag: string, attrs: Attrs = {}, ...children: (Node | string | null | false)[]): HTMLElement {
  const node = document.createElement(tag)
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value)
  for (const child of children) if (child) node.append(child)
  return node
}

function icon(status: Status): SVGElement {
  const svg = document.createElementNS(SVG, 'svg')
  for (const [key, value] of Object.entries({ viewBox: '0 0 24 24', width: '20', height: '20', 'aria-hidden': 'true', focusable: 'false' })) svg.setAttribute(key, value)
  const path = document.createElementNS(SVG, 'path')
  path.setAttribute('d', icons[status])
  svg.append(path)
  return svg
}

function percent(value: number, lang: Lang): string {
  return new Intl.NumberFormat(lang === 'en' ? 'en-US' : 'zh-CN', { style: 'percent', minimumFractionDigits: 2, maximumFractionDigits: 2 }).format(value)
}

function time(value: string, lang: Lang, withDate = true): HTMLElement {
  const date = new Date(value)
  const text = new Intl.DateTimeFormat(lang === 'en' ? 'en-US' : 'zh-CN', {
    ...(withDate ? { year: 'numeric', month: '2-digit', day: '2-digit' } : {}), hour: '2-digit', minute: '2-digit', timeZoneName: 'short',
  }).format(date)
  return el('time', { datetime: date.toISOString() }, text)
}

function history(component: Component, lang: Lang): HTMLElement {
  const m = messages(lang)
  const detail = el('p', { class: 'st-day-detail', 'aria-live': 'polite' })
  const list = el('ol', { class: 'st-bars', 'aria-label': fill(m.historyLabel, { name: component.name }) })
  const describe = (day: Day) => day.uptime === null
    ? fill(m.dayDetail, { day: day.day, status: m.status[day.status] })
    : fill(m.dayDetailUptime, { day: day.day, status: m.status[day.status], value: percent(day.uptime, lang) })
  const bars = component.history.map((day, index) => {
    const bar = el('li', { class: `st-bar st-${day.status}`, 'aria-label': describe(day), tabindex: index === component.history.length - 1 ? '0' : '-1' })
    const show = () => { detail.textContent = describe(day) }
    bar.addEventListener('mouseenter', show)
    bar.addEventListener('focus', show)
    bar.addEventListener('keydown', (event) => {
      const step = event.key === 'ArrowLeft' ? -1 : event.key === 'ArrowRight' ? 1 : 0
      const next = bars[index + step]
      if (!step || !next) return
      event.preventDefault()
      bar.setAttribute('tabindex', '-1'); next.setAttribute('tabindex', '0'); next.focus()
    })
    return bar
  })
  list.append(...bars)
  const uptime = component.uptime_90d === null ? m.uptimeNone : fill(m.uptime90, { value: percent(component.uptime_90d, lang) })
  return el('div', { class: 'st-history' }, list,
    el('div', { class: 'st-axis' }, el('span', { class: 'st-axis-90' }, m.days90), el('span', { class: 'st-axis-30' }, m.days30),
      el('span', { class: 'st-uptime' }, uptime), el('span', {}, m.today)), detail)
}

function incident(item: Incident, names: Map<string, string>, lang: Lang, full: boolean): HTMLElement {
  const m = messages(lang)
  const affected = item.component_ids.map((id) => names.get(id)).filter((name): name is string => Boolean(name))
  const updates = full ? item.updates : item.updates.slice(0, 1)
  return el('article', { class: `st-incident st-impact-${item.impact}` },
    el('h3', {}, item.title, ' ', el('span', { class: `st-badge st-${item.impact}` }, m.impact[item.impact])),
    item.kind === 'maintenance' && item.scheduled_start && item.scheduled_end
      ? el('p', { class: 'st-muted' }, ...windowText(item.scheduled_start, item.scheduled_end, lang)) : null,
    affected.length ? el('p', { class: 'st-muted' }, fill(m.affected, { names: affected.join(m.listSeparator) })) : null,
    el('ol', { class: 'st-updates' }, ...updates.map((update) => el('li', {},
      el('strong', {}, m.incidentStatus[update.status as keyof typeof m.incidentStatus] ?? update.status), ' · ', time(update.created_at, lang),
      el('p', {}, update.message)))))
}

function around(template: string, token: string, node: Node): (Node | string)[] {
  const [before, after = ''] = template.split(token)
  return [before, node, after].filter((part) => part !== '')
}

function windowText(start: string, end: string, lang: Lang): (Node | string)[] {
  const [before, middle, after] = messages(lang).window.split(/\{start\}|\{end\}/)
  return [before, time(start, lang), middle, time(end, lang), after].filter((part) => part !== '')
}

export function renderView(root: HTMLElement, view: View, lang: Lang, stale: boolean): void {
  const m = messages(lang)
  const names = new Map(view.components.map((item) => [item.id, item.name]))
  const banner = el('section', { class: `st-banner st-${view.status}`, role: 'status' }, icon(view.status),
    el('div', {}, el('h2', {}, m.banner[view.status]),
      el('p', { class: 'st-muted' }, ...around(m.updatedAt, '{time}', time(view.generated_at, lang, false)), stale ? ` · ${m.stale}` : '')))
  const sections: (HTMLElement | null)[] = [banner]
  if (view.active.length) sections.push(el('section', {}, el('h2', {}, m.active), ...view.active.map((item) => incident(item, names, lang, false))))
  if (view.upcoming.length) sections.push(el('section', {}, el('h2', {}, m.upcoming), ...view.upcoming.map((item) => incident(item, names, lang, false))))
  sections.push(el('section', {}, el('h2', {}, m.components), view.components.length
    ? el('ul', { class: 'st-components' }, ...view.components.map((item) => el('li', { class: 'st-card' },
      el('div', { class: 'st-row' }, el('div', {}, el('h3', {}, item.name), item.description ? el('p', { class: 'st-muted' }, item.description) : null),
        el('span', { class: `st-state st-${item.status}` }, icon(item.status), m.status[item.status])),
      history(item, lang))))
    : el('p', { class: 'st-muted' }, m.noComponents)))
  sections.push(el('section', {}, el('h2', {}, m.recent), ...(view.recent.length
    ? view.recent.map((item) => incident(item, names, lang, true)) : [el('p', { class: 'st-muted' }, m.noRecent)])))
  root.replaceChildren(...sections.filter((node): node is HTMLElement => node !== null))
}
