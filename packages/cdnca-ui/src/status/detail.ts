import { axisTrack } from './axis'
import { renderBody } from './body'
import { el, icon, time, type Child } from './dom'
import { duration, fill, messages } from './i18n'
import { DAY_MS, affectedComponents, dayStart, impactOf, incidentSpan, segmentsIn, text, type Incident, type Lang, type View } from './model'

// 事件详情页（#/incident/<id>）：返回、日期徽标与标题、状态与时间、影响（每个组件一条时段轴）、时间线。所有正文都按文本渲染。
const fmt = (lang: Lang, options: Intl.DateTimeFormatOptions) => new Intl.DateTimeFormat(lang === 'en' ? 'en-US' : 'zh-CN', options)

function backLink(lang: Lang): HTMLElement {
  return el('a', { class: 'st-back', href: '#/' }, icon('left'), el('span', {}, messages(lang).viewCurrent))
}

/** 事件起止之外的展示：同一天写「日期 开始–结束 时区」，跨天或进行中走通用写法。 */
function whenLine(item: Incident, lang: Lang): HTMLElement {
  const m = messages(lang)
  const { start, end } = incidentSpan(item)
  const s = new Date(start)
  if (!end) return el('p', { class: 'st-when' }, ...m.detailOngoing.split('{start}').flatMap((part, i): Child[] => (i ? [time(start, lang), part] : [part])).filter((p) => p !== ''))
  const e = new Date(end)
  const day = fmt(lang, { year: 'numeric', month: 'long', day: 'numeric' })
  if (day.format(s) === day.format(e)) {
    const clock = fmt(lang, { hour: 'numeric', minute: '2-digit' })
    const zone = fmt(lang, { timeZoneName: 'short' }).formatToParts(s).find((p) => p.type === 'timeZoneName')?.value ?? ''
    const range = lang === 'en' ? `${day.format(s)}, ${clock.format(s)} – ${clock.format(e)} ${zone}` : `${day.format(s)} ${clock.format(s)} – ${clock.format(e)} ${zone}`
    return el('p', { class: 'st-when' }, el('time', { datetime: s.toISOString() }, range))
  }
  const [before, middle, after] = m.window.split(/\{start\}|\{end\}/)
  return el('p', { class: 'st-when' }, ...[before, time(start, lang), middle, time(end, lang), after].filter((p) => p !== ''))
}

function dateBadge(start: string, lang: Lang): HTMLElement {
  const date = new Date(start)
  return el('div', { class: 'st-datebadge', 'aria-hidden': 'true' },
    el('span', {}, fmt(lang, { month: lang === 'en' ? 'short' : 'long' }).format(date)), el('strong', {}, String(date.getDate())))
}

/** 影响一节的时段轴：窗口取事件所在的 UTC 日（跨天就铺满这几天），事件占的部分用影响色标出。 */
function impactAxis(item: Incident, label: string, now: number): HTMLElement {
  const { start, end } = incidentSpan(item)
  const s = new Date(start).getTime()
  const e = end ? new Date(end).getTime() : Math.max(now, s)
  const from = dayStart(new Date(s).toISOString().slice(0, 10))
  // 结束时间正好是 0 点时算前一天的末尾，不多铺一天。
  const lastDay = dayStart(new Date(e > s ? e - 1 : e).toISOString().slice(0, 10))
  const to = Math.max(from + DAY_MS, lastDay + DAY_MS)
  // 同一天：两端 00:00 / 24:00，中间 UTC，和当天卡片一致；跨天：两端写起止日期加时间。
  const same = to - from === DAY_MS
  const md = (ms: number) => new Date(ms).toISOString().slice(5, 10)
  const ends = same ? ['00:00', 'UTC', '24:00'] : [`${md(from)} 00:00`, 'UTC', `${md(to - 1)} 24:00`]
  return el('div', { class: 'st-axis-wrap' }, axisTrack(segmentsIn(from, to, [{ impact: item.impact, start: s, end: e }]), label),
    el('div', { class: 'st-axis-ends', 'aria-hidden': 'true' }, ...ends.map((t) => el('span', {}, t))))
}

function timeline(item: Incident, lang: Lang): HTMLElement {
  const m = messages(lang)
  if (!item.updates.length) return el('p', { class: 'st-muted' }, m.detailNoUpdates)
  return el('ol', { class: 'st-timeline' }, ...item.updates.map((update) => el('li', { class: `st-step st-step-${update.status}` },
    el('span', { class: 'st-step-dot', 'aria-hidden': 'true' }),
    el('div', { class: 'st-step-head' }, el('strong', {}, m.incidentStatus[update.status] ?? update.status), time(update.created_at, lang)),
    renderBody(text(update.message, lang)))))
}

export function incidentTitle(item: Incident, lang: Lang): string { return text(item.title, lang) }

export function renderIncident(root: HTMLElement, view: View, item: Incident, lang: Lang): void {
  const m = messages(lang)
  const impact = impactOf(item.impact)
  const { start, end } = incidentSpan(item)
  const statusKey = item.status || (end ? 'resolved' : 'investigating')
  const spent = end ? Math.max(0, Math.round((new Date(end).getTime() - new Date(start).getTime()) / 60_000)) : 0
  const affected = affectedComponents(view, item.component_keys, lang)
  const now = new Date(view.generated_at).getTime()
  const rows = affected.length ? affected.map((a) => {
    const name = a.parent ? `${a.parent} / ${a.name}` : a.name
    return el('li', { class: 'st-impact-row' },
      el('div', { class: 'st-impact-name' }, el('strong', {}, name),
        el('span', { class: `st-badge st-impact-${impact}` }, m.impact[impact])),
      impactAxis(item, `${name}，${m.impact[impact]}`, now))
  }) : [el('li', { class: 'st-muted' }, m.detailNoImpact)]
  const article = el('article', { class: `st-detail st-impact-${impact}` },
    backLink(lang),
    el('header', { class: 'st-detail-head' }, dateBadge(start, lang),
      el('div', {}, el('h2', { id: 'st-detail-title', tabindex: '-1' }, incidentTitle(item, lang)),
        el('p', { class: 'st-detail-status' }, el('span', { class: `st-step-dot st-step-${statusKey}`, 'aria-hidden': 'true' }), el('strong', {}, m.incidentStatus[statusKey] ?? statusKey),
          end && item.kind === 'maintenance' ? el('span', { class: 'st-muted' }, fill(m.eventMaintenance, { duration: duration(spent, lang) })) : null),
        whenLine(item, lang))),
    el('section', { 'aria-labelledby': 'st-impact-h' }, el('h3', { id: 'st-impact-h' }, m.detailImpact), el('ul', { class: 'st-impact-list' }, ...rows)),
    el('section', { 'aria-labelledby': 'st-timeline-h' }, el('h3', { id: 'st-timeline-h' }, m.detailTimeline), timeline(item, lang)))
  root.replaceChildren(article)
}

export function renderNotFound(root: HTMLElement, lang: Lang): void {
  const m = messages(lang)
  root.replaceChildren(el('article', { class: 'st-detail st-notfound' }, backLink(lang),
    el('h2', { id: 'st-detail-title', tabindex: '-1' }, m.notFoundTitle), el('p', { class: 'st-muted' }, m.notFoundBody)))
}
