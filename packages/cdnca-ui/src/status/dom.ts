import type { Lang, Status } from './model'

// 状态页共用的 DOM 小工具：只用 createElement / textContent，不使用 innerHTML。
export type Child = Node | string | null | false
const SVG = 'http://www.w3.org/2000/svg'
// 图标路径（24x24 描边）：状态图标、事件图标、导航箭头。
const icons = {
  operational: 'M20 6 9 17l-5-5',
  degraded: 'M12 9v4m0 4h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z',
  outage: 'M18 6 6 18M6 6l12 12',
  maintenance: 'M14.7 6.3a4 4 0 0 0 5 5L22 14l-8 8-2.3-2.3a4 4 0 0 0-5-5L2 10l8-8z',
  no_data: 'M6 12h12',
  unconfigured: 'M6 12h12',
  chevron: 'm6 9 6 6 6-6',
  left: 'm15 6-6 6 6 6',
  right: 'm9 6 6 6-6 6',
  clock: 'M12 7v5l3 2M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0z',
}
export type IconName = keyof typeof icons

export function el(tag: string, attrs: Record<string, string> = {}, ...children: Child[]): HTMLElement {
  const node = document.createElement(tag)
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value)
  for (const child of children) if (child) node.append(child)
  return node
}

export function icon(name: IconName): SVGElement {
  const svg = document.createElementNS(SVG, 'svg')
  for (const [key, value] of Object.entries({ viewBox: '0 0 24 24', 'aria-hidden': 'true', focusable: 'false' })) svg.setAttribute(key, value)
  const path = document.createElementNS(SVG, 'path')
  path.setAttribute('d', icons[name])
  svg.append(path)
  return svg
}

export function statusIcon(status: Status | 'no_data'): SVGElement { return icon(status) }

export function time(value: string, lang: Lang, withDate = true): HTMLElement {
  const date = new Date(value)
  const label = new Intl.DateTimeFormat(lang === 'en' ? 'en-US' : 'zh-CN', {
    ...(withDate ? { year: 'numeric', month: '2-digit', day: '2-digit' } : {}), hour: '2-digit', minute: '2-digit', timeZoneName: 'short',
  }).format(date)
  return el('time', { datetime: date.toISOString() }, label)
}

export function around(template: string, token: string, node: Node): Child[] {
  const [before, after = ''] = template.split(token)
  return [before, node, after].filter((part) => part !== '')
}
