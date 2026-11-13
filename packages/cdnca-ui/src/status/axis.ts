import { el } from './dom'
import type { Segment } from './model'

/** 横向时段轴：底色表示正常，事件占的时段用对应影响色叠上去（中断红、降级琥珀、维护蓝）。整条是一张图，读屏用 label 概括。 */
export function axisTrack(segments: Segment[], label: string): HTMLElement {
  const track = el('div', { class: 'st-axis', role: 'img', 'aria-label': label })
  for (const seg of segments) {
    const node = el('span', { class: `st-seg st-impact-${seg.impact}` })
    node.style.left = `${seg.left.toFixed(3)}%`
    node.style.width = `${seg.width.toFixed(3)}%`
    track.append(node)
  }
  return track
}
