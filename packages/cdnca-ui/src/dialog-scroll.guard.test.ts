// Guard (fix-scrollbar): dialog scroll areas show no scrollbar but still scroll.
// 1. styles.css hides the bar on .ant-modal-body / .ant-drawer-body /
//    .cdnca-dialog-scroll and fades the bottom only while more is below.
// 2. In the four front ends, a vertical scroll box (max-height + overflow
//    auto/scroll) used in a file that renders a Modal / Drawer carries
//    .cdnca-dialog-scroll, so no dialog brings back its own grey bar.
// Usage rules: ../COMPONENTS.md "弹窗滚动区不显示滚动条".
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { describe, expect, it } from 'vitest'

const root = join(__dirname, '..', '..', '..')
const ends = ['apps/web/src', 'apps/operator-console/src', 'apps/license-portal/src', 'apps/seller-portal/src']
const shared = readFileSync(join(__dirname, 'styles.css'), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '')

function files(dir: string, ext: RegExp): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return name === 'node_modules' || name === 'dist' ? [] : files(path, ext)
    return ext.test(name) && !/\.test\./.test(name) ? [path] : []
  })
}

// Classes that make an element a vertical scroll box (last class of each selector).
export function scrollBoxClasses(css: string): Set<string> {
  const found = new Set<string>()
  for (const [, selector, body] of css.replace(/\/\*[\s\S]*?\*\//g, '').matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
    if (!/max-height\s*:/.test(body) || !/overflow(?:-y)?\s*:\s*(?:auto|scroll)/.test(body)) continue
    for (const part of selector.split(',')) {
      // The element that scrolls is the last compound (".x pre" scrolls the pre, not .x).
      const last = part.trim().split(/[\s>+~]+/).pop()?.match(/\.[\w-]+/g)?.pop()?.slice(1)
      if (last && !last.startsWith('ant-') && last !== 'cdnca-dialog-scroll') found.add(last)
    }
  }
  return found
}

// Scroll boxes in a dialog file that lack the shared class.
export function unmarkedDialogScrolls(file: string, text: string, boxes: Set<string>): string[] {
  if (!/<(?:Modal|Drawer)\b/.test(text)) return []
  const found: string[] = []
  const line = (index: number) => text.slice(0, index).split('\n').length
  for (const match of text.matchAll(/<\w[\w.]*\b((?:[^<>{}]|\{(?:[^{}]|\{[^{}]*\})*\})*)>/g)) {
    const attrs = match[1]
    const classes = (attrs.match(/className=(?:"([^"]*)"|\{`([^`]*)`\})/)?.slice(1).find(Boolean) ?? '').split(/\s+/)
    if (classes.includes('cdnca-dialog-scroll')) continue
    const box = classes.find((name) => boxes.has(name))
    const inline = /style=\{\{[^}]*overflowY?:\s*['"](?:auto|scroll)/.test(attrs)
    if (box || inline) found.push(`${file}:${line(match.index!)} ${box ?? 'inline overflow'}`)
  }
  return found
}

describe('dialog scroll areas hide the scrollbar (fix-scrollbar)', () => {
  it('hides the bar on modal / drawer bodies and the shared class', () => {
    for (const selector of ['.ant-modal-body', '.ant-drawer-body', '.cdnca-dialog-scroll']) {
      expect(shared).toMatch(new RegExp(`${selector.replace('.', '\\.')}[^{]*\\{[^}]*scrollbar-width:\\s*none;`))
      expect(shared).toMatch(new RegExp(`${selector.replace('.', '\\.')}::-webkit-scrollbar[^{]*\\{\\s*display:\\s*none;`))
    }
  })

  it('fades the bottom only on a scrolling box and keeps focused controls clear of it', () => {
    expect(shared).toMatch(/scroll-padding-block-end:\s*24px;/)
    expect(shared).toMatch(/@keyframes cdnca-scroll-fade\s*\{[\s\S]*?from\s*\{[^}]*--cdnca-scroll-fade:\s*24px;[^}]*mask-image:/)
    expect(shared).toMatch(/animation-timeline:\s*scroll\(self block\);/)
    // The mask is only in the keyframes: a body that does not scroll is never masked.
    const outsideKeyframes = shared.replace(/@keyframes[^{]*\{(?:[^{}]|\{[^{}]*\})*\}/g, '')
    expect(outsideKeyframes).not.toMatch(/mask-image/)
  })

  it('flags an unmarked scroll box inside a dialog file', () => {
    const boxes = new Set(['list'])
    expect(unmarkedDialogScrolls('a.tsx', '<Modal open><div className="list">x</div></Modal>', boxes)).toHaveLength(1)
    expect(unmarkedDialogScrolls('a.tsx', "<Modal open><div style={{ maxHeight: '60vh', overflowY: 'auto' }}>x</div></Modal>", boxes)).toHaveLength(1)
    expect(unmarkedDialogScrolls('a.tsx', '<Modal open><div className="list cdnca-dialog-scroll">x</div></Modal>', boxes)).toEqual([])
    expect(unmarkedDialogScrolls('a.tsx', '<div className="list">no dialog here</div>', boxes)).toEqual([])
    expect(scrollBoxClasses('.a .list { max-height: 10px; overflow-y: auto; } .row { overflow: auto; } .card pre { max-height: 9px; overflow: auto; }')).toEqual(new Set(['list']))
  })

  it('finds none in the four front ends', () => {
    const offenders = ends.flatMap((end) => {
      const dir = join(root, end)
      const boxes = scrollBoxClasses(files(dir, /\.css$/).map((path) => readFileSync(path, 'utf8')).join('\n'))
      return files(dir, /\.tsx$/).flatMap((path) => unmarkedDialogScrolls(relative(root, path), readFileSync(path, 'utf8'), boxes))
    })
    expect(offenders).toEqual([])
  })
})
