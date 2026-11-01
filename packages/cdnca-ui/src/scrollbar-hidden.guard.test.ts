// Guard: every scroll area in the five front ends
// hides its scrollbar but still scrolls (wheel, touchpad, touch, keyboard).
// 1. styles.css hides the bar once for every element (scrollbar-width: none
//    !important + ::-webkit-scrollbar), so a page rule cannot bring it back.
// 2. Wide tables stay discoverable: the edge the table can still scroll to
//    shows a shadow (antd ping-left / ping-right) in the theme's colours.
// 3. A scroll box reached by keyboard shows the focus ring.
// 4. No front-end stylesheet brings a bar back with !important (the only way
//    past rule 1): scrollbar-width thin/auto, scrollbar-color, or a
//    ::-webkit-scrollbar display other than none. Older page rules without
//    !important (thin bars, 11px heights) are overridden and harmless.
// Usage rules: ../COMPONENTS.md "滚动条一律隐藏".
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { describe, expect, it } from 'vitest'

const root = join(__dirname, '..', '..', '..')
const ends = ['apps/web/src', 'packages/cdnca-ui/src']
const shared = readFileSync(join(__dirname, 'styles.css'), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '')

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return name === 'node_modules' || name === 'dist' ? [] : files(path)
    return name.endsWith('.css') ? [path] : []
  })
}

// Declarations that win over the shared rule and make a scrollbar visible again.
export function visibleScrollbarRules(file: string, css: string): string[] {
  const found: string[] = []
  const text = css.replace(/\/\*[\s\S]*?\*\//g, '')
  for (const match of text.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
    const [, selector, body] = match
    const line = text.slice(0, match.index).split('\n').length
    if (/scrollbar-(?:width\s*:\s*(?:thin|auto)|color\s*:)[^;]*!important/.test(body)) found.push(`${file}:${line}`)
    else if (/::-webkit-scrollbar(?![\w-])/.test(selector) && /(?:^|;)\s*display\s*:\s*(?!none)[\w-]+\s*!important/.test(body)) found.push(`${file}:${line}`)
  }
  return found
}

describe('scrollbars are hidden everywhere but areas still scroll', () => {
  it('hides every scrollbar once in the shared stylesheet', () => {
    expect(shared).toMatch(/\*,\s*\*::before,\s*\*::after\s*\{[^}]*scrollbar-width:\s*none\s*!important;/)
    expect(shared).toMatch(/\*::-webkit-scrollbar\s*\{[^}]*display:\s*none\s*!important;/)
    // antd virtual lists (Select / Cascader dropdowns) draw their own bar.
    expect(shared).toMatch(/\.rc-virtual-list-scrollbar[^{]*\{[^}]*display:\s*none\s*!important;/)
  })

  it('marks the side a wide table can still scroll to', () => {
    for (const side of ['left', 'right']) {
      const inset = side === 'left' ? '' : '-'
      expect(shared).toMatch(new RegExp(`\\.ant-table-ping-${side}:not\\(\\.ant-table-has-fix-${side}\\) \\.ant-table-container::${side === 'left' ? 'before' : 'after'}\\s*\\{[^}]*box-shadow:\\s*inset ${inset}14px 0 12px -10px [^;]*--cdnca-color-`))
    }
  })

  it('shows the focus ring on a keyboard-focused scroll box', () => {
    expect(shared).toMatch(/\.ant-table-content:focus-visible[^{]*\{[^}]*outline:\s*2px solid var\(--cdnca-color-focus-ring\)/)
  })

  it('flags a rule that brings a bar back', () => {
    expect(visibleScrollbarRules('a.css', '.x { scrollbar-width: thin !important; }')).toEqual(['a.css:1'])
    expect(visibleScrollbarRules('a.css', '.x::-webkit-scrollbar { display: block !important; }')).toEqual(['a.css:1'])
    expect(visibleScrollbarRules('a.css', '.x { scrollbar-color: #ccc transparent !important; }')).toEqual(['a.css:1'])
    // Overridden by the shared rule: harmless.
    expect(visibleScrollbarRules('a.css', '.x { scrollbar-width: thin; }\n.x::-webkit-scrollbar { height: 11px !important; }')).toEqual([])
  })

  it('finds none in the front ends', () => {
    const offenders = ends.flatMap((end) => files(join(root, end))
      .flatMap((path) => visibleScrollbarRules(relative(root, path), readFileSync(path, 'utf8'))))
    expect(offenders).toEqual([])
  })
})
