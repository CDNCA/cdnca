// Guard (fix-advfilter3, user 10-28): in a filter row whose fields carry a label
// above the control, 查询 / 重置 / 高级筛选 sit on the controls' bottom edge, not
// on the label line. The shared AdvancedFilters bar does it with
// align-items: flex-end, and the toggle takes the row's button height (antd
// buttons are 32px in apps/web, 34px in the operator console) instead of a
// fixed one. Pages must not undo it by re-aligning the bar (center / start /
// baseline); a page that lays the bar out as a column (390 wide) may stretch.
// Also: the ticket list summary must not force a 112px minimum per item below
// 768px (4 items overflowed the 390 viewport to 461px).
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { describe, expect, it } from 'vitest'

const root = join(__dirname, '..', '..', '..')
const ends = ['packages/cdnca-ui/src', 'apps/web/src', 'apps/operator-console/src', 'apps/license-portal/src', 'apps/seller-portal/src']

function cssFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return name === 'node_modules' || name === 'dist' ? [] : cssFiles(path)
    return name.endsWith('.css') ? [path] : []
  })
}

type Rule = { file: string; media: string; selector: string; body: string }

function rules(file: string): Rule[] {
  const text = readFileSync(file, 'utf8').replace(/\/\*[\s\S]*?\*\//g, '')
  const out: Rule[] = []
  const stack: string[] = []
  let buffer = ''
  for (const char of text) {
    if (char === '{') { stack.push(buffer.trim().replace(/\s+/g, ' ')); buffer = '' }
    else if (char === '}') {
      const selector = stack.pop() ?? ''
      if (!selector.startsWith('@') && buffer.trim()) out.push({ file: relative(root, file), media: stack.filter((s) => s.startsWith('@')).join(' '), selector, body: buffer })
      buffer = ''
    } else buffer += char
  }
  return out
}

const all = ends.flatMap((end) => cssFiles(join(root, end))).flatMap(rules)
const decl = (body: string, prop: string) => body.match(new RegExp(`(?:^|;)\\s*${prop}\\s*:\\s*([^;]+)`))?.[1].trim()
// The rule's last compound is the bar itself (not a child of it).
const targetsBar = (selector: string) => selector.split(',').some((part) => /\.cdnca-adv-filters-bar$/.test(part.trim()))

describe('AdvancedFilters buttons sit on the fields\' bottom edge', () => {
  const shared = all.filter((r) => r.file === 'packages/cdnca-ui/src/styles.css' && !r.media)

  it('the shared bar aligns its row to the bottom', () => {
    const bar = shared.find((r) => r.selector === '.cdnca-adv-filters-bar')
    expect(bar && decl(bar.body, 'align-items')).toBe('flex-end')
  })

  it('the query / reset / toggle group stretches the toggle to the buttons\' height', () => {
    const actions = shared.find((r) => r.selector.split(',').map((s) => s.trim()).includes('.cdnca-adv-filters-actions'))
    expect(actions && decl(actions.body, 'align-items')).toBe('stretch')
    const toggle = shared.find((r) => r.selector === '.cdnca-adv-filters-toggle')
    expect(toggle && decl(toggle.body, 'height')).toBeUndefined()
    expect(toggle && decl(toggle.body, 'min-height')).toBe('var(--cdnca-control-height)')
  })

  it('no page re-aligns the bar unless it lays it out as a column', () => {
    const offenders = all.filter((r) => targetsBar(r.selector) && decl(r.body, 'align-items') && decl(r.body, 'align-items') !== 'flex-end'
      && decl(r.body, 'flex-direction') !== 'column')
      .map((r) => `${r.file} ${r.media} ${r.selector} { align-items: ${decl(r.body, 'align-items')} }`)
    expect(offenders).toEqual([])
  })
})

describe('ticket list summary fits a 390 viewport', () => {
  it('drops the 112px item minimum below 768px', () => {
    const narrow = all.filter((r) => r.file === 'apps/web/src/pages/tickets/TicketsChat.css' && /max-width:\s*767px/.test(r.media)
      && r.selector === '.ticket-list-summary li')
    expect(narrow.map((r) => decl(r.body, 'min-width'))).toEqual(['0'])
  })
})
