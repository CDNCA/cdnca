// Guard (fix-dblscroll): a table has exactly one horizontal scroll container.
// An antd <Table scroll={{ x }}> already scrolls inside .ant-table-content, so
//   1. neither the Table (its className lands on .ant-table-wrapper) nor any
//      JSX ancestor in the same file may carry a class that CSS gives
//      overflow(-x): auto|scroll, or an inline overflowX auto|scroll; and
//   2. no CSS rule may force .ant-table / .ant-table-container /
//      .ant-table-content wider (min-width > 0) under the
//      classes that Table sits in: that is what pushed the outer box into a
//      second bar below the pagination (刷新预热 → 操作记录, 10-28).
// A box that must scroll by itself (a non-antd table, or an antd Table that
// relies on the outer box) keeps overflow-x, and its Table drops scroll.x.
// Limits: ancestors are only seen inside the same file (a Table rendered by a
// child component is checked against the child's own markup).
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import ts from 'typescript'
import { describe, expect, it } from 'vitest'

const root = join(__dirname, '..', '..', '..')
const ends = ['apps/web/src', 'apps/operator-console/src', 'apps/license-portal/src', 'apps/seller-portal/src']

function files(dir: string, ext: RegExp): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return name === 'node_modules' || name === 'dist' ? [] : files(path, ext)
    return ext.test(name) && !/\.test\./.test(name) && !path.includes('/tests/') ? [path] : []
  })
}

type Rule = { file: string; selector: string; body: string }

// Flat rules with their full selector (the innermost one; @media wrappers are kept apart).
export function cssRules(file: string, css: string): Rule[] {
  const rules: Rule[] = []
  const text = css.replace(/\/\*[\s\S]*?\*\//g, '')
  const stack: string[] = []
  let buffer = ''
  for (const char of text) {
    if (char === '{') { stack.push(buffer.trim().replace(/\s+/g, ' ')); buffer = '' }
    else if (char === '}') {
      const selector = stack.pop() ?? ''
      if (!selector.startsWith('@') && buffer.trim()) rules.push({ file, selector, body: buffer })
      buffer = ''
    } else buffer += char
  }
  // Declarations of a rule that also had nested blocks were consumed above;
  // rules in this codebase never mix both, so this flat view is exact enough.
  return rules
}

const classes = (part: string) => [...part.matchAll(/\.([A-Za-z_][\w-]*)/g)].map((m) => m[1])
// The element a selector part styles: its last compound.
const lastCompound = (part: string) => part.trim().split(/\s*[\s>+~]\s*/).pop() ?? ''

export type Scroller = { target: string; scope: string[]; where: string }
export type Widener = { scope: string[]; where: string }

export function scrollRules(rules: Rule[]): { scrollers: Scroller[]; wideners: Widener[] } {
  const scrollers: Scroller[] = []
  const wideners: Widener[] = []
  for (const { file, selector, body } of rules) {
    // overflow-y other than visible/clip turns a visible overflow-x into auto.
    const scrolls = /(?:^|;)\s*overflow(?:-x)?\s*:\s*(?:auto|scroll)\b/.test(body)
      || (/(?:^|;)\s*overflow-y\s*:\s*(?:auto|scroll|hidden)\b/.test(body) && !/(?:^|;)\s*overflow-x\s*:/.test(body))
    const widens = /(?:^|;)\s*min-width\s*:\s*[1-9]/.test(body)
    if (!scrolls && !widens) continue
    for (const part of selector.split(',')) {
      const last = lastCompound(part)
      if (/::|:hover|:focus/.test(last)) continue
      const scope = classes(part).filter((name) => !name.startsWith('ant-'))
      const where = `${file}: ${part.trim()}`
      if (scrolls) {
        const target = classes(last).filter((name) => !name.startsWith('ant-') || name === 'ant-table-wrapper').pop()
        if (target && (target === 'ant-table-wrapper' || !classes(last).some((name) => name.startsWith('ant-') && name !== 'ant-table-wrapper'))) scrollers.push({ target, scope, where })
      }
      // (min-width on the <table> inside .ant-table-content only widens what
      // the inner scroller scrolls, so it is not a widener.)
      if (widens && /\.ant-table(?:-container|-content)?$/.test(last)) wideners.push({ scope, where })
    }
  }
  return { scrollers, wideners }
}

const classNames = (attr: ts.JsxAttribute | undefined) => attr?.initializer ? [...attr.initializer.getText().matchAll(/[A-Za-z_][\w-]*/g)].map((m) => m[0]) : []
const attribute = (el: ts.JsxOpeningLikeElement, name: string) => el.attributes.properties.find((a): a is ts.JsxAttribute => ts.isJsxAttribute(a) && a.name.getText() === name)

// Tables with scroll.x that sit in a second horizontal scroll container.
export function doubleScrolls(file: string, text: string, scrollers: Scroller[], wideners: Widener[]): string[] {
  if (!/scroll=\{\{[^}]*\bx\s*:/.test(text)) return []
  const found: string[] = []
  const source = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX)
  // Page roots often sit in a sibling component of the same file.
  const classes = new Set<string>()
  const collect = (node: ts.Node) => {
    if (ts.isJsxAttribute(node) && node.name.getText() === 'className') classNames(node).forEach((name) => classes.add(name))
    ts.forEachChild(node, collect)
  }
  collect(source)
  const visit = (node: ts.Node, outer: string[], inlineScroll: boolean) => {
    let here = outer
    let inline = inlineScroll
    if (ts.isJsxElement(node) || ts.isJsxSelfClosingElement(node)) {
      const el = ts.isJsxElement(node) ? node.openingElement : node
      const own = classNames(attribute(el, 'className'))
      const style = attribute(el, 'style')?.initializer?.getText() ?? ''
      const scrollX = attribute(el, 'scroll')?.initializer?.getText() ?? ''
      if (/^Table$/.test(el.tagName.getText()) && /\bx\s*:/.test(scrollX)) {
        const line = source.getLineAndCharacterOfPosition(el.getStart()).line + 1
        const boxes = new Set([...outer, ...own])
        // The nearest plain class of a selector must be on the Table or an
        // ancestor; the outer ones only need to appear in the same file.
        const applies = (scope: string[]) => scope.length === 0 || (boxes.has(scope[scope.length - 1]) && scope.every((name) => boxes.has(name) || classes.has(name)))
        const outerBox = scrollers.find((s) => (s.target === 'ant-table-wrapper' || boxes.has(s.target)) && applies(s.scope))
        if (outerBox) found.push(`${file}:${line} 外层滚动 ${outerBox.where}`)
        if (inline) found.push(`${file}:${line} 外层滚动 inline overflowX`)
        const widener = wideners.find((w) => w.scope.length > 0 && applies(w.scope))
        if (widener) found.push(`${file}:${line} 撑宽 ${widener.where}`)
      }
      here = [...outer, ...own]
      inline = inline || /overflowX\s*:\s*['"](?:auto|scroll)/.test(style)
    }
    ts.forEachChild(node, (child) => visit(child, here, inline))
  }
  visit(source, [], false)
  return found
}

describe('table horizontal scroll guard', () => {
  it('flags an outer overflow-x box and a forced .ant-table min-width around a scroll.x Table', () => {
    const css = '.wrap { overflow-x: auto } .wrap .ant-table { min-width: 900px } .pane { overflow: hidden } .tall { overflow-y: auto }'
      + ' .page .box { overflow-x: auto } .page .box .ant-table-content > table { min-width: 900px }'
    const { scrollers, wideners } = scrollRules(cssRules('a.css', css))
    const check = (tsx: string) => doubleScrolls('a.tsx', `export const Root = () => <main className="page" />\nexport const A = () => ${tsx}`, scrollers, wideners)
    expect(check('<section className="wrap"><Table scroll={{ x: 900 }} /></section>')).toEqual(['a.tsx:2 外层滚动 a.css: .wrap', 'a.tsx:2 撑宽 a.css: .wrap .ant-table'])
    expect(check('<section className="pane"><Table scroll={{ x: 900 }} /></section>')).toEqual([])
    expect(check('<section className="tall"><Table scroll={{ x: 900 }} /></section>')).toEqual(['a.tsx:2 外层滚动 a.css: .tall'])
    expect(check('<section className="wrap"><Table /></section>')).toEqual([])
    // .page is rendered elsewhere; .box is the ancestor; a min-width on the inner <table> is fine.
    expect(check('<div className="box"><Table scroll={{ x: 900 }} /></div>')).toEqual(['a.tsx:2 外层滚动 a.css: .page .box'])
    expect(check('<div style={{ overflowX: "auto" }}><Table scroll={{ x: 9 }} /></div>')).toEqual(['a.tsx:2 外层滚动 inline overflowX'])
  })

  it('no Table with scroll.x in the four front ends sits in a second horizontal scroll container', () => {
    const rules = [...ends, 'packages/cdnca-ui/src'].flatMap((end) => files(join(root, end), /\.css$/).map((path) => cssRules(relative(root, path), readFileSync(path, 'utf8')))).flat()
    const { scrollers, wideners } = scrollRules(rules)
    expect(scrollers.length).toBeGreaterThan(10)
    const found = ends.flatMap((end) => files(join(root, end), /\.tsx$/).flatMap((path) => doubleScrolls(relative(root, path), readFileSync(path, 'utf8'), scrollers, wideners)))
    expect(found).toEqual([])
  })
})
