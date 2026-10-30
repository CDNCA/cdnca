// Guard (ui-feedback-modal): every Modal / Drawer in the four front ends can be
// closed by the user. A dialog with footer={null} AND closable={false} hides
// both the footer buttons and ×; it is only allowed when its body renders its
// own close button. Static calls (modal.confirm / Modal.info ...) must not pass
// both footer: null and closable: false either.
// Usage rules: ../COMPONENTS.md "弹窗一定能关".
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { describe, expect, it } from 'vitest'

const root = join(__dirname, '..', '..', '..')
const ends = ['apps/web/src', 'apps/operator-console/src', 'apps/license-portal/src', 'apps/seller-portal/src', 'packages/cdnca-ui/src']

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return name === 'node_modules' || name === 'dist' ? [] : sources(path)
    return /\.tsx?$/.test(name) && !/\.test\.tsx?$/.test(name) ? [path] : []
  })
}

// The JSX opening tag starting at `start` (handles braces and strings inside attributes).
function openingTag(text: string, start: number): { attrs: string; end: number; selfClosing: boolean } {
  let depth = 0
  let quote: string | null = null
  for (let i = start; i < text.length; i++) {
    const c = text[i]
    if (quote) { if (c === quote && text[i - 1] !== '\\') quote = null; continue }
    if (c === '"' || c === "'" || c === '`') { quote = c; continue }
    if (c === '{') depth++
    else if (c === '}') depth--
    else if (c === '>' && depth === 0) return { attrs: text.slice(start, i + 1), end: i + 1, selfClosing: text[i - 1] === '/' }
  }
  return { attrs: text.slice(start), end: text.length, selfClosing: true }
}

// Body up to the matching closing tag (same-name nesting counted).
function body(text: string, from: number, name: string): string {
  const open = new RegExp(`<${name}[\\s>]`, 'g')
  const close = new RegExp(`</${name}>`, 'g')
  let depth = 1
  let i = from
  while (depth > 0) {
    open.lastIndex = i
    close.lastIndex = i
    const o = open.exec(text)
    const c = close.exec(text)
    if (!c) return text.slice(from)
    if (o && o.index < c.index) { depth++; i = o.index + 1 } else { depth--; i = c.index + 1; if (depth === 0) return text.slice(from, c.index) }
  }
  return ''
}

// A button in the body whose click handler closes something.
const closesInBody = /<Button\b[^>]*onClick=\{[^}]*(?:close|Close|onCancel|onClose|setOpen\(false\)|set\w+\((?:null|false|undefined)\))/

export function unclosableDialogs(file: string, text: string): string[] {
  const found: string[] = []
  const line = (index: number) => text.slice(0, index).split('\n').length
  for (const match of text.matchAll(/<(Modal|Drawer)\b/g)) {
    const name = match[1]
    const tag = openingTag(text, match.index!)
    const footerNull = /\bfooter=\{null\}/.test(tag.attrs)
    const noX = /\bclosable=\{false\}/.test(tag.attrs)
    if (!footerNull || !noX) continue
    if (!tag.selfClosing && closesInBody.test(body(text, tag.end, name))) continue
    found.push(`${file}:${line(match.index!)} <${name} footer={null} closable={false}> without its own close button`)
  }
  for (const match of text.matchAll(/\b(?:modal|Modal)\.(?:confirm|info|error|warning|success)\(\{/g)) {
    const call = text.slice(match.index!, match.index! + 1500)
    if (/\bfooter:\s*null\b/.test(call) && /\bclosable:\s*false\b/.test(call)) {
      found.push(`${file}:${line(match.index!)} ${match[0]} footer: null + closable: false`)
    }
  }
  return found
}

describe('every dialog can be closed (ui-feedback-modal)', () => {
  it('flags footer={null} + closable={false} without an own close button', () => {
    expect(unclosableDialogs('a.tsx', '<Modal open footer={null} closable={false} onCancel={x}>\n<p>busy</p>\n</Modal>')).toHaveLength(1)
    expect(unclosableDialogs('a.tsx', '<Drawer open closable={false} footer={null} />')).toHaveLength(1)
    expect(unclosableDialogs('a.tsx', 'modal.info({ title, footer: null, closable: false })')).toHaveLength(1)
  })

  it('accepts dialogs with a footer, ×, or an own close button', () => {
    expect(unclosableDialogs('a.tsx', '<Modal open footer={null} onCancel={close}>x</Modal>')).toEqual([])
    expect(unclosableDialogs('a.tsx', '<Modal open closable={false} onCancel={close}>x</Modal>')).toEqual([])
    expect(unclosableDialogs('a.tsx', '<Modal open footer={null} closable={false}><Modal open>inner</Modal><Button onClick={() => setOpen(false)}>关闭</Button></Modal>')).toEqual([])
    expect(unclosableDialogs('a.tsx', '<Modal open footer={null} closable={false} title={<b>{x > 1 ? "a" : "b"}</b>}><Button onClick={closePanel}>关闭</Button></Modal>')).toEqual([])
  })

  it('finds none in the four front ends', () => {
    const offenders = ends.flatMap((end) => sources(join(root, end))
      .flatMap((path) => unclosableDialogs(relative(root, path), readFileSync(path, 'utf8'))))
    expect(offenders).toEqual([])
  })
})
