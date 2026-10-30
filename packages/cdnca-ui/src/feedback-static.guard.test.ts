// Guard (fix-feedbackui): errors and warnings in every front end go through the
// shared dialog (useFeedback / FeedbackWhen / FeedbackDialog), which keeps the
// title short, shows the request ID as a copyable line and puts every button in
// one bottom row. antd's static Modal.error / Modal.warning (and the App
// modal.error / modal.warning) bypass that layout, and message.error /
// message.warning flash at the top where nobody reads them.
// Usage rules: ../COMPONENTS.md "错误与警告反馈".
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { describe, expect, it } from 'vitest'

const root = join(__dirname, '..', '..', '..')
const ends = ['apps/web/src', 'apps/operator-console/src', 'apps/license-portal/src', 'apps/seller-portal/src', 'apps/www/src']

function sources(dir: string): string[] {
  let names: string[]
  try { names = readdirSync(dir) } catch { return [] }
  return names.flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return name === 'node_modules' || name === 'dist' ? [] : sources(path)
    return /\.tsx?$/.test(name) && !/\.test\.tsx?$/.test(name) ? [path] : []
  })
}

const staticDialog = /\b(?:Modal|modal)\.(?:error|warning)\(/g

export function staticErrorDialogs(file: string, text: string): string[] {
  const found: string[] = []
  for (const match of text.matchAll(staticDialog)) found.push(`${file}:${text.slice(0, match.index).split('\n').length}`)
  return found
}

describe('errors and warnings use the shared dialog (fix-feedbackui)', () => {
  it('flags static error / warning dialogs', () => {
    expect(staticErrorDialogs('a.tsx', 'onError: (e) => void modal.error({ title: refused(e) }),')).toEqual(['a.tsx:1'])
    expect(staticErrorDialogs('a.tsx', 'x\nModal.warning({ title })')).toEqual(['a.tsx:2'])
    expect(staticErrorDialogs('a.tsx', 'modal.confirm({ title }); feedback.error(t("x"))')).toEqual([])
  })

  it('finds none in the five front ends', () => {
    const offenders = ends.flatMap((end) => sources(join(root, end))
      .flatMap((path) => staticErrorDialogs(relative(root, path), readFileSync(path, 'utf8'))))
    expect(offenders).toEqual([])
  })
})
