import { describe, expect, it } from 'vitest'

// Page stylesheets read shared colours through --cdnca-* variables
// (packages/cdnca-ui/src/styles.css). Visual tests assert the variable name;
// this file pins what each variable resolves to and keeps hard-coded copies of
// the shared colours from creeping back into apps/web CSS.
const sharedCSS = Object.values(import.meta.glob('../../../../packages/cdnca-ui/src/styles.css', {
  eager: true, import: 'default', query: '?raw',
}))[0] as string
const webCSS = import.meta.glob(['../**/*.css'], { eager: true, import: 'default', query: '?raw' }) as Record<string, string>

const sharedColors: Record<string, string> = {
  'color-primary': '#2d8cf0', 'color-link-hover': '#57a3f3', 'color-text': '#515a6e',
  'color-text-secondary': '#808695', 'color-border': '#dcdee2', 'color-bg-layout': '#f5f7f9',
  'color-border-secondary': '#e8eaec', 'color-bg-page': '#eceef2', 'color-bg-login': '#f7f7f7',
  'color-sidebar-dark': '#001529', 'color-title': '#17233d', 'color-placeholder': '#c5c8ce',
  'color-success': '#19be6b', 'color-warning': '#ff9900', 'color-error': '#ed4014', 'color-table-header': '#f8f8f9',
}

describe('shared --cdnca-* colour variables', () => {
  it('defines every shared colour with the management-console value', () => {
    for (const [name, value] of Object.entries(sharedColors)) {
      expect(sharedCSS).toContain(`--cdnca-${name}: ${value};`)
    }
  })

  it('keeps apps/web stylesheets on the variables instead of hard-coded shared colours', () => {
    const hex = new RegExp(`#(${Object.values(sharedColors).map((v) => v.slice(1)).join('|')})(?![0-9a-f])`, 'gi')
    const offenders: string[] = []
    for (const [file, css] of Object.entries(webCSS)) {
      css.split('\n').forEach((line, index) => {
        // var(--x, #hex) fallbacks are allowed; only bare values are offenders.
        const bare = line.replace(/var\(--[\w-]+,\s*#[0-9a-f]{3,8}\)/gi, '')
        if (hex.test(bare)) offenders.push(`${file}:${index + 1}`)
        hex.lastIndex = 0
      })
    }
    expect(Object.keys(webCSS).length).toBeGreaterThan(50)
    expect(offenders).toEqual([])
  })
})
