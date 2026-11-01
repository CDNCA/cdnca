import { render } from '@testing-library/react'
import { CdncaProvider, contrastRatio, darkPalette, darkSeedsFromCSSVariables, mixHex, type CdncaDarkSeeds } from '@cdnca/ui'
import { theme as antdTheme, type ThemeConfig } from 'antd'
import { afterEach, describe, expect, it } from 'vitest'

import defaultTheme from '../../../../libs/themepack/builtin/default.json'

// Dark mode guard. Dark mode (<html data-theme="dark">) re-points every
// --cdnca-color-* at the theme's *-dark seeds in @cdnca/ui dark.css, so pages
// need no dark rules of their own. jsdom has no color-mix(), so this file
// resolves dark.css itself for the built-in theme and checks the result:
// containers are never white and text keeps WCAG AA.
const sharedCSS = Object.values(import.meta.glob('../../../../packages/cdnca-ui/src/styles.css', {
  eager: true, import: 'default', query: '?raw',
}))[0] as string
const darkCSS = Object.values(import.meta.glob('../../../../packages/cdnca-ui/src/dark.css', {
  eager: true, import: 'default', query: '?raw',
}))[0] as string

function declarations(block: string): Record<string, string> {
  const out: Record<string, string> = {}
  for (const match of block.matchAll(/(--[a-z0-9-]+)\s*:\s*([^;]+);/g)) out[match[1]] = match[2].trim()
  return out
}

const rootBlock = /:root\s*\{([\s\S]*?)\n\}/.exec(sharedCSS)?.[1] ?? ''
const darkBlock = /:root\[data-theme="dark"\]:not\(#cdnca-dark\)\s*\{([\s\S]*?)\n\}/.exec(darkCSS)?.[1] ?? ''

const seedVariable = (name: string) => `--cdnca-${name.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`)}`

// The variables a page sees in dark mode for one theme: :root defaults, the
// theme's own values, then the dark block (it outranks the theme's selector).
function resolver(tokens: Record<string, unknown>) {
  const values: Record<string, string> = { ...declarations(rootBlock) }
  for (const [name, value] of Object.entries(tokens)) if (typeof value === 'string' && /^#[0-9a-f]{6}$/i.test(value)) values[seedVariable(name)] = value
  Object.assign(values, declarations(darkBlock))
  const resolve = (expression: string, depth = 0): string => {
    if (depth > 20) throw new Error(`cycle in ${expression}`)
    const value = expression.trim()
    const reference = /^var\((--[a-z0-9-]+)(?:,\s*(.+))?\)$/.exec(value)
    if (reference) {
      const next = values[reference[1]] ?? reference[2]
      if (next === undefined) throw new Error(`undefined ${reference[1]}`)
      return resolve(next, depth + 1)
    }
    const mix = /^color-mix\(in srgb,\s*(.+?)\s+(\d+)%,\s*(.+)\)$/.exec(value)
    if (mix) return mixHex(resolve(mix[1], depth + 1), Number(mix[2]), resolve(mix[3], depth + 1))
    if (/^#[0-9a-f]{6}$/i.test(value)) return value.toLowerCase()
    if (value === '#fff') return '#ffffff'
    throw new Error(`cannot resolve ${value}`)
  }
  return (name: string) => resolve(`var(${name})`)
}

const themes: [string, Record<string, unknown>][] = [
  ['default', (defaultTheme as { tokens?: Record<string, unknown> }).tokens ?? {}],
]

function seedsOf(tokens: Record<string, unknown>): CdncaDarkSeeds {
  return darkSeedsFromCSSVariables(Object.fromEntries(Object.entries(tokens).map(([k, v]) => [seedVariable(k), String(v)])))
}

const containers = [
  '--cdnca-color-bg-container', '--cdnca-color-bg-layout', '--cdnca-color-bg-page', '--cdnca-color-bg-panel',
  '--cdnca-color-bg-subtle', '--cdnca-color-bg-field', '--cdnca-color-table-header', '--cdnca-color-info-bg',
  '--cdnca-color-success-bg', '--cdnca-color-warning-bg', '--cdnca-color-error-bg', '--cdnca-color-primary-bg',
]

describe('dark mode palette', () => {
  afterEach(() => { delete document.documentElement.dataset.theme })

  it('finds the dark block in the shared stylesheet', () => {
    expect(sharedCSS).toContain("@import './dark.css';")
    expect(Object.keys(declarations(darkBlock)).length).toBeGreaterThan(200)
  })

  it('re-points every numbered light step a page stylesheet can use', () => {
    const dark = declarations(darkBlock)
    // Only the steps that are already dark or used as shadows/masks keep their light value.
    const keep = new Set(['blue45', 'blue46', 'blue48', 'blue50', 'blue51', 'neutral64', 'neutral76', 'neutral79', 'neutral80'])
    const missing = Object.keys(declarations(rootBlock))
      .filter((name) => /^--cdnca-color-(blue|neutral|green|orange|red|purple)\d+$/.test(name))
      .filter((name) => !dark[name] && !keep.has(name.replace('--cdnca-color-', '')))
    expect(missing).toEqual([])
  })

  for (const [id, tokens] of themes) {
    describe(id, () => {
      const value = resolver(tokens)

      it('never paints a container white', () => {
        for (const name of containers) expect([name, value(name)]).not.toEqual([name, '#ffffff'])
        for (const name of containers) expect(contrastRatio(value(name), '#ffffff'), name).toBeGreaterThan(10)
      })

      it('keeps titles and body text at 4.5:1 on every surface', () => {
        const surfaces = ['--cdnca-color-bg-container', '--cdnca-color-bg-page', '--cdnca-color-bg-panel', '--cdnca-color-bg-field', '--cdnca-color-table-header', '--cdnca-color-table-row-hover']
        const texts = ['--cdnca-color-title', '--cdnca-color-text', '--cdnca-color-text-secondary', '--cdnca-color-text-hint', '--cdnca-color-text-faint', '--cdnca-color-placeholder', '--cdnca-color-neutral57']
        for (const surface of surfaces) for (const text of texts) {
          expect(contrastRatio(value(text), value(surface)), `${text} on ${surface}`).toBeGreaterThanOrEqual(4.5)
        }
        // Alerts and selected rows carry body and secondary text.
        for (const surface of ['--cdnca-color-info-bg', '--cdnca-color-success-bg', '--cdnca-color-warning-bg', '--cdnca-color-error-bg', '--cdnca-color-primary-bg']) {
          for (const text of ['--cdnca-color-title', '--cdnca-color-text', '--cdnca-color-text-secondary']) {
            expect(contrastRatio(value(text), value(surface)), `${text} on ${surface}`).toBeGreaterThanOrEqual(4.5)
          }
        }
      })

      it('keeps brand, status and link text at 4.5:1 on the card and their own tints', () => {
        const card = value('--cdnca-color-bg-container')
        for (const [fg, tint] of [['primary', 'info-bg'], ['link', 'primary-bg'], ['success', 'success-bg'], ['warning', 'warning-bg'], ['error', 'error-bg']]) {
          expect(contrastRatio(value(`--cdnca-color-${fg}`), card), `${fg} on card`).toBeGreaterThanOrEqual(4.5)
          expect(contrastRatio(value(`--cdnca-color-${fg}`), value(`--cdnca-color-${tint}`)), `${fg} on ${tint}`).toBeGreaterThanOrEqual(4.5)
        }
        // Text on a primary-filled button.
        expect(contrastRatio(value('--cdnca-color-text-inverse'), value('--cdnca-color-primary'))).toBeGreaterThanOrEqual(4.5)
      })

      it('keeps input outlines and the focus ring at 3:1', () => {
        const card = value('--cdnca-color-bg-container')
        expect(contrastRatio(value('--cdnca-color-border'), card)).toBeGreaterThanOrEqual(3)
        expect(contrastRatio(value('--cdnca-color-border-input'), value('--cdnca-color-bg-field'))).toBeGreaterThanOrEqual(3)
        expect(contrastRatio(value('--cdnca-color-focus-ring'), card)).toBeGreaterThanOrEqual(3)
      })

      it('feeds antd the same palette the CSS derives', () => {
        const palette = darkPalette(seedsOf(tokens))
        expect(palette.card).toBe(value('--cdnca-color-bg-container'))
        expect(palette.title).toBe(value('--cdnca-color-title'))
        expect(palette.textWeak).toBe(value('--cdnca-color-text-faint'))
        expect(palette.rowSelected).toBe(value('--cdnca-color-primary-bg'))
        expect(palette.borderInput).toBe(value('--cdnca-color-border'))
        expect(palette.rowHover).toBe(value('--cdnca-color-table-row-hover'))
        expect(palette.linkHover).toBe(value('--cdnca-color-link-hover'))
        expect(palette.success).toBe(value('--cdnca-color-success'))
        expect(contrastRatio(palette.text, palette.elevated)).toBeGreaterThanOrEqual(4.5)
        expect(contrastRatio(palette.textSecondary, palette.rowSelected)).toBeGreaterThanOrEqual(4.5)
        expect(contrastRatio(palette.onPrimary, palette.primary)).toBeGreaterThanOrEqual(4.5)
      })
    })
  }

  it('switches antd to the dark algorithm when <html data-theme="dark">', async () => {
    let seen: ThemeConfig | undefined
    const Probe = () => {
      const { token } = antdTheme.useToken()
      seen = { token }
      return null
    }
    document.documentElement.dataset.theme = 'dark'
    render(<CdncaProvider><Probe /></CdncaProvider>)
    const palette = darkPalette()
    expect(seen?.token?.colorBgContainer).toBe(palette.card)
    expect(seen?.token?.colorText).toBe(palette.text)
    expect(seen?.token?.colorPrimary).toBe(palette.primary)
    expect(seen?.token?.colorBgContainer).not.toBe('#ffffff')
  })

  it('stays light without the switch', () => {
    let background: string | undefined
    const Probe = () => {
      background = antdTheme.useToken().token.colorBgContainer
      return null
    }
    render(<CdncaProvider><Probe /></CdncaProvider>)
    expect(background).toBe('#ffffff')
  })
})
