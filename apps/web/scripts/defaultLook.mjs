// Shared by the default-look lock tests: expands the theme variables that
// apps/web CSS wraps around its hard-coded colors back to the default values,
// so a stylesheet can be compared declaration by declaration with its
// pre-theme text.
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

// import.meta.url is a file: URL under node --test, an http one under vitest+jsdom.
const here = import.meta.url.startsWith('file:') ? dirname(fileURLToPath(import.meta.url)) : resolve(process.cwd(), 'scripts')
const sharedStyles = resolve(here, '../../../packages/cdnca-ui/src/styles.css')

/** The --cdnca-* defaults declared on :root by @cdnca/ui/styles.css. */
export function defaultVariables() {
  const css = readFileSync(sharedStyles, 'utf8')
  const root = css.slice(css.indexOf(':root {'), css.indexOf('}', css.indexOf(':root {')))
  const variables = new Map()
  for (const match of root.matchAll(/^\s*(--cdnca-[a-z0-9-]+):\s*([^;]+);/gm)) variables.set(match[1], match[2].trim())
  return variables
}

// var(--cdnca-x, fallback) with one level of nested parentheses in fallback.
export const wrappedVariable = /var\((--cdnca-[a-z0-9-]+),\s*((?:[^()]|\([^()]*\))+)\)/g

const hex2 = (n) => Number(n).toString(16).padStart(2, '0')
const alphaText = (a) => String(Math.round(a * 1e6) / 1e6)

// Translucent colors compare by computed value: rgba(45, 140, 240, .1),
// rgb(45 140 240 / 10%) and color-mix(in srgb, #2d8cf0 10%, transparent)
// (how a theme-derived translucent color is written) all become
// "#2d8cf0/0.1"; an opaque rgb() becomes its hex.
function canonicalColors(value) {
  return value
    .replace(/color-mix\(in srgb,\s*#([0-9a-fA-F]{6})\s+([\d.]+)%,\s*transparent\)/g, (_, h, p) => `#${h.toLowerCase()}/${alphaText(parseFloat(p) / 100)}`)
    .replace(/rgba?\(\s*(\d+)[\s,]+(\d+)[\s,]+(\d+)\s*(?:[,/]\s*([\d.]+)(%?)\s*)?\)/g, (_, r, g, b, a, pct) => {
      const hex = `#${hex2(r)}${hex2(g)}${hex2(b)}`
      if (a === undefined) return hex
      const alpha = pct ? parseFloat(a) / 100 : parseFloat(a)
      return alpha === 1 ? hex : `${hex}/${alphaText(alpha)}`
    })
}

export function normalizeValue(value) {
  return canonicalColors(value
    .replace(/#([0-9a-fA-F]{3})\b/g, (_, h) => `#${[...h].map((c) => c + c).join('')}`))
    .replace(/#([0-9a-fA-F]{6})\b/g, (_, h) => `#${h.toLowerCase()}`)
    .replace(/\s+/g, ' ')
    .trim()
}

/** Replaces every var(--cdnca-x, fallback) by its fallback. */
export function expandFallbacks(css) {
  let previous
  let current = css
  do {
    previous = current
    current = current.replace(wrappedVariable, (_, _name, fallback) => fallback.trim())
  } while (current !== previous)
  return current
}

/** Flat list "selector { property: value }" of a stylesheet, comments dropped. */
export function declarations(css) {
  const text = css.replace(/\/\*[\s\S]*?\*\//g, '')
  const result = []
  const stack = []
  let buffer = ''
  for (const char of text) {
    if (char === '{') {
      stack.push(buffer.trim().replace(/\s+/g, ' '))
      buffer = ''
    } else if (char === '}' || char === ';') {
      const body = buffer.trim()
      if (body) {
        const colon = body.indexOf(':')
        result.push(`${stack.join(' >> ')} { ${body.slice(0, colon).trim()}: ${normalizeValue(body.slice(colon + 1))} }`)
      }
      buffer = ''
      if (char === '}') stack.pop()
    } else {
      buffer += char
    }
  }
  return result
}

// themeColor('--cdnca-x', 'fallback') / themeColorAlpha('--cdnca-x', 'fallback', alpha)
// in apps/web scripts (src/theme/themeColor.ts).
export const scriptVariable = /themeColor(?:Alpha)?\('(--cdnca-[a-z0-9-]+)',\s*'([^']+)'/g

// A color literal left in a stylesheet or script, outside var(--cdnca-*, …)
// and themeColor(…): what the "no hard-coded color" check counts.
const colorLiteral = /#[0-9a-fA-F]{8}\b|#[0-9a-fA-F]{6}\b|#[0-9a-fA-F]{3}\b|rgba?\([^)]*\)/g

/** Color literals of a stylesheet (css) or script, comments and theme reads removed. */
export function hardCodedColors(text, css) {
  let body = text.replace(/\/\*[\s\S]*?\*\//g, '')
  if (!css) body = body.replace(/(^|[^:'"`])\/\/.*$/gm, '$1')
  body = css ? expandAway(body) : body.replace(scriptVariable, '')
  return body.match(colorLiteral) ?? []
}

function expandAway(css) {
  let previous
  let current = css
  do {
    previous = current
    current = current.replace(wrappedVariable, 'VAR')
  } while (current !== previous)
  return current
}

// Allowed literals: the tech look's own fixed colors (tech-look.css is the
// tech theme, not the default look), fully transparent black (no color to
// theme) and themeColorAlpha's rgba() template. theme/customize.ts writes
// theme token values (shadow text), it paints nothing itself.
export const colorExceptions = { files: ['apps/web/src/styles/tech-look.css', 'apps/web/src/theme/themeColor.ts', 'apps/web/src/theme/customize.ts'], literals: ['rgba(0, 0, 0, 0)'] }

/** "file: literal" for every hard-coded color apps/web still has. */
export function leftoverColors(files, read) {
  const result = []
  for (const file of files) {
    if (colorExceptions.files.includes(file) || !/\.(css|tsx?)$/.test(file) || /\.test\.|\/tests?\//.test(file)) continue
    for (const literal of hardCodedColors(read(file), file.endsWith('.css'))) {
      if (!colorExceptions.literals.includes(literal)) result.push(`${file}: ${literal}`)
    }
  }
  return result
}
