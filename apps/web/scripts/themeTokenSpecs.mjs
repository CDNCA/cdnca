// Builds apps/web/src/theme/tokenSpecs.json for the theme customize panel:
// each token's kind, group, range, antd flag and CSS aliases from
// libs/themepack/tokens.go, plus "used_in": the apps/web / @cdnca/ui
// stylesheets that read the token's variable. Regenerate with
//   node apps/web/scripts/themeTokenSpecs.mjs --write
// (libs/themepack TestWebTokenSpecsMatch and src/theme/tokenSpecs.test.ts check it).
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs'
import { dirname, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = import.meta.url.startsWith('file:') ? dirname(fileURLToPath(import.meta.url)) : resolve(process.cwd(), 'scripts')
const repo = resolve(here, '../../..')
const kinds = { Color: 'color', Length: 'length', Number: 'number', FontFamily: 'font_family', Shadow: 'shadow' }

function cssFiles(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return name === 'node_modules' ? [] : cssFiles(path)
    return name.endsWith('.css') ? [path] : []
  })
}

export function buildTokenSpecs() {
  const source = readFileSync(join(repo, 'libs/themepack/tokens.go'), 'utf8')
  const sheets = [...cssFiles(join(repo, 'apps/web/src')), ...cssFiles(join(repo, 'packages/cdnca-ui/src'))]
    .map((path) => ({ file: relative(repo, path), text: readFileSync(path, 'utf8') }))
  const specs = {}
  for (const match of source.matchAll(/\{Name: "(\w+)", Kind: Token(\w+), Group: Group(\w+)(.*?)\},?\n/g)) {
    const [, name, kind, group, rest] = match
    const spec = { kind: kinds[kind], group: group.toLowerCase() }
    const min = /Min: ([\d.]+)/.exec(rest)
    const max = /Max: ([\d.]+)/.exec(rest)
    if (min) spec.min = Number(min[1])
    if (max) spec.max = Number(max[1])
    if (rest.includes('Antd: true')) spec.antd = true
    const aliases = /CSSVariables: \[\]string\{(.*?)\}/.exec(rest)
    if (aliases) spec.css_variables = [...aliases[1].matchAll(/"([^"]+)"/g)].map((item) => item[1])
    // The stylesheets reading the variable (its main name or an alias).
    const names = [kebabName(name), ...(spec.css_variables ?? [])]
    const pattern = new RegExp(`var\\((?:${names.map((item) => item.replace(/[-]/g, '\\-')).join('|')})[,)\\s]`)
    const usedIn = sheets.filter((sheet) => pattern.test(sheet.text)).map((sheet) => sheet.file.replace(/^apps\/web\/src\//, '').replace(/^packages\/cdnca-ui\/src\//, '@cdnca/ui/'))
    if (usedIn.length > 0) spec.used_in = usedIn.sort()
    specs[name] = spec
  }
  return specs
}

// libs/themepack CSSVariable: --cdnca-<kebab-case>, digits kept attached.
function kebabName(name) {
  return `--cdnca-${name.replace(/[A-Z]/g, (letter) => `-${letter.toLowerCase()}`)}`
}

export function tokenSpecsText() {
  return `${JSON.stringify(buildTokenSpecs(), null, 2)}\n`
}

if (process.argv.includes('--write')) {
  writeFileSync(join(repo, 'apps/web/src/theme/tokenSpecs.json'), tokenSpecsText())
}
