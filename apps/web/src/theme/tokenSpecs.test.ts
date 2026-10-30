import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

// @ts-expect-error plain ESM helper shared with node
import { tokenSpecsText } from '../../scripts/themeTokenSpecs.mjs'

// tokenSpecs.json (customize panel groups and "used in" files) is generated
// from tokens.go and the stylesheets; regenerate it when either changes.
describe('theme token specs', () => {
  it('equals node apps/web/scripts/themeTokenSpecs.mjs --write output', () => {
    const stored = readFileSync(resolve(__dirname, 'tokenSpecs.json'), 'utf8')
    expect(stored, 'run: node apps/web/scripts/themeTokenSpecs.mjs --write').toBe(tokenSpecsText())
  })
})
