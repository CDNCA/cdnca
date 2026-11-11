// Default-look lock: the colors apps/web wraps in var(--cdnca-*, fallback)
// must keep the pre-theme look. Each fallback equals the variable's default,
// and every stylesheet with the variables expanded equals its text at the
// base commit (scripts/default-look-lock.test.mjs, also runnable with node --test).
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

// @ts-expect-error plain ESM helper shared with node --test
import { declarations, defaultVariables, expandFallbacks, leftoverColors, normalizeValue, removedOnPurpose, scriptVariable, standaloneStylesheets, wrappedVariable } from '../../scripts/defaultLook.mjs'

const repo = resolve(__dirname, '../../../..') + '/'
const base = process.env.DEFAULT_LOOK_BASE ?? 'b3150d535'
const git = (...args: string[]) => execFileSync('git', ['-C', repo, ...args], { encoding: 'utf8', maxBuffer: 64 << 20, stdio: ['ignore', 'pipe', 'ignore'] })
const files = git('ls-files', 'apps/web/src/*.css', 'apps/web/src/**/*.css').split('\n').filter(Boolean)

function baseText(file: string): string | null {
  try { return git('show', `${base}:${file}`) } catch { return null }
}

// A new component's own root class: every selector of the rule starts with a
// class that no base stylesheet uses, so the rule cannot reach an old screen.
const baseCSS = files.map((file) => baseText(file) ?? '').join('\n')
const baseClasses = new Set(baseCSS.match(/\.[A-Za-z_][\w-]*/g) ?? [])
function ownRootClass(line: string): boolean {
  const selector = line.replace(/^(@media[^>]*>> )/, '').split(' { ')[0]
  if (selector.includes(' >> ')) return false
  return selector.split(',').every((part) => {
    const root = part.trim().match(/^\.[A-Za-z_][\w-]*/)?.[0]
    return root !== undefined && !baseClasses.has(root)
  })
}

describe('default look lock', () => {
  it('wraps colors only with the shared default as fallback', () => {
    const defaults = defaultVariables() as Map<string, string>
    const mismatches: string[] = []
    for (const file of files) {
      for (const match of readFileSync(repo + file, 'utf8').matchAll(wrappedVariable)) {
        const value = defaults.get(match[1])
        if (value === undefined || normalizeValue(value) !== normalizeValue(match[2])) mismatches.push(`${file}: ${match[0]}`)
      }
    }
    expect(mismatches).toEqual([])
  })

  it('reads script colors (charts, inline styles) with the shared default as fallback', () => {
    const defaults = defaultVariables() as Map<string, string>
    const scripts = git('ls-files', 'apps/web/src/*.ts', 'apps/web/src/**/*.ts', 'apps/web/src/*.tsx', 'apps/web/src/**/*.tsx').split('\n').filter(Boolean)
    const mismatches: string[] = []
    let reads = 0
    for (const file of scripts) {
      for (const match of readFileSync(repo + file, 'utf8').matchAll(scriptVariable)) {
        reads++
        const value = defaults.get(match[1])
        if (value === undefined || normalizeValue(value) !== normalizeValue(match[2])) mismatches.push(`${file}: ${match[0]}`)
      }
    }
    expect(mismatches).toEqual([])
    expect(reads).toBeGreaterThan(40)
  })

  it('leaves no hard-coded color outside the listed exceptions', () => {
    const all = git('ls-files', 'apps/web/src').split('\n').filter(Boolean)
    expect(leftoverColors(all, (file: string) => readFileSync(repo + file, 'utf8'))).toEqual([])
  })

  it.skipIf(baseText('apps/web/src/styles.css') === null)('keeps every stylesheet equal to the base commit once variables are expanded', () => {
    let compared = 0
    for (const file of files) {
      if (standaloneStylesheets.includes(file)) continue
      const before = baseText(file)
      const after = readFileSync(repo + file, 'utf8')
      if (before === null) {
        // New files add theme-look rules, or style a new component that did not
        // exist at the base (its own root class), which cannot change the old look.
        for (const line of declarations(after) as string[]) {
          if (ownRootClass(line)) continue
          expect(line, file).toMatch(/html\[data-cdnca-(look|motion)=|@keyframes|^(@media[^>]*>> )?\.theme-customizer[ ,{]/)
        }
        continue
      }
      // Every base declaration survives unchanged; rules added since (new
      // components of later fixes) cannot alter an existing screen.
      const kept = new Set(declarations(expandFallbacks(after)) as string[])
      expect((declarations(expandFallbacks(before)) as string[]).filter((line) => !kept.has(line) && !removedOnPurpose(file, line)), file).toEqual([])
      compared++
    }
    expect(compared).toBeGreaterThan(50)
  })
})
