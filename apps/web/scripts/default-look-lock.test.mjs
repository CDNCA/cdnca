// Default-look lock (node --test): every apps/web stylesheet, with the theme
// variables expanded to their defaults, must equal its text at the base
// commit declaration by declaration. Run after a change that wraps colors in
// var(--cdnca-*):
//   DEFAULT_LOOK_BASE=<commit> node --test apps/web/scripts/default-look-lock.test.mjs
// Files new since the base must only add rules scoped to a theme look (or to
// a component new since the base, see below).
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { fileURLToPath } from 'node:url'

import { declarations, defaultVariables, expandFallbacks, leftoverColors, normalizeValue, removedOnPurpose, scriptVariable, wrappedVariable } from './defaultLook.mjs'

const repo = fileURLToPath(new URL('../../../', import.meta.url))
const base = process.env.DEFAULT_LOOK_BASE ?? 'b3150d535'
const git = (...args) => execFileSync('git', ['-C', repo, ...args], { encoding: 'utf8', maxBuffer: 64 << 20, stdio: ['ignore', 'pipe', 'ignore'] })
const files = git('ls-files', 'apps/web/src/*.css', 'apps/web/src/**/*.css').split('\n').filter(Boolean)
// Same rule as src/tests/DefaultLookLock.test.ts: a new file may style a
// component that did not exist at the base under its own root class.
const baseText = (file) => { try { return git('show', `${base}:${file}`) } catch { return null } }
const baseClasses = new Set(files.map((file) => baseText(file) ?? '').join('\n').match(/\.[A-Za-z_][\w-]*/g) ?? [])
function ownRootClass(line) {
  const selector = line.replace(/^(@media[^>]*>> )/, '').split(' { ')[0]
  if (selector.includes(' >> ')) return false
  return selector.split(',').every((part) => {
    const root = part.trim().match(/^\.[A-Za-z_][\w-]*/)?.[0]
    return root !== undefined && !baseClasses.has(root)
  })
}

test(`apps/web CSS keeps the default look of ${base}`, () => {
  let compared = 0
  for (const file of files) {
    let before
    try { before = git('show', `${base}:${file}`) } catch { before = null }
    const after = readFileSync(repo + file, 'utf8')
    if (before === null) {
      // New file: everything must sit under a theme look attribute or be a keyframe.
      for (const line of declarations(after)) {
        // …or style a component new since the base under its own root class
        // (theme customizer), which cannot change any existing screen.
        if (ownRootClass(line)) continue
        assert.match(line, /html\[data-cdnca-(look|motion)=|@keyframes|^@media[^>]*>> html\[data-cdnca-(look|motion)=|^(@media[^>]*>> )?\.theme-customizer[ ,{]/, `${file}: unscoped rule ${line}`)
      }
      continue
    }
    // Every declaration of the base must survive unchanged; rules added since
    // (new components of later fixes) cannot alter an existing screen.
    const kept = new Set(declarations(expandFallbacks(after)))
    assert.deepEqual(declarations(expandFallbacks(before)).filter((line) => !kept.has(line) && !removedOnPurpose(file, line)), [], file)
    compared++
  }
  assert.ok(compared > 50, `compared ${compared} files`)
})

// A wrapped color only keeps the default look if its fallback is exactly the
// variable's default (with no theme loaded the variable, not the fallback, wins).
test('every var(--cdnca-*, fallback) fallback equals the shared default', () => {
  const defaults = defaultVariables()
  const mismatches = []
  for (const file of files) {
    for (const match of readFileSync(repo + file, 'utf8').matchAll(wrappedVariable)) {
      const [, name, fallback] = match
      const value = defaults.get(name)
      if (value === undefined || normalizeValue(value) !== normalizeValue(fallback)) mismatches.push(`${file}: ${match[0]} (default ${value})`)
    }
  }
  assert.deepEqual(mismatches, [])
})

// Chart and inline colors read in script: themeColor('--cdnca-x', fallback)
// must fall back to the variable's default too.
test('every themeColor(variable, fallback) in scripts falls back to the shared default', () => {
  const defaults = defaultVariables()
  const scripts = git('ls-files', 'apps/web/src/*.ts', 'apps/web/src/**/*.ts', 'apps/web/src/*.tsx', 'apps/web/src/**/*.tsx').split('\n').filter(Boolean)
  const mismatches = []
  let reads = 0
  for (const file of scripts) {
    for (const match of readFileSync(repo + file, 'utf8').matchAll(scriptVariable)) {
      reads++
      const value = defaults.get(match[1])
      if (value === undefined || normalizeValue(value) !== normalizeValue(match[2])) mismatches.push(`${file}: ${match[0]} (default ${value})`)
    }
  }
  assert.deepEqual(mismatches, [])
  assert.ok(reads > 40, `found ${reads} themeColor reads`)
})

test('apps/web has no hard-coded color outside the listed exceptions', () => {
  const all = git('ls-files', 'apps/web/src').split('\n').filter(Boolean)
  assert.deepEqual(leftoverColors(all, (file) => readFileSync(repo + file, 'utf8')), [])
})
