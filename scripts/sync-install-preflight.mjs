#!/usr/bin/env node
// Embeds the shared installer libraries verbatim into both one-file installers
// between their BEGIN/END markers. `--check` only verifies.
//   scripts/lib/install-preflight.sh  -> "install-preflight"
//   scripts/lib/systemd-compat.sh     -> "systemd-compat"
//   scripts/lib/ssh-guard.sh          -> "ssh-guard" (fail2ban sshd, every installer)
//   scripts/lib/install-progress.sh   -> "install-progress" (stage/progress display)
//   scripts/lib/package-automation.sh -> "package-automation" (apt-daily/unattended-upgrades)
import { readFileSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
export const libraries = { 'install-preflight': 'scripts/lib/install-preflight.sh', 'systemd-compat': 'scripts/lib/systemd-compat.sh',
  'ssh-guard': 'scripts/lib/ssh-guard.sh', 'install-progress': 'scripts/lib/install-progress.sh',
  'package-automation': 'scripts/lib/package-automation.sh' }
// Libraries each installer embeds.
export const embeds = {
  'scripts/install-control.sh': ['install-preflight', 'systemd-compat', 'ssh-guard', 'install-progress', 'package-automation'],
  'scripts/install-node.sh': ['install-preflight', 'systemd-compat', 'ssh-guard', 'install-progress', 'package-automation'],
}
// Installers that embed install-preflight (tests/install-preflight.test.mjs).
export const installers = Object.keys(embeds).filter((relative) => embeds[relative].includes('install-preflight'))

const markers = (name) => ({
  begin: `# >>> BEGIN ${name} (generated from ${libraries[name]}; do not edit here)\n`,
  end: `# <<< END ${name}\n`,
})

export function embedded(text, name = 'install-preflight') {
  const { begin, end } = markers(name)
  const start = text.indexOf(begin), stop = text.indexOf(end)
  if (start < 0 || stop < start || text.indexOf(begin, start + 1) >= 0) throw new Error(`missing or duplicated ${name} markers`)
  return { before: text.slice(0, start + begin.length), body: text.slice(start + begin.length, stop), after: text.slice(stop) }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const check = process.argv.includes('--check')
  let stale = false
  for (const relative of Object.keys(embeds)) {
    const file = path.join(root, relative)
    let text = readFileSync(file, 'utf8'), changed = false
    for (const name of embeds[relative]) {
      const library = readFileSync(path.join(root, libraries[name]), 'utf8')
      const parts = embedded(text, name)
      if (parts.body === library) continue
      changed = true
      text = parts.before + library + parts.after
    }
    if (!changed) continue
    stale = true
    if (!check) writeFileSync(file, text)
    console.log(`${check ? 'stale' : 'updated'} ${relative}`)
  }
  if (check && stale) process.exit(1)
}
