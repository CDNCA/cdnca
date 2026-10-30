import { readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

export function listFiles(dir, keep) {
  const out = []
  let entries
  try {
    entries = readdirSync(dir)
  } catch {
    return out
  }
  for (const name of entries) {
    if (name === 'node_modules' || name === 'dist' || name.startsWith('.')) continue
    const full = join(dir, name)
    if (statSync(full).isDirectory()) out.push(...listFiles(full, keep))
    else if (keep(full)) out.push(full)
  }
  return out.sort()
}

export function lineOf(src, index) {
  let n = 1
  for (let i = 0; i < index; i++) if (src.charCodeAt(i) === 10) n++
  return n
}

export const rel = (repo, file) => relative(repo, file)
