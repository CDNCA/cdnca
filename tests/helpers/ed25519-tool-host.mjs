// Test-only: a host-native build of tools/ed25519-tool (production installs
// the pinned linux/amd64 build). Built once per test process.
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdtempSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

let cached

export function hostEd25519Tool() {
  if (cached) return cached
  const path = join(mkdtempSync(join(tmpdir(), 'cdnca-ed25519-host-')), 'cdnca-ed25519')
  const env = { ...process.env, GOWORK: 'off', CGO_ENABLED: '0' }
  for (const name of ['GOFLAGS', 'GOEXPERIMENT', 'GOOS', 'GOARCH']) delete env[name]
  execFileSync('go', ['build', '-trimpath', '-o', path, '.'], {
    cwd: new URL('../../tools/ed25519-tool/', import.meta.url).pathname, env, stdio: ['ignore', 'pipe', 'pipe'],
  })
  const bytes = readFileSync(path)
  cached = { path, bytes, sha256: createHash('sha256').update(bytes).digest('hex') }
  return cached
}

// Replace the installer pin with the host build's digest (scripts embedded in tests).
export function withHostEd25519Pin(script) {
  const tool = hostEd25519Tool()
  const pinned = script.replace(/^readonly CDNCA_ED25519_TOOL_SHA256="[a-f0-9]{64}"$/m, `readonly CDNCA_ED25519_TOOL_SHA256="${tool.sha256}"`)
  if (pinned === script) throw new Error('installer Ed25519 pin not found')
  return pinned
}
