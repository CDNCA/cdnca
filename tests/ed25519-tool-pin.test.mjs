import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

// docs/install/ed25519-tool-security.md: the installers pin the reproducible
// linux/amd64 build of tools/ed25519-tool; the package builder enforces it too.
const repository = new URL('..', import.meta.url).pathname
const pin = (relative) => /^readonly CDNCA_ED25519_TOOL_SHA256="([a-f0-9]{64})"$/m.exec(readFileSync(join(repository, relative), 'utf8'))?.[1]

test('control and node installers pin the same Ed25519 tool', () => {
  assert.match(pin('scripts/install-control.sh') ?? '', /^[a-f0-9]{64}$/)
  assert.equal(pin('scripts/install-node.sh'), pin('scripts/install-control.sh'))
})

test('the reproducible tool build matches the installer pin', () => {
  const directory = mkdtempSync(join(tmpdir(), 'cdnca-ed25519-pin-'))
  try {
    const output = join(directory, 'cdnca-ed25519')
    execFileSync('sh', [join(repository, 'tools/ed25519-tool/build.sh'), output], { stdio: ['ignore', 'pipe', 'pipe'], timeout: 600000 })
    assert.equal(createHash('sha256').update(readFileSync(output)).digest('hex'), pin('scripts/install-node.sh'),
      'tools/ed25519-tool changed: rebuild with build.sh and update CDNCA_ED25519_TOOL_SHA256 in both installers')
  } finally { rmSync(directory, { recursive: true, force: true }) }
})

test('the tool uses only the Go standard library', () => {
  assert.equal(readFileSync(join(repository, 'tools/ed25519-tool/go.mod'), 'utf8').trim(), 'module cdnca/tools/ed25519-tool\n\ngo 1.27.0\n\ntoolchain go1.27.3')
  const imports = [...readFileSync(join(repository, 'tools/ed25519-tool/main.go'), 'utf8').matchAll(/^\t"([^"]+)"$/gm)].map((match) => match[1])
  assert.ok(imports.length > 0 && imports.every((name) => !name.includes('.')), `non-standard import: ${imports}`)
})
