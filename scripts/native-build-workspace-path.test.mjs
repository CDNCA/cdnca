import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { tmpdir } from 'node:os'
import childProcess from 'node:child_process'
import { syncBuiltinESMExports } from 'node:module'
import { test } from 'node:test'
import { buildInitialNativeRelease } from './native-initial-release-package.mjs'
import { buildNativeRelease, createNativeManifest } from './native-release-package.mjs'

const realExec = childProcess.execFileSync, realMkdtemp = fs.mkdtempSync
const predecessor = '8b26d83421351b96a715fefa1d7f4fcdbb94ed1a'
const predecessorTree = '110d3367f0aa9f7f96f1f7c3739f551cbdfdc397'
const commit = 'd'.repeat(40), tree = 'e'.repeat(40), remoteRef = 'refs/heads/main'

for (const [name, build] of [['initial', buildInitialNativeRelease], ['upgrade', buildNativeRelease]]) {
  test(`${name} builder gives real Go a canonical workspace even when the temporary parent is a symlink`, (t) => {
    const root = fs.realpathSync(realMkdtemp(path.join(tmpdir(), 'cdnca-go-workspace-test-')))
    t.after(() => fs.rmSync(root, { recursive: true, force: true }))
    const alias = path.join(root, 'alias'), previousRelease = path.join(root, 'previous')
    fs.symlinkSync(root, alias)
    for (const file of ['bin/control-api', 'bin/agent-gateway', 'static/web/index.html', 'migrations/001_test.up.sql']) {
      fs.mkdirSync(path.dirname(path.join(previousRelease, file)), { recursive: true })
      fs.writeFileSync(path.join(previousRelease, file), 'fixture', { mode: file.startsWith('bin/') ? 0o755 : 0o644 })
    }
    fs.writeFileSync(path.join(previousRelease, 'release.manifest.json'), JSON.stringify(createNativeManifest(previousRelease, {
      version: '1.0.2', built_at: '2026-10-08T00:00:00Z', platform: { os: 'linux', arch: 'amd64' },
      source: { commit: predecessor, tree: predecessorTree, previous_commit: 'a'.repeat(40) },
    })))
    const temporary = [], listed = [], stopAfterProbe = new Error('real Go probe completed')
    const mkdtemp = t.mock.method(fs, 'mkdtempSync', () => {
      const directory = realMkdtemp(path.join(root, 'build-'))
      temporary.push(directory)
      return path.join(alias, path.basename(directory))
    })
    const command = t.mock.method(childProcess, 'execFileSync', (program, args, options) => {
      if (program === 'git') {
        const flags = args.filter((arg) => arg !== '--no-replace-objects')
        if (flags[0] === 'ls-remote') return `${commit}\t${remoteRef}`
        if (flags[0] === 'rev-parse') return flags[1].endsWith('^{commit}') ? commit
          : flags[1].startsWith(predecessor) ? predecessorTree : tree
        if (flags[0] === 'ls-tree') return '001_test.up.sql\n001_test.down.sql'
        if (['merge-base', 'archive'].includes(flags[0])) return ''
      }
      if (program === 'tar' && args[0] === '-xf') {
        const source = args[args.indexOf('-C') + 1]
        const files = { 'go.work': 'go 1.24.0\nuse ./services/control-api\n',
          'services/control-api/go.mod': 'module example.invalid/control\ngo 1.24.0\n',
          'services/control-api/cmd/control-api/main.go': 'package main\nfunc main() {}\n' }
        for (const [file, body] of Object.entries(files)) {
          fs.mkdirSync(path.dirname(path.join(source, file)), { recursive: true })
          fs.writeFileSync(path.join(source, file), body)
        }
        return ''
      }
      if (program === 'go') {
        listed.push(realExec('go', ['list', args.at(-1)], { ...options, stdio: ['ignore', 'pipe', 'pipe'],
          env: { ...options.env, GOTOOLCHAIN: 'local', GOPROXY: 'off', GOSUMDB: 'off' } }).trim())
        assert.equal(options.cwd, fs.realpathSync(options.cwd))
        assert.equal(options.env.GOWORK, path.join(options.cwd, 'go.work'))
        throw stopAfterProbe
      }
      throw new Error(`unexpected probe command: ${program}`)
    })
    syncBuiltinESMExports()
    try {
      assert.throws(() => build({ commit, remoteRef, previousSourceCommit: predecessor, previousRelease,
        outputDir: path.join(root, 'output'), version: '1.0.3', arch: 'amd64', allowEmptySiteKey: true }),
      (error) => error === stopAfterProbe)
      assert.deepEqual(listed, ['example.invalid/control/cmd/control-api'])
      assert.ok(temporary.every((directory) => !fs.existsSync(directory)))
      assert.equal(fs.existsSync(path.join(root, 'output')), false)
    } finally { command.mock.restore(); mkdtemp.mock.restore(); syncBuiltinESMExports() }
  })
}
