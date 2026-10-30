import { spawn, spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { describe, expect, it } from 'vitest'

import { buildInstallerCommand, type InstallerCommand } from './installerCommand'

// The generated command runs in a real bash with curl replaced by a shell
// function: no network, no real installer. The stand-in installer records its
// arguments and stdin and exits with $MODE_STATUS.
const curlStub = String.raw`
curl() {
  local out='' url=''
  while [ "$#" -gt 0 ]; do
    case "$1" in
      -o) out="$2"; shift 2 ;;
      --proto|--proto-redir) shift 2 ;;
      -fsSL) shift ;;
      https://*) url="$1"; shift ;;
      *) return 91 ;;
    esac
  done
  printf '%s\n' "$url" >> "$T/downloads"
  case "$MODE:$url" in
    curl-fail:*|fallback:https://a.example/*) return 22 ;;
    curl-timeout:*) return 28 ;;
    empty:*) : > "$out"; return 0 ;;
    truncated:*) printf '#!/usr/bin/env bash\necho half\n' > "$out"; return 0 ;;
  esac
  cat > "$out" <<'SCRIPT'
#!/usr/bin/env bash
main() {
  printf '%s\n' "$@" > "$T/args"
  if [ "$READ_STDIN" = 1 ]; then IFS= read -r line; printf '%s' "$line" > "$T/stdin"; fi
  for a in "$@"; do case "$a" in /*) cat "$a" > "$T/secret"; stat -c '%a' "$a" > "$T/mode" 2>/dev/null || stat -f '%Lp' "$a" > "$T/mode" ;; esac; done
  if [ "$MODE" = sigint ]; then kill -INT "$PPID"; sleep 0.3; fi
  exit "$MODE_STATUS"
}
main "$@"
SCRIPT
}
`

function run(command: string, mode: string, status = 0, extra = '') {
  const directory = mkdtempSync(join(tmpdir(), 'cdnca-installer-command-'))
  const temp = join(directory, 'tmp')
  spawnSync('mkdir', [temp])
  const result = spawnSync('/bin/bash', ['-c', `${curlStub}\n${extra}\n${command}`], {
    encoding: 'utf8', timeout: 10_000,
    env: { PATH: '/usr/bin:/bin', T: directory, TMPDIR: temp, MODE: mode, MODE_STATUS: String(status), READ_STDIN: '1' },
  })
  const files = new Map(readdirSync(directory).filter((name) => name !== 'tmp')
    .map((name) => [name, readFileSync(join(directory, name), 'utf8')]))
  const read = (name: string) => files.get(name) ?? null
  const leftovers = readdirSync(temp)
  rmSync(directory, { recursive: true, force: true })
  return { status: result.status, stderr: result.stderr, read, leftovers }
}

const base: InstallerCommand = {
  urls: ['https://a.example/downloads/install-node.sh', 'https://b.example/downloads/install-node.sh'],
  protocols: '=https', label: '[cdnca-edge]', args: "--control-plane 'https://a.example'",
}
const stdinCommand = buildInstallerCommand({ ...base, stdinSecret: "k'1" })
const fileCommand = buildInstallerCommand({ ...base, args: "--licensing-server 'https://a.example'", secretFile: { flag: '--activation-code-file', value: 'AbC-123_x' } })

describe('one-line installer command', () => {
  it('is a single line in one subshell', () => {
    for (const command of [stdinCommand, fileCommand]) {
      expect(command).not.toContain('\n')
      expect(command.startsWith('(') && command.endsWith(')')).toBe(true)
    }
  })

  it.each([0, 1, 22, 28, 47])('returns the installer exit status %i and removes the downloaded script', (status) => {
    for (const command of [stdinCommand, fileCommand]) {
      const result = run(command, 'ok', status)
      expect(result.status).toBe(status)
      expect(result.leftovers).toEqual([])
    }
  })

  it('passes the stdin secret and arguments to the installer', () => {
    const result = run(stdinCommand, 'ok')
    expect(result.read('stdin')).toBe("k'1")
    expect(result.read('args')).toBe('--control-plane\nhttps://a.example\n')
  })

  it('hands the credential over in a private temporary file and deletes it afterwards', () => {
    const result = run(fileCommand, 'ok', 47)
    expect(result.status).toBe(47)
    expect(result.read('secret')).toBe('AbC-123_x\n')
    expect(result.read('mode')?.trim()).toBe('600')
    expect(result.read('args')?.split('\n').slice(0, 3)).toEqual(['--licensing-server', 'https://a.example', '--activation-code-file'])
    expect(result.leftovers).toEqual([])
  })

  it('falls back to the second URL', () => {
    const result = run(stdinCommand, 'fallback', 0)
    expect(result.status).toBe(0)
    expect(result.read('downloads')?.trim().split('\n')).toEqual(base.urls)
  })

  it.each([['curl-fail', 22], ['curl-timeout', 28]] as const)('a failed download (%s) returns curl status %i and never runs the installer', (mode, status) => {
    const result = run(stdinCommand, mode)
    expect(result.status).toBe(status)
    expect(result.stderr).toContain('[cdnca-edge] error: 无法下载安装脚本')
    expect(result.read('args')).toBeNull()
    expect(result.leftovers).toEqual([])
  })

  it.each(['empty', 'truncated'])('an %s download returns non-zero and never runs', (mode) => {
    const result = run(fileCommand, mode)
    expect(result.status).toBe(1)
    expect(result.stderr).toContain('下载的安装脚本为空或不完整')
    expect(result.read('args')).toBeNull()
    expect(result.leftovers).toEqual([])
  })

  it('a credential file that cannot be written returns non-zero and never runs the installer', () => {
    // The second mktemp (the credential file) fails.
    const failing = 'mktemp() { if [ -e "$T/once" ]; then return 1; fi; : > "$T/once"; command mktemp "$@"; }'
    const result = run(fileCommand, 'ok', 0, failing)
    expect(result.status).toBe(1)
    expect(result.stderr).toContain('无法写入临时凭据文件')
    expect(result.read('args')).toBeNull()
    expect(result.leftovers).toEqual([])
  })

  it('cleans up after SIGINT and returns 130', () => {
    for (const command of [stdinCommand, fileCommand]) {
      const result = run(command, 'sigint', 0)
      expect(result.status).toBe(130)
      expect(result.leftovers).toEqual([])
    }
  })

  it('cleans up when the operator interrupts the whole command', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'cdnca-installer-command-'))
    const temp = join(directory, 'tmp')
    spawnSync('mkdir', [temp])
    const slow = String.raw`
curl() { local out=''; while [ "$#" -gt 0 ]; do [ "$1" = -o ] && out="$2"; shift; done
  printf '#!/usr/bin/env bash\nmain() { : > "$T/started"; sleep 5; }\nmain "$@"\n' > "$out"; }`
    const child = spawn('/bin/bash', ['-c', `${slow}\n${fileCommand}`], {
      detached: true, env: { PATH: '/usr/bin:/bin', T: directory, TMPDIR: temp },
    })
    const status = await new Promise<number | null>((resolve) => {
      const poll = setInterval(() => {
        if (existsSync(join(directory, 'started'))) { clearInterval(poll); process.kill(-child.pid!, 'SIGINT') }
      }, 20)
      child.on('exit', (code, signal) => { clearInterval(poll); resolve(code ?? (signal ? 128 : null)) })
    })
    const leftovers = readdirSync(temp)
    rmSync(directory, { recursive: true, force: true })
    expect(status).not.toBe(0)
    expect(leftovers).toEqual([])
  })
})
