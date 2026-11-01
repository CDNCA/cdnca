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

  // a Chinese UI passes --lang zh as well (a stock Ubuntu runs with LANG=C.UTF-8 and the
  // installer, without a terminal to ask on, would otherwise fall back to English).
  it('an English UI passes --lang en and a Chinese UI --lang zh to the installer; no UI language passes none', () => {
    for (const language of ['en-US', 'en']) {
      const result = run(buildInstallerCommand({ ...base, stdinSecret: 'k', language }), 'ok')
      expect(result.read('args')).toBe('--control-plane\nhttps://a.example\n--lang\nen\n')
    }
    const plain = stdinCommand.replace("k'\"'\"'1", 'k')
    for (const language of ['zh-CN', 'zh-TW', 'zh']) {
      const command = buildInstallerCommand({ ...base, stdinSecret: 'k', language })
      expect(command).toBe(plain.replace(/\)$/, ' --lang zh)'))
      expect(run(command, 'ok').read('args')).toBe('--control-plane\nhttps://a.example\n--lang\nzh\n')
    }
    for (const language of [undefined, '', 'qps-ploc']) {
      expect(buildInstallerCommand({ ...base, stdinSecret: 'k', language })).toBe(plain)
    }
    const zhFile = run(buildInstallerCommand({ ...base, secretFile: { flag: '--activation-code-file', value: 'A' }, language: 'zh-CN' }), 'ok')
    expect(zhFile.read('args')?.split('\n').slice(0, 5)).toEqual(['--control-plane', 'https://a.example', '--lang', 'zh', '--activation-code-file'])
    const file = run(buildInstallerCommand({ ...base, secretFile: { flag: '--activation-code-file', value: 'A' }, language: 'en-US' }), 'ok')
    expect(file.read('args')?.split('\n').slice(0, 4)).toEqual(['--control-plane', 'https://a.example', '--lang', 'en'])
  })

  // pagescan-auth2: the wrapper's own error lines run before the installer, so they follow the UI language as well.
  it('an English UI prints the wrapper errors in English, with no Chinese in the command', () => {
    const english = { ...base, language: 'en-US' }
    expect(buildInstallerCommand({ ...english, secretFile: { flag: '--activation-code-file', value: 'A' } })).not.toMatch(/[\u4e00-\u9fff]/)
    expect(run(buildInstallerCommand({ ...english, stdinSecret: 'k' }), 'curl-fail').stderr).toContain('[cdnca-edge] error: cannot download the installer')
    expect(run(buildInstallerCommand({ ...english, secretFile: { flag: '--activation-code-file', value: 'A' } }), 'empty').stderr)
      .toContain('[cdnca-edge] error: the downloaded installer is empty or incomplete')
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

// a console on the installer-generated self-signed root.
// A real openssl s_server serves /downloads over HTTPS and the real curl runs.
describe('one-line installer command against a self-signed HTTPS console', () => {
  const openssl = ['/opt/homebrew/bin/openssl', '/usr/local/bin/openssl', '/usr/bin/openssl'].find((path) => existsSync(path))!
  const ca = { url: 'https://127.0.0.1:PORT/downloads/gateway-ca.pem', sha256: '' }

  async function withConsole(check: (origin: string, root: string, directory: string) => void) {
    const directory = mkdtempSync(join(tmpdir(), 'cdnca-installer-tls-'))
    const sh = (script: string) => {
      const result = spawnSync('/bin/bash', ['-c', script], { cwd: directory, encoding: 'utf8' })
      if (result.status !== 0) throw new Error(result.stderr)
    }
    sh(`set -e; mkdir -p downloads tmp
      "${openssl}" req -x509 -newkey rsa:2048 -nodes -days 2 -subj '/CN=CDNCA local control root' -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign -keyout ca-key.pem -out downloads/gateway-ca.pem 2>/dev/null
      "${openssl}" req -newkey rsa:2048 -nodes -subj '/CN=127.0.0.1' -keyout key.pem -out server.csr 2>/dev/null
      printf 'subjectAltName=IP:127.0.0.1\\nbasicConstraints=CA:FALSE\\nextendedKeyUsage=serverAuth\\n' > ext.cnf
      "${openssl}" x509 -req -in server.csr -CA downloads/gateway-ca.pem -CAkey ca-key.pem -CAcreateserial -days 2 -extfile ext.cnf -out server.pem 2>/dev/null
      printf '#!/usr/bin/env bash\\nmain() { printf "%%s\\\\n" "$@" > "$T/args"; for a in "$@"; do case "$a" in /*) cat "$a" > "$T/ca"; esac; done; IFS= read -r line; printf "%%s" "$line" > "$T/stdin"; }\\nmain "$@"\\n' > downloads/install-node.sh`)
    const port = 20000 + Math.floor(Math.random() * 20000)
    const server = spawn(openssl, ['s_server', '-WWW', '-quiet', '-accept', String(port), '-cert', 'server.pem', '-key', 'key.pem'],
      { cwd: directory, stdio: 'ignore' })
    try {
      const origin = `https://127.0.0.1:${port}`
      for (let attempt = 0; attempt < 100; attempt += 1) {
        if (spawnSync('curl', ['-k', '-fsS', '-o', '/dev/null', `${origin}/downloads/gateway-ca.pem`]).status === 0) break
        await new Promise((resolve) => setTimeout(resolve, 50))
      }
      check(origin, readFileSync(join(directory, 'downloads/gateway-ca.pem'), 'utf8'), directory)
    } finally {
      server.kill()
      rmSync(directory, { recursive: true, force: true })
    }
  }

  function runReal(command: string, directory: string) {
    const out = join(directory, 'out')
    rmSync(out, { recursive: true, force: true })
    spawnSync('mkdir', ['-p', join(out, 'tmp')])
    const result = spawnSync('/bin/bash', ['-c', command], {
      encoding: 'utf8', timeout: 20_000, env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', T: out, TMPDIR: join(out, 'tmp') },
    })
    const read = (name: string) => existsSync(join(out, name)) ? readFileSync(join(out, name), 'utf8') : null
    return { status: result.status, stderr: result.stderr, read, leftovers: readdirSync(join(out, 'tmp')) }
  }

  const sha256 = (text: string) => spawnSync('/bin/bash', ['-c', 'shasum -a 256 | cut -d " " -f 1'], { input: text, encoding: 'utf8' }).stdout.trim()
  const command = (origin: string, digest?: string, language?: string) => buildInstallerCommand({
    urls: [`${origin}/downloads/install-node.sh`], protocols: '=https', label: '[cdnca-edge]',
    args: `--control-plane '${origin}' --registration-key-stdin`, stdinSecret: 'k', language,
    controlPlaneCA: digest === undefined ? undefined : { ...ca, url: `${origin}/downloads/gateway-ca.pem`, sha256: digest },
  })

  it('without the pin the system trust store rejects the console (curl 60), the bug this fixes', async () => {
    await withConsole((origin, _root, directory) => {
      const result = runReal(command(origin), directory)
      expect(result.status).toBe(60)
      expect(result.stderr).toContain('[cdnca-edge] error: 无法下载安装脚本')
      expect(result.read('args')).toBeNull()
    })
  })

  it('with the published pin it downloads the installer over the pinned root and hands the root to it', async () => {
    await withConsole((origin, root, directory) => {
      const digest = sha256(root)
      const result = runReal(command(origin, digest), directory)
      expect(result.status, result.stderr).toBe(0)
      const args = result.read('args')!.split('\n')
      expect(args.slice(0, 4)).toEqual(['--control-plane', origin, '--registration-key-stdin', '--control-plane-ca-file'])
      expect(args[4]).toMatch(/^\//)
      expect(args.slice(5)).toEqual(['--control-plane-ca-sha256', digest, ''])
      expect(result.read('ca')).toBe(root)
      expect(result.read('stdin')).toBe('k')
      expect(result.leftovers).toEqual([])
    })
  })

  it.each([['zh-CN', '无法下载主控根证书或其指纹不符'], ['en-US', 'cannot download the management root CA or its fingerprint does not match']])(
    'a root that does not match the pin stops before anything is downloaded or run (%s)', async (language, text) => {
      await withConsole((origin, _root, directory) => {
        const result = runReal(command(origin, 'ab'.repeat(32), language), directory)
        expect(result.status).toBe(1)
        expect(result.stderr).toContain(`[cdnca-edge] error: ${text}`)
        expect(result.read('args')).toBeNull()
        expect(result.leftovers).toEqual([])
      })
    })

  it('refuses a malformed pin and leaves commands without one unchanged', () => {
    expect(() => command('https://a.example', 'AB'.repeat(32))).toThrow()
    expect(() => command('https://a.example', "ab'; id")).toThrow()
    expect(command('https://a.example')).not.toContain('--cacert')
    expect(command('https://a.example')).not.toContain(' -k ')
  })
})
