// Linux 单个 argv 元素上限 MAX_ARG_STRLEN=128KiB（内核常量），把 install-node.sh/install-control.sh
// 全文作为 `bash -c <脚本>` 的参数会 E2BIG（spawnSync status=null）；macOS 没有这个单参数上限。
// 这里的 spawnSync/spawn 与 node:child_process 同签名：脚本超过阈值时写入私有临时文件，
// 改为 `bash -c '. <文件>' <$0> <$@...>`。source 不带参数时沿用外层的 $0 与位置参数，语义与原 -c 相同。
import * as childProcess from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const threshold = 64 * 1024
const shells = new Set(['bash', '/bin/bash', '/usr/bin/bash', 'sh', '/bin/sh'])

// 测试常只抽取安装器里的个别函数运行，不含嵌入的 install-i18n 库；这里给 bash -c 脚本
// 预置与库同义的 msg（INSTALL_LANG 未设时输出中文），脚本自己定义 msg 时以脚本为准。
const msgFallback = 'declare -F msg >/dev/null || msg() { if [ "${INSTALL_LANG:-zh}" = en ]; then printf \'%s\' "$2"; else printf \'%s\' "$1"; fi; }\n'

function withMessages(command, args) {
  if (!shells.has(command) || !Array.isArray(args)) return args
  const index = args.indexOf('-c')
  if (index < 0 || typeof args[index + 1] !== 'string') return args
  const replaced = [...args]
  replaced[index + 1] = msgFallback + args[index + 1]
  return replaced
}

function externalise(command, args) {
  args = withMessages(command, args)
  if (!shells.has(command) || !Array.isArray(args)) return { args, cleanup() {} }
  const index = args.indexOf('-c')
  const script = index >= 0 ? args[index + 1] : undefined
  if (typeof script !== 'string' || Buffer.byteLength(script) <= threshold) return { args, cleanup() {} }
  const directory = mkdtempSync(join(tmpdir(), 'cdnca-large-script.'))
  const file = join(directory, 'script.sh')
  writeFileSync(file, script, { mode: 0o600 })
  const replaced = [...args]
  replaced[index + 1] = `. '${file.replaceAll("'", "'\\''")}'`
  return { args: replaced, cleanup: () => rmSync(directory, { recursive: true, force: true }) }
}

export function spawnSync(command, args, options) {
  const prepared = externalise(command, args)
  try {
    return childProcess.spawnSync(command, prepared.args, options)
  } finally {
    prepared.cleanup()
  }
}

export function spawn(command, args, options) {
  const prepared = externalise(command, args)
  const child = childProcess.spawn(command, prepared.args, options)
  child.once('close', prepared.cleanup)
  child.once('error', prepared.cleanup)
  return child
}
