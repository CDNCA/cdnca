#!/usr/bin/env node
import { execFileSync } from 'node:child_process'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { createHash } from 'node:crypto'
import { fileURLToPath } from 'node:url'

const prefix = '/opt/cdnca-node/current/runtime'
const libraryPath = `${prefix}/openresty/luajit/lib:${prefix}/openresty/openssl3/lib:${prefix}/openresty/pcre2/lib:${prefix}/lib:${prefix}/usr/lib`
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex')

// Resolve image-root symlinks inside that root, never against the build host.
export function copyRuntimeTree(root, relative, destination, ancestors = new Set()) {
  let parts = relative.split('/').filter(Boolean), filename
  for (let links = 0; ; links++) {
    if (links > 32 || parts.some((part) => part === '..' || part === '.')) throw new Error('unsafe runtime symlink')
    let changed = false
    for (let index = 0; index < parts.length; index++) {
      filename = path.join(root, ...parts.slice(0, index + 1))
      const stat = fs.lstatSync(filename)
      if (!stat.isSymbolicLink()) continue
      const target = fs.readlinkSync(filename)
      const resolved = path.posix.normalize(target.startsWith('/') ? target.slice(1) : path.posix.join(...parts.slice(0, index), target))
      if (resolved === '..' || resolved.startsWith('../')) throw new Error('runtime link escapes its image root')
      parts = [...resolved.split('/').filter(Boolean), ...parts.slice(index + 1)]
      changed = true
      break
    }
    if (!changed) break
  }
  if (ancestors.has(filename)) throw new Error('runtime directory cycle')
  const stat = fs.lstatSync(filename)
  if (stat.isDirectory()) {
    fs.mkdirSync(destination, { recursive: true, mode: 0o755 })
    const next = new Set([...ancestors, filename])
    for (const name of fs.readdirSync(filename).sort()) {
      if (!/^[A-Za-z0-9_.+-]+$/.test(name)) throw new Error('unsafe runtime filename')
      if (/\.(a|la|h|old)$/.test(name)) continue
      copyRuntimeTree(root, `${parts.join('/')}/${name}`, path.join(destination, name), next)
    }
  } else if (stat.isFile()) {
    fs.mkdirSync(path.dirname(destination), { recursive: true, mode: 0o755 })
    fs.copyFileSync(filename, destination, fs.constants.COPYFILE_EXCL)
    fs.chmodSync(destination, stat.mode & 0o111 ? 0o555 : 0o444)
  } else throw new Error('runtime contains a non-regular file')
}

export function runtimeELF(bytes) {
  if (bytes.subarray(0, 4).toString('hex') !== '7f454c46') return null
  if (bytes.length < 64 || bytes[4] !== 2 || bytes[5] !== 1 || bytes.readUInt16LE(18) !== 62 || ![2, 3].includes(bytes.readUInt16LE(16))) {
    throw new Error('runtime ELF must be Linux x86-64 executable/shared object')
  }
  const offset = Number(bytes.readBigUInt64LE(32)), size = bytes.readUInt16LE(54), count = bytes.readUInt16LE(56)
  if (!Number.isSafeInteger(offset) || size < 56 || offset + size * count > bytes.length) throw new Error('invalid runtime ELF program headers')
  let interpreter = false, dynamic = false
  for (let index = 0; index < count; index++) {
    const type = bytes.readUInt32LE(offset + index * size)
    if (type === 3) interpreter = true
    if (type === 2) dynamic = true
  }
  return { interpreter, dynamic }
}

// This only exports/builds. Runtime acceptance and publisher signing happen later.
export function exportNativeRuntime(rootDirectory, outputDirectory) {
  const root = path.resolve(rootDirectory), output = path.resolve(outputDirectory)
  if (fs.realpathSync(root) !== root || !fs.lstatSync(root).isDirectory() || fs.existsSync(output) || output.startsWith(root + '/')) {
    throw new Error('unsafe runtime source or output')
  }
  fs.mkdirSync(output, { mode: 0o755 })
  const copy = (source, target) => copyRuntimeTree(root, source, path.join(output, target))
  for (const name of ['bin/openresty', 'nginx/sbin', 'nginx/modules', 'nginx/conf', 'lualib', 'luajit/lib', 'openssl3/lib', 'pcre2/lib']) {
    copy(`usr/local/openresty/${name}`, `runtime/openresty/${name}`)
  }
  for (const directory of ['lib', 'usr/lib']) {
    for (const name of fs.readdirSync(path.join(root, directory)).sort()) {
      if (/\.so(?:\.|$)/.test(name)) copy(`${directory}/${name}`, `runtime/${directory}/${name}`)
    }
  }
  copy('usr/local/share/cdnca', 'lua/share/cdnca')
  copy('opt/cdnca/l4geo', 'lua/l4geo')
  // The HTTP/3 health probe the Agent runs (openresty.http3_probe). It is a
  // static Go executable: nothing to relink, and it must stay that way.
  const h3probe = path.join(output, 'runtime/bin/h3probe')
  if (!fs.lstatSync(path.join(root, 'usr/local/bin/h3probe'), { throwIfNoEntry: false })?.isFile()) throw new Error('runtime image has no h3probe')
  copy('usr/local/bin/h3probe', 'runtime/bin/h3probe')
  const probe = runtimeELF(fs.readFileSync(h3probe))
  if (!probe || probe.interpreter || probe.dynamic) throw new Error('h3probe must be a static x86-64 executable')
  const loader = path.join(output, 'runtime/lib/ld-musl-x86_64.so.1')
  const loaderHash = sha256(fs.readFileSync(loader))
  const files = []
  const walk = (directory) => {
    for (const name of fs.readdirSync(directory).sort()) {
      const filename = path.join(directory, name)
      if (fs.lstatSync(filename).isDirectory()) { walk(filename); continue }
      const bytes = fs.readFileSync(filename), elf = runtimeELF(bytes)
      if (elf && sha256(bytes) !== loaderHash && filename !== h3probe) {
        fs.chmodSync(filename, 0o755)
        const args = ['--set-rpath', libraryPath]
        if (elf.interpreter) args.push('--set-interpreter', `${prefix}/lib/ld-musl-x86_64.so.1`)
        execFileSync('patchelf', [...args, filename], { stdio: 'pipe' })
      }
      fs.chmodSync(filename, elf ? 0o555 : 0o444)
      files.push({ path: path.relative(output, filename), sha256: sha256(fs.readFileSync(filename)) })
    }
  }
  walk(output)
  const openresty = files.find((entry) => entry.path === 'runtime/openresty/bin/openresty')
  const nginx = files.find((entry) => entry.path === 'runtime/openresty/nginx/sbin/nginx')
  if (!openresty || openresty.sha256 !== nginx?.sha256) throw new Error('native OpenResty binary aliases differ')
  return { schema: 'cdnca.native-node.runtime-export/v1', interpreter: `${prefix}/lib/ld-musl-x86_64.so.1`, files }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 4) throw new Error('usage: native-node-export.mjs IMAGE_ROOT NEW_OUTPUT_DIRECTORY')
  console.log(JSON.stringify(exportNativeRuntime(process.argv[2], process.argv[3]), null, 2))
}
