// 打包：theme.config.json → dist/theme.json（cdnca.site-theme/v2 content）+ dist/manifest.json
// + dist/schemas/config.schema.json，并打印 sha256。签名不在这里做：--sign 时调用平台的
// cdnca-plugin sign-manifest（services/market-service/cmd/cdnca-plugin），不另写签名逻辑。
//
// 输出是确定的：同样的输入得到同样的字节（键顺序固定、文件按路径排序、无时间戳）。
import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { dirname, join, relative, resolve, sep } from 'node:path'

import { checkContent, DEFAULT_ENTRY, sha256Hex } from './rules.mjs'

const ORDER = ['user', 'site']

function readJSON(path) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'))
  } catch (error) {
    throw new Error(`${path}: ${error.message}`)
  }
}

function walk(dir) {
  const out = []
  for (const name of readdirSync(dir).sort()) {
    const full = join(dir, name)
    if (statSync(full).isDirectory()) out.push(...walk(full))
    else out.push(full)
  }
  return out
}

/** 页面包目录 → [{path, data}]，跳过以 . 开头的文件（.DS_Store 等），返回被跳过的列表。 */
export function bundleFiles(dir) {
  const files = []
  const skipped = []
  for (const full of walk(dir)) {
    const path = relative(dir, full).split(sep).join('/')
    if (path.split('/').some((segment) => segment.startsWith('.'))) skipped.push(path)
    else files.push({ path, data: readFileSync(full) })
  }
  files.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))
  return { files, skipped }
}

/** 读取工程，组装 content 对象（键顺序固定）。 */
export function buildContent(root, { version } = {}) {
  const config = readJSON(join(root, 'theme.config.json'))
  const v = version ?? config.version
  const scopes = ORDER.filter((s) => (config.applies_to ?? []).includes(s))
  const extra = (config.applies_to ?? []).filter((s) => !ORDER.includes(s))
  const content = {
    schema: config.schema,
    id: config.id,
    version: v,
    name: config.name,
    ...(config.description ? { description: config.description } : {}),
    applies_to: [...scopes, ...extra],
  }
  const skipped = []
  if (typeof config.console_theme === 'string') {
    const console = readJSON(join(root, config.console_theme))
    content.console_theme = { ...console, id: console.id ?? config.id, version: v }
  }
  if (config.site_bundle) {
    const { files, skipped: s } = bundleFiles(join(root, config.site_bundle.dir ?? 'site'))
    skipped.push(...s)
    content.site_bundle = {
      entry: config.site_bundle.entry ?? DEFAULT_ENTRY,
      files: files.map((f) => ({ path: f.path, sha256: sha256Hex(f.data), data_base64: f.data.toString('base64') })),
    }
  }
  if (config.auth_style) {
    const images = {}
    for (const slot of Object.keys(config.auth_style.images ?? {}).sort()) {
      images[slot] = readFileSync(join(root, config.auth_style.images[slot])).toString('base64')
    }
    content.auth_style = {
      css: readFileSync(join(root, config.auth_style.css), 'utf8'),
      ...(Object.keys(images).length ? { images } : {}),
    }
  }
  if (typeof config.content_schema === 'string') content.content_schema = readJSON(join(root, config.content_schema))
  // 预览图：theme.config.json 的 preview 指向文件，否则工程根目录的 preview.webp/png/jpg（有就带上）。
  const previewPath = previewFile(root, config)
  if (previewPath) content.preview = readFileSync(previewPath).toString('base64')
  return { config, content, skipped, previewPath }
}

/** 主题卡片预览图（首页截图）的文件路径，没有时返回 null。 */
export function previewFile(root, config) {
  if (typeof config.preview === 'string') return join(root, config.preview)
  for (const name of PREVIEW_FILES) if (existsSync(join(root, name))) return join(root, name)
  return null
}

/** 未在 theme.config.json 指定时按顺序查找的预览图文件名（preview --screenshot 生成 preview.webp）。 */
export const PREVIEW_FILES = ['preview.webp', 'preview.png', 'preview.jpg', 'preview.jpeg']

/** 打包到 outDir；返回 {contentSHA256, manifestPath, findings, ...}。findings 非空时不写 manifest。 */
export function pack(root, { outDir = join(root, 'dist'), version, pluginID } = {}) {
  const { config, content, skipped, previewPath } = buildContent(root, { version })
  const bytes = Buffer.from(`${JSON.stringify(content)}\n`)
  const manifestTemplate = readJSON(join(root, 'plugin.manifest.json'))
  const id = pluginID ?? manifestTemplate.metadata?.id
  const findings = checkContent(bytes, { pluginID: id })
  // 没有预览图不算错：市场与主控回落到色块，只提示。
  const notices = previewPath ? [] : ['建议提供预览图：在工程根目录放 preview.webp（1200×750，≤512 KiB），或运行 preview --screenshot 生成']
  const result = { skipped, findings: findings.items, contentBytes: bytes.length, notices, previewPath }
  if (!findings.ok) return result
  const schemaPath = manifestTemplate.spec.configuration_schema.path
  const schema = readFileSync(join(root, schemaPath))
  const entryPath = manifestTemplate.spec.entrypoint.path ?? 'theme.json'
  const manifest = structuredClone(manifestTemplate)
  manifest.metadata.version = content.version
  manifest.spec.entrypoint = { type: 'theme', path: entryPath, sha256: sha256Hex(bytes) }
  manifest.spec.configuration_schema = { path: schemaPath, sha256: sha256Hex(schema) }
  delete manifest.integrity
  // theme.config.json 的 supply_chain {sbom, provenance} 指向文件时，按文件内容填摘要。
  const files = config.supply_chain ?? {}
  if (files.sbom || files.provenance) {
    manifest.spec.supply_chain = {
      ...manifest.spec.supply_chain,
      ...(files.sbom ? { sbom_sha256: sha256Hex(readFileSync(join(root, files.sbom))) } : {}),
      ...(files.provenance ? { provenance_sha256: sha256Hex(readFileSync(join(root, files.provenance))) } : {}),
    }
  }
  // 授权端同步目录时要求 supply_chain 两个摘要是真实的 64 位 hex（plugin_manifest_verifier.go）。
  const hex = /^[a-f0-9]{64}$/
  const chain = manifest.spec.supply_chain ?? {}
  result.warnings = ['sbom_sha256', 'provenance_sha256'].filter((key) => !hex.test(chain[key] ?? ''))
    .map((key) => `spec.supply_chain.${key} 还不是 64 位小写 hex，授权端会拒绝该 manifest`)
  const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`)
  mkdirSync(join(outDir, dirname(schemaPath)), { recursive: true })
  writeFileSync(join(outDir, entryPath), bytes)
  writeFileSync(join(outDir, schemaPath), schema)
  writeFileSync(join(outDir, 'manifest.json'), manifestBytes)
  return {
    ...result,
    outDir,
    contentPath: join(outDir, entryPath),
    contentSHA256: sha256Hex(bytes),
    schemaSHA256: sha256Hex(schema),
    manifestPath: join(outDir, 'manifest.json'),
    manifestSHA256: sha256Hex(manifestBytes),
  }
}

/**
 * 找 cdnca-plugin：--cdnca-plugin 参数、环境变量 CDNCA_PLUGIN、PATH，最后在仓库里用 go run。
 * 返回 [命令, 参数前缀]。
 */
export function locateSigner(explicit) {
  const named = explicit ?? process.env.CDNCA_PLUGIN
  if (named) return [named, []]
  for (const dir of (process.env.PATH ?? '').split(':')) {
    if (dir && existsSync(join(dir, 'cdnca-plugin'))) return [join(dir, 'cdnca-plugin'), []]
  }
  let dir = resolve(import.meta.dirname)
  for (let i = 0; i < 6; i++) {
    const cmd = join(dir, 'services/market-service/cmd/cdnca-plugin')
    if (existsSync(cmd)) return ['go', ['-C', join(dir, 'services/market-service'), 'run', './cmd/cdnca-plugin']]
    dir = dirname(dir)
  }
  throw new Error('cdnca-plugin not found: download it from the seller site, put it on PATH or pass --cdnca-plugin')
}

/** 用 cdnca-plugin sign-manifest 签名 dist/manifest.json → dist/manifest.signed.json。 */
export function sign(manifestPath, keyPath, signer) {
  const [cmd, prefix] = locateSigner(signer)
  const out = join(dirname(manifestPath), 'manifest.signed.json')
  execFileSync(cmd, [...prefix, 'sign-manifest', '-key', resolve(keyPath), '-in', resolve(manifestPath), '-out', resolve(out)],
    { stdio: ['ignore', 'inherit', 'inherit'] })
  return out
}
