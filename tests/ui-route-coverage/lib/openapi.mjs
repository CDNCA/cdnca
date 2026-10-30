// OpenAPI 交叉校验：按缩进解析 api/openapi/v1/*.yaml 的 paths → method → x-required-permissions。
// 不引入 YAML 依赖；只认两空格缩进的 paths 段（仓库内所有契约均如此）。
import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'

const VERBS = new Set(['get', 'post', 'put', 'patch', 'delete', 'head'])

export function openapiOperations(repo) {
  const dir = join(repo, 'api/openapi/v1')
  const ops = []
  for (const name of readdirSync(dir).filter((f) => f.endsWith('.yaml')).sort()) {
    const lines = readFileSync(join(dir, name), 'utf8').split('\n')
    let inPaths = false
    let path
    let op
    lines.forEach((line, i) => {
      if (/^paths:\s*$/.test(line)) return void (inPaths = true)
      if (/^\S/.test(line)) return void (inPaths = false)
      if (!inPaths) return
      let m
      if ((m = line.match(/^  (\/\S*):\s*$/))) [path, op] = [m[1].replace(/^'|'$/g, ''), undefined]
      else if ((m = line.match(/^    ([a-z]+):\s*$/)) && VERBS.has(m[1]) && path) {
        op = { file: `api/openapi/v1/${name}`, line: i + 1, method: m[1].toUpperCase(), path, permissions: [] }
        ops.push(op)
      } else if (op && (m = line.match(/^      x-required-permissions:\s*\[([^\]]*)\]/))) {
        op.permissions = m[1].split(',').map((s) => s.trim().replace(/^['"]|['"]$/g, '')).filter(Boolean)
      } else if (op && /^      x-required-permissions:\s*$/.test(line)) {
        for (let j = i + 1; j < lines.length && /^        - /.test(lines[j]); j++) op.permissions.push(lines[j].replace(/^        - /, '').trim())
      }
    })
  }
  return ops
}
