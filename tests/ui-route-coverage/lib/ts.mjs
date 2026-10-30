import { existsSync, readdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createRequire } from 'node:module'

let cached
// 用仓库 pnpm 安装的 typescript（不新增依赖）。被审计目录没有 node_modules（如测试夹具）时，回落到本工具所在仓库。
export function loadTS(repo) {
  if (cached) return cached
  const toolRepo = join(dirname(fileURLToPath(import.meta.url)), '../../..')
  for (const root of [repo, toolRepo]) {
    const store = join(root, 'node_modules/.pnpm')
    if (!existsSync(store)) continue
    const dir = readdirSync(store).filter((d) => d.startsWith('typescript@')).sort().pop()
    if (dir) return (cached = createRequire(import.meta.url)(join(store, dir, 'node_modules/typescript')))
  }
  throw new Error(`${repo}/node_modules/.pnpm 没有 typescript，先 pnpm install --frozen-lockfile`)
}
