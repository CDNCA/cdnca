// Guard: antd 的上一页/下一页按钮读屏名是图标英文名 left/right，只有 ./pagination.tsx 的 Table / Pagination
// 按 locale 给它们命名。四端源码（及本包其他文件）不得直接从 'antd' 取 Table 或 Pagination。
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import ts from 'typescript'
import { describe, expect, it } from 'vitest'

const root = join(__dirname, '..', '..', '..')
const ends = ['apps/web/src', 'apps/www/src', 'packages/cdnca-ui/src']
const allowed = 'packages/cdnca-ui/src/pagination.tsx'

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return name === 'node_modules' || name === 'dist' ? [] : files(path)
    return /\.tsx?$/.test(name) && !/\.test\.|\.d\.ts$/.test(name) && !path.includes('/tests/') && !path.includes('/test/') ? [path] : []
  })
}

export function antdPagingImports(file: string, text: string): string[] {
  const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, file.endsWith('x') ? ts.ScriptKind.TSX : ts.ScriptKind.TS)
  return sf.statements.flatMap((stmt) => {
    if (!ts.isImportDeclaration(stmt) || !ts.isStringLiteral(stmt.moduleSpecifier) || stmt.moduleSpecifier.text !== 'antd') return []
    const clause = stmt.importClause
    const named = clause?.namedBindings
    if (!clause || clause.isTypeOnly || !named || !ts.isNamedImports(named)) return []
    return named.elements
      .filter((el) => !el.isTypeOnly && ['Table', 'Pagination'].includes((el.propertyName ?? el.name).text))
      .map((el) => `${file}: ${el.getText(sf)}`)
  })
}

describe('pagination names guard', () => {
  it('flags value imports of Table / Pagination from antd and lets types through', () => {
    expect(antdPagingImports('a.tsx', "import { Button, Table as T, type TableProps } from 'antd'")).toEqual(['a.tsx: Table as T'])
    expect(antdPagingImports('a.tsx', "import type { PaginationProps } from 'antd'\nimport { Pagination } from '@cdnca/ui'")).toEqual([])
  })

  it('takes Table and Pagination only from @cdnca/ui in the console, the website and this package', () => {
    const found = ends.flatMap((end) => files(join(root, end)))
      .map((path) => relative(root, path))
      .filter((file) => file !== allowed)
      .flatMap((file) => antdPagingImports(file, readFileSync(join(root, file), 'utf8')))
    expect(found).toEqual([])
  })
})
