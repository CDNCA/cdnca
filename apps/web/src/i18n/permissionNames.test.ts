import { readdirSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'

import { changeLocale } from './index'
import { permissionName, permissionNameCodes } from './permissionNames'

// Every permission code the control plane seeds (INSERT INTO permissions in
// the control-api migrations) must have a Chinese display name (W4).
function migrationPermissionCodes(): string[] {
  const dir = resolve(process.cwd(), '../../services/control-api/migrations')
  const codes = new Set<string>()
  for (const file of readdirSync(dir).filter((name) => name.endsWith('.up.sql'))) {
    const sql = readFileSync(resolve(dir, file), 'utf8')
    for (const insert of sql.matchAll(/INSERT INTO permissions\s*\([^)]*\)\s*VALUES([\s\S]*?);/gi)) {
      for (const row of insert[1].matchAll(/\(\s*'([a-z0-9_.-]+)'/g)) codes.add(row[1])
    }
  }
  return [...codes].sort()
}

describe('permission display names', () => {
  afterEach(async () => { await changeLocale('zh-CN') })

  it('names every permission code seeded by the control-plane migrations', () => {
    const seeded = migrationPermissionCodes()
    expect(seeded.length).toBeGreaterThan(100)
    expect(seeded.filter((code) => !permissionNameCodes.includes(code))).toEqual([])
    expect(permissionNameCodes.filter((code) => !seeded.includes(code))).toEqual([])
  })

  it('shows Chinese names and falls back to the code for English and unknown codes', async () => {
    await changeLocale('zh-CN')
    expect(permissionName('announcements.manage')).toBe('管理公告')
    expect(permissionNameCodes.every((code) => /[一-鿿]/.test(permissionName(code)))).toBe(true)
    expect(permissionName('future.feature.read')).toBe('future.feature.read')
    await changeLocale('zh-TW')
    expect(permissionName('announcements.manage')).toBe('管理公告')
    expect(permissionName('sites.read')).toBe('查看網站')
    await changeLocale('en-US')
    expect(permissionName('announcements.manage')).toBe('announcements.manage')
  })
})
