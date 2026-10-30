import { readdirSync, readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

import { notificationTemplateName, notificationTemplateNames, notificationVariableName, notificationVariableNames } from './notificationTemplateNames'

const controlAPI = resolve(__dirname, '../../../../services/control-api')
const localeSuffix = /\.(zh-cn|en-us)$/

// seeded reads every template the control plane ships: migration INSERTs plus
// the Go constants for code-registered templates (announcement, platform user).
function seeded(): { ids: Set<string>; variables: Set<string> } {
  const ids = new Set<string>()
  const variables = new Set<string>()
  const migrations = join(controlAPI, 'migrations')
  for (const file of readdirSync(migrations).filter((name) => name.endsWith('.up.sql'))) {
    const sql = readFileSync(join(migrations, file), 'utf8')
    for (const insert of sql.matchAll(/INSERT INTO notification_templates\s*\([^)]*\)\s*(?:VALUES|SELECT)([\s\S]*?);\s*$/gm)) {
      for (const row of insert[1].matchAll(/\(\s*'([a-z][a-z0-9._-]+)'\s*,\s*\d+\s*,\s*'(?:email|sms)'/g)) ids.add(row[1].replace(localeSuffix, ''))
      for (const list of insert[1].matchAll(/ARRAY\[([^\]]*)\]/g)) for (const name of list[1].matchAll(/'([^']+)'/g)) variables.add(name[1])
    }
  }
  const constants = [
    'internal/notification/template.go', 'internal/systemusersettings/notification_templates.go',
  ].map((file) => readFileSync(join(controlAPI, file), 'utf8')).join('\n')
  for (const match of constants.matchAll(/TemplateID\s*=\s*"([a-z][a-z0-9._-]+)"/g)) ids.add(match[1])
  for (const name of ['title', 'body', 'username', 'captcha']) variables.add(name)
  return { ids, variables }
}

describe('notification template names (W2)', () => {
  const { ids, variables } = seeded()

  it('finds the seeded templates', () => {
    expect(ids.size).toBeGreaterThanOrEqual(80)
    expect(ids).toContain('market.seller.defaulted')
    expect(ids).toContain('announcement_published')
  })

  it('has a Chinese name for every seeded template ID', () => {
    expect([...ids].filter((id) => !notificationTemplateNames[id]).sort()).toEqual([])
  })

  it('has a Chinese description for every seeded variable', () => {
    expect([...variables].filter((name) => !notificationVariableNames[name]).sort()).toEqual([])
  })

  it('strips the locale suffix and leaves unknown values unnamed', () => {
    expect(notificationTemplateName('market.seller.defaulted.zh-cn')).toBe('节点市场：供货方被判定失联')
    expect(notificationTemplateName('operator_custom')).toBeUndefined()
    expect(notificationVariableName('currency')).toBe('币种（currency）')
    expect(notificationVariableName('unknown_var')).toBe('unknown_var')
  })
})
