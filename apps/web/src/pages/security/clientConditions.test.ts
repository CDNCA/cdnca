import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

import { timeWindowForm, timeWindowProblem } from './ClientConditionInputs'
import { wafBrowserNames, wafDeviceKinds, wafVersionBrowsers } from './conditionFields'

// The browser names and device kinds must be edgeconfig.WAFBrowserNames /
// WAFDeviceKinds (the node's table); read them from the Go source.
const goSource = readFileSync(resolve(__dirname, '../../../../../libs/edgeconfig/waf_client_conditions.go'), 'utf8')

function goConstant(name: string): string {
  const match = new RegExp(`\\b${name}\\s*=\\s*"([^"]+)"`).exec(goSource)
  if (!match) throw new Error(`missing ${name}`)
  return match[1]
}

describe('client condition values', () => {
  it('lists the browsers in the Go detection order, unknown last', () => {
    const block = /var uaBrowserRules = \[\]uaBrowserRule\{([\s\S]*?)\n\}/.exec(goSource)?.[1] ?? ''
    const order = [...block.matchAll(/name:\s*(WAFBrowser\w+)/g)].map((match) => goConstant(match[1]))
    expect([...wafBrowserNames]).toEqual([...order, goConstant('WAFBrowserUnknown')])
    expect(wafVersionBrowsers).not.toContain(goConstant('WAFBrowser360'))
  })

  it('lists the device kinds of the Go source', () => {
    const line = /var WAFDeviceKinds = \[\]string\{([^}]*)\}/.exec(goSource)?.[1] ?? ''
    expect([...wafDeviceKinds]).toEqual(line.split(',').map((name) => goConstant(name.trim())))
  })

  it('checks request time values like CompileWAFTimeMatch', () => {
    expect(timeWindowProblem('mon,fri 09:00-18:00')).toBeNull()
    expect(timeWindowProblem('fri 22:00-02:00')).toBeNull()
    expect(timeWindowProblem(' 09:00-18:00')).toBe('noDay')
    expect(timeWindowProblem('mon 09:00-09:00')).toBe('sameTime')
    expect(timeWindowForm('2026-11-11T00:00:00 / 2026-11-12T00:00:00')).toBe('ranges')
    expect(timeWindowProblem('2026-11-11T00:00:00 / 2026-11-12T00:00:00')).toBeNull()
    expect(timeWindowProblem('2026-11-12T00:00:00 / 2026-11-11T00:00:00')).toBe('noRange')
    expect(timeWindowProblem(' / ')).toBe('noRange')
  })
})
