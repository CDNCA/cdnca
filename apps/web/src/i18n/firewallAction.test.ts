import { describe, expect, it } from 'vitest'

import { enUSFirewallAction, pseudoFirewallAction, zhCNFirewallAction } from './firewallAction'

function keys(value: unknown, prefix = ''): string[] {
  if (typeof value !== 'object' || value === null) return [prefix]
  return Object.entries(value).flatMap(([key, child]) => keys(child, prefix ? `${prefix}.${key}` : key)).sort()
}

describe('firewallAction locale contract', () => {
  it('keeps Chinese, English, and pseudo locale keys aligned', () => {
    expect(keys(enUSFirewallAction)).toEqual(keys(zhCNFirewallAction))
    expect(keys(pseudoFirewallAction)).toEqual(keys(zhCNFirewallAction))
  })
})
