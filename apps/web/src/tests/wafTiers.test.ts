import { wafTiersMessages } from '../i18n/wafTiers'
import { setEnabled, toggleSet } from '../pages/security/CRSTierDetails'

function keys(value: unknown, prefix = ''): string[] {
  return typeof value === 'string' ? [prefix]
    : Object.entries(value as Record<string, unknown>).flatMap(([key, child]) => keys(child, prefix ? `${prefix}.${key}` : key))
}

describe('WAF protection tiers', () => {
  it('has the same keys in Chinese, English and the pseudo locale, with the four friendly tier names', () => {
    const zh = keys(wafTiersMessages['zh-CN']).sort()
    expect(keys(wafTiersMessages['en-US']).sort()).toEqual(zh)
    expect(keys(wafTiersMessages['qps-ploc']).sort()).toEqual(zh)
    expect(Object.values(wafTiersMessages['zh-CN'].tiers)).toEqual(['仅记录', '标准防护', '严格防护', '极严格防护'])
    expect(Object.keys(wafTiersMessages['zh-CN'].sets)).toHaveLength(11)
  })

  it('turns a rule group off by excluding all its rules and on by removing them', () => {
    const set = { key: 'waf_set:crs_ssti', name: 'SSTI', paranoia: 2, rules_by_paranoia: { 1: 1, 2: 1 }, rules: [934180, 934200] }
    expect(setEnabled(set, [942100])).toBe(true)
    const off = toggleSet(set, [942100, 934180], false)
    expect(off).toEqual([934180, 934200, 942100])
    expect(setEnabled(set, off)).toBe(false)
    expect(toggleSet(set, off, true)).toEqual([942100])
  })
})
