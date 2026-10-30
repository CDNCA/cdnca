import { enUS, pseudoCN, zhCN } from '../i18n/resources'

type TranslationTree = { [key: string]: string | TranslationTree }

function leaves(value: TranslationTree, prefix = ''): Array<[string, string]> {
  return Object.entries(value).flatMap(([key, child]) => {
    const next = prefix ? `${prefix}.${key}` : key
    return typeof child === 'string' ? [[next, child]] : leaves(child, next)
  })
}

describe('web i18n audit gate', () => {
  it('keeps zh-CN, en-US, and qps-ploc leaf keys synchronized', () => {
    const expected = leaves(zhCN).map(([key]) => key).sort()
    expect(leaves(enUS).map(([key]) => key).sort()).toEqual(expected)
    expect(leaves(pseudoCN).map(([key]) => key).sort()).toEqual(expected)
  })

  it('keeps node scheduling in the main resource graph with pseudo coverage', () => {
    expect(zhCN.nodeScheduling).toBeTypeOf('object')
    expect(enUS.nodeScheduling).toBeTypeOf('object')
    expect(pseudoCN.nodeScheduling).toBeTypeOf('object')
    expect(leaves(pseudoCN.nodeScheduling as TranslationTree).length).toBe(
      leaves(zhCN.nodeScheduling as TranslationTree).length,
    )
  })

  it('localizes site algorithms, table headings, and stream protocols in the pseudo locale', () => {
    const pseudoLeaves = new Map(leaves(pseudoCN))
    expect(zhCN.sites.edit.basic.origin.ipHash).toBe('IP 哈希')
    expect(enUS.sites.edit.basic.origin.ipHash).toBe('IP Hash')
    expect(pseudoLeaves.get('sites.edit.basic.origin.ipHash')).toMatch(/^［.+］$/)
    expect(pseudoLeaves.get('sites.edit.basic.origin.ipHash')).not.toBe('IP Hash')
    expect(pseudoLeaves.get('sites.columns.https')).toMatch(/^［.+］$/)
    expect(pseudoLeaves.get('streams.values.tcp')).toMatch(/^［.+］$/)
    expect(pseudoLeaves.get('streams.form.uuidPlaceholder')).toMatch(/^［.+］$/)
  })

  it('reports missing keys and pseudo-locale layout violations', async () => {
    // The audit script is a Node entrypoint and intentionally has no package-local TS facade.
    // @ts-expect-error The runtime module is checked by the CI command.
    const { auditLocaleKeys, auditPseudoLocale, visibleSourceLiterals } = await import('../../../../scripts/audit-web-i18n.mjs')
    const zh = { common: { title: '标题' } }
    const en = { common: {} }
    const pseudo = { common: { title: '标题' } }
    expect(auditLocaleKeys({ 'zh-CN': zh, 'en-US': en, 'qps-ploc': pseudo }))
      .toEqual(expect.arrayContaining([
        expect.objectContaining({ category: 'missing-locale-key', detail: 'en-US: common.title' }),
      ]))
    expect(auditPseudoLocale(zh, pseudo))
      .toEqual(expect.arrayContaining([
        expect.objectContaining({ category: 'pseudo-locale-frame' }),
      ]))
    expect(visibleSourceLiterals(`
      const options = [{ value: 'ip_hash', label: 'IP Hash' }]
      const withinRange = value > 1 && value < 10
      const view = <span>{'Hardcoded expression'}</span>
    `)).toEqual(['IP Hash', 'Hardcoded expression'])
    expect(visibleSourceLiterals(`
      const view = <span>{assetT(on ? 'assetValues.autoRenewEnabled' : 'assetValues.autoRenewDisabled')}</span>
      const raw = <span>{on ? 'On text' : 'Off text'}</span>
    `)).toEqual(['On text', 'Off text'])
  })

  it('keeps HTML markup intact in the pseudo locale', () => {
    const pseudoLeaves = new Map(leaves(pseudoCN))
    const notice = pseudoLeaves.get('systemGlobalSettings.placeholders.purchaseNotice')
    expect(notice).toMatch(/^［<p>.+<\/p>］$/)
    expect(notice).not.toContain('<~')
    expect(pseudoLeaves.get('systemGlobalSettings.hints.globalJS')).toContain('<script>')
  })
})
