import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

import { enUS, zhCN } from '../i18n/resources'

describe('DNS-07 wildcard certificate semantics', () => {
  it('explains exact one-label wildcard coverage in Chinese and English', () => {
    const chinese = zhCN.certificates.editor.domainsExtra
    expect(chinese).toContain('仅覆盖一层子域名')
    expect(chinese).toContain('不覆盖 example.com')
    expect(chinese).toContain('a.b.example.com')

    const english = enUS.certificates.editor.domainsExtra
    expect(english).toContain('one subdomain label only')
    expect(english).toContain('does not cover example.com')
    expect(english).toContain('a.b.example.com')
  })

  it('preserves literal wildcard SANs in the certificate order payload', () => {
    const source = readFileSync(resolve(process.cwd(), 'src/pages/CertificateListPage.tsx'), 'utf8')
    expect(source).toContain('return wildcard ? `*.${value}` : value')
    expect(source).toMatch(/const input: CreateCertificateOrderInput = \{\s+domains,/m)
  })
})
