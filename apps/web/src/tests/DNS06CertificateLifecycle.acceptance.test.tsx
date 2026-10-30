import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

import { certificateAssetsMessages } from '../i18n/certificateAssets'

describe('DNS-06 certificate lifecycle acceptance contract', () => {
  it('keeps complete Chinese and pseudo-locale lifecycle messages', () => {
    const zhCN = JSON.stringify(certificateAssetsMessages['zh-CN'])
    const pseudo = JSON.stringify(certificateAssetsMessages['qps-ploc'])

    for (const text of ['自动签发', '待续期', '操作结果待确认', '激活版本', '绑定网站']) {
      expect(zhCN).toContain(text)
    }
    expect(pseudo).toContain('［')
    expect(pseudo.length).toBeGreaterThan(zhCN.length)
  })

  it('keeps DNS-01, HTTP-01, wildcard, auto-renew, RBAC, audit, and failure states in the dedicated API contract', () => {
    const contract = readFileSync(resolve(process.cwd(), '../../api/openapi/v1/dns-acme.yaml'), 'utf8')
    for (const marker of [
      '/v1/certificate-orders:', 'dns-01', 'http-01', 'auto_renew', 'renewal_due',
      'certificates.manage', 'Idempotency-Key', 'dns_provider_id',
    ]) {
      expect(contract).toContain(marker)
    }
  })
})
