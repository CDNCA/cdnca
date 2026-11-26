import type { SiteBasicConfig } from '../../api/sites'
import i18n from '../../i18n'
import '../../i18n/siteListenerDomains'
import { validateBasicConfig } from './siteEditValidation'

const basic: SiteBasicConfig = {
  package_id: null,
  package_name: null,
  group_id: null,
  group_name: null,
  domains: ['www.example.com'],
  http_enabled: true,
  http_listen_ports: ['80'],
  https_listen_ports: ['443'],
  tls_protocols: ['TLSv1.2', 'TLSv1.3'],
  origins: ['192.0.2.10'],
  cname: 'edge.example.net',
  ipv6_enabled: false,
  https_enabled: true,
  enabled: true,
  status: 'active',
  sync_status: 'synced',
  is_default: false,
}

describe('validateBasicConfig listener and domain rules', () => {
  it('accepts exact and wildcard multi-level domains and rejects unsafe domain sets', () => {
    const t = i18n.getFixedT('zh-CN', ['sites', 'siteTLS', 'siteListenerDomains'])
    expect(validateBasicConfig({
      ...basic,
      domains: ['www.example.com', '*.edge.example.com', 'deep.api.example.com'],
    }, t).domains).toBeUndefined()

    for (const invalid of [
      ['example'],
      ['api.*.example.com'],
      ['*example.com'],
      ['-bad.example.com'],
      Array.from({ length: 101 }, (_, index) => `host-${index}.example.com`),
    ]) {
      expect(validateBasicConfig({ ...basic, domains: invalid }, t).domains)
        .toBe('请输入 1 到 100 个有效且不重复的域名，可使用 *.example.com 通配符。')
    }
  })

  it('rejects duplicate, out-of-range, and colliding HTTPS listener ports; a blank list means 443', () => {
    const t = i18n.getFixedT('zh-CN', ['sites', 'siteTLS', 'siteListenerDomains'])
    // HTTPS on with the ports left blank is saved as 443, not refused
    expect(validateBasicConfig({ ...basic, https_listen_ports: [] }, t).https_listen_ports).toBeUndefined()
    expect(validateBasicConfig({ ...basic, http_listen_ports: ['443'], https_listen_ports: [] }, t).https_listen_ports)
      .toBe('HTTP 与 HTTPS 监听端口不能重复。')
    expect(validateBasicConfig({ ...basic, https_listen_ports: ['443', '443'] }, t).https_listen_ports)
      .toBe('HTTPS 端口需为 1 到 32 个不重复的 1-65535 端口，留空默认 443。')
    expect(validateBasicConfig({ ...basic, https_listen_ports: ['65536'] }, t).https_listen_ports)
      .toBe('HTTPS 端口需为 1 到 32 个不重复的 1-65535 端口，留空默认 443。')
    expect(validateBasicConfig({ ...basic, https_listen_ports: ['80'] }, t).https_listen_ports)
      .toBe('HTTP 与 HTTPS 监听端口不能重复。')
    expect(validateBasicConfig({ ...basic, https_enabled: false, https_listen_ports: [] }, t).https_listen_ports)
      .toBeUndefined()
  })
})
