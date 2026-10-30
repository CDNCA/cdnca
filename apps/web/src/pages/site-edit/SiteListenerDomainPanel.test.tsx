import { fireEvent, screen } from '@testing-library/react'

import type { SiteBasicConfig } from '../../api/sites'
import i18n from '../../i18n'
import '../../i18n/siteListenerDomains'
import { renderWithProviders } from '../../test/render'
import SiteListenerDomainPanel from './SiteListenerDomainPanel'
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

describe('SiteListenerDomainPanel', () => {
  it('renders and emits the complete canonical multi-domain set', () => {
    const onChange = vi.fn()
    renderWithProviders(
      <SiteListenerDomainPanel
        value={{ ...basic, domains: ['api.example.com', '*.edge.example.com'] }}
        ipv6RuntimeState="disabled"
        errors={{}}
        onChange={onChange}
      />,
    )

    const domains = screen.getByLabelText('域名')
    expect(domains).toHaveValue('api.example.com\n*.edge.example.com')
    fireEvent.change(domains, {
      target: { value: ' BÜCHER.example.\n*.Edge.Example.com\napi.example.com\nAPI.EXAMPLE.COM ' },
    })
    expect(onChange).toHaveBeenLastCalledWith({
      ...basic,
      domains: ['*.edge.example.com', 'api.example.com', 'xn--bcher-kva.example'],
    })
  })

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

  it('renders the mounted site contract and emits only listener/domain changes', () => {
    const onChange = vi.fn()
    renderWithProviders(
      <SiteListenerDomainPanel
        value={basic}
        ipv6RuntimeState="disabled"
        errors={{}}
        onChange={onChange}
      />,
    )

    expect(screen.getByRole('heading', { name: '域名与监听端口' })).toBeInTheDocument()
    expect(screen.getByLabelText('域名')).toHaveValue('www.example.com')
    expect(screen.getByLabelText('HTTP监听端口')).toHaveValue('80')
    expect(screen.getByRole('switch', { name: 'HTTPS 监听' })).toBeChecked()
    expect(screen.getByLabelText('HTTPS监听端口')).toHaveValue('443')
    expect(screen.getByRole('switch', { name: 'IPv6 监听' })).not.toBeChecked()
    expect(screen.getByText('未启用')).toBeInTheDocument()
    expect(screen.getByText('HTTP 始终开启；HTTPS 可独立开关。保存的是控制面期望状态，不代表节点已经生效。')).toBeInTheDocument()

    fireEvent.change(screen.getByLabelText('HTTPS监听端口'), { target: { value: '8443, 9443' } })
    expect(onChange).toHaveBeenLastCalledWith({
      ...basic,
      https_listen_ports: ['8443', '9443'],
    })

    fireEvent.click(screen.getByRole('switch', { name: 'IPv6 监听' }))
    expect(onChange).toHaveBeenLastCalledWith({ ...basic, ipv6_enabled: true })
  })

  it('keeps every listener/domain control inert when the parent revokes write access', () => {
    const onChange = vi.fn()
    renderWithProviders(
      <SiteListenerDomainPanel
        value={basic}
        ipv6RuntimeState="disabled"
        errors={{}}
        readOnly
        onChange={onChange}
      />,
    )

    expect(screen.getByLabelText('域名')).toBeDisabled()
    expect(screen.getByLabelText('HTTP监听端口')).toBeDisabled()
    expect(screen.getByRole('switch', { name: 'HTTPS 监听' })).toBeDisabled()
    expect(screen.getByLabelText('HTTPS监听端口')).toBeDisabled()
    fireEvent.change(screen.getByLabelText('HTTPS监听端口'), { target: { value: '9443' } })
    expect(onChange).not.toHaveBeenCalled()
  })

  it('rejects missing, duplicate, out-of-range, and colliding HTTPS listener ports', () => {
    const t = i18n.getFixedT('zh-CN', ['sites', 'siteTLS', 'siteListenerDomains'])
    expect(validateBasicConfig({ ...basic, https_listen_ports: [] }, t).https_listen_ports)
      .toBe('启用 HTTPS 时必须填写 1 到 32 个不重复的 1-65535 端口。')
    expect(validateBasicConfig({ ...basic, https_listen_ports: ['443', '443'] }, t).https_listen_ports)
      .toBe('启用 HTTPS 时必须填写 1 到 32 个不重复的 1-65535 端口。')
    expect(validateBasicConfig({ ...basic, https_listen_ports: ['65536'] }, t).https_listen_ports)
      .toBe('启用 HTTPS 时必须填写 1 到 32 个不重复的 1-65535 端口。')
    expect(validateBasicConfig({ ...basic, https_listen_ports: ['80'] }, t).https_listen_ports)
      .toBe('HTTP 与 HTTPS 监听端口不能重复。')
    expect(validateBasicConfig({ ...basic, https_enabled: false, https_listen_ports: [] }, t).https_listen_ports)
      .toBeUndefined()
  })
})
