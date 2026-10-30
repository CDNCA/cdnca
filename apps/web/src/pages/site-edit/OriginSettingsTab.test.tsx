import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { SiteOriginPool } from '../../api/sites'
import i18n from '../../i18n'
import BalanceKeyFields from './BalanceKeyFields'
import OriginSettingsTab, { type OriginSettingsTabProps } from './OriginSettingsTab'

function pool(changes: Partial<SiteOriginPool> = {}): SiteOriginPool {
  return {
    origins: [{ host: '192.0.2.10', port: 80, weight: 1, enabled: true }],
    balance_method: 'round_robin', failover_tries: 1, connect_timeout_ms: 3000, read_timeout_ms: 30000,
    ...changes,
  }
}

function renderTab(props: Partial<Omit<OriginSettingsTabProps, 'onChange'>> = {}) {
  const onChange = vi.fn()
  const result = render(<MemoryRouter><OriginSettingsTab pool={pool()} {...props} onChange={onChange} /></MemoryRouter>)
  return { ...result, onChange }
}

const lastPool = (onChange: { mock: { lastCall?: unknown[] } }) => onChange.mock.lastCall?.[0] as SiteOriginPool

describe('OriginSettingsTab', () => {
  beforeEach(async () => {
    await i18n.changeLanguage('zh-CN')
  })

  it('shows the values in effect in the summary and jumps to their section (site-parity4)', () => {
    renderTab({ pool: pool({ scheme: 'https', https_port: 8443, request_host: { mode: 'custom', value: 'origin.example.com' } }) })
    const summary = screen.getByRole('region', { name: '本页摘要' })
    expect(summary).toHaveTextContent('HTTPS:8443')
    expect(summary).toHaveTextContent('origin.example.com')
    expect(summary).toHaveTextContent('30 秒 / 3 秒')
    const scroll = vi.fn()
    Element.prototype.scrollIntoView = scroll
    fireEvent.click(screen.getByRole('button', { name: /超时（读取\/连接）/u }))
    expect(scroll).toHaveBeenCalled()
    expect(document.activeElement).toHaveTextContent('回源超时')
  })

  it('renders the sections in order with server defaults', () => {
    renderTab({ canReadOriginAuth: true, conditional: <div>条件回源编辑器</div> })
    const headings = screen.getAllByRole('heading', { level: 2 }).map((heading) => heading.textContent)
    expect(headings).toEqual(['回源协议与端口', '回源域名', '回源超时', '连接复用', '回源鉴权', '其它回源选项'])
    expect(screen.getByRole('radio', { name: /^HTTP 使用 HTTP 连接源站/u })).toBeChecked()
    expect(screen.getByRole('radio', { name: /^跟随协议 按访客访问协议回源/u })).toBeInTheDocument()
    expect(screen.getByRole('radio', { name: /^跟随协议和端口 协议和端口都跟随访客请求/u })).toBeInTheDocument()
    expect(screen.getByRole('spinbutton', { name: 'HTTP 回源端口' })).toHaveValue('80')
    expect(screen.queryByRole('spinbutton', { name: 'HTTPS 回源端口' })).toBeNull()
    expect(screen.getByRole('radio', { name: /^访问域名 使用访客/u })).toBeChecked()
    expect(screen.getByRole('radio', { name: /^访问域名\+端口 Host 带上访问端口/u })).toBeInTheDocument()
    expect(screen.getByRole('switch', { name: '回源鉴权开关' })).toBeChecked()
    expect(screen.getByRole('radio', { name: /^固定 Host/u })).toBeInTheDocument()
    expect(screen.getByRole('spinbutton', { name: '回源超时' })).toHaveValue('30')
    expect(screen.getByRole('spinbutton', { name: '连接超时' })).toHaveValue('3')
    expect(screen.getByRole('switch', { name: '回源 Keepalive' })).toBeChecked()
    expect(screen.getByRole('spinbutton', { name: '空闲超时' })).toHaveValue('60')
    expect(screen.getByRole('link', { name: '管理回源鉴权规则' })).toHaveAttribute('href', '/site/origin-auth/rules')
    // WebSocket lives only in 高级设置 → 性能与协议.
    expect(screen.queryByRole('switch', { name: 'WebSocket' })).toBeNull()
    expect(screen.queryByLabelText('源站 TLS SNI')).toBeNull()
    // Our conditional origin editor sits folded below the main fields.
    expect(screen.getByRole('button', { name: /高级：条件回源/u })).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByText('条件回源编辑器')).toBeNull()
  })

  it('hides the rules link without origin_auth.read and opens the fold when asked', () => {
    renderTab({ conditional: <div>条件回源编辑器</div>, conditionalOpen: true })
    expect(screen.getByRole('switch', { name: '回源鉴权开关' })).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: '管理回源鉴权规则' })).toBeNull()
    expect(screen.getByText('条件回源编辑器')).toBeInTheDocument()
  })

  it('writes protocol, host, timeouts and keepalive into the same pool fields', () => {
    const { onChange, rerender } = renderTab()
    fireEvent.click(screen.getByRole('radio', { name: /^HTTPS 使用 HTTPS/u }))
    expect(lastPool(onChange)).toMatchObject({ scheme: 'https', https_port: 443 })

    fireEvent.click(screen.getByRole('radio', { name: /^跟随协议 按访客/u }))
    expect(lastPool(onChange)).toMatchObject({ scheme: 'follow', follow_port: false })

    fireEvent.click(screen.getByRole('radio', { name: /固定 Host/u }))
    expect(lastPool(onChange).request_host).toEqual({ mode: 'custom', value: '' })
    rerender(<MemoryRouter><OriginSettingsTab pool={pool({ request_host: { mode: 'custom', value: '' } })} onChange={onChange} /></MemoryRouter>)
    fireEvent.change(screen.getByLabelText('自定义 Host'), { target: { value: 'origin.example.com' } })
    expect(lastPool(onChange).request_host).toEqual({ mode: 'custom', value: 'origin.example.com' })

    fireEvent.change(screen.getByRole('spinbutton', { name: '回源超时' }), { target: { value: '60' } })
    expect(lastPool(onChange).read_timeout_ms).toBe(60_000)
    fireEvent.change(screen.getByRole('spinbutton', { name: '连接超时' }), { target: { value: '10' } })
    expect(lastPool(onChange).connect_timeout_ms).toBe(10_000)

    fireEvent.click(screen.getByRole('switch', { name: '回源 Keepalive' }))
    expect(lastPool(onChange)).toMatchObject({ keepalive_enabled: false, keepalive_idle_timeout_ms: 60_000 })
    fireEvent.change(screen.getByRole('spinbutton', { name: '空闲超时' }), { target: { value: '50' } })
    expect(lastPool(onChange)).toMatchObject({ keepalive_enabled: true, keepalive_idle_timeout_ms: 50_000 })

  })

  // tp-b3a-be：回源协议四选一、HTTP/HTTPS 回源端口、访问域名+端口、回源鉴权开关。
  it('maps the four protocols to scheme, follow_port and the ports each one uses', () => {
    const { onChange, rerender } = renderTab({ pool: pool({ http_port: 8080 }) })
    fireEvent.click(screen.getByRole('radio', { name: /^跟随协议和端口/u }))
    expect(lastPool(onChange)).toMatchObject({ scheme: 'follow', follow_port: true, http_port: 80, https_port: 443 })

    rerender(<MemoryRouter><OriginSettingsTab pool={pool({ scheme: 'follow', follow_port: true })} onChange={onChange} /></MemoryRouter>)
    expect(screen.getByRole('radio', { name: /^跟随协议和端口/u })).toBeChecked()
    expect(screen.queryByRole('spinbutton', { name: 'HTTP 回源端口' })).toBeNull()
    expect(screen.queryByRole('spinbutton', { name: 'HTTPS 回源端口' })).toBeNull()

    rerender(<MemoryRouter><OriginSettingsTab pool={pool({ scheme: 'follow', https_port: 8443 })} onChange={onChange} /></MemoryRouter>)
    expect(screen.getByRole('spinbutton', { name: 'HTTP 回源端口' })).toHaveValue('80')
    expect(screen.getByRole('spinbutton', { name: 'HTTPS 回源端口' })).toHaveValue('8443')
    fireEvent.click(screen.getByRole('radio', { name: /^HTTPS 使用 HTTPS/u }))
    expect(lastPool(onChange)).toMatchObject({ scheme: 'https', follow_port: false, http_port: 80, https_port: 8443 })
    fireEvent.click(screen.getByRole('radio', { name: /^HTTP 使用 HTTP/u }))
    expect(lastPool(onChange)).toMatchObject({ scheme: 'http', http_port: 80, https_port: 443, tls: { trust: 'system' } })
  })

  it('moves port-inherited origins with the pool port and keeps explicit ones', () => {
    const { onChange } = renderTab({ pool: pool({ origins: [
      { host: '192.0.2.10', port: 80, weight: 1, enabled: true, port_inherited: true },
      { host: '192.0.2.11', port: 9000, weight: 1, enabled: true },
    ] }) })
    fireEvent.change(screen.getByRole('spinbutton', { name: 'HTTP 回源端口' }), { target: { value: '8080' } })
    expect(lastPool(onChange)).toMatchObject({ http_port: 8080 })
    expect(lastPool(onChange).origins.map((origin) => origin.port)).toEqual([8080, 9000])
  })

  it('sends visitor host with port and switches origin auth off', () => {
    const { onChange } = renderTab({ canReadOriginAuth: true })
    fireEvent.click(screen.getByRole('radio', { name: /^访问域名\+端口/u }))
    expect(lastPool(onChange).request_host).toEqual({ mode: 'visitor_port', value: '' })
    expect(screen.getByText('已开启，按回源鉴权规则向源站发送鉴权信息。')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('switch', { name: '回源鉴权开关' }))
    expect(lastPool(onChange).origin_auth_enabled).toBe(false)
  })

  it('hides the rules link while origin auth is off', () => {
    renderTab({ canReadOriginAuth: true, pool: pool({ origin_auth_enabled: false }) })
    expect(screen.getByRole('switch', { name: '回源鉴权开关' })).not.toBeChecked()
    expect(screen.getByText('关闭后不会向源站发送鉴权信息。')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: '管理回源鉴权规则' })).toBeNull()
  })

  it('offers SNI and verification for HTTPS', () => {
    renderTab({ pool: pool({ scheme: 'https', tls: { trust: 'custom', ca_pem: '' } }) })
    expect(screen.getByLabelText('源站 TLS SNI')).toBeInTheDocument()
    expect(screen.getByLabelText('自定义 CA 证书（PEM）')).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: '源站证书校验' })).toBeInTheDocument()
  })

  // AUDIT-FINAL C7: a self-signed origin needs a way not to
  // verify; it is opt-in (verification stays the default), drops the CA and
  // says what it costs.
  it('lets HTTPS skip origin certificate verification with a MITM warning', () => {
    const { onChange } = renderTab({ pool: pool({ scheme: 'https', tls: { sni: 'o.example.test', trust: 'custom', ca_pem: 'PEM' } }) })
    fireEvent.mouseDown(screen.getByRole('combobox', { name: '源站证书校验' }))
    fireEvent.click(screen.getByText('不校验源站证书（源站自签证书时选，存在中间人风险）'))
    expect(lastPool(onChange).tls).toEqual({ sni: 'o.example.test', trust: 'none' })
  })

  it('shows the warning and no CA field while verification is off', () => {
    renderTab({ pool: pool({ scheme: 'https', tls: { trust: 'none' } }) })
    expect(screen.getByText('不校验源站证书（源站自签证书时选，存在中间人风险）')).toBeInTheDocument()
    expect(screen.getByText(/^已关闭源站证书校验/u).closest('[role="alert"]')).not.toBeNull()
    expect(screen.queryByLabelText('自定义 CA 证书（PEM）')).toBeNull()
  })

  // User 10-27: 证书校验 was read as this site's certificate. It is the
  // origin's; the visitor certificate lives on the HTTPS tab.
  it('names the origin certificate and leads to HTTPS settings, or to a request when the site has none', () => {
    const onOpenHttps = vi.fn()
    const onRequestCertificate = vi.fn()
    const { rerender } = renderTab({ pool: pool({ scheme: 'https' }), certificateBound: true, onOpenHttps, onRequestCertificate })
    expect(screen.getByText('用公共 CA 校验（源站证书由正规机构签发）')).toBeInTheDocument()
    expect(screen.getByText(/访客访问本站用的 HTTPS 证书在「HTTPS设置」中配置/u)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '去 HTTPS 设置' }))
    expect(onOpenHttps).toHaveBeenCalled()
    expect(screen.queryByRole('button', { name: '申请证书' })).toBeNull()
    rerender(<MemoryRouter><OriginSettingsTab pool={pool({ scheme: 'https' })} certificateBound={false} onOpenHttps={onOpenHttps}
      onRequestCertificate={onRequestCertificate} onChange={vi.fn()} /></MemoryRouter>)
    fireEvent.click(screen.getByRole('button', { name: '申请证书' }))
    expect(onRequestCertificate).toHaveBeenCalled()
    // HTTP origins have no origin certificate: no hint.
    rerender(<MemoryRouter><OriginSettingsTab pool={pool()} onOpenHttps={onOpenHttps} onChange={vi.fn()} /></MemoryRouter>)
    expect(screen.queryByText(/访客访问本站用的 HTTPS 证书/u)).toBeNull()
  })

  it('edits trusted proxies line by line', () => {
    const { onChange } = renderTab()
    fireEvent.change(screen.getByLabelText('可信代理'), { target: { value: '10.0.0.0/8\n2001:db8::/32' } })
    expect(lastPool(onChange).trusted_proxy_cidrs).toEqual(['10.0.0.0/8', '2001:db8::/32'])
  })

  // ge36：回源跟随跳转开关、最大次数、是否允许跨源。
  it('turns origin redirect following on with the default hops, then edits hops and cross origin', () => {
    const { onChange, rerender } = renderTab()
    expect(screen.getByLabelText('最大跳转次数')).toBeDisabled()
    fireEvent.click(screen.getByRole('switch', { name: '跟随源站跳转' }))
    expect(lastPool(onChange).follow_redirect).toEqual({ enabled: true, max_hops: 3, cross_origin: false })
    rerender(<MemoryRouter><OriginSettingsTab pool={pool({ follow_redirect: { enabled: true, max_hops: 3, cross_origin: false } })} onChange={onChange} /></MemoryRouter>)
    fireEvent.change(screen.getByLabelText('最大跳转次数'), { target: { value: '5' } })
    expect(lastPool(onChange).follow_redirect).toEqual({ enabled: true, max_hops: 5, cross_origin: false })
    fireEvent.click(screen.getByRole('switch', { name: '允许跳转到其他主机' }))
    expect(lastPool(onChange).follow_redirect).toEqual({ enabled: true, max_hops: 3, cross_origin: true })
  })

  it('is read only when asked', () => {
    renderTab({ readOnly: true })
    for (const radio of screen.getAllByRole('radio')) expect(radio).toBeDisabled()
    expect(screen.getByRole('spinbutton', { name: '回源超时' })).toBeDisabled()
    expect(screen.getByRole('switch', { name: '回源 Keepalive' })).toBeDisabled()
  })

  it('has English text', async () => {
    await i18n.changeLanguage('en-US')
    renderTab()
    expect(screen.getByRole('heading', { name: 'Origin protocol and port' })).toBeInTheDocument()
    expect(screen.getByLabelText('Trusted proxies')).toBeInTheDocument()
  })
})

describe('BalanceKeyFields', () => {
  beforeEach(async () => {
    await i18n.changeLanguage('zh-CN')
  })

  it('edits the custom hash key and sticky name only for those methods', () => {
    const onChange = vi.fn()
    const { rerender, container } = render(<BalanceKeyFields pool={pool()} onChange={onChange} />)
    expect(container).toBeEmptyDOMElement()
    rerender(<BalanceKeyFields pool={pool({ balance_method: 'hash', hash_key: '$uri' })} onChange={onChange} />)
    fireEvent.change(screen.getByLabelText('自定义哈希键'), { target: { value: '$cookie_uid' } })
    expect(lastPool(onChange).hash_key).toBe('$cookie_uid')
    rerender(<BalanceKeyFields pool={pool({ balance_method: 'sticky', sticky: { source: 'cookie', name: 'sid' } })} onChange={onChange} />)
    fireEvent.change(screen.getByLabelText('名称'), { target: { value: 'route' } })
    expect(lastPool(onChange).sticky).toEqual({ source: 'cookie', name: 'route' })
  })
})
