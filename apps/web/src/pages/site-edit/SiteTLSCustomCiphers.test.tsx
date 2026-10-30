import { fireEvent, screen } from '@testing-library/react'
import type { TFunction } from 'i18next'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import {
  siteTLSCustomCipherSuites,
  validSiteTLSCipherSuites,
  validSiteTLSProfile,
  type SiteBasicConfig,
} from '../../api/sites'
import i18n from '../../i18n'
import { siteDefaultValueError } from '../siteDefaultValue'
import { renderWithProviders } from '../../test/render'
import HttpsSiteTab from './HttpsSiteTab'
import { validateBasicConfig } from './siteEditValidation'

// 编辑站点 > HTTPS 加密套件「自定义」，只能从白名单多选（与
// edgeconfig.TLSCustomCipherSuites 同一份），默认设置 #11 用同一规则。

function basic(extra: Partial<SiteBasicConfig> = {}): SiteBasicConfig {
  return {
    package_id: null, package_name: null, group_id: null, group_name: null,
    domains: ['example.com'], http_enabled: true, http_listen_ports: ['80'], https_listen_ports: ['443'],
    ipv6_enabled: false, tls_protocols: ['TLSv1.2', 'TLSv1.3'], origins: ['192.0.2.10'], cname: '',
    https_enabled: true, enabled: true, status: 'active', sync_status: 'synced', is_default: false,
    ...extra,
  }
}

function renderHttpsTab(value: SiteBasicConfig, onChange: (next: SiteBasicConfig) => void) {
  return renderWithProviders(
    <HttpsSiteTab
      siteId="55555555-5555-4555-8555-555555555555"
      siteScopeId="66666666-6666-4666-8666-666666666666"
      accessToken="tls-token"
      scopeKind="tenant"
      principalScopeId="66666666-6666-4666-8666-666666666666"
      permissions={[]}
      sessionEpoch={1}
      value={value}
      errors={validateBasicConfig(value, i18n.t.bind(i18n) as unknown as TFunction<['sites', 'siteTLS', 'siteListenerDomains']>)}
      readOnly={false}
     
      onChange={onChange}
    />,
  )
}

const pair = ['ECDHE-RSA-AES128-GCM-SHA256', 'ECDHE-ECDSA-AES128-GCM-SHA256']

beforeEach(async () => {
  vi.restoreAllMocks()
  await i18n.changeLanguage('zh-CN')
})

describe('site TLS custom cipher suites', () => {
  it('keeps the whitelist free of weak suites and applies the control plane rule', () => {
    expect(siteTLSCustomCipherSuites).toHaveLength(20)
    for (const suite of siteTLSCustomCipherSuites) {
      expect(suite).not.toMatch(/NULL|EXP|RC4|DES|MD5|PSK|SRP|CCM|ARIA|CAMELLIA|DSS|^DHE-/)
    }
    expect(validSiteTLSCipherSuites([...siteTLSCustomCipherSuites])).toBe(true)
    expect(validSiteTLSCipherSuites(pair)).toBe(true)
    expect(validSiteTLSCipherSuites([])).toBe(false)
    expect(validSiteTLSCipherSuites(['ECDHE-RSA-AES128-GCM-SHA256', 'ECDHE-ECDSA-AES128-SHA'])).toBe(false)
    expect(validSiteTLSCipherSuites([...pair, 'DES-CBC3-SHA'])).toBe(false)
    expect(validSiteTLSCipherSuites([...pair, pair[0]!])).toBe(false)
    expect(validSiteTLSProfile({ tls_cipher_preset: 'custom', tls_cipher_suites: pair, tls_protocols: ['TLSv1.3'] })).toBe(false)
    expect(validSiteTLSProfile({ tls_cipher_preset: 'custom', tls_cipher_suites: pair, tls_protocols: ['TLSv1.2'] })).toBe(true)
    expect(validSiteTLSProfile({ tls_cipher_preset: 'modern', tls_cipher_suites: pair })).toBe(false)
  })

  it('choosing 自定义 opens the safe-suite multi-select seeded with the modern suites', () => {
    const onChange = vi.fn()
    renderHttpsTab(basic(), onChange)
    fireEvent.mouseDown(screen.getByRole('combobox', { name: '加密套件' }))
    fireEvent.click(screen.getByText('自定义'))
    expect(onChange).toHaveBeenLastCalledWith(expect.objectContaining({
      tls_cipher_preset: 'custom', tls_cipher_suites: siteTLSCustomCipherSuites.slice(0, 6),
    }))
  })

  it('shows the list with 仅可选安全套件 and flags a list without both AEAD kinds', () => {
    const onChange = vi.fn()
    renderHttpsTab(basic({ tls_cipher_preset: 'custom', tls_cipher_suites: ['ECDHE-RSA-AES128-GCM-SHA256'] }), onChange)
    expect(screen.getByRole('combobox', { name: '自定义套件' })).toBeInTheDocument()
    expect(screen.getByText(/仅可选安全套件/)).toBeInTheDocument()
    expect(screen.getByText(/自定义套件至少要包含一个 ECDHE-ECDSA/)).toBeInTheDocument()
  })

  it('leaving custom drops the list; TLS 1.3 only goes back to modern', () => {
    const onChange = vi.fn()
    renderHttpsTab(basic({ tls_cipher_preset: 'custom', tls_cipher_suites: pair }), onChange)
    fireEvent.mouseDown(screen.getByRole('combobox', { name: 'TLS协议' }))
    fireEvent.click(screen.getByText('仅 TLS 1.3'))
    expect(onChange).toHaveBeenLastCalledWith(expect.objectContaining({
      tls_protocols: ['TLSv1.3'], tls_cipher_preset: 'modern', tls_cipher_suites: undefined,
    }))
  })

  it('默认设置 #11 accepts only whitelisted lists', () => {
    expect(siteDefaultValueError('ssl_cipher_suites', pair.join(':'))).toBeNull()
    expect(siteDefaultValueError('ssl_cipher_suites', 'RC4-SHA')).toBe('cipherSuites')
    expect(siteDefaultValueError('ssl_cipher_suites', 'ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA')).toBe('cipherSuites')
  })
})
