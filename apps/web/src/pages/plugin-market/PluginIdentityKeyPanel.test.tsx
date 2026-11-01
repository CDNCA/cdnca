import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { apiKeysApi, type IssuedAPIKey } from '../../api/apiKeys'
import { ApiError } from '../../api/auth'
import type { PluginInstallation } from '../../api/pluginInstallations'
import { changeLocale } from '../../i18n'
import { principal } from '../../test/fixtures'
import { renderWithProviders } from '../../test/render'
import { PluginIdentityKeyPanel, pluginIdentityScopes } from './PluginIdentityKeyPanel'

const scopeID = '018cc251-f400-7def-8000-000000000030'
const authorizationID = '018cc251-f400-7def-8000-000000000032'
const installationID = '018cc251-f400-7def-8000-000000000033'

function installation(overrides: Partial<PluginInstallation> = {}): PluginInstallation {
  return {
    schema: 'cdnca.control.plugin-installation/v1', tenant_scope_id: scopeID,
    authorization_id: authorizationID, installation_id: installationID, verification_id: installationID,
    plugin_id: 'io.cdnca.cf-optimize', version: '1.0.0', resource_scope: 'tenant', entrypoint_type: 'external_https',
    manifest_sha256: 'a'.repeat(64), configuration_schema_sha256: 'b'.repeat(64),
    manifest_scopes: ['dns.read', 'dns.records.manage', 'edge.tenant.manage'],
    approved_scopes: ['dns.read', 'dns.records.manage', 'edge.tenant.manage'], sensitive_scopes: [], new_scopes: [],
    status: 'enabled', revision: 1, identity_generation: 1, lkg_verification_id: installationID,
    lkg_version: '1.0.0', stable_reason_code: null, updated_at: '2026-10-30T08:00:00Z',
    ...overrides,
  }
}

const user = principal({
  scope_kind: 'tenant', scope_id: scopeID, permissions: ['api_keys.self.manage', 'dns.read', 'dns.records.manage'],
})

function issued(): IssuedAPIKey {
  return {
    key: {
      id: '018cc251-f400-7def-8000-000000000040', key_id: 'cfk_AAAAAAAAAAAAAAAAAAAAAA', key_prefix: 'cfk_AAAAAAAAAAAAAAAAAAAAAA.',
      scope_id: scopeID, tenant_id: scopeID, user_id: scopeID, name: 'Plugin io.cdnca.cf-optimize',
      scopes: ['dns.read', 'dns.records.manage'], ip_allowlist: [], status: 'active', revision: 1,
      created_at: '2026-10-30T08:00:00Z', updated_at: '2026-10-30T08:00:00Z',
      plugin_installation_authorization_id: authorizationID, plugin_installation_id: installationID, plugin_id: 'io.cdnca.cf-optimize',
    },
    secret: 'S'.repeat(43),
  }
}

describe('PluginIdentityKeyPanel', () => {
  beforeEach(async () => {
    vi.restoreAllMocks()
    await changeLocale('zh-CN')
  })

  it('limits the key to approved scopes the user holds', () => {
    expect(pluginIdentityScopes(installation(), user)).toEqual(['dns.read', 'dns.records.manage'])
    expect(pluginIdentityScopes(installation({ approved_scopes: ['api_keys.self.manage'] }),
      principal({ permissions: ['api_keys.self.manage'] }))).toEqual([])
  })

  it('issues a key bound to the installation and shows it once', async () => {
    const create = vi.spyOn(apiKeysApi, 'create').mockResolvedValue(issued())
    renderWithProviders(<PluginIdentityKeyPanel token="token" principal={user} installation={installation()} />)
    expect(screen.getByText('这把 Key 的权限：dns.read, dns.records.manage')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: '签发 Key' }))
    await waitFor(() => expect(create).toHaveBeenCalledTimes(1))
    const [token, input, key] = create.mock.calls[0]!
    expect(token).toBe('token')
    expect(input).toEqual({
      name: '插件 io.cdnca.cf-optimize', scopes: ['dns.read', 'dns.records.manage'], ip_allowlist: [],
      plugin_installation_authorization_id: authorizationID,
    })
    expect(key).toMatch(/^plugin-identity-key-/)
    expect(await screen.findByLabelText('插件 Key')).toHaveValue(`cfk_AAAAAAAAAAAAAAAAAAAAAA.${'S'.repeat(43)}`)
  })

  it('explains a refused binding and hides for paused plugins or users without API key permission', async () => {
    vi.spyOn(apiKeysApi, 'create').mockRejectedValue(new ApiError('conflict', 409, 'plugin_installation_unavailable'))
    const { unmount } = renderWithProviders(<PluginIdentityKeyPanel token="token" principal={user} installation={installation()} />)
    await userEvent.click(screen.getByRole('button', { name: '签发 Key' }))
    expect(await screen.findByText('插件未在运行，不能签发 Key。请先恢复使用这个插件。')).toBeInTheDocument()
    unmount()
    const paused = renderWithProviders(<PluginIdentityKeyPanel token="token" principal={user} installation={installation({ status: 'disabled' })} />)
    expect(screen.queryByText('为插件签发 Key')).not.toBeInTheDocument()
    paused.unmount()
    renderWithProviders(<PluginIdentityKeyPanel token="token" principal={principal({ permissions: ['dns.read'] })} installation={installation()} />)
    expect(screen.queryByText('为插件签发 Key')).not.toBeInTheDocument()
  })
})
