import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { cachePoliciesApi, type CachePolicyDocument, type CachePolicyView } from '../../api/cachePolicies'
import { useSessionStore } from '../../auth/session'
import i18n from '../../i18n'
import '../../i18n/cachePolicy'
import { ApiError } from '../../api/auth'
import { authResponse, principal } from '../../test/fixtures'
import { renderWithProviders } from '../../test/render'
import CacheSiteTab from './CacheSiteTab'

// live-retest2 S3a (ui-small-1024): "svg" was refused (扩展名必须以点开头);
// the server stores extensions with the dot (cachecontrol/validate.go), so
// the editor adds it.
const siteID = 'site-1'
const document: CachePolicyDocument = {
  mode: 'override', rules: [{ order: 1, extensions: ['.css'], path_prefix: '', status_codes: [200], ttl_seconds: 3600 }],
  query_mode: 'preserve', query_names: [], vary_headers: ['accept-encoding'], disk_quota_bytes: 1024 * 1024 * 1024,
}
const view = (revision: number, value: CachePolicyDocument): CachePolicyView => ({
  site_id: siteID, revision, binding_mode: 'override', definition_id: siteID, definition_revision: revision, document: value,
  created_by_user_id: '11111111-1111-4111-8111-111111111111', request_id: `request-${revision}`, created_at: '2026-08-03T08:00:00Z',
})
const text = (key: string) => i18n.t(key, { ns: 'cachePolicy' })

describe('cache rule extensions', () => {
  afterEach(() => vi.restoreAllMocks())

  it('adds the leading dot to an extension typed without it', async () => {
    await i18n.changeLanguage('zh-CN')
    const permissions = ['sites.read', 'sites.manage']
    const actor = principal({ permissions, scope_kind: 'tenant', tenant_id: '22222222-2222-4222-8222-222222222222' })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    vi.spyOn(cachePoliciesApi, 'get').mockResolvedValue(view(3, document))
    const publish = vi.spyOn(cachePoliciesApi, 'publish').mockResolvedValue(view(4, document))
    const user = userEvent.setup()
    renderWithProviders(<CacheSiteTab siteId={siteID} accessToken={useSessionStore.getState().accessToken!} scopeKind="tenant" permissions={permissions}
      lockedForTenant={false} sessionEpoch={useSessionStore.getState().sessionEpoch} userId={actor.user_id}
      scopeId={actor.scope_id} tenantId={actor.tenant_id} onDirtyChange={() => undefined} />)
    // tp-b3c-be: an extension rule opens as 缓存范围 后缀 in the rule dialog
    await user.click(await screen.findByRole('button', { name: text('table.edit') }))
    const dialog = within(await screen.findByRole('dialog', { name: text('dialog.editTitle') }))
    const extensions = dialog.getByLabelText(text('dialog.scopeInput.suffix'))
    expect(extensions).toHaveValue('css')
    await user.clear(extensions)
    await user.click(extensions)
    await user.paste('svg|.PNG')
    // fix-siteinstant: the dialog's 确定 saves the policy
    await user.click(dialog.getByRole('button', { name: text('dialog.ok') }))
    await waitFor(() => expect(publish).toHaveBeenCalledTimes(1))
    expect(publish.mock.calls[0]![2].document.rules[0]!.extensions).toEqual(['.png', '.svg'])
    expect(screen.queryByText(text('validation.invalidExtension'))).not.toBeInTheDocument()
  })
})

// CU-SITE-03: a definite refusal of the save carrying a dialog's rule reopens
// the dialog with the typed rule and the reason (request ID included); a
// corrected 确定 saves it.
describe('cache rule dialog save outcome', () => {
  afterEach(() => vi.restoreAllMocks())

  it('reopens the dialog with the typed rule and the reason when the save is refused', async () => {
    await i18n.changeLanguage('zh-CN')
    const permissions = ['sites.read', 'sites.manage']
    const actor = principal({ permissions, scope_kind: 'tenant', tenant_id: '22222222-2222-4222-8222-222222222222' })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    // the report's case: 遵循源站 with no rules, then 添加规则 → 目录
    const followOrigin: CachePolicyDocument = { ...document, mode: 'follow_origin', rules: [] }
    vi.spyOn(cachePoliciesApi, 'get').mockResolvedValue(view(3, followOrigin))
    const publish = vi.spyOn(cachePoliciesApi, 'publish')
      .mockRejectedValueOnce(new ApiError('bad request', 400, 'invalid_request', 'cache-policy-publish-req-1'))
      .mockImplementation(async (_token, _site, input) => view(4, input.document))
    const user = userEvent.setup({ pointerEventsCheck: 0 })
    renderWithProviders(<CacheSiteTab siteId={siteID} accessToken={useSessionStore.getState().accessToken!} scopeKind="tenant" permissions={permissions}
      lockedForTenant={false} sessionEpoch={useSessionStore.getState().sessionEpoch} userId={actor.user_id}
      scopeId={actor.scope_id} tenantId={actor.tenant_id} onDirtyChange={() => undefined} />)
    await user.click(await screen.findByRole('button', { name: text('actions.addRule') }))
    const dialog = within(await screen.findByRole('dialog', { name: text('dialog.addTitle') }))
    await user.click(dialog.getByRole('radio', { name: text('dialog.scopes.dir') }))
    await user.click(dialog.getByLabelText(text('dialog.scopeInput.dir')))
    await user.paste('/review-codex/')
    await user.click(dialog.getByRole('button', { name: text('dialog.ok') }))
    await waitFor(() => expect(publish).toHaveBeenCalledTimes(1))
    expect(publish.mock.calls[0]![2].document.rules[0]!.path_prefix).toBe('/review-codex/')

    // the closing dialog may still be animating out: take the one with the reason
    await waitFor(() => expect(globalThis.document.querySelector('.cache-rule-dialog-error')).not.toBeNull())
    const alert = globalThis.document.querySelector('.cache-rule-dialog-error') as HTMLElement
    const reopened = within(alert.closest('[role="dialog"]') as HTMLElement)
    expect(alert).toHaveTextContent(text('errors.invalid_request'))
    expect(alert).toHaveTextContent('cache-policy-publish-req-1')
    expect(reopened.getByLabelText(text('dialog.scopeInput.dir'))).toHaveValue('/review-codex/')
    await user.click(reopened.getByRole('button', { name: text('dialog.ok') }))
    await waitFor(() => expect(publish).toHaveBeenCalledTimes(2))
    expect(publish.mock.calls[1]![2].document.rules[0]!.path_prefix).toBe('/review-codex/')
    await waitFor(() => expect(globalThis.document.querySelector('.cache-rule-dialog-error')).toBeNull())
  })
})
