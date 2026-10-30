import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { securityPoliciesApi } from '../api/securityPolicies'
import { wafRuleSubscriptionsApi } from '../api/wafRuleSubscriptions'
import { useSessionStore } from '../auth/session'
import SecurityPoliciesPage from '../pages/SecurityPoliciesPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// JA4 指纹与地理字段在 WAF 规则编辑器里可选，
// 字段下拉按 基础/客户端/请求头与内容/Bot 与指纹/地理 分组，JA4 可多行（在列表内）。
const ja4A = 't13d1516h2_8daaf6152771_b186095e22b6'
const ja4B = 't13d1517h2_8daaf6152771_02713d6af862'

beforeEach(() => {
  vi.spyOn(wafRuleSubscriptionsApi, 'libraries').mockResolvedValue([])
  vi.spyOn(wafRuleSubscriptionsApi, 'pendingPublications').mockResolvedValue([])
})
afterEach(() => vi.restoreAllMocks())

const openSelect = (combobox: HTMLElement) =>
  fireEvent.mouseDown(combobox.closest('.ant-select')!.querySelector('.ant-select-selector')!)
const option = (text: string) => screen.findByText(text, { selector: '.ant-select-item-option-content' })

async function openWAFEditor() {
  const actor = principal({ permissions: ['security_policies.read', 'security_policies.manage'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
  vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [], total: 0, page: 1, limit: 20 })
  const create = vi.spyOn(securityPoliciesApi, 'create').mockImplementation(async (_token, input) => ({
    ...input, id: '33333333-3333-4333-8333-333333333333', scope_id: actor.scope_id, version: 1,
    created_at: '2026-10-27T00:00:00Z', updated_at: '2026-10-27T00:00:00Z', rules: input.rules }))
  const user = userEvent.setup()
  renderWithProviders(<SecurityPoliciesPage kind="waf" />, ['/site/waf-rule'])
  await user.click(await screen.findByRole('button', { name: '添加规则集' }))
  const editor = await screen.findByRole('dialog')
  return { user, editor, create }
}

describe('WAF 规则条件字段：JA4 与地理', () => {
  it('groups the field options and offers JA4 and the IP intelligence fields with a one-line help', async () => {
    const { editor } = await openWAFEditor()
    openSelect(within(editor).getByRole('combobox', { name: '匹配字段' }))
    for (const group of ['基础', '客户端', '请求头与内容', 'Bot 与指纹', '地理与网络']) {
      expect(await screen.findByText(group, { selector: '.ant-select-item-group' })).toBeInTheDocument()
    }
    for (const label of ['TLS 指纹（JA4）', '国家/地区', 'ASN', '省份', '城市', '运营商', 'IDC 机房']) {
      expect(await option(label)).toBeInTheDocument()
    }
    // 每项一句中文说明（下拉项 title，悬停可见）。
    expect((await option('TLS 指纹（JA4）')).closest('.ant-select-item-option')).toHaveAttribute('title', expect.stringContaining('TLS 握手'))
  })

  it('saves a multi-line JA4 list as one in condition and refuses a malformed fingerprint', async () => {
    const { user, editor, create } = await openWAFEditor()
    await user.type(within(editor).getByLabelText('名称'), 'JA4 名单')
    await user.type(within(editor).getByLabelText('规则名称'), '屏蔽脚本指纹')
    openSelect(within(editor).getByRole('combobox', { name: '匹配字段' }))
    await user.click(await option('TLS 指纹（JA4）'))
    openSelect(within(editor).getByRole('combobox', { name: '运算符' }))
    expect(await option('在列表内')).toBeInTheDocument()
    // 不在列表内（WAF_JA4_NEGATION）；没有“不等于”，只保留一种写法。
    expect(await option('不在列表内')).toBeInTheDocument()
    expect(screen.queryByText('不等于', { selector: '.ant-select-item-option-content' })).not.toBeInTheDocument()
    expect(screen.queryByText('包含', { selector: '.ant-select-item-option-content' })).not.toBeInTheDocument()
    await user.click(await option('在列表内'))
    const values = within(editor).getByLabelText('匹配值')
    await user.type(values, 'not-a-ja4')
    await user.click(within(editor).getByRole('button', { name: '保存' }))
    expect(await within(editor).findByText(/JA4 指纹格式不对/)).toBeInTheDocument()
    expect(create).not.toHaveBeenCalled()
    await user.clear(values)
    await user.type(values, `${ja4A}\n${ja4B}`)
    await user.click(within(editor).getByRole('button', { name: '保存' }))
    await waitFor(() => expect(create).toHaveBeenCalled())
    expect(create.mock.calls[0][1].rules[0].conditions).toEqual([{ field: 'ja4', operator: 'in', values: [ja4A, ja4B] }])
  })
})
