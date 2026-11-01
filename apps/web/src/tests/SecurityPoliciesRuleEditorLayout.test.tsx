import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { securityPoliciesApi, type SecurityPolicy } from '../api/securityPolicies'
import { wafRuleSubscriptionsApi } from '../api/wafRuleSubscriptions'
import { useSessionStore } from '../auth/session'
import SecurityPoliciesPage from '../pages/SecurityPoliciesPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// 编辑/添加安全规则集弹窗按任务分层——
// 基本信息一行、策略设置卡片、每条规则一张卡（头部一行 + 更多菜单），条件区表格对齐，
// “添加条件”在条件区末尾，规则区工具在区头右侧；WAF/CC/ACL 都核对。

const base = {
  scope_id: '22222222-2222-4222-8222-222222222222', enabled: true, default_action: 'allow' as const, version: 3,
  created_at: '2026-10-27T10:00:00Z', updated_at: '2026-10-27T10:00:00Z',
}
const wafPolicy: SecurityPolicy = {
  ...base, id: '33333333-3333-4333-8333-333333333331', kind: 'waf', name: 'Admin guard', description: 'protect /admin',
  waf_settings: { mode: '', auto_block: { window_seconds: 60, hit_threshold: 10, block_seconds: 600 } },
  rules: [
    { id: '44444444-4444-4444-8444-444444444441', name: 'Admin path', priority: 1, enabled: true, action: 'block', flow: 'stop', action_config: {},
      conditions: [{ field: 'path', operator: 'prefix', values: ['/admin'] }, { field: 'client_ip', operator: 'not_ip_in_cidr', values: ['10.0.0.0/8'] }] },
    { id: '44444444-4444-4444-8444-444444444442', name: 'Scanner UA', priority: 2, enabled: true, action: 'block', flow: 'stop', action_config: {},
      conditions: [{ field: 'user_agent', operator: 'contains', values: ['sqlmap'] }] },
  ],
}
const ccPolicy: SecurityPolicy = {
  ...base, id: '33333333-3333-4333-8333-333333333332', kind: 'cc', name: 'API limit', description: '',
  rules: [
    { id: '44444444-4444-4444-8444-444444444443', name: 'API', priority: 1, enabled: true, action: 'block', flow: 'stop', action_config: {},
      conditions: [{ field: 'path', operator: 'prefix', values: ['/api/'] }] },
    { id: '44444444-4444-4444-8444-444444444444', name: 'Static', priority: 2, enabled: true, action: 'allow', flow: 'stop', action_config: {},
      conditions: [{ field: 'path', operator: 'prefix', values: ['/static/'] }] },
  ],
}
const aclPolicy: SecurityPolicy = {
  ...base, id: '33333333-3333-4333-8333-333333333333', kind: 'acl', name: 'Office', description: '', default_action: 'block',
  rules: [{ id: '44444444-4444-4444-8444-444444444445', name: '规则 1', priority: 1, enabled: true, action: 'allow', flow: 'stop', action_config: {},
    conditions: [{ field: 'client_ip', operator: 'ip_in_cidr', values: ['203.0.113.0/24'] }] }],
}

beforeEach(() => {
  const actor = principal({ permissions: ['security_policies.read', 'security_policies.manage'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
  vi.spyOn(wafRuleSubscriptionsApi, 'libraries').mockResolvedValue([])
  vi.spyOn(wafRuleSubscriptionsApi, 'pendingPublications').mockResolvedValue([])
})
afterEach(() => vi.restoreAllMocks())

async function openEditor(item: SecurityPolicy) {
  vi.spyOn(securityPoliciesApi, 'list').mockResolvedValue({ items: [item], total: 1, page: 1, limit: 20 })
  const update = vi.spyOn(securityPoliciesApi, 'update').mockResolvedValue(item)
  const user = userEvent.setup()
  const path = item.kind === 'acl' ? '/site/acl' : `/site/${item.kind}-rule`
  renderWithProviders(<SecurityPoliciesPage kind={item.kind} />, [path])
  await user.click(await screen.findByRole('button', { name: `编辑${item.name}` }))
  const editor = await screen.findByRole('dialog')
  await within(editor).findByDisplayValue(item.name)
  return { user, editor, update }
}

const before = (a: Element, b: Element) => Boolean(a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING)

describe('规则集编辑弹窗分层布局', () => {
  it('WAF：基本信息一行、类型只读标签、说明单行可展开，策略设置是卡片而不是 fieldset', async () => {
    const { editor } = await openEditor(wafPolicy)
    expect(editor.querySelector('fieldset')).toBeNull()
    const basic = within(editor).getByRole('region', { name: '基本信息' })
    expect(within(basic).getByText('WAF', { selector: '.sp-editor-kind' })).toBeInTheDocument()
    expect(within(basic).queryByRole('combobox', { name: '规则类型' })).toBeNull()
    const grid = basic.querySelector('.sp-editor-basic-grid')!
    for (const label of ['名称', '说明']) expect(grid).toContainElement(within(basic).getByLabelText(label))
    expect(grid).toContainElement(within(basic).getByRole('combobox', { name: '未命中动作' }))
    expect(grid).toContainElement(within(basic).getByRole('switch', { name: '启用' }))
    const description = within(basic).getByLabelText('说明')
    expect(description.tagName).toBe('TEXTAREA')
    expect(description).toHaveAttribute('rows', '1')

    const settings = within(editor).getByRole('region', { name: '策略设置' })
    expect(settings).toHaveClass('sp-editor-card')
    const autoBlock = within(settings).getByRole('switch', { name: 'WAF 命中自动封禁' })
    // 开关与说明同行。
    expect(autoBlock.closest('.sp-editor-setting')).toHaveTextContent('同一客户端在窗口内被本策略拦截或挑战达到次数后临时封禁')
    expect(within(settings).getByText(/需要节点支持 WAF v2/)).toHaveClass('sp-editor-hint')
    expect(within(settings).getByRole('spinbutton', { name: '统计窗口（秒）' })).toHaveValue('60')
  })

  it('WAF：每条规则一张卡，头部一行，上移/下移/删除收进更多菜单，条件区表格对齐且添加条件在末尾', async () => {
    const { user, editor, update } = await openEditor(wafPolicy)
    const rules = within(editor).getByRole('region', { name: '匹配规则' })
    const head = rules.querySelector('.sp-editor-rules-head')!
    expect(within(head as HTMLElement).getByRole('button', { name: '添加规则' })).toBeInTheDocument()
    expect(within(head as HTMLElement).getByRole('combobox', { name: '选择要导入的系统规则' })).toBeInTheDocument()

    const first = within(rules).getByTestId('rule-0')
    expect(first).toHaveClass('sp-editor-rule')
    const ruleHead = first.querySelector('.sp-editor-rule-head') as HTMLElement
    expect(within(ruleHead).getByLabelText('规则名称')).toHaveValue('Admin path')
    for (const name of ['动作', '后续处理']) expect(within(ruleHead).getByRole('combobox', { name })).toBeInTheDocument()
    expect(within(ruleHead).getByRole('spinbutton', { name: '优先级' })).toHaveValue('1')
    expect(within(ruleHead).getByRole('switch')).toBeChecked()
    expect(within(editor).queryByRole('button', { name: '删除第1条规则' })).toBeNull()
    expect(within(editor).queryByRole('button', { name: '上移规则 1' })).toBeNull()

    const conditions = first.querySelector('.sp-editor-conds') as HTMLElement
    const header = conditions.querySelector('.sp-editor-cond-header') as HTMLElement
    expect(header).toHaveTextContent('匹配字段运算符匹配值')
    const rows = [...conditions.querySelectorAll('.sp-editor-cond-row')] as HTMLElement[]
    expect(rows).toHaveLength(2)
    for (const row of rows) {
      const remove = within(row).getByRole('button', { name: '删除条件' })
      expect(row.lastElementChild).toContainElement(remove)
    }
    const add = within(conditions).getByRole('button', { name: '添加条件' })
    expect(before(rows[1]!, add)).toBe(true)

    await user.click(within(ruleHead).getByRole('button', { name: '规则 1 的更多操作' }))
    const up = await screen.findByRole('menuitem', { name: '上移规则 1' })
    expect(up).toHaveAttribute('aria-disabled', 'true')
    expect(screen.getByRole('menuitem', { name: '删除规则' })).toBeInTheDocument()
    await user.click(screen.getByRole('menuitem', { name: '下移规则 1' }))
    await waitFor(() => expect(within(within(rules).getByTestId('rule-0')).getByLabelText('规则名称')).toHaveValue('Scanner UA'))

    await user.click(within(editor).getByRole('button', { name: '保存' }))
    await waitFor(() => expect(update).toHaveBeenCalled())
    const sent = update.mock.calls[0]![3]
    expect(sent.rules.map((rule) => rule.name)).toEqual(['Scanner UA', 'Admin path'])
    expect(sent.rules.map((rule) => rule.priority)).toEqual([1, 2])
    expect(sent.waf_settings).toEqual({ mode: '', auto_block: { window_seconds: 60, hit_threshold: 10, block_seconds: 600 } })
  }, 20_000)

  it('WAF：更多菜单删除规则，只剩一条时删除不可用', async () => {
    const { user, editor } = await openEditor(wafPolicy)
    await user.click(within(editor).getByRole('button', { name: '规则 2 的更多操作' }))
    await user.click(await screen.findByRole('menuitem', { name: '删除规则' }))
    await waitFor(() => expect(within(editor).queryByTestId('rule-1')).toBeNull())
    fireEvent.click(within(editor).getByRole('button', { name: '规则 1 的更多操作' }))
    await waitFor(() => expect(screen.getAllByRole('menuitem', { name: '删除规则' }).at(-1)).toHaveAttribute('aria-disabled', 'true'))
  }, 20_000)

  it('CC：没有策略设置卡片，条件提示在规则区底部只出现一次', async () => {
    const { editor } = await openEditor(ccPolicy)
    expect(within(editor).queryByRole('region', { name: '策略设置' })).toBeNull()
    expect(within(editor).getAllByTestId(/^rule-/)).toHaveLength(2)
    expect(within(editor).getAllByText(/客户端IP 可填 CIDR/)).toHaveLength(1)
    const rules = within(editor).getByRole('region', { name: '匹配规则' })
    expect(rules.querySelector('.sp-editor-footnotes')).toHaveTextContent(/客户端IP 可填 CIDR/)
  }, 20_000)

  it('ACL：启用与名称、备注、默认行为同在基本信息一行，不再单独落在底部', async () => {
    const { editor } = await openEditor(aclPolicy)
    const basic = within(editor).getByRole('region', { name: '基本信息' })
    const grid = basic.querySelector('.acl-editor-basic-grid')!
    expect(grid).toContainElement(within(basic).getByLabelText('名称'))
    expect(grid).toContainElement(within(basic).getByRole('switch', { name: '启用' }))
    expect(grid).toContainElement(within(basic).getByRole('radio', { name: '拒绝' }))
    expect(editor.querySelector('.acl-editor-enabled-row')).toBeNull()
  }, 20_000)

  it('弹窗内只有正文一个滚动区，底部操作条在滚动区外', async () => {
    const { editor } = await openEditor(wafPolicy)
    const body = editor.querySelector('.ant-modal-body') as HTMLElement
    expect(body.style.overflowY).toBe('auto')
    expect(body.style.maxHeight).not.toBe('')
    const footer = editor.querySelector('.ant-modal-footer')!
    expect(body.contains(footer)).toBe(false)
    expect(within(footer as HTMLElement).getByRole('button', { name: '保存' })).toBeInTheDocument()
  }, 20_000)
})
