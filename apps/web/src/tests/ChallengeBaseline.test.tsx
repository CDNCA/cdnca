import { Form } from 'antd'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from '../api/auth'
import {
  securityPoliciesApi, type SecurityActivationStatus, type SecurityPolicy, type SecurityPolicyChallengeConfig,
} from '../api/securityPolicies'
import { useSessionStore } from '../auth/session'
import i18n from '../i18n'
import { ChallengeFields, challengeFieldsFor } from '../pages/security/ManagedRuleFields'
import SecurityActivationPanel from '../pages/security/SecurityActivationPanel'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const proofOfWork: SecurityPolicyChallengeConfig = {
  type: 'five_second', failure_window_seconds: 60, max_failures: 5, pass_seconds: 21600, ban_seconds: 360,
  pass_window_seconds: 5, pass_max_requests: 300, pass_max_requests_per_uri: 50,
  pow_bits: 18, delay_seconds: 5, challenge_seconds: 120, bind_ipv4_prefix: 24, bind_ipv6_prefix: 64, key_rotate_seconds: 86400,
}

function ChallengeForm({ initial, onSubmit }: { initial?: SecurityPolicyChallengeConfig; onSubmit: (value: unknown) => void }) {
  const [form] = Form.useForm()
  return (
    <Form form={form} initialValues={{ rules: [{ action_config: { challenge: initial } }] }} onFinish={onSubmit}>
      <Form.List name="rules">{() => <ChallengeFields ruleName={0} form={form} />}</Form.List>
      <button type="submit">submit</button>
    </Form>
  )
}

// From the 1.0.35 baseline every challenge carries proof of work: there is no
// compatible challenge to switch to and no publish option for older nodes.
describe('challenges always carry proof of work', () => {
  afterEach(() => vi.restoreAllMocks())

  it('asks for every proof-of-work parameter without a PoW switch', async () => {
    await i18n.changeLanguage('zh-CN')
    expect(challengeFieldsFor('five_second', false).map(([field]) => field)).toEqual(expect.arrayContaining(
      ['pow_bits', 'delay_seconds', 'challenge_seconds', 'bind_ipv4_prefix', 'bind_ipv6_prefix', 'key_rotate_seconds']))
    const submitted = vi.fn()
    const actor = userEvent.setup()
    renderWithProviders(<ChallengeForm initial={{ ...proofOfWork, pow_bits: undefined }} onSubmit={submitted} />)
    expect(screen.queryByRole('switch', { name: '工作量证明（PoW）' })).toBeNull()
    expect(screen.queryByText('兼容挑战（未启用 PoW）')).toBeNull()
    // ui-small-1024: prefilled with the server default; clearing it still blocks saving.
    const pow = await screen.findByLabelText('PoW 难度(位)')
    expect(pow).toHaveValue('16')
    await actor.clear(pow)
    await actor.click(screen.getByRole('button', { name: 'submit' }))
    await waitFor(() => expect(document.querySelectorAll('.ant-form-item-explain-error').length).toBeGreaterThan(0))
    expect(submitted).not.toHaveBeenCalled()
  })
})

// final-fix-d: "超限才挑战" (trigger_window_seconds + trigger_max_requests, both or neither).
describe('challenge trigger (超限才挑战)', () => {
  const challengeOf = (submitted: ReturnType<typeof vi.fn>) => submitted.mock.calls[0][0].rules[0].action_config.challenge

  it('leaves both empty to challenge every request', async () => {
    await i18n.changeLanguage('zh-CN')
    const submitted = vi.fn()
    const actor = userEvent.setup()
    renderWithProviders(<ChallengeForm initial={proofOfWork} onSubmit={submitted} />)
    expect(await screen.findByLabelText('时间窗口(秒)')).toHaveValue('')
    expect(screen.getByLabelText('超过次数')).toHaveValue('')
    await actor.click(screen.getByRole('button', { name: 'submit' }))
    await waitFor(() => expect(submitted).toHaveBeenCalled())
    expect(challengeOf(submitted).trigger_window_seconds ?? undefined).toBeUndefined()
    expect(challengeOf(submitted).trigger_max_requests ?? undefined).toBeUndefined()
  })

  it('submits both when filled', async () => {
    await i18n.changeLanguage('zh-CN')
    const submitted = vi.fn()
    const actor = userEvent.setup()
    renderWithProviders(<ChallengeForm initial={proofOfWork} onSubmit={submitted} />)
    await actor.type(await screen.findByLabelText('时间窗口(秒)'), '10')
    await actor.type(screen.getByLabelText('超过次数'), '20')
    await actor.click(screen.getByRole('button', { name: 'submit' }))
    await waitFor(() => expect(submitted).toHaveBeenCalled())
    expect(challengeOf(submitted)).toMatchObject({ trigger_window_seconds: 10, trigger_max_requests: 20 })
  })

  it('refuses only one of the two', async () => {
    await i18n.changeLanguage('zh-CN')
    const submitted = vi.fn()
    const actor = userEvent.setup()
    renderWithProviders(<ChallengeForm initial={proofOfWork} onSubmit={submitted} />)
    await actor.type(await screen.findByLabelText('时间窗口(秒)'), '10')
    await actor.click(screen.getByRole('button', { name: 'submit' }))
    expect(await screen.findByText('时间窗口和超过次数要同时填写，或同时留空')).toBeInTheDocument()
    expect(submitted).not.toHaveBeenCalled()
  })

  it('shows the stored trigger when editing', async () => {
    await i18n.changeLanguage('zh-CN')
    renderWithProviders(<ChallengeForm initial={{ ...proofOfWork, trigger_window_seconds: 10, trigger_max_requests: 20 }} onSubmit={vi.fn()} />)
    expect(await screen.findByLabelText('时间窗口(秒)')).toHaveValue('10')
    expect(screen.getByLabelText('超过次数')).toHaveValue('20')
  })
})

describe('publishing a challenge to nodes that do not run it', () => {
  const siteID = '11111111-1111-4111-8111-111111111111'
  const oldNode = '22222222-2222-4222-8222-222222222222'
  const otherNode = '55555555-5555-4555-8555-555555555555'
  const policy = { id: '33333333-3333-4333-8333-333333333333', scope_id: '44444444-4444-4444-8444-444444444444', kind: 'cc',
    name: 'PoW', description: '', enabled: true, default_action: 'allow', version: 2, created_at: '', updated_at: '',
    rules: [] } as unknown as SecurityPolicy
  const status = { binding: null, latest_candidate: null } as unknown as SecurityActivationStatus

  afterEach(() => vi.restoreAllMocks())

  it('names the refused nodes and offers no compatible challenge', async () => {
    await i18n.changeLanguage('zh-CN')
    const user = principal({ permissions: ['security_policies.read', 'security_policies.manage'] })
    useSessionStore.getState().setSession(authResponse(user), user)
    vi.spyOn(securityPoliciesApi, 'getActivationStatus').mockResolvedValue(status)
    const refusal = new ApiError('node does not support CC verification pages with proof of work', 422, 'node_capability_unavailable')
    refusal.capability = { node_id: oldNode, capability: 'CAPABILITY_NAME_CC', required_version: 3, other_node_ids: [otherNode] }
    const publish = vi.spyOn(securityPoliciesApi, 'publishActivation').mockRejectedValueOnce(refusal)
    const actor = userEvent.setup()
    renderWithProviders(<SecurityActivationPanel kind="cc" policies={[policy]} policiesLoading={false} />,
      [`/site/cc-rule?site_id=${siteID}`])
    // waf-tenant-fix：租户发布不再填节点/过期，由控制面按站点套餐线路组选节点。
    expect(await screen.findByRole('button', { name: /发布/ })).toBeInTheDocument()
    expect(screen.queryByLabelText('目标节点 ID')).not.toBeInTheDocument()
    expect(screen.queryByRole('checkbox', { name: '对不支持的节点使用兼容挑战' })).toBeNull()
    await actor.click(screen.getByRole('button', { name: /发布/ }))
    expect(await screen.findByText(/目标节点版本不支持这个规则集用到的功能/)).toBeInTheDocument()
    expect(screen.getByText(new RegExp(`需要升级的节点：${oldNode}、${otherNode}`))).toBeInTheDocument()
    expect(publish.mock.calls[0][1]).toMatchObject({ target_node_ids: [] })
    expect(publish.mock.calls[0][1]).not.toHaveProperty('compatible_challenge')
  })
})
