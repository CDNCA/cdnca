import { Form } from 'antd'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from '../api/auth'
import { securityPoliciesApi, type SecurityPolicy } from '../api/securityPolicies'
import { useSessionStore } from '../auth/session'
import i18n from '../i18n'
import { ChallengeFields } from '../pages/security/ManagedRuleFields'
import SecurityActivationPanel from '../pages/security/SecurityActivationPanel'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

// live-retest2 S5 (ui-small-1024): a new challenge rule had no defaults, and
// an automatic publish refused with 409 publication_state_conflict said nothing.
function NewChallenge({ type, onSubmit }: { type: string; onSubmit: (value: unknown) => void }) {
  const [form] = Form.useForm()
  return (
    <Form form={form} initialValues={{ rules: [{ action_config: { challenge: { type } } }] }} onFinish={onSubmit}>
      <Form.List name="rules">{() => <ChallengeFields ruleName={0} form={form} />}</Form.List>
      <button type="submit">submit</button>
    </Form>
  )
}

const challengeOf = (submitted: ReturnType<typeof vi.fn>) =>
  (submitted.mock.calls[0]![0] as { rules: Array<{ action_config: { challenge: Record<string, unknown> } }> }).rules[0]!.action_config.challenge

describe('new challenge rule defaults', () => {
  it('saves the server default JS challenge without typing anything', async () => {
    await i18n.changeLanguage('zh-CN')
    const submitted = vi.fn()
    renderWithProviders(<NewChallenge type="js" onSubmit={submitted} />)
    await userEvent.setup().click(await screen.findByRole('button', { name: 'submit' }))
    await waitFor(() => expect(submitted).toHaveBeenCalledTimes(1))
    // libs/rulepack/params.go DefaultCCChallenge / DefaultCCChallengeBanSeconds
    expect(challengeOf(submitted)).toEqual({
      type: 'js', failure_window_seconds: 60, max_failures: 5, ban_seconds: 600, pass_seconds: 3600, pow_bits: 16,
      challenge_seconds: 120, bind_ipv4_prefix: 24, bind_ipv6_prefix: 64, key_rotate_seconds: 86400,
    })
  })

  it('adds the 5-second wait only for 5秒盾 and no PoW for redirect', async () => {
    await i18n.changeLanguage('zh-CN')
    const five = vi.fn()
    const { unmount } = renderWithProviders(<NewChallenge type="five_second" onSubmit={five} />)
    await userEvent.setup().click(await screen.findByRole('button', { name: 'submit' }))
    await waitFor(() => expect(five).toHaveBeenCalledTimes(1))
    expect(challengeOf(five)).toMatchObject({ delay_seconds: 5, pow_bits: 16 })
    unmount()
    const redirect = vi.fn()
    renderWithProviders(<NewChallenge type="redirect" onSubmit={redirect} />)
    await userEvent.setup().click(await screen.findByRole('button', { name: 'submit' }))
    await waitFor(() => expect(redirect).toHaveBeenCalledTimes(1))
    expect(challengeOf(redirect)).not.toHaveProperty('pow_bits')
    expect(challengeOf(redirect)).not.toHaveProperty('delay_seconds')
  })

  it('drops ban_seconds when switched to log only (server requires 0)', async () => {
    await i18n.changeLanguage('zh-CN')
    const submitted = vi.fn()
    const actor = userEvent.setup()
    renderWithProviders(<NewChallenge type="js" onSubmit={submitted} />)
    await actor.click(await screen.findByRole('switch'))
    await actor.click(screen.getByRole('button', { name: 'submit' }))
    await waitFor(() => expect(submitted).toHaveBeenCalledTimes(1))
    expect(challengeOf(submitted)).not.toHaveProperty('ban_seconds')
  })
})

describe('publish refused by an unfinished release', () => {
  afterEach(() => vi.restoreAllMocks())

  it('explains publication_state_conflict in the feedback dialog', async () => {
    await i18n.changeLanguage('zh-CN')
    const user = principal({ permissions: ['security_policies.read', 'security_policies.manage'] })
    useSessionStore.getState().setSession(authResponse(user), user)
    const siteID = '33333333-3333-4333-8333-333333333333'
    const policy = { id: '44444444-4444-4444-8444-444444444444', kind: 'cc', name: '超限转挑战', enabled: true, version: 1, rules: [] } as unknown as SecurityPolicy
    vi.spyOn(securityPoliciesApi, 'getActivationStatus').mockResolvedValue({ binding: null, latest_candidate: null, operation: null })
    const publish = vi.spyOn(securityPoliciesApi, 'publishActivation')
      .mockRejectedValue(new ApiError('the publication state does not allow this operation', 409, 'publication_state_conflict'))
    renderWithProviders(<SecurityActivationPanel kind="cc" policies={[policy]} policiesLoading={false} autoPublish={{ id: policy.id, version: 1 }} />,
      [`/site/cc-rule?site_id=${siteID}`])
    await waitFor(() => expect(publish).toHaveBeenCalledTimes(1))
    expect(await screen.findByRole('dialog', { name: '发布操作失败' })).toBeInTheDocument()
    expect(screen.getByText(/本站点还有安全策略下发未完成.*请稍后点「重新加载状态」/)).toBeInTheDocument()
    expect(screen.queryByText(/请求失败，请稍后重试/)).not.toBeInTheDocument()
  })
})
