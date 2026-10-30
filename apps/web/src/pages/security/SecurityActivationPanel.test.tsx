import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useLocation } from 'react-router-dom'
import { vi } from 'vitest'

import { ApiError } from '../../api/auth'
import {
  securityPoliciesApi,
  type SecurityActivationStatus,
  type SecurityPolicy,
} from '../../api/securityPolicies'
import { useSessionStore } from '../../auth/session'
import { authResponse, principal } from '../../test/fixtures'
import { renderWithProviders } from '../../test/render'
import SecurityActivationPanel from './SecurityActivationPanel'

// OutcomeUnknown 的标题同时出现在恢复条和说明弹窗里，这里只认原位的恢复条。
const OUTCOME_BAR = { selector: '.cdnca-outcome-bar .ant-alert-message' }

const siteID = '33333333-3333-4333-8333-333333333333'
const policyID = '44444444-4444-4444-8444-444444444444'
const nodeID = '55555555-5555-4555-8555-555555555555'
const candidateID = '66666666-6666-4666-8666-666666666666'

const policy: SecurityPolicy = {
  id: policyID,
  scope_id: '22222222-2222-4222-8222-222222222222',
  kind: 'cc',
  name: '登录保护',
  description: '',
  enabled: true,
  default_action: 'allow',
  version: 3,
  created_at: '2026-08-04T08:00:00Z',
  updated_at: '2026-08-04T09:00:00Z',
  rules: [],
}

const candidate = {
  id: candidateID,
  tenant_scope_id: '22222222-2222-4222-8222-222222222222',
  site_id: siteID,
  binding_id: '77777777-7777-4777-8777-777777777777',
  binding_revision: 4,
  last_bundle_id: '88888888-8888-4888-8888-888888888888',
  last_claimed_policy_version: 3,
  expected_active_policy_version: 2,
  candidate_source_revision: 5,
  candidate_config_version_id: '99999999-9999-4999-8999-999999999999',
  candidate_artifact_sha256: Array.from({ length: 32 }, (_, index) => index + 1),
  target_snapshot_sha256: Array.from({ length: 32 }, (_, index) => 32 - index),
  required_capabilities: [{ name: 1, api_version: 1 }],
  candidate_status: 'promoted' as const,
  canary_node_ids: [nodeID],
  expand_node_ids: [],
  expires_at: '2026-08-04T12:00:00Z',
  created_at: '2026-08-04T09:00:00Z',
  updated_at: '2026-08-04T09:05:00Z',
}

const activeStatus: SecurityActivationStatus = {
  binding: {
    id: candidate.binding_id,
    policy_id: policyID,
    binding_revision: 5,
    active_policy_version: 3,
    last_claimed_policy_version: 3,
  },
  latest_candidate: candidate,
  operation: 'activation',
}

function authenticate(permissions = ['security_policies.read', 'security_policies.manage']) {
  const user = principal({ permissions })
  useSessionStore.getState().setSession(authResponse(user), user)
}

function LocationProbe() {
  return <output data-testid="location-search">{useLocation().search}</output>
}

describe('SecurityActivationPanel', () => {
  it.each([
    [{ binding: null, latest_candidate: null, operation: null }, '待发布'],
    [{ ...activeStatus, latest_candidate: { ...candidate, candidate_status: 'canary' } }, '灰度中'],
    [{ ...activeStatus, latest_candidate: { ...candidate, candidate_status: 'expanding' } }, '扩展中'],
    [activeStatus, '已生效'],
    [{ ...activeStatus, operation: 'rollback', latest_candidate: { ...candidate, candidate_status: 'canary' } }, '回滚中'],
    [{ ...activeStatus, operation: 'rollback' }, '已回滚'],
    [{ ...activeStatus, latest_candidate: { ...candidate, candidate_status: 'failed' } }, '失败'],
  ] as Array<[SecurityActivationStatus, string]>)('renders the %s activation state', async (status, expected) => {
    authenticate()
    vi.spyOn(securityPoliciesApi, 'getActivationStatus').mockResolvedValue(status)
    renderWithProviders(
      <SecurityActivationPanel kind="cc" policies={[policy]} policiesLoading={false} />,
      [`/site/cc-rule?site_id=${siteID}`],
    )
    expect(await screen.findByText(expected)).toBeInTheDocument()
  })

  it('P11: shows the reason each node reported for a failed candidate', async () => {
    authenticate()
    vi.spyOn(securityPoliciesApi, 'getActivationStatus').mockResolvedValue({
      ...activeStatus,
      latest_candidate: { ...candidate, candidate_status: 'failed' },
      failure_reasons: [{ node_id: nodeID, node_name: 'edge-hk-1', node_ip: '203.0.113.7', phase: 'canary', reason: 'waf_engine_unavailable', message: 'managed WAF unavailable: no waf engine module is installed' }],
    })
    renderWithProviders(
      <SecurityActivationPanel kind="waf" policies={[policy]} policiesLoading={false} />,
      [`/site/waf-rule?site_id=${siteID}`],
    )
    expect(await screen.findByText('发布失败，节点回报的原因')).toBeInTheDocument()
    // sec-ui-polish: the node by name and IP, full ID as title and copyable.
    const node = screen.getByText('edge-hk-1（203.0.113.7）')
    expect(node).toHaveAttribute('title', nodeID)
    expect(screen.getByRole('button', { name: '复制完整节点 ID' })).toBeInTheDocument()
    expect(screen.queryByText(new RegExp(nodeID))).not.toBeInTheDocument()
    expect(screen.getByText(/：managed WAF unavailable/)).toBeInTheDocument()
    expect(screen.getByText(/节点未安装托管 WAF（OWASP CRS）引擎模块/)).toBeInTheDocument()
  })

  it('sec-ui-polish P11: short ID without a name or IP; the WAF hint follows the reason code, not the text', async () => {
    authenticate()
    vi.spyOn(securityPoliciesApi, 'getActivationStatus').mockResolvedValue({
      ...activeStatus,
      latest_candidate: { ...candidate, candidate_status: 'failed' },
      failure_reasons: [
        { node_id: nodeID, node_name: '', node_ip: '', phase: 'canary', message: 'managed WAF unavailable: reworded by the node' },
      ],
    })
    renderWithProviders(
      <SecurityActivationPanel kind="waf" policies={[policy]} policiesLoading={false} />,
      [`/site/waf-rule?site_id=${siteID}`],
    )
    expect(await screen.findByText(`${nodeID.slice(0, 8)}…`)).toHaveAttribute('title', nodeID)
    expect(screen.queryByText(/节点未安装托管 WAF（OWASP CRS）引擎模块/)).not.toBeInTheDocument()
  })

  it('site-parity3b: a platform administrator reads and publishes the site activation, no tenant switch', async () => {
    const admin = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['platform.admin'] })
    useSessionStore.getState().setSession(authResponse(admin), admin)
    const status = vi.spyOn(securityPoliciesApi, 'getActivationStatus').mockResolvedValue(activeStatus)
    renderWithProviders(
      <SecurityActivationPanel kind="waf" policies={[policy]} policiesLoading={false} />,
      [`/site/waf-rule?site_id=${siteID}`],
    )
    await waitFor(() => expect(status).toHaveBeenCalledWith(expect.any(String), siteID, 'waf', expect.anything()))
    expect(screen.queryByText('安全规则发布由租户操作')).not.toBeInTheDocument()
    expect(screen.queryByText('无权管理安全规则发布')).not.toBeInTheDocument()
    expect(await screen.findByRole('button', { name: '重新加载状态' })).toBeEnabled()
  })

  it('persists the site in the URL and publishes the selected listed policy with binding CAS', async () => {
    authenticate()
    vi.spyOn(securityPoliciesApi, 'getActivationStatus').mockResolvedValue(activeStatus)
    const publish = vi.spyOn(securityPoliciesApi, 'publishActivation').mockResolvedValue({ candidate })
    const user = userEvent.setup()

    renderWithProviders(<>
      <SecurityActivationPanel kind="cc" policies={[policy]} policiesLoading={false} />
      <LocationProbe />
    </>, ['/site/cc-rule'])

    await user.type(screen.getByLabelText('站点 ID'), siteID)
    await user.click(screen.getByRole('button', { name: '应用站点' }))
    expect(screen.getByTestId('location-search')).toHaveTextContent(`site_id=${siteID}`)
    expect(await screen.findByText('已生效')).toBeInTheDocument()
    await user.click(screen.getByRole('combobox', { name: '待发布规则集' }))
    await user.click(await screen.findByRole('option', { name: '登录保护 (v3)' }))
    await user.click(screen.getByRole('button', { name: '发布' }))

    await waitFor(() => expect(publish).toHaveBeenCalledTimes(1))
    expect(publish.mock.calls[0][1]).toEqual({
      site_id: siteID,
      policy_id: policyID,
      policy_version: 3,
      expected_binding_revision: 5,
      expected_active_policy_version: 3,
      // 10-22 自动下发: the control plane picks the site's package line-group nodes.
      target_node_ids: [],
      canary_size: 0,
      expires_at: expect.any(String),
    })
    const expires = Date.parse(publish.mock.calls[0][1].expires_at)
    expect(expires - Date.now()).toBeGreaterThan(5 * 60 * 1000)
    expect(expires - Date.now()).toBeLessThanOrEqual(15 * 60 * 1000)
    expect(screen.queryByLabelText('目标节点 ID')).not.toBeInTheDocument()
    expect(screen.queryByLabelText('灰度节点数')).not.toBeInTheDocument()
    expect(screen.queryByLabelText('候选过期时间')).not.toBeInTheDocument()
    expect(publish.mock.calls[0][2].traceparent).toMatch(/^00-[0-9a-f]{32}-[0-9a-f]{16}-01$/)
  })

  it('reconciles from the latest immutable candidate and rolls back from its prior active version', async () => {
    authenticate()
    vi.spyOn(securityPoliciesApi, 'getActivationStatus').mockResolvedValue({
      ...activeStatus,
      rollback: { available: true, candidate_id: candidateID, policy_id: policyID, source_policy_version: 2 },
    })
    const reconcile = vi.spyOn(securityPoliciesApi, 'reconcileActivation').mockResolvedValue({ candidate, action: 'wait' })
    const rollback = vi.spyOn(securityPoliciesApi, 'rollbackActivation').mockResolvedValue({ candidate })
    const user = userEvent.setup()
    renderWithProviders(
      <SecurityActivationPanel kind="cc" policies={[policy]} policiesLoading={false} />,
      [`/site/cc-rule?site_id=${siteID}`],
    )

    expect(await screen.findByText('已生效')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '对账并推进' }))
    await waitFor(() => expect(reconcile).toHaveBeenCalledWith(
      expect.any(String), candidateID, { promotion_cas: expect.objectContaining({
        binding_revision: 4,
        candidate_source_revision: 5,
        candidate_config_version_id: candidate.candidate_config_version_id,
      }) }, expect.objectContaining({ traceparent: expect.any(String) }),
    ))
    await user.click(screen.getByRole('button', { name: '回滚' }))
    await waitFor(() => expect(rollback).toHaveBeenCalledWith(
      expect.any(String), candidateID, expect.objectContaining({
        source_policy_version: 2,
        expected_binding_revision: 5,
        expected_active_policy_version: 3,
        target_node_ids: [],
      }), expect.objectContaining({ traceparent: expect.any(String) }),
    ))
  })

  it('locks an unknown write result until status reload confirms persisted facts', async () => {
    authenticate()
    const status = vi.spyOn(securityPoliciesApi, 'getActivationStatus')
      .mockResolvedValueOnce({ binding: null, latest_candidate: null, operation: null })
      .mockResolvedValueOnce(activeStatus)
    vi.spyOn(securityPoliciesApi, 'publishActivation').mockRejectedValue(
      new ApiError('private upstream', 503, 'request_failed'),
    )
    const user = userEvent.setup()
    renderWithProviders(
      <SecurityActivationPanel kind="cc" policies={[policy]} policiesLoading={false} />,
      [`/site/cc-rule?site_id=${siteID}`],
    )

    expect(await screen.findByText('待发布')).toBeInTheDocument()
    await user.click(screen.getByRole('combobox', { name: '待发布规则集' }))
    await user.click(await screen.findByRole('option', { name: '登录保护 (v3)' }))
    await user.click(screen.getByRole('button', { name: '发布' }))

    expect(await screen.findByText('发布结果待确认', OUTCOME_BAR)).toBeInTheDocument()
    expect(screen.queryByText('private upstream')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '发布' })).toBeDisabled()
    await user.click(screen.getByRole('button', { name: '重新加载状态' }))
    await waitFor(() => expect(status).toHaveBeenCalledTimes(2))
    expect(await screen.findByText('已生效')).toBeInTheDocument()
    expect(screen.queryByText('发布结果待确认')).not.toBeInTheDocument()
  })

  it('shows localized loading and forbidden states without issuing unauthorized reads', async () => {
    authenticate(['security_policies.read'])
    const status = vi.spyOn(securityPoliciesApi, 'getActivationStatus')
    renderWithProviders(
      <SecurityActivationPanel kind="cc" policies={[policy]} policiesLoading={false} />,
      [`/site/cc-rule?site_id=${siteID}`],
    )

    expect(await screen.findByText('无权管理安全规则发布')).toBeInTheDocument()
    expect(status).not.toHaveBeenCalled()
  })
  it.each([
    ['package_feature_denied', 403, '当前套餐未开通该防护功能'],
    ['activation_expiry_too_late', 400, '最多为当前时间后 15 分钟'],
    ['no_target_nodes', 422, '线路组里没有可用节点'],
  ])('explains %s instead of the generic failure', async (code, status, text) => {
    authenticate()
    vi.spyOn(securityPoliciesApi, 'getActivationStatus').mockResolvedValue(activeStatus)
    vi.spyOn(securityPoliciesApi, 'publishActivation').mockRejectedValue(new ApiError('private', status, code))
    const user = userEvent.setup()
    renderWithProviders(
      <SecurityActivationPanel kind="waf" policies={[{ ...policy, kind: 'waf' }]} policiesLoading={false} />,
      [`/site/waf-rule?site_id=${siteID}`],
    )
    expect(await screen.findByText('已生效')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '发布' }))
    expect(await screen.findByText(new RegExp(text))).toBeInTheDocument()
    expect(screen.queryByText(/请求失败，请稍后重试/)).not.toBeInTheDocument()
  })

  it('publishes a library just saved for the site without any button', async () => {
    authenticate()
    vi.spyOn(securityPoliciesApi, 'getActivationStatus').mockResolvedValue({ binding: null, latest_candidate: null, operation: null })
    const publish = vi.spyOn(securityPoliciesApi, 'publishActivation').mockResolvedValue({ candidate })
    renderWithProviders(
      <SecurityActivationPanel kind="cc" policies={[policy]} policiesLoading={false} autoPublish={{ id: policyID, version: 3 }} />,
      [`/site/cc-rule?site_id=${siteID}`],
    )
    await waitFor(() => expect(publish).toHaveBeenCalledTimes(1))
    expect(publish.mock.calls[0][1]).toMatchObject({ policy_id: policyID, policy_version: 3, target_node_ids: [] })
  })
  // sec-rebind (live-waf CC 恢复段): another library over the active one,
  // withdrawing it (confirmed), and the rollback button's reason.
  const otherPolicyID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
  const otherPolicy: SecurityPolicy = { ...policy, id: otherPolicyID, name: '放行全部', version: 1 }

  // SEC-ACCOUNT-01: A@v3 active, saving B@v3 must still publish B; A@v3 again must not.
  it('SEC-ACCOUNT-01: auto-publishes another library with the same version number', async () => {
    authenticate()
    vi.spyOn(securityPoliciesApi, 'getActivationStatus').mockResolvedValue(activeStatus)
    const publish = vi.spyOn(securityPoliciesApi, 'publishActivation').mockResolvedValue({ candidate })
    renderWithProviders(
      <SecurityActivationPanel kind="cc" policies={[policy, { ...otherPolicy, version: 3 }]} policiesLoading={false}
        autoPublish={{ id: otherPolicyID, version: 3 }} />,
      [`/site/cc-rule?site_id=${siteID}`],
    )
    await waitFor(() => expect(publish).toHaveBeenCalledTimes(1))
    expect(publish.mock.calls[0][1]).toMatchObject({
      policy_id: otherPolicyID, policy_version: 3, expected_binding_revision: 5, expected_active_policy_version: 3,
    })
  })

  it('SEC-ACCOUNT-01: does not re-publish the library@version already active', async () => {
    authenticate()
    const status = vi.spyOn(securityPoliciesApi, 'getActivationStatus').mockResolvedValue(activeStatus)
    const publish = vi.spyOn(securityPoliciesApi, 'publishActivation').mockResolvedValue({ candidate })
    renderWithProviders(
      <SecurityActivationPanel kind="cc" policies={[policy]} policiesLoading={false} autoPublish={{ id: policyID, version: 3 }} />,
      [`/site/cc-rule?site_id=${siteID}`],
    )
    expect(await screen.findByText('登录保护 (v3)')).toBeInTheDocument()
    await waitFor(() => expect(status).toHaveBeenCalled())
    expect(publish).not.toHaveBeenCalled()
  })

  it('SEC-ACCOUNT-01: auto-publishes the same library at a newer version', async () => {
    authenticate()
    vi.spyOn(securityPoliciesApi, 'getActivationStatus').mockResolvedValue(activeStatus)
    const publish = vi.spyOn(securityPoliciesApi, 'publishActivation').mockResolvedValue({ candidate })
    renderWithProviders(
      <SecurityActivationPanel kind="cc" policies={[{ ...policy, version: 4 }]} policiesLoading={false}
        autoPublish={{ id: policyID, version: 4 }} />,
      [`/site/cc-rule?site_id=${siteID}`],
    )
    await waitFor(() => expect(publish).toHaveBeenCalledTimes(1))
    expect(publish.mock.calls[0][1]).toMatchObject({ policy_id: policyID, policy_version: 4 })
  })

  it('switches the site to another library through a normal publish', async () => {
    authenticate()
    vi.spyOn(securityPoliciesApi, 'getActivationStatus').mockResolvedValue(activeStatus)
    const publish = vi.spyOn(securityPoliciesApi, 'publishActivation').mockResolvedValue({ candidate })
    const user = userEvent.setup()
    renderWithProviders(
      <SecurityActivationPanel kind="cc" policies={[policy, otherPolicy]} policiesLoading={false} />,
      [`/site/cc-rule?site_id=${siteID}`],
    )
    expect(await screen.findByText('登录保护 (v3)')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '换用其他规则库' })).toBeDisabled()
    await user.click(screen.getByRole('combobox', { name: '待发布规则集' }))
    // role=option 是 antd 的无障碍占位，点它只对第一项生效；点可见选项。
    await user.click(await screen.findByText('放行全部 (v1)', { selector: '.ant-select-item-option-content' }))
    expect(screen.getByRole('button', { name: '发布' })).toBeDisabled()
    await user.click(screen.getByRole('button', { name: '换用其他规则库' }))
    await waitFor(() => expect(publish).toHaveBeenCalledTimes(1))
    expect(publish.mock.calls[0][1]).toEqual(expect.objectContaining({
      policy_id: otherPolicyID, policy_version: 1, expected_binding_revision: 5, expected_active_policy_version: 3,
    }))
    expect(publish.mock.calls[0][1].detach).toBeUndefined()
  })

  it('withdraws the active library only after confirmation', async () => {
    authenticate()
    vi.spyOn(securityPoliciesApi, 'getActivationStatus').mockResolvedValue(activeStatus)
    const publish = vi.spyOn(securityPoliciesApi, 'publishActivation').mockResolvedValue({ candidate })
    const user = userEvent.setup()
    renderWithProviders(
      <SecurityActivationPanel kind="cc" policies={[policy]} policiesLoading={false} />,
      [`/site/cc-rule?site_id=${siteID}`],
    )
    await user.click(await screen.findByRole('button', { name: '撤下' }))
    // CdncaProvider 下确认框标题同时在 .ant-modal-title 与 .ant-modal-confirm-title，只认后者。
    expect(await screen.findByText('撤下本站的CC规则？', { selector: '.ant-modal-confirm-title' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '取消' }))
    expect(publish).not.toHaveBeenCalled()
    await user.click(screen.getByRole('button', { name: '撤下' }))
    await user.click(await screen.findByRole('button', { name: '确认撤下' }))
    await waitFor(() => expect(publish).toHaveBeenCalledTimes(1))
    expect(publish.mock.calls[0][1]).toEqual(expect.objectContaining({
      policy_id: policyID, policy_version: 3, expected_binding_revision: 5, expected_active_policy_version: 3, detach: true,
    }))
  })

  it('names a deleted active library and explains why rollback is unavailable', async () => {
    authenticate()
    const deletedID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
    vi.spyOn(securityPoliciesApi, 'getActivationStatus').mockResolvedValue({
      ...activeStatus,
      binding: { ...activeStatus.binding!, policy_id: deletedID, active_policy_version: 1 },
      rollback: { available: false, reason: 'no_previous' },
    })
    renderWithProviders(
      <SecurityActivationPanel kind="cc" policies={[policy]} policiesLoading={false} />,
      [`/site/cc-rule?site_id=${siteID}`],
    )
    expect(await screen.findByText(`已删除的规则库（${deletedID}） (v1)`)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '回滚' })).toBeDisabled()
    expect(screen.getByText(/本次生效之前本站没有生效的规则/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '撤下' })).toBeEnabled()
  })

  it('shows a finished withdrawal as withdrawn', async () => {
    authenticate()
    vi.spyOn(securityPoliciesApi, 'getActivationStatus').mockResolvedValue({
      ...activeStatus,
      binding: { ...activeStatus.binding!, active_policy_version: 0 },
      latest_detach: true,
      rollback: { available: true, candidate_id: candidateID, policy_id: policyID, source_policy_version: 3 },
    })
    renderWithProviders(
      <SecurityActivationPanel kind="cc" policies={[policy]} policiesLoading={false} />,
      [`/site/cc-rule?site_id=${siteID}`],
    )
    expect(await screen.findByText('已撤下')).toBeInTheDocument()
    expect(screen.getByText('未生效')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '撤下' })).not.toBeInTheDocument()
    expect(screen.getByText('回滚到：登录保护 v3')).toBeInTheDocument()
  })
})
