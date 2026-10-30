import { Form } from 'antd'
import { fireEvent, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { ApiError, responseApiError } from '../api/auth'
import { securityPoliciesApi, type SecurityActivationStatus, type SecurityPolicy, type SecurityPolicyRule } from '../api/securityPolicies'
import type { SystemRule } from '../api/securitySystemRules'
import { useSessionStore } from '../auth/session'
import i18n from '../i18n'
import { countByMessages } from '../i18n/securityPoliciesCountBy'
import {
  countByFromForm, countByPreview, countByProblem, countByToForm, reorderedPriorities,
} from '../pages/security/countBy'
import { CountByFields } from '../pages/security/CountByFields'
import { CatalogImport } from '../pages/security/ManagedRuleFields'
import SecurityActivationPanel from '../pages/security/SecurityActivationPanel'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const banRule = (count_by?: SecurityPolicyRule['count_by']): SecurityPolicyRule => ({
  name: 'r', priority: 1, enabled: true, action: 'rate_limit', flow: 'stop',
  conditions: [{ field: 'path', operator: 'prefix', values: ['/'] }],
  action_config: { rate_limit: { algorithm: 'fixed_window', window_seconds: 10, max_requests: 30, response_action: 'temporary_ban', ban_seconds: 60 } },
  count_by,
})

describe('CC count_by (统计对象) helpers', () => {
  it('normalizes to the stored form', () => {
    expect(countByFromForm(['client_ip'], {})).toBeUndefined()
    expect(countByFromForm([], {})).toBeUndefined()
    expect(countByFromForm(['uri', 'client_cidr'], {})).toEqual([{ key: 'client_cidr', ipv4_prefix: 24, ipv6_prefix: 64 }, { key: 'uri' }])
    expect(countByFromForm(['client_cidr'], { ipv4_prefix: 16, ipv6_prefix: 48 })).toEqual([{ key: 'client_cidr', ipv4_prefix: 16, ipv6_prefix: 48 }])
    expect(countByFromForm(['ja4', 'host'], {})).toEqual([{ key: 'host' }, { key: 'ja4' }])
  })

  it('reports the combinations the server refuses', () => {
    expect(countByProblem(banRule([{ key: 'client_ip' }, { key: 'client_cidr', ipv4_prefix: 24, ipv6_prefix: 64 }]))).toBe('ipAndCidr')
    expect(countByProblem(banRule([{ key: 'uri' }, { key: 'uri_path' }]))).toBe('uriAndPath')
    expect(countByProblem(banRule([{ key: 'host' }, { key: 'uri' }, { key: 'ja4' }]))).toBe('tooMany')
    const stats = banRule([{ key: 'host' }])
    stats.conditions.push({ field: 'distinct_user_agents', operator: 'number_gte', values: ['3'] })
    expect(countByProblem(stats)).toBe('statistics')
    const challenge: SecurityPolicyRule = { ...banRule([{ key: 'host' }]), action: 'challenge', action_config: { challenge: { type: 'js' } } }
    expect(countByProblem(challenge)).toBe('challengeTrigger')
    challenge.action_config.challenge = { type: 'js', trigger_window_seconds: 10, trigger_max_requests: 30 }
    expect(countByProblem(challenge)).toBeUndefined()
    expect(countByProblem({ ...challenge, action_target: 'count_key' })).toBe('target')
    const reject = banRule([{ key: 'ja4' }])
    reject.action_config.rate_limit!.response_action = 'reject_429'
    expect(countByProblem({ ...reject, action_target: 'count_key' })).toBe('target')
    expect(countByProblem({ ...banRule([{ key: 'ja4' }]), action_target: 'count_key' })).toBeUndefined()
  })

  it('previews the rule', async () => {
    await i18n.changeLanguage('zh-CN')
    const t = i18n.getFixedT('zh-CN', 'securityPolicies')
    expect(countByPreview(t, banRule([{ key: 'client_cidr', ipv4_prefix: 24, ipv6_prefix: 64 }, { key: 'uri' }])))
      .toBe('同一 /24 网段（IPv6 /64） + 同一 URI，10 秒超过 30 次 → 封禁 60 秒')
    expect(countByPreview(t, { ...banRule([{ key: 'ja4' }]), action_target: 'count_key' }))
      .toBe('同一 TLS 指纹（JA4），10 秒超过 30 次 → 封禁该统计对象 60 秒')
    expect(countByPreview(t, banRule())).toBe('同一 客户端 IP，10 秒超过 30 次 → 封禁 60 秒')
    // final-fix-d: 超限才挑战 names the challenge type; no trigger means no preview.
    const challenge: SecurityPolicyRule = { ...banRule(), action: 'challenge', action_config: { challenge: { type: 'js', trigger_window_seconds: 10, trigger_max_requests: 20 } } }
    expect(countByPreview(t, challenge)).toBe('同一 客户端 IP，10 秒超过 20 次 → JS 挑战')
    expect(countByPreview(t, { ...challenge, action_config: { challenge: { type: 'js' } } })).toBeUndefined()
  })

  it('renumbers priority strictly increasing in the new order (FX26)', () => {
    expect(reorderedPriorities([10, 20, 30], 2, 0)).toEqual([[2, 10], [0, 20], [1, 30]])
    // Equal priorities would run in rule ID order on the node: renumber.
    expect(reorderedPriorities([5, 5, 7], 0, 2)).toEqual([[1, 10], [2, 20], [0, 30]])
    expect(reorderedPriorities([10, 20], 0, 0)).toEqual([[0, 10], [1, 20]])
  })

  it('registers the same keys in every locale', () => {
    const keys = (value: object): string[] => JSON.stringify(value, (_, v) => (typeof v === 'string' ? '' : v)).split('').sort()
    for (const locale of ['en-US', 'qps-ploc', 'qps-Ploc'] as const) {
      expect(keys(countByMessages[locale])).toEqual(keys(countByMessages['zh-CN']))
    }
  })
})

function CountByForm({ rule, onSubmit }: { rule: SecurityPolicyRule; onSubmit: (value: unknown) => void }) {
  const [form] = Form.useForm()
  return (
    <Form form={form} initialValues={{ rules: [rule] }} onFinish={onSubmit}>
      <Form.List name="rules">{() => <CountByFields ruleName={0} form={form} />}</Form.List>
      <button type="submit">submit</button>
    </Form>
  )
}

describe('CC count_by editor', () => {
  it('chooses network + URI, offers banning the bucket only for a temporary ban, and submits the stored form', async () => {
    await i18n.changeLanguage('zh-CN')
    const submitted = vi.fn()
    const actor = userEvent.setup()
    renderWithProviders(<CountByForm rule={banRule()} onSubmit={submitted} />)
    expect(screen.queryByRole('checkbox', { name: '封禁整个统计对象' })).toBeNull()
    const select = screen.getByRole('combobox', { name: '统计对象' })
    await actor.click(select)
    await actor.click(await screen.findByTitle('客户端网段'))
    await actor.click(await screen.findByTitle('URI（含参数）'))
    expect(await screen.findByLabelText('IPv4 前缀')).toHaveValue('24')
    expect(screen.getByText('同一 /24 网段（IPv6 /64） + 同一 URI，10 秒超过 30 次 → 封禁 60 秒')).toBeInTheDocument()
    await actor.click(screen.getByRole('checkbox', { name: '封禁整个统计对象' }))
    await actor.click(screen.getByRole('button', { name: 'submit' }))
    await waitFor(() => expect(submitted).toHaveBeenCalled())
    const values = submitted.mock.calls[0][0].rules[0]
    expect(countByFromForm(values.count_keys, values.count_prefix)).toEqual([{ key: 'client_cidr', ipv4_prefix: 24, ipv6_prefix: 64 }, { key: 'uri' }])
    expect(values.action_target).toBe('count_key')
  })

  it('explains ja4 and refuses more than two keys', async () => {
    await i18n.changeLanguage('zh-CN')
    const submitted = vi.fn()
    const actor = userEvent.setup()
    renderWithProviders(<CountByForm rule={banRule()} onSubmit={submitted} />)
    await actor.click(screen.getByRole('combobox', { name: '统计对象' }))
    await actor.click(await screen.findByTitle('TLS 指纹（JA4）'))
    expect(await screen.findByText(/没有 TLS 指纹的请求（明文 HTTP、HTTP\/3）不计入/)).toBeInTheDocument()
    await actor.click(screen.getByRole('combobox', { name: '统计对象' }))
    await actor.click(await screen.findByTitle('域名（Host）'))
    await actor.click(await screen.findByTitle('URI（不含参数）'))
    await actor.click(screen.getByRole('button', { name: 'submit' }))
    expect(await screen.findByText('最多选 2 个统计对象')).toBeInTheDocument()
    expect(submitted).not.toHaveBeenCalled()
  })
})

describe('CC v7 统计对象 (fix-ja4rule ③)', () => {
  it('normalizes the named keys and refuses a missing or duplicate name', () => {
    expect(countByFromForm(['ja4', 'header'], {}, { header: 'X-Api-Key' })).toEqual([{ key: 'ja4' }, { key: 'header', name: 'x-api-key' }])
    expect(countByFromForm(['query', 'cookie'], {}, { cookie: 'sid', query: 'token' })).toEqual([{ key: 'cookie', name: 'sid' }, { key: 'query', name: 'token' }])
    expect(countByFromForm(['user_agent'], {})).toEqual([{ key: 'user_agent' }])
    expect(countByToForm([{ key: 'header', name: 'x-api-key' }]).count_names).toEqual({ header: 'x-api-key' })
  })

  it('offers User-Agent, Referer and a named header with a name input and previews it', async () => {
    await i18n.changeLanguage('zh-CN')
    const submitted = vi.fn()
    const actor = userEvent.setup()
    renderWithProviders(<CountByForm rule={banRule()} onSubmit={submitted} />)
    await actor.click(screen.getByRole('combobox', { name: '统计对象' }))
    for (const title of ['浏览器 UA（User-Agent）', '请求来源（Referer）', 'Cookie', '查询参数']) {
      expect(await screen.findByTitle(title)).toBeInTheDocument()
    }
    await actor.click(await screen.findByTitle('指定请求头'))
    await actor.type(await screen.findByLabelText('请求头名称'), 'X-Api-Key')
    expect(await screen.findByText(/同一 请求头 x-api-key，10 秒超过 30 次/)).toBeInTheDocument()
    expect(screen.getByText(/需要节点支持 CC v7/)).toBeInTheDocument()
    await actor.click(screen.getByRole('button', { name: 'submit' }))
    await waitFor(() => expect(submitted).toHaveBeenCalled())
    const values = submitted.mock.calls[0][0].rules[0]
    expect(countByFromForm(values.count_keys, values.count_prefix, values.count_names)).toEqual([{ key: 'header', name: 'x-api-key' }])
  })
})

describe('importing several CC system rule groups (#16)', () => {
  afterEach(() => vi.restoreAllMocks())

  it('imports groups in the chosen order and reports duplicates and conflicts', async () => {
    await i18n.changeLanguage('zh-CN')
    const group = (key: string, name: string) => ({ system_key: key, kind: 'cc_rule_group', name, status: 'active', selectable: true, body: {} }) as unknown as SystemRule
    const onImport = vi.fn().mockResolvedValue({ rules: [], duplicates: [{ group_key: 'cc_rule:6', rule: 'b', same_as: 'cc_rule:1' }],
      conflicts: [{ group_key: 'cc_rule:6', rule: '宽松 · 频率', with: 'cc_rule:1' }] })
    const actor = userEvent.setup()
    renderWithProviders(<CatalogImport kind="cc" catalog={[group('cc_rule:1', '严格'), group('cc_rule:6', '宽松')]} onImport={onImport} />)
    await actor.click(screen.getByRole('combobox', { name: '选择要导入的系统规则' }))
    await actor.click(await screen.findByTitle('严格'))
    await actor.click(await screen.findByTitle('宽松'))
    await actor.click(screen.getByRole('button', { name: '从系统规则导入' }))
    await waitFor(() => expect(onImport).toHaveBeenCalledWith(['cc_rule:1', 'cc_rule:6']))
    expect(await screen.findByText('已去重 1 条与先选规则库相同的规则')).toBeInTheDocument()
    expect(screen.getByText(/与先选规则库匹配条件相同但动作不同，先选的规则库优先：宽松 · 频率/)).toBeInTheDocument()
  })
})

describe('finding a WAF rule set in the import dropdown (final-fix-a, live-waf P12)', () => {
  afterEach(() => vi.restoreAllMocks())

  it('finds SQL注入 by its name with or without spaces, and by its key', async () => {
    await i18n.changeLanguage('zh-CN')
    const set = (key: string, name: string) => ({ system_key: key, kind: 'waf_rule_set', name, status: 'active', selectable: true,
      body: { waf_rule_set: { rules: [{ id: 'r', name: 'r', enabled: true, action: 'log', matcher_groups: [] }] } } }) as unknown as SystemRule
    const catalog = [set('waf_set:sqli', 'SQL注入'), set('waf_set:xss', 'XSS'), set('waf_set:file_include', '文件包含')]
    renderWithProviders(<CatalogImport kind="waf" catalog={catalog} onImport={vi.fn().mockResolvedValue({ rules: [] })} />)
    const select = screen.getByRole('combobox', { name: '选择要导入的系统规则' })
    fireEvent.mouseDown(select)
    for (const query of ['SQL注入', 'sql 注入', 'sqli']) {
      fireEvent.change(select, { target: { value: query } })
      expect(await screen.findByTitle('SQL注入')).toBeInTheDocument()
      await waitFor(() => expect(screen.queryByTitle('XSS')).not.toBeInTheDocument())
    }
  })
})

describe('responseApiError for a capability refusal', () => {
  const node = '22222222-2222-4222-8222-222222222222'
  const json = (body: unknown, status = 422) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

  it('keeps the verified structured refusal and no raw server text', async () => {
    const error = await responseApiError(json({ error: { code: 'node_capability_unavailable', message: 'raw-server-detail',
      request_id: 'req-1', capability: { node_id: node, capability: 'CAPABILITY_NAME_CC', required_version: 4, other_node_ids: [] } } }))
    expect(error).toMatchObject({ status: 422, code: 'node_capability_unavailable', requestId: 'req-1',
      capability: { node_id: node, capability: 'CAPABILITY_NAME_CC', required_version: 4, other_node_ids: [] } })
    expect(JSON.stringify(error)).not.toContain('raw-server-detail')
    expect(error.message).not.toContain('raw-server-detail')
  })

  it.each([
    ['other code', json({ error: { code: 'publication_not_ready', capability: { node_id: node, capability: 'CAPABILITY_NAME_CC', required_version: 4, other_node_ids: [] } } })],
    ['bad capability name', json({ error: { code: 'node_capability_unavailable', capability: { node_id: node, capability: '<b>', required_version: 4, other_node_ids: [] } } })],
    ['bad version', json({ error: { code: 'node_capability_unavailable', capability: { node_id: node, capability: 'CAPABILITY_NAME_CC', required_version: -1, other_node_ids: [] } } })],
  ])('drops a capability it cannot verify: %s', async (_name, response) => {
    expect(await responseApiError(response)).not.toHaveProperty('capability')
  })

  it.each([
    ['non-JSON', new Response('<html>bad gateway</html>', { status: 502 })],
    ['empty', new Response(null, { status: 503 })],
    ['JSON null', json(null, 500)],
  ])('falls back to request_failed for a %s body', async (_name, response) => {
    const error = await responseApiError(response)
    expect(error).toMatchObject({ code: 'request_failed', status: response.status })
    expect(error).not.toHaveProperty('capability')
  })
})

describe('publishing a count_by rule set to old nodes', () => {
  const siteID = '11111111-1111-4111-8111-111111111111'
  const oldNode = '22222222-2222-4222-8222-222222222222'
  const otherNode = '55555555-5555-4555-8555-555555555555'
  const policy = { id: '33333333-3333-4333-8333-333333333333', scope_id: '44444444-4444-4444-8444-444444444444', kind: 'cc',
    name: 'cidr', description: '', enabled: true, default_action: 'allow', version: 2, created_at: '', updated_at: '',
    rules: [] } as unknown as SecurityPolicy

  afterEach(() => vi.restoreAllMocks())

  it('says the release waits for the upgrade and shows the waiting release', async () => {
    await i18n.changeLanguage('zh-CN')
    const user = principal({ permissions: ['security_policies.read', 'security_policies.manage'] })
    useSessionStore.getState().setSession(authResponse(user), user)
    const waiting = { binding: null, latest_candidate: null, operation: null,
      capability_wait: { node_ids: [oldNode, otherNode], required_cc_version: 4, policy_version: 2, created_at: '2026-10-17T00:00:00Z' } } as unknown as SecurityActivationStatus
    vi.spyOn(securityPoliciesApi, 'getActivationStatus').mockResolvedValue(waiting)
    vi.spyOn(securityPoliciesApi, 'publishActivation').mockRejectedValueOnce(new ApiError(
      `node ${oldNode} (agent 1.0.34) does not support CC rules counting by network, host, URI or TLS fingerprint (统计对象); upgrade the node or count by client IP (CC_API v4 required, v3 declared); upgrade the node agent or remove the feature; also unsupported on nodes ${otherNode}; the release is recorded and is published automatically once the nodes are upgraded`,
      422, 'node_capability_unavailable'))
    const actor = userEvent.setup()
    renderWithProviders(<SecurityActivationPanel kind="cc" policies={[policy]} policiesLoading={false} />, [`/site/cc-rule?site_id=${siteID}`])
    expect(await screen.findByText(`等待节点升级后自动发布（策略版本 v2，节点：${oldNode}、${otherNode}）`)).toBeInTheDocument()
    // 目标节点由控制面按站点套餐线路组选择、过期时间自动生成，面板不再有这两个输入
    await actor.click(screen.getByRole('button', { name: /发布/ }))
    expect(await screen.findByText(/部分节点版本过低，不支持按网段\/域名\/URI\/TLS 指纹计数。已记录本次发布，节点升级后会自动发布/)).toBeInTheDocument()
    expect(screen.getByText(`需要升级的节点：${oldNode}、${otherNode}`, { exact: false })).toBeInTheDocument()
    fireEvent.blur(document.body)
  })

  // The body control-api writes (edgepublishhttp writeError): the client
  // drops the raw message, so the nodes come from error.capability.
  const refusalBody = (capability: unknown) => new Response(JSON.stringify({ error: {
    code: 'node_capability_unavailable',
    message: `node ${oldNode} (agent 1.0.35) does not support CC rules counting by network, host, URI or TLS fingerprint (统计对象); also unsupported on nodes ${otherNode}`,
    request_id: '66666666-6666-4666-8666-666666666666', capability,
  } }), { status: 422, headers: { 'Content-Type': 'application/json' } })

  it('lists the refused nodes from the real error body', async () => {
    await i18n.changeLanguage('zh-CN')
    const user = principal({ permissions: ['security_policies.read', 'security_policies.manage'] })
    useSessionStore.getState().setSession(authResponse(user), user)
    vi.spyOn(securityPoliciesApi, 'getActivationStatus').mockResolvedValue({ binding: null, latest_candidate: null } as unknown as SecurityActivationStatus)
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(refusalBody({
      node_id: oldNode, capability: 'CAPABILITY_NAME_CC', required_version: 4, other_node_ids: [otherNode, oldNode],
    }))
    const actor = userEvent.setup()
    renderWithProviders(<SecurityActivationPanel kind="cc" policies={[policy]} policiesLoading={false} />, [`/site/cc-rule?site_id=${siteID}`])
    // 目标节点由控制面按站点套餐线路组选择、过期时间自动生成，面板不再有这两个输入
    await actor.click(await screen.findByRole('button', { name: /发布/ }))
    expect(await screen.findByText(`需要升级的节点：${oldNode}、${otherNode}`, { exact: false })).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('does not support')
    fireEvent.blur(document.body)
  })

  // A valid refusal of another capability lists its nodes (ChallengeBaseline.test.tsx).
  it.each([
    [{ node_id: 'raw-secret', capability: 'CAPABILITY_NAME_CC', required_version: 4, other_node_ids: [] }],
    [{ node_id: oldNode, capability: 'CAPABILITY_NAME_CC', required_version: 4, other_node_ids: ['raw-secret'] }],
    [undefined],
  ])('falls back to the generic hint without nodes for an unusable refusal: %j', async (capability) => {
    await i18n.changeLanguage('zh-CN')
    const user = principal({ permissions: ['security_policies.read', 'security_policies.manage'] })
    useSessionStore.getState().setSession(authResponse(user), user)
    vi.spyOn(securityPoliciesApi, 'getActivationStatus').mockResolvedValue({ binding: null, latest_candidate: null } as unknown as SecurityActivationStatus)
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(refusalBody(capability))
    const actor = userEvent.setup()
    renderWithProviders(<SecurityActivationPanel kind="cc" policies={[policy]} policiesLoading={false} />, [`/site/cc-rule?site_id=${siteID}`])
    // 目标节点由控制面按站点套餐线路组选择、过期时间自动生成，面板不再有这两个输入
    await actor.click(await screen.findByRole('button', { name: /发布/ }))
    expect(await screen.findByText(/目标节点版本不支持这个规则集用到的功能/)).toBeInTheDocument()
    expect(screen.queryByText(/需要升级的节点/)).not.toBeInTheDocument()
    expect(document.body.textContent).not.toContain('raw-secret')
    fireEvent.blur(document.body)
  })
})
