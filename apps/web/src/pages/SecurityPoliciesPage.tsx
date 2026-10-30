import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  Button,
  Dropdown,
  Form,
  Input,
  InputNumber,
  Modal,
  Pagination,
  Popconfirm,
  Radio,
  Result,
  Select,
  Space,
  Switch,
  Table,
  Tag,
  Tabs,
  Tooltip,
  type FormInstance,
  type TableColumnsType,
} from 'antd'
import { AdvancedFilters, useFeedbackMessage, useFeedback, FeedbackWhen, OutcomeUnknown, submitErrorFields, useFormSubmitError, IdOrNameInput, useLiveApply } from '@cdnca/ui'
import { filterParam, useFilterUrl } from './filterUrl'
import { userSearch } from './idNameSources'
import { ArrowDown, ArrowUp, CheckCircle2, ChevronDown, FlaskConical, GripVertical, Pencil, Plus, RefreshCw, Trash2 } from 'lucide-react'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'

import { ApiError, type Principal } from '../api/auth'
import {
	SecurityPolicyImportApiError,
  isQuickBlockRuleID,
  parsePreviewHeaders,
  securityPoliciesApi,
  type RequestFacts,
  type SecurityPolicy,
  type SecurityPolicyAction,
  type SecurityPolicyCondition,
  type SecurityPolicyCountKeyName,
  type SecurityPolicyFields,
  type SecurityPolicyKind,
  type SecurityPolicyReference,
  type SecurityPolicyFilterFields,
  type SecurityPolicyMatcherFields,
  type SecurityPolicyRule,
  type SecurityPolicyWAFFilter,
  systemDefaultWAFKey,
} from '../api/securityPolicies'
import type { SecurityPolicyBatchAction, SecurityPolicyBatchResult, SecurityPolicyScope } from '../api/securityPolicies'
import { openrestySecurityApi, type OpenRestySecurityRuleGroup } from '../api/openrestySecurity'
import { roleForPrincipal, useSessionStore } from '../auth/session'
import { listSecurityIPLists, type SecurityIPListAudience } from '../api/securityIPLists'
import { formatDateTime } from '../i18n/formatters'
import { localizedUnknownApiError } from '../i18n/apiError'
import '../i18n/challengePolicies'
import '../i18n/securityPoliciesAcl'
import '../i18n/securityPoliciesReference'
import '../i18n/securityPoliciesSec05'
import '../i18n/securityPoliciesSec11'
import '../i18n/securityPoliciesCountBy'
import '../i18n/securityPoliciesQuickBlock'
import ChallengePoliciesPanel from './security/ChallengePoliciesPanel'
import SecurityActivationPanel from './security/SecurityActivationPanel'
import RebindStatusNotice from './security/RebindStatusNotice'
import { conditionValues } from './security/conditionValues'
import { conditionValuePlaceholder, groupedFieldOptions, invalidJA4Values, wafGeoFields, wafJA4Operators, wafSetFields, wafSetOperators } from './security/conditionFields'
import CCStatsPanel from './security/CCStatsPanel'
import { SystemRuleCatalogSection, useSystemRules } from './security/SystemRuleCatalogTable'
import { CatalogImport, ChallengeFields, ManagedWAFFields, managedWAFFromForm, managedWAFToForm } from './security/ManagedRuleFields'
import { CountByFields } from './security/CountByFields'
import { countByFromForm, countByToForm, reorderedPriorities, type CountNames, type CountPrefix } from './security/countBy'
import WAFPendingPublications from './security/WAFPendingPublications'
import { useWAFLibraries, WAFSubscriptionActions, WAFSubscriptionTag } from './security/WAFLibrarySection'
import type { WAFRuleLibrary } from '../api/wafRuleSubscriptions'
import WAFRuleSubscriptionsPanel from './security/WAFRuleSubscriptionsPanel'
import TenantScopeSelect from '../components/TenantScopeSelect'
import { themeColor } from '../theme/themeColor'
import './SecurityPoliciesPage.css'

interface ConditionForm extends Omit<SecurityPolicyCondition, 'values'> { values: string }
interface RuleForm extends Omit<SecurityPolicyRule, 'conditions' | 'count_by'> {
  conditions: ConditionForm[]
  // CC 统计对象 (countByFromForm makes count_by of them).
  count_keys?: SecurityPolicyCountKeyName[]
  count_prefix?: CountPrefix
  count_names?: CountNames
  // CC「全部客户端」: no condition to fill; submitted as path prefix "/" (the
  // backend needs at least one condition; same as catalogMatcherConditions).
  match_all?: boolean
}
interface PolicyForm extends Omit<SecurityPolicyFields, 'rules'> {
  // WAF: the auto block switch (waf_settings.auto_block is kept while off).
  waf_auto_block?: boolean
  target_scope_id?: string
  owner_id?: string
  rules: RuleForm[]
}

interface EvaluationForm extends Omit<RequestFacts, 'headers'> { headers: string }

type WriteAttempt =
  | { kind: 'create'; input: SecurityPolicyFields & { target_scope_id?: string; owner_id?: string }; key: string }
  | { kind: 'update'; id: string; version: number; input: SecurityPolicyFields; key: string }
  | { kind: 'delete'; id: string; version: number; key: string }

type CCReferenceView = 'groups' | 'matchers' | 'filters' | 'challenges' | 'stats'

function ccReferenceView(value: string | null): CCReferenceView {
  if (value === 'matcher' || value === 'matchers') return 'matchers'
  if (value === 'filter' || value === 'filters') return 'filters'
  if (value === 'challenge' || value === 'challenges') return 'challenges'
  if (value === 'stats') return 'stats'
  return 'groups'
}

// Request-content fields carry the self-developed detection (contains /
// regex / detect: sqli, xss) imported from the system rule catalog.
const wafContentFields = ['args', 'query', 'body', 'request_uri', 'cookie', 'user_agent', 'referer', 'upload_filename', 'upload_extension', 'header_names', 'content_type',
  // waf-php2shell (node WAF v5): multipart part names (PHP2Shell virtual patch).
  'multipart_field_names']
// Length / count fields take number_* operators (cdnca_waf number targets).
const wafNumberFields = ['request_length', 'body_length', 'uri_length', 'header_max_length', 'header_count', 'arg_count',
  'multipart_part_count', 'multipart_field_max_length']
// ge36-waf: http_version (equals / not_equals 1.0 1.1 2 3) and ip_list (a named IP list).
// ja4 (JA4 v1) and the IP intelligence fields (IP_INTEL v2) the node already runs.
const wafFields = ['client_ip', 'ip_list', 'path', 'method', 'header', 'port', 'http_version', ...wafContentFields, ...wafNumberFields, 'ja4', ...wafGeoFields]
// Mirrors securitypolicy wafContentOperators / wafLengthOperators / wafKeyedFields / wafBodyFields.
const wafLengthOperators = ['number_gt', 'number_gte', 'number_lt', 'number_lte', 'number_eq', 'number_neq']
const wafContentOperators = ['contains', 'not_contains', 'contains_all', 'regex', 'not_regex', 'detect', 'equals', 'not_equals', 'prefix', 'suffix', ...wafLengthOperators]
const wafKeyedFields = ['args', 'query', 'body', 'cookie']
const wafBodyFields = ['args', 'body', 'upload_filename', 'upload_extension', 'body_length', 'request_length',
  'multipart_field_names', 'multipart_part_count', 'multipart_field_max_length']
const wafFilterNames: SecurityPolicyWAFFilter[] = ['lowercase', 'base64_decode', 'unicode_decode', 'html_unescape', 'length']
const ccFields = ['client_ip', 'host', 'path', 'method', 'port']
// CC v6 rule conditions (NF32): header / User-Agent / Referer matches.
const ccHeaderFields = ['header', 'user_agent', 'referer']
const ccCountFields = ['distinct_user_agents', 'status_404_count']
// CC v7: JA4 equals / in.
const ccFingerprintFields = ['ja4']
const actions: SecurityPolicyAction[] = ['allow', 'block', 'rate_limit', 'challenge', 'log']
const challengeTypes = ['js', 'five_second', 'click', 'simple_click', 'slider', 'simple_slider', 'captcha', 'rotate_image', 'redirect']
const ccFilterTypes = ['req_rate', 'browser_verify_auto', 'five_second', 'click', 'simple_click', 'slider', 'simple_slider', 'captcha', 'rotate_image', '302_challenge', 'url_auth'] as const

const ccFilterTypeLabels: Record<(typeof ccFilterTypes)[number], string> = {
  req_rate: 'cc.types.reqRate', browser_verify_auto: 'cc.types.browserVerify', five_second: 'cc.types.fiveSecond',
  click: 'cc.types.click', simple_click: 'cc.types.simpleClick', slider: 'cc.types.slider',
  simple_slider: 'cc.types.simpleSlider', captcha: 'cc.types.captcha', rotate_image: 'cc.types.rotateImage',
  '302_challenge': 'cc.types.redirect', url_auth: 'cc.types.urlAuth',
}

function writeKey(kind: WriteAttempt['kind'] | 'enable' | 'disable'): string {
  const suffix = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`
  return `security-policy-${kind}-${suffix}`
}

function formatReferenceDateTime(value: string, locale?: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return ''
  const parts = new Intl.DateTimeFormat(locale === 'en-US' ? 'en-US' : 'zh-CN', {
    timeZone: 'Asia/Shanghai', year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23',
  }).formatToParts(date)
  const values = Object.fromEntries(parts.map(({ type, value: part }) => [type, part]))
  return `${values.year}-${values.month}-${values.day} ${values.hour}:${values.minute}:${values.second}`
}

function referenceCheck(checked: boolean, label: string) {
  return checked
    ? <CheckCircle2 className="cc-reference-check" size={14} aria-label={label} role="img" />
    : <span className="cc-reference-check cc-reference-check--muted" role="img" aria-label={label}>—</span>
}

function ccFilterTypeOptions(t: TFunction<'securityPolicies'>, current?: string) {
  const options: Array<{ value: string; label: string }> = ccFilterTypes.map((value) => ({ value, label: t(ccFilterTypeLabels[value]) }))
  if (current && !ccFilterTypes.includes(current as (typeof ccFilterTypes)[number])) {
    options.push({ value: current, label: current })
  }
  return options
}

function unknownOutcome(error: unknown): boolean {
  return !(error instanceof ApiError) || error.status === 0 || error.status === 408 || error.status === 429 || error.status >= 500
}

// SEC-ACCOUNT-05: CC matcher/filter parameters must be a JSON object (ccreference
// rejects numbers, booleans, strings, arrays and null), so the form must too.
function isParameterObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

// SEC-05：过滤器的常用计数参数（within_second/max_req/max_req_per_uri）用数字表单编辑，
// 其余字段留在"高级参数（JSON）"。只有非负整数才拆进表单，其它写法原样留在 JSON 里。
const ccFilterNumberParameters = ['within_second', 'max_req', 'max_req_per_uri'] as const
type CCFilterNumberParameter = (typeof ccFilterNumberParameters)[number]

function splitFilterParameters(parameters: Record<string, unknown> | undefined): { numbers: Partial<Record<CCFilterNumberParameter, number>>; rest: Record<string, unknown> } {
  const rest: Record<string, unknown> = { ...(parameters ?? {}) }
  const numbers: Partial<Record<CCFilterNumberParameter, number>> = {}
  for (const key of ccFilterNumberParameters) {
    const value = rest[key]
    if (typeof value === 'number' && Number.isInteger(value) && value >= 0) {
      numbers[key] = value
      delete rest[key]
    }
  }
  return { numbers, rest }
}

function errorMessage(error: ApiError, t: TFunction<'securityPolicies'>): string {
  switch (error.code) {
    case 'security_policy_in_use': // D3: active on a site, delete refused
    case 'validation_error':
    case 'permission_denied':
    case 'version_conflict':
    case 'idempotency_conflict':
    case 'security_policy_name_conflict':
		case 'cc_reference_name_conflict':
		case 'cc_reference_not_found':
		case 'acl_import_invalid':
    case 'quick_block_site_override_conflict':
    case 'request_failed':
      return t(`errors.${error.code}`)
    default:
      return localizedUnknownApiError(error, t('errors.request_failed'))
  }
}

// D3 (sec-ui-polish): the sites a refused delete names, each linked to its
// security publish panel (switch to another library or withdraw, sec-rebind).
const policyKindPaths: Record<SecurityPolicyKind, string> = { waf: '/site/waf-rule', cc: '/site/cc-rule', acl: '/site/acl' }

function inUseDescription(error: ApiError, kind: SecurityPolicyKind, t: TFunction<'securityPolicies'>, onNavigate: () => void): ReactNode {
  if (error.code !== 'security_policy_in_use') return undefined
  if (!error.inUseSites?.length) return t('errors.inUseNextStep')
  return (
    <>
      <p>{t('errors.inUseSites')}</p>
      <ul className="security-policy-in-use-sites">
        {error.inUseSites.map((site) => (
          <li key={site.id}>
            <Link to={`${policyKindPaths[kind]}?site_id=${encodeURIComponent(site.id)}`} onClick={onNavigate}>{site.domain}</Link>
          </li>
        ))}
      </ul>
      <p>{t('errors.inUseNextStep')}</p>
    </>
  )
}

function importErrorDescription(error: ApiError, t: TFunction<'securityPolicies'>): string | undefined {
	if (!(error instanceof SecurityPolicyImportApiError)) return undefined
	return error.lineErrors.map((item) => t('import.lineError', {
		line: item.line,
		reason: t(`import.${item.code}`),
	})).join('\n')
}

type CCSystemRuleRow = {
  key: string
  matcher?: SecurityPolicyReference
  filter1?: SecurityPolicyReference
  filter2?: SecurityPolicyReference
  enabled: boolean
}

function systemRuleValue(item: OpenRestySecurityRuleGroup): string {
  return item.system_rule_key ?? item.system_rule_id ?? item.id
}

function ccSystemRuleFingerprint(item: SecurityPolicyReference): string {
  return item.system_rule_key?.trim() || item.system_rule_id?.trim() || JSON.stringify([item.name, item.field, item.operator, item.key, item.values ?? [], item.type, item.parameters ?? {}])
}

function uniqueCCSystemRuleReferences(items: SecurityPolicyReference[]): SecurityPolicyReference[] {
  return Array.from(new Map(items.filter((item) => item.system_rule).map((item) => [ccSystemRuleFingerprint(item), item])).values())
}

function ccSystemRuleOptions(items: SecurityPolicyReference[]): { value: string; label: string }[] {
  return uniqueCCSystemRuleReferences(items).flatMap((item) => {
    const key = item.system_rule_key?.trim() || item.system_rule_id?.trim()
    return key ? [{ value: key, label: item.name }] : []
  })
}

function ccSystemRuleRows(
  group: OpenRestySecurityRuleGroup,
  matchers: SecurityPolicyReference[],
  filters: SecurityPolicyReference[],
): CCSystemRuleRow[] {
  const matchesGroup = (item: SecurityPolicyReference) => item.system_rule && item.name.startsWith(group.name)
  const grouped = new Map<string, CCSystemRuleRow>()
  for (const item of uniqueCCSystemRuleReferences(matchers).filter(matchesGroup)) {
    const key = item.name
    const current = grouped.get(key) ?? { key, enabled: item.status === 'enabled' }
    current.matcher = item
    current.enabled = current.enabled && item.status === 'enabled'
    grouped.set(key, current)
  }
  for (const item of uniqueCCSystemRuleReferences(filters).filter(matchesGroup)) {
    const key = item.name
    const current = grouped.get(key) ?? { key, enabled: item.status === 'enabled' }
    if (!current.filter1) current.filter1 = item
    else if ((current.filter1.system_rule_key || current.filter1.system_rule_id || current.filter1.id) !== (item.system_rule_key || item.system_rule_id || item.id) && !current.filter2) current.filter2 = item
    current.enabled = current.enabled && item.status === 'enabled'
    grouped.set(key, current)
  }
  return Array.from(grouped.values()).sort((left, right) => {
    const leftSort = left.matcher?.sort ?? left.filter1?.sort ?? 0
    const rightSort = right.matcher?.sort ?? right.filter1?.sort ?? 0
    return leftSort - rightSort || left.key.localeCompare(right.key)
  })
}

function CCSystemRuleEditor({
  open, group, matchers, filters, loading, pending, canToggle, onToggle, onClose,
}: {
  open: boolean
  group: OpenRestySecurityRuleGroup | null
  matchers: SecurityPolicyReference[]
  filters: SecurityPolicyReference[]
  loading: boolean
  pending: boolean
  canToggle: boolean
  onToggle: (enabled: boolean) => void
  onClose: () => void
}) {
  const { t } = useTranslation('securityPolicies')
  const [addOpen, setAddOpen] = useState(false)
  const [moreOpen, setMoreOpen] = useState(false)
  const [addForm] = Form.useForm<{ matcher?: string; filter1?: string; filter2?: string; action: string; flow: string; enabled: boolean }>()
  const [messageApi, messageContext] = useFeedbackMessage()
  const rows = group ? ccSystemRuleRows(group, matchers, filters) : []
  const matcherOptions = [
    { value: 'builtin', label: t('cc.editor.matcherBuiltin') },
    { value: 'static', label: t('cc.editor.matcherStatic') },
    { value: 'all', label: t('cc.editor.matcherAll') },
    ...ccSystemRuleOptions(matchers),
  ].filter((item, index, all) => all.findIndex((candidate) => candidate.value === item.value) === index)
  const filterOptions = ccSystemRuleOptions(filters)
  const tableColumns: TableColumnsType<CCSystemRuleRow> = [
    { title: t('cc.editor.matcher'), key: 'matcher', width: 180, render: (_value, row) => row.matcher?.name || t('cc.editor.unavailable') },
    { title: t('cc.editor.filterOne'), key: 'filter1', width: 210, render: (_value, row) => row.filter1?.name || t('cc.editor.unavailable') },
    { title: t('cc.editor.filterTwo'), key: 'filter2', width: 210, render: (_value, row) => row.filter2?.name || t('cc.editor.unavailable') },
    { title: t('cc.editor.action'), key: 'action', width: 120, render: () => t('cc.editor.block') },
    { title: t('cc.editor.flow'), key: 'flow', width: 150, render: () => t('cc.editor.stop') },
    { title: t('cc.editor.enabled'), key: 'enabled', width: 90, render: (_value, row) => <Switch size="small" checked={row.enabled} disabled /> },
  ]

  useEffect(() => {
    if (open) {
      setAddOpen(false)
      setMoreOpen(false)
    }
  }, [open, group?.id])

  const addRule = async () => {
    await addForm.validateFields()
    messageApi.info(t('cc.editor.systemManagedNotice'))
    setAddOpen(false)
  }

  return (
    <>
      {messageContext}
      <Modal
        className="cc-system-rule-editor-modal"
        width={1080}
        open={open}
        title={t('cc.editor.editGroup')}
        destroyOnHidden
        onCancel={onClose}
        footer={[
          <Button key="cancel" onClick={onClose}>{t('actions.cancel')}</Button>,
          <Button key="ok" type="primary" onClick={onClose}>{t('actions.confirm')}</Button>,
        ]}
      >
        {group ? <div className="cc-system-rule-editor">
          <section className="cc-system-rule-section">
            <h3><span aria-hidden="true" />{t('cc.editor.basicInfo')}</h3>
            <div className="cc-system-rule-basic-grid">
              <div className="cc-system-rule-field cc-system-rule-field--full">
                <label>{t('cc.editor.type')}</label>
                <Radio.Group value="system" disabled options={[{ value: 'system', label: t('cc.values.system') }, { value: 'custom', label: t('cc.values.custom') }]} />
              </div>
              <div className="cc-system-rule-field">
                <label htmlFor="cc-system-rule-name">{t('cc.editor.name')}</label>
                <Input id="cc-system-rule-name" value={group.name} readOnly />
              </div>
              <div className="cc-system-rule-field">
                <label htmlFor="cc-system-rule-remark">{t('cc.editor.remark')}</label>
                <Input id="cc-system-rule-remark" value={t('cc.editor.builtIn')} readOnly />
              </div>
            </div>
            <div className="cc-system-rule-meta">{group.id} · {group.name}</div>
          </section>

          <section className="cc-system-rule-section">
            <div className="cc-system-rule-section-head">
              <h3><span aria-hidden="true" />{t('cc.editor.ruleList')}</h3>
              <span className="cc-system-rule-count">{t('cc.editor.configured', { count: rows.length })}</span>
            </div>
            <Button className="cc-system-rule-add" onClick={() => { addForm.resetFields(); addForm.setFieldsValue({ action: 'block', flow: 'continue', enabled: true }); setAddOpen(true) }}>{t('cc.editor.addRule')}</Button>
            <Table
              className="cc-system-rule-list"
              rowKey="key"
              size="small"
              columns={tableColumns}
              dataSource={rows}
              loading={loading}
              pagination={false}
              locale={{ emptyText: t('cc.editor.emptyRules') }}
              scroll={{ x: 960 }}
            />
            <p className="cc-system-rule-order-note">{t('cc.editor.orderNote')}</p>
          </section>

          <section className="cc-system-rule-more-section">
            <button type="button" className="cc-system-rule-more-toggle" aria-expanded={moreOpen} onClick={() => setMoreOpen((value) => !value)}>
              <span />{t('cc.editor.more')}<ChevronDown size={18} aria-hidden="true" className={moreOpen ? 'is-open' : ''} /><span />
            </button>
            {moreOpen ? <div className="cc-system-rule-more-content">
              <span>{t('cc.editor.groupId')}: {group.id}</span>
              <span>{t('cc.editor.sort')}: {group.sort ?? t('cc.editor.unavailable')}</span>
              <span>{t('cc.editor.state')}: {group.enabled ? t('cc.values.normal') : t('states.disabled')}</span>
              <span>{t('cc.editor.policyNotice')}</span>
            </div> : null}
          </section>

          <div className="cc-system-rule-state-row">
            <span>{t('cc.values.normal')}</span>
            <Switch aria-label={t('cc.values.normal')} checked={group.enabled} loading={pending} disabled={!canToggle || pending} onChange={onToggle} />
          </div>
          {canToggle ? null : <p className="cc-system-rule-order-note">{t('cc.editor.systemReadOnly')}</p>}
        </div> : null}
      </Modal>

      <Modal
        className="cc-system-rule-add-modal"
        width={700}
        open={addOpen}
        title={t('cc.editor.addRule')}
        onCancel={() => setAddOpen(false)}
        onOk={() => { void addRule() }}
        okText={t('actions.confirm')}
        cancelText={t('actions.cancel')}
      >
        <Form form={addForm} layout="horizontal" labelCol={{ flex: '120px' }} wrapperCol={{ flex: '1' }}>
          <Form.Item name="matcher" label={t('cc.editor.matcher')} rules={[{ required: true, message: t('cc.editor.matcherRequired') }]}>
            <Select placeholder={t('cc.editor.matcherPlaceholder')} options={matcherOptions} />
          </Form.Item>
          <Form.Item name="filter1" label={t('cc.editor.filterOne')} rules={[{ required: true, message: t('cc.editor.filterRequired') }]}>
            <Select placeholder={t('cc.editor.filterOnePlaceholder')} options={filterOptions} />
          </Form.Item>
          <Form.Item name="filter2" label={t('cc.editor.filterTwo')}>
            <Select allowClear placeholder={t('cc.editor.filterTwoPlaceholder')} options={filterOptions} />
          </Form.Item>
          <Form.Item name="action" label={t('cc.editor.action')}>
            <Select options={[{ value: 'block', label: t('cc.editor.block') }, { value: 'allow', label: t('cc.editor.allow') }, { value: 'challenge', label: t('cc.editor.challenge') }]} />
          </Form.Item>
          <Form.Item name="flow" label={t('cc.editor.matchMode')}>
            <Radio.Group options={[{ value: 'continue', label: t('cc.editor.continue') }, { value: 'stop', label: t('cc.editor.stop') }]} />
          </Form.Item>
          <div className="cc-system-rule-flow-help">{t('cc.editor.flowHelp')}</div>
          <Form.Item name="enabled" label={t('cc.editor.enabled')} valuePropName="checked">
            <Switch />
          </Form.Item>
          <p className="cc-system-rule-managed-note">{t('cc.editor.systemManagedNotice')}</p>
        </Form>
      </Modal>
    </>
  )
}

function emptyRule(action: SecurityPolicyAction = 'block'): RuleForm {
  return {
    name: '', priority: 100, enabled: true, action, flow: 'stop', action_config: {},
    conditions: [{ field: 'client_ip', operator: 'ip_in_cidr', values: '' }],
  }
}

function formFromPolicy(item: SecurityPolicy): PolicyForm {
  return {
    kind: item.kind, name: item.name, description: item.description, enabled: item.enabled,
    default_action: item.default_action,
		acl_import: '',
    ...(item.kind === 'waf' ? wafSettingsToForm(item.waf_settings) : {}),
    // Quick block rules are system-managed (site 防护 page card); the server
    // re-derives them on every save, so the editor does not show them.
    rules: item.rules.filter((rule) => !isQuickBlockRuleID(rule.id)).map((rule) => ruleToForm(rule)),
  }
}

const defaultAutoBlock = { window_seconds: 60, hit_threshold: 10, block_seconds: 600 }

function wafSettingsToForm(settings: SecurityPolicy['waf_settings']): Pick<PolicyForm, 'waf_settings' | 'waf_auto_block'> {
  return {
    waf_settings: { mode: settings?.mode ?? '', auto_block: settings?.auto_block ?? defaultAutoBlock },
    waf_auto_block: Boolean(settings?.auto_block),
  }
}

function wafSettingsFromForm(values: PolicyForm): SecurityPolicyFields['waf_settings'] {
  const mode = values.waf_settings?.mode ?? ''
  const autoBlock = values.waf_auto_block ? values.waf_settings?.auto_block : undefined
  return mode || autoBlock ? { mode, auto_block: autoBlock } : undefined
}

const matchAllCondition: SecurityPolicyCondition = { field: 'path', operator: 'prefix', values: ['/'] }
const isMatchAll = (conditions: SecurityPolicyRule['conditions']) => conditions.length === 1 &&
  conditions[0].field === 'path' && conditions[0].operator === 'prefix' && conditions[0].values.length === 1 && conditions[0].values[0] === '/'

function ruleToForm(rule: SecurityPolicyRule): RuleForm {
  const { count_by: countBy, ...rest } = rule
  return {
    ...rest,
    ...countByToForm(countBy),
    ...(isMatchAll(rule.conditions) ? { match_all: true } : {}),
    conditions: rule.conditions.map((condition) => ({ ...condition, values: condition.values.join('\n') })),
    action_config: rule.action_config.managed_waf ? { managed_waf: managedWAFToForm(rule.action_config.managed_waf) } : rule.action_config,
  }
}

function fieldsFromForm(values: PolicyForm): SecurityPolicyFields {
	const aclImport = values.kind === 'acl' ? values.acl_import?.trim() : undefined
  return {
    kind: values.kind,
    name: values.name.trim(),
    description: values.description?.trim() ?? '',
    enabled: values.enabled,
    default_action: values.default_action,
		acl_import: aclImport || undefined,
    waf_settings: values.kind === 'waf' ? wafSettingsFromForm(values) : undefined,
		rules: aclImport ? [] : values.rules.map(({ count_keys: countKeys, count_prefix: countPrefix, count_names: countNames, match_all: matchAll, ...rule }) => ({
      ...rule,
      count_by: values.kind === 'cc' ? countByFromForm(countKeys, countPrefix, countNames) : undefined,
      action_target: values.kind === 'cc' && countByFromForm(countKeys, countPrefix, countNames) && rule.action === 'rate_limit' &&
        rule.action_config.rate_limit?.response_action === 'temporary_ban' ? rule.action_target : undefined,
      name: rule.name.trim(),
			comment: rule.comment?.trim() || undefined,
			expires_at: rule.expires_at?.trim() || undefined,
      // managed_waf runs for the whole site: no conditions.
      conditions: rule.action === 'managed_waf' ? [] : values.kind === 'cc' && matchAll ? [{ ...matchAllCondition, values: [...matchAllCondition.values] }] : rule.conditions.map(({ filters, body_overflow: bodyOverflow, ...condition }) => ({
        ...condition,
        key: condition.field === 'header' || (values.kind === 'waf' && wafKeyedFields.includes(condition.field)) ? condition.key?.trim() || undefined : undefined,
        values: conditionValues(condition.values),
        filters: values.kind === 'waf' && filters?.length ? filters : undefined,
        body_overflow: values.kind === 'waf' && bodyOverflow && wafBodyFields.includes(condition.field) ? bodyOverflow : undefined,
      })),
      action_config: rule.action === 'rate_limit'
        ? { rate_limit: rule.action_config.rate_limit }
        : rule.action === 'ban'
          ? { waf_ban: rule.action_config.waf_ban }
        : rule.action === 'challenge' && values.kind === 'waf'
          ? { waf_challenge: rule.action_config.waf_challenge }
        : rule.action === 'challenge'
          ? { challenge: rule.action_config.challenge }
          : rule.action === 'managed_waf' && rule.action_config.managed_waf
            ? { managed_waf: managedWAFFromForm(rule.action_config.managed_waf) }
            : {},
    })),
  }
}

// ruleEditor: the CC rule editor (CC v6 operators); the CC matcher reference
// editor keeps its own contract.
function conditionOperators(kind: SecurityPolicyKind, field: string, ruleEditor = false): string[] {
  if (kind === 'acl') return ['ip_in_cidr']
  if (kind === 'cc') {
    if (ccCountFields.includes(field)) return ['number_gte']
    if (field === 'client_ip') return ruleEditor ? ['equals', 'ip_in_cidr', 'ip_not_in_cidr'] : ['equals', 'ip_in_cidr']
    if (ccHeaderFields.includes(field)) return ['equals', 'prefix', 'contains', 'regex']
    if (field === 'path') return ['equals', 'prefix']
    if (field === 'port') return ['number_eq']
    if (field === 'ja4') return ruleEditor ? ['in', 'equals'] : ['equals']
    return ['equals']
  }
  if (field === 'client_ip') return ['ip_in_cidr']
  if (field === 'ip_list') return ['in_ip_list', 'not_in_ip_list']
  if (field === 'http_version') return ['equals', 'not_equals']
  if (field === 'port') return ['number_eq']
  if (field === 'ja4') return wafJA4Operators
  if (wafSetFields.includes(field)) return wafSetOperators
  if (wafNumberFields.includes(field)) return wafLengthOperators
  // number_* on a content field needs the length filter last.
  if (field === 'path' || field === 'header' || wafContentFields.includes(field)) return wafContentOperators
  return ['equals']
}

// The editor form marks a refused field of the last save (owner_id from the
// create body is the form's owner_id; everything else is the same path).
const policyFieldMap = { owner_id: 'owner_id' }
function useSubmitFieldError(form: FormInstance<PolicyForm>, submitError: ApiError | null, onFieldMarked?: (marked: boolean) => void) {
  const mark = useFormSubmitError(form, policyFieldMap)
  useEffect(() => {
    onFieldMarked?.(Boolean(submitError && mark(submitError)))
  }, [mark, onFieldMarked, submitError])
}

function ACLPolicyEditor({
  open, item, isAdmin, pending, onCancel, onSubmit, accessToken = '', catalogKey = '', canListTenants = false, submitError = null, onFieldMarked,
}: {
  open: boolean
  item: SecurityPolicy | null
  isAdmin: boolean
  pending: boolean
  onCancel: () => void
  onSubmit: (values: PolicyForm) => void
  accessToken?: string
  catalogKey?: string
  canListTenants?: boolean
  submitError?: ApiError | null
  onFieldMarked?: (marked: boolean) => void
}) {
  const { t } = useTranslation('securityPolicies')
  const [form] = Form.useForm<PolicyForm>()
  useSubmitFieldError(form, submitError, onFieldMarked)
  const targetScope = Form.useWatch('target_scope_id', form)
  const ownerKey = catalogKey

  useEffect(() => {
    if (!open) return
    form.setFieldsValue(item ? {
      ...formFromPolicy(item),
      target_scope_id: item.scope_id,
      owner_id: item.owner?.id,
      acl_import: '',
    } : {
      kind: 'acl', name: '', description: '', enabled: true, default_action: 'allow',
      target_scope_id: '', owner_id: '', acl_import: '', rules: [{
        ...emptyRule(), name: '规则 1', flow: 'stop', action: 'allow', conditions: [{ field: 'client_ip', operator: 'ip_in_cidr', values: '' }],
      }],
    })
  }, [form, item, open])

  return (
    <Modal
      className="security-policy-modal acl-policy-modal"
      title={item ? t('acl.editor.editTitle') : t('acl.editor.createTitle')}
      open={open}
      width={700}
      confirmLoading={pending}
      okText={t('actions.save')}
      cancelText={t('actions.cancel')}
      onCancel={onCancel}
      onOk={() => void form.validateFields().then((values) => onSubmit({
        ...values,
        rules: (values.rules ?? []).map((rule, index) => ({
          ...rule,
          priority: index + 1,
          flow: 'stop',
          conditions: [{ field: 'client_ip', operator: 'ip_in_cidr', values: rule.conditions?.[0]?.values ?? '' }],
        })),
      })).catch(() => undefined)}
      styles={{ body: { maxHeight: '68vh', overflowY: 'auto' } }}
      destroyOnClose
    >
      <Form form={form} layout="vertical" requiredMark={false}>
        <Form.Item name="kind" hidden><Input /></Form.Item>
        {isAdmin && !item ? <>
          <Form.Item name="target_scope_id" label={t('acl.editor.targetScope')} rules={[{ required: true, whitespace: true, message: t('acl.editor.targetScopeRequired') }]}>
            <TenantScopeSelect
              accessToken={accessToken}
              ownerKey={ownerKey}
              canList={canListTenants}
              queryKeyPrefix="acl-editor-tenants"
              ariaLabel={t('acl.editor.targetScope')}
              placeholder={t('acl.editor.targetScopePlaceholder')}
              emptyText={t('acl.editor.targetScopeEmpty')}
              value={targetScope ?? ''}
              onChange={(scopeID) => form.setFieldValue('target_scope_id', scopeID)}
              onPickUser={(user) => { if (user) form.setFieldValue('owner_id', user.id) }}
            />
          </Form.Item>
          <Form.Item name="owner_id" label={t('acl.editor.owner')} rules={[{ required: true, whitespace: true, message: t('acl.editor.ownerRequired') }]}>
            <Input placeholder={t('acl.editor.ownerPlaceholder')} />
          </Form.Item>
        </> : null}
        <div className="acl-editor-basic-grid">
          <Form.Item name="name" label={t('acl.editor.name')} rules={[{ required: true, whitespace: true, max: 128 }]}>
            <Input />
          </Form.Item>
          <Form.Item name="description" label={t('acl.editor.description')} rules={[{ max: 1000 }]}>
            <Input />
          </Form.Item>
        </div>
        <Form.Item name="default_action" label={t('acl.editor.defaultAction')} rules={[{ required: true }]}>
          <Radio.Group options={[{ value: 'allow', label: t('acl.editor.allow') }, { value: 'block', label: t('acl.editor.block') }]} />
        </Form.Item>
        <div className="acl-editor-rules-head">
          <strong>{t('acl.editor.rules')}</strong>
          <Button size="small" icon={<Plus size={14} />} onClick={() => {
            const rules = form.getFieldValue('rules') as RuleForm[] ?? []
            form.setFieldValue('rules', [...rules, { ...emptyRule(), name: `规则 ${rules.length + 1}`, flow: 'stop', action: 'allow', conditions: [{ field: 'client_ip', operator: 'ip_in_cidr', values: '' }] }])
          }}>{t('acl.editor.addRule')}</Button>
        </div>
        <div className="acl-editor-rule-table" role="table" aria-label={t('acl.editor.rules')}>
          <div className="acl-editor-rule-row acl-editor-rule-header" role="row">
            <span role="columnheader">{t('acl.editor.match')}</span>
            <span role="columnheader">{t('acl.editor.action')}</span>
            <span role="columnheader" aria-label={t('columns.actions')} />
          </div>
          <Form.List name="rules">
            {(fields, { remove }) => fields.map((field, index) => (
              <div className="acl-editor-rule-row" role="row" key={field.key}>
                <Form.Item name={[field.name, 'name']} hidden><Input /></Form.Item>
                <Form.Item name={[field.name, 'priority']} hidden><InputNumber /></Form.Item>
                <Form.Item name={[field.name, 'flow']} hidden><Input /></Form.Item>
                <Form.Item name={[field.name, 'enabled']} hidden><Switch /></Form.Item>
                <Form.Item name={[field.name, 'conditions', 0, 'field']} hidden><Input /></Form.Item>
                <Form.Item name={[field.name, 'conditions', 0, 'operator']} hidden><Input /></Form.Item>
                <Form.Item className="acl-editor-match-item" name={[field.name, 'conditions', 0, 'values']} rules={[{ required: true, whitespace: true, message: t('acl.editor.matchRequired') }]}>
                  <Input placeholder={t('acl.editor.cidrPlaceholder')} aria-label={`${t('acl.editor.match')} ${index + 1}`} />
                </Form.Item>
                <Form.Item className="acl-editor-action-item" name={[field.name, 'action']} rules={[{ required: true, message: t('acl.editor.actionRequired') }]}>
                  <Select aria-label={`${t('acl.editor.action')} ${index + 1}`} options={[{ value: 'allow', label: t('acl.editor.allow') }, { value: 'block', label: t('acl.editor.block') }]} />
                </Form.Item>
                <Tooltip title={t('acl.editor.removeRule')}>
                  <Button danger type="text" aria-label={`${t('acl.editor.removeRule')} ${index + 1}`} icon={<Trash2 size={15} />} disabled={fields.length === 1} onClick={() => remove(field.name)} />
                </Tooltip>
              </div>
            ))}
          </Form.List>
        </div>
        <div className="acl-editor-enabled-row">
          <Form.Item name="enabled" label={t('acl.editor.enabled')} valuePropName="checked"><Switch /></Form.Item>
        </div>
        {isAdmin ? <details className="acl-editor-advanced">
          <summary>{t('acl.editor.advanced')}</summary>
          <Form.Item name="acl_import" label={t('acl.editor.import')} extra={t('acl.editor.importHint')}>
            <Input.TextArea rows={3} />
          </Form.Item>
        </details> : null}
      </Form>
    </Modal>
  )
}

type PolicyEditorProps = {
  open: boolean
  item: SecurityPolicy | null
  kind: SecurityPolicyKind
  isAdmin: boolean
  pending: boolean
  onCancel: () => void
  onSubmit: (values: PolicyForm) => void
  // A save refusal naming a field (rules[n]..., name) is
  // marked under it in the open editor; onFieldMarked reports whether it was.
  submitError?: ApiError | null
  onFieldMarked?: (marked: boolean) => void
  accessToken?: string
  catalogKey?: string
  canListTenants?: boolean
  // CU-SITE-04: 新增放行规则 from a site: an allow rule is appended to the draft (WAF/CC editor);
  // a new library is made for the site's tenant and owner (administrators).
  appendAllowRule?: boolean
  createTarget?: { scopeId: string; ownerId: string }
}

function PolicyEditor(props: PolicyEditorProps) {
  if (props.kind === 'acl') return <ACLPolicyEditor open={props.open} item={props.item} isAdmin={props.isAdmin} pending={props.pending} onCancel={props.onCancel} onSubmit={props.onSubmit} accessToken={props.accessToken} catalogKey={props.catalogKey} canListTenants={props.canListTenants} submitError={props.submitError} onFieldMarked={props.onFieldMarked} />
  return <RulePolicyEditor {...props} />
}

function RulePolicyEditor({
  open, item, kind, isAdmin, pending, onCancel, onSubmit, accessToken = '', catalogKey = '', appendAllowRule = false, createTarget,
  submitError = null, onFieldMarked,
}: PolicyEditorProps) {
  const { t } = useTranslation('securityPolicies')
  const [form] = Form.useForm<PolicyForm>()
  useSubmitFieldError(form, submitError, onFieldMarked)
  // managed_waf (OWASP CRS rule sets) exists only in WAF policies.
  const ruleActions = kind === 'waf' ? [...actions, 'ban' as const, 'managed_waf' as const] : actions
  const catalog = useSystemRules(accessToken, kind === 'waf' ? 'waf_rule_set' : 'cc_rule_group', catalogKey)
  // PA-12: the CRS profile packs a managed_waf rule may select.
  const crsProfiles = useQuery({
    queryKey: ['security-policies', 'crs-profiles', catalogKey],
    enabled: open && kind === 'waf' && Boolean(accessToken),
    retry: false,
    queryFn: ({ signal }) => securityPoliciesApi.listCRSProfiles(accessToken, signal),
  })
  // ge36-waf W2: the IP lists an ip_list condition may name (own + platform).
  const ipListAudience: SecurityIPListAudience = isAdmin ? 'admin' : 'tenant'
  const ipLists = useQuery({
    queryKey: ['security-ip-lists', ipListAudience, 'editor'],
    enabled: open && kind === 'waf' && Boolean(accessToken),
    retry: false,
    queryFn: () => listSecurityIPLists(accessToken, ipListAudience),
  })
  const importRules = async (keys: string[]) => {
    const targetScope = (item?.scope_id ?? (form.getFieldValue('target_scope_id') as string | undefined)?.trim()) || undefined
    const scopeArgument = isAdmin && targetScope ? [targetScope] as const : [] as const
    const result = await securityPoliciesApi.catalogRules(accessToken, kind === 'waf' ? 'waf' : 'cc', keys, ...scopeArgument)
    const { rules } = result
    const current = (form.getFieldValue('rules') as RuleForm[] | undefined ?? []).filter((rule) => rule.name || rule.conditions.some((condition) => condition.values))
    const next = Math.max(0, ...current.map((rule) => rule.priority))
    form.setFieldValue('rules', [...current, ...rules.map((rule, index) => ({ ...ruleToForm(rule), priority: next + index + 1 }))])
    return result
  }
  // 使用系统默认 WAF: the 系统设置 default WAF (switch, modules, auto block)
  // as the draft of a new policy.
  const [defaultMessage, setDefaultMessage] = useState('')
  const applySystemDefault = async () => {
    const result = await importRules([systemDefaultWAFKey])
    const value = result.default
    setDefaultMessage(!value?.enabled || value.rules.length === 0 ? t('editor.systemDefaultEmpty') : '')
    if (!value) return
    form.setFieldsValue({ enabled: value.enabled, ...wafSettingsToForm(value.waf_settings) })
  }
  // FX26: move a rule (drag or keyboard) and renumber priorities in the new
  // order, strictly increasing so the node runs them as shown.
  const [dragging, setDragging] = useState<number | null>(null)
  const moveRule = (from: number, to: number) => {
    const current = form.getFieldValue('rules') as RuleForm[]
    if (from === to || to < 0 || to >= current.length) return
    form.setFieldValue('rules', reorderedPriorities(current.map((rule) => rule.priority), from, to)
      .map(([index, priority]) => ({ ...current[index], priority })))
  }
  const availableConditionFields = kind === 'cc' ? [...ccFields, ...ccHeaderFields, ...ccCountFields, ...ccFingerprintFields] : wafFields
  useEffect(() => {
    if (!open) return
    setDefaultMessage('')
    const values: PolicyForm = item ? formFromPolicy(item) : {
			kind, name: '', description: '', enabled: true, default_action: 'allow', acl_import: '', rules: appendAllowRule ? [] : [emptyRule()],
      ...(kind === 'waf' ? wafSettingsToForm(undefined) : {}),
      ...(appendAllowRule && createTarget ? { target_scope_id: createTarget.scopeId, owner_id: createTarget.ownerId } : {}),
    }
    if (appendAllowRule) {
      // D1: rules run by ascending priority and a block+stop ends the scan, so an allow
      // appended last is shadowed. The site's new allow goes first; the other rules keep their order.
      const appended = [...values.rules, { ...emptyRule('allow'), priority: Math.max(0, ...values.rules.map((rule) => rule.priority)) + 1 }]
      values.rules = reorderedPriorities(appended.map((rule) => rule.priority), appended.length - 1, 0)
        .map(([index, priority]) => ({ ...appended[index], priority }))
    }
    form.setFieldsValue(values)
  // eslint-disable-next-line react-hooks/exhaustive-deps -- createTarget is read when the editor opens
  }, [appendAllowRule, form, item, kind, open])

  return (
    <Modal
      className="security-policy-modal"
      title={item ? t('editor.editTitle') : t('editor.createTitle')}
      open={open}
      width={920}
      confirmLoading={pending}
      okText={t('actions.save')}
      cancelText={t('actions.cancel')}
      onCancel={onCancel}
      onOk={() => void form.validateFields().then(onSubmit).catch(() => undefined)}
      styles={{ body: { maxHeight: '68vh', overflowY: 'auto' } }}
      destroyOnHidden
    >
      <Form form={form} layout="vertical" requiredMark={false}>
        {isAdmin && !item ? (
          <Space size={12} wrap style={{ width: '100%' }}>
            <Form.Item name="target_scope_id" label={t('editor.targetScope')} rules={[{ required: true }]}>
              <Input placeholder={t('editor.targetScopePlaceholder')} style={{ width: 320 }} />
            </Form.Item>
            <Form.Item name="owner_id" label={t('editor.owner')} rules={[{ required: true }]}>
              <Input placeholder={t('editor.ownerPlaceholder')} style={{ width: 320 }} />
            </Form.Item>
          </Space>
        ) : null}
        <Space size={12} wrap style={{ width: '100%' }}>
          <Form.Item name="kind" label={t('editor.kind')} rules={[{ required: true }]}>
            <Select disabled options={[{ value: kind, label: t(`kinds.${kind}`) }]} style={{ width: 140 }} />
          </Form.Item>
          <Form.Item name="name" label={t('editor.name')} rules={[{ required: true, whitespace: true, max: 128 }]}>
            <Input style={{ width: 260 }} />
          </Form.Item>
          <Form.Item name="default_action" label={t('editor.defaultAction')} rules={[{ required: true }]}>
            <Select style={{ width: 150 }} options={['allow', 'block'].map((value) => ({ value, label: t(`actionsMap.${value}`) }))} />
          </Form.Item>
          <Form.Item name="enabled" label={t('editor.enabled')} valuePropName="checked">
            <Switch />
          </Form.Item>
        </Space>
        <Form.Item name="description" label={t('editor.description')} rules={[{ max: 1000 }]}>
          <Input.TextArea rows={2} />
        </Form.Item>
        {kind === 'waf' ? (
          <fieldset className="security-policy-waf-settings">
            <legend>{t('editor.wafSettings')}</legend>
            <Space size={12} wrap align="start">
              <Form.Item name={['waf_settings', 'mode']} label={t('editor.wafMode')}>
                <Select style={{ width: 220 }} options={[{ value: '', label: t('editor.wafModes.defend') }, { value: 'observe', label: t('editor.wafModes.observe') }]} />
              </Form.Item>
              <Form.Item name="waf_auto_block" label={t('editor.autoBlock')} valuePropName="checked">
                <Switch />
              </Form.Item>
              <Form.Item noStyle shouldUpdate={(previous, current) => previous.waf_auto_block !== current.waf_auto_block}>
                {({ getFieldValue }) => getFieldValue('waf_auto_block') ? (
                  <Space size={12} wrap>
                    <Form.Item name={['waf_settings', 'auto_block', 'window_seconds']} label={t('editor.autoBlockWindow')} rules={[{ required: true, type: 'number', min: 1, max: 86_400 }]}>
                      <InputNumber min={1} max={86_400} precision={0} />
                    </Form.Item>
                    <Form.Item name={['waf_settings', 'auto_block', 'hit_threshold']} label={t('editor.autoBlockHits')} rules={[{ required: true, type: 'number', min: 1, max: 1_000_000 }]}>
                      <InputNumber min={1} max={1_000_000} precision={0} />
                    </Form.Item>
                    <Form.Item name={['waf_settings', 'auto_block', 'block_seconds']} label={t('editor.autoBlockSeconds')} rules={[{ required: true, type: 'number', min: 1, max: 604_800 }]}>
                      <InputNumber min={1} max={604_800} precision={0} />
                    </Form.Item>
                  </Space>
                ) : null}
              </Form.Item>
            </Space>
            <div className="security-policy-condition-hint">{t('editor.autoBlockHint')}</div>
          </fieldset>
        ) : null}
        {item?.rules.some((rule) => isQuickBlockRuleID(rule.id)) ? (
          <Alert className="identity-alert" type="info" showIcon role="status" message={t('quickBlock.editorNotice')} />
        ) : null}
        <Form.List name="rules">
          {(ruleFields, { add, remove }) => (
            <>
              <div className="identity-toolbar">
                <strong>{t('editor.rules')}</strong>
                <Space size={8} wrap>
                  {accessToken ? <CatalogImport kind={kind} catalog={catalog.data ?? []} onImport={importRules} /> : null}
                  {accessToken && kind === 'waf' && !item ? (
                    <Button size="small" onClick={() => void applySystemDefault()}>{t('editor.useSystemDefault')}</Button>
                  ) : null}
                  <Button size="small" icon={<Plus size={14} />} onClick={() => add(emptyRule())}>{t('actions.addRule')}</Button>
                </Space>
              </div>
              {defaultMessage ? <Alert className="identity-alert" type="info" showIcon role="status" message={defaultMessage} /> : null}
              {appendAllowRule ? <Alert className="identity-alert" type="info" showIcon role="status" message={t('editor.allowFirstHint')} /> : null}
              {ruleFields.map((ruleField, ruleIndex) => (
                <div key={ruleField.key} data-testid={`rule-${ruleIndex}`} style={{ borderTop: `1px solid ${themeColor('--cdnca-color-border-light', '#f0f0f0')}`, paddingTop: 12, marginTop: 8 }}
                  onDragOver={(event) => { if (dragging !== null) event.preventDefault() }}
                  onDrop={(event) => { event.preventDefault(); if (dragging !== null) moveRule(dragging, ruleIndex); setDragging(null) }}>
                  <Space size={10} wrap align="start">
                    <Space size={2} style={{ paddingTop: 30 }}>
                      <span draggable role="button" tabIndex={-1} aria-label={t('ruleOrder.drag')} title={t('ruleOrder.drag')} style={{ cursor: 'grab' }}
                        onDragStart={(event) => { setDragging(ruleIndex); event.dataTransfer?.setData('text/plain', String(ruleIndex)) }}
                        onDragEnd={() => setDragging(null)}><GripVertical size={15} /></span>
                      <Button size="small" type="text" icon={<ArrowUp size={14} />} aria-label={t('ruleOrder.moveUp', { index: ruleIndex + 1 })}
                        disabled={ruleIndex === 0} onClick={() => moveRule(ruleIndex, ruleIndex - 1)} />
                      <Button size="small" type="text" icon={<ArrowDown size={14} />} aria-label={t('ruleOrder.moveDown', { index: ruleIndex + 1 })}
                        disabled={ruleIndex === ruleFields.length - 1} onClick={() => moveRule(ruleIndex, ruleIndex + 1)} />
                    </Space>
                    <Form.Item name={[ruleField.name, 'name']} label={t('editor.ruleName')} rules={[{ required: true, whitespace: true, max: 128 }]}>
                      <Input style={{ width: 190 }} />
                    </Form.Item>
                    <Form.Item name={[ruleField.name, 'priority']} label={t('editor.priority')} rules={[{ required: true, type: 'number', min: 1, max: 1_000_000 }]}>
                      <InputNumber min={1} max={1_000_000} precision={0} style={{ width: 110 }} />
                    </Form.Item>
                    <Form.Item name={[ruleField.name, 'action']} label={t('editor.action')} rules={[{ required: true }]}>
                      <Select style={{ width: 140 }} options={ruleActions.map((value) => ({ value, label: t(`actionsMap.${value}`) }))} />
                    </Form.Item>
                    <Form.Item name={[ruleField.name, 'flow']} label={t('editor.flow')} rules={[{ required: true }]}>
                      <Select style={{ width: 120 }} options={['continue', 'stop'].map((value) => ({ value, label: t(`flows.${value}`) }))} />
                    </Form.Item>
                    <Form.Item name={[ruleField.name, 'enabled']} label={t('editor.enabled')} valuePropName="checked">
                      <Switch />
                    </Form.Item>
                    <Tooltip title={t('actions.deleteRule')}>
                      <Button danger type="text" aria-label={t('actions.deleteRuleNamed', { index: ruleIndex + 1 })} icon={<Trash2 size={15} />} disabled={ruleFields.length === 1} onClick={() => remove(ruleField.name)} />
                    </Tooltip>
                  </Space>
                  <Form.Item noStyle shouldUpdate={(previous, current) => previous.rules?.[ruleField.name]?.action !== current.rules?.[ruleField.name]?.action}>
                    {({ getFieldValue }) => {
                      const action = getFieldValue(['rules', ruleField.name, 'action']) as SecurityPolicyAction
                      if (action === 'rate_limit') return (
                        <Space size={10} wrap>
                          <Form.Item name={[ruleField.name, 'action_config', 'rate_limit', 'window_seconds']} label={t('editor.windowSeconds')} rules={[{ required: true, type: 'number', min: 1, max: 3600 }]}>
                            <InputNumber min={1} max={3600} precision={0} />
                          </Form.Item>
                          <Form.Item name={[ruleField.name, 'action_config', 'rate_limit', 'max_requests']} label={t('editor.maxRequests')} rules={[{ required: true, type: 'number', min: 1, max: 1_000_000 }]}>
                            <InputNumber min={1} max={1_000_000} precision={0} />
                          </Form.Item>
                        </Space>
                      )
                      if (action === 'ban') return (
                        <Form.Item name={[ruleField.name, 'action_config', 'waf_ban', 'ban_seconds']} label={t('editor.banSeconds')} initialValue={600} rules={[{ required: true, type: 'number', min: 1, max: 604_800 }]}>
                          <InputNumber min={1} max={604_800} precision={0} />
                        </Form.Item>
                      )
                      if (action === 'challenge' && kind === 'waf') return (
                        <Space size={10} wrap>
                          <Form.Item name={[ruleField.name, 'action_config', 'waf_challenge', 'pass_seconds']} label={t('editor.passSeconds')} initialValue={1800} rules={[{ required: true, type: 'number', min: 60, max: 86_400 }]}>
                            <InputNumber min={60} max={86_400} precision={0} />
                          </Form.Item>
                          <Form.Item name={[ruleField.name, 'action_config', 'waf_challenge', 'pow_bits']} label={t('editor.powBits')} initialValue={16} rules={[{ required: true, type: 'number', min: 8, max: 24 }]}>
                            <InputNumber min={8} max={24} precision={0} />
                          </Form.Item>
                        </Space>
                      )
                      if (action === 'challenge') return (
                        <>
                          {/* A new challenge starts as the JS page (rulepack DefaultCCChallenge.Mode). */}
                          <Form.Item name={[ruleField.name, 'action_config', 'challenge', 'type']} label={t('editor.challengeType')}
                            initialValue="js" rules={[{ required: true }]}>
                            <Select aria-label={t('editor.challengeType')} style={{ width: 220 }}
                              options={challengeTypes.map((value) => ({ value, label: t(`countBy.actions.challengeTypes.${value}`) }))} />
                          </Form.Item>
                          <ChallengeFields ruleName={ruleField.name} form={form} />
                        </>
                      )
                      if (action === 'managed_waf') return <ManagedWAFFields ruleName={ruleField.name} form={form} profiles={crsProfiles.data?.items} />
                      return null
                    }}
                  </Form.Item>
                  {kind === 'cc' ? <CountByFields ruleName={ruleField.name} form={form} /> : null}
                  {kind === 'cc' ? (
                    <Form.Item className="security-policy-match-all" name={[ruleField.name, 'match_all']} label={t('editor.matchAllClients')} valuePropName="checked" tooltip={t('editor.matchAllClientsHelp')}>
                      <Switch aria-label={t('editor.matchAllClients')} />
                    </Form.Item>
                  ) : null}
                  <Form.Item noStyle shouldUpdate={(previous, current) => previous.rules?.[ruleField.name]?.action !== current.rules?.[ruleField.name]?.action ||
                    previous.rules?.[ruleField.name]?.match_all !== current.rules?.[ruleField.name]?.match_all}>
                  {({ getFieldValue }) => getFieldValue(['rules', ruleField.name, 'action']) === 'managed_waf' ||
                    kind === 'cc' && getFieldValue(['rules', ruleField.name, 'match_all']) ? null : (
                  <Form.List name={[ruleField.name, 'conditions']}>
                    {(conditionFields, conditionOperations) => (
                      <>
                        {conditionFields.map((conditionField, conditionIndex) => (
                          <Space key={conditionField.key} size={8} wrap align="start">
                            <Form.Item name={[conditionField.name, 'field']} label={conditionIndex === 0 ? t('editor.field') : undefined} rules={[{ required: true }]}>
                              <Select
                                virtual={false}
                                style={{ width: 160 }}
                                options={groupedFieldOptions(t, availableConditionFields)}
                                onChange={(value) => {
                                  form.setFieldValue(['rules', ruleField.name, 'conditions', conditionField.name, 'operator'], conditionOperators(kind, value, true)[0])
                                }}
                              />
                            </Form.Item>
                            <Form.Item noStyle shouldUpdate>
                              {({ getFieldValue }) => {
                                const field = getFieldValue(['rules', ruleField.name, 'conditions', conditionField.name, 'field']) as string
                                const available = conditionOperators(kind, field, true)
                                return (
                                  <Form.Item name={[conditionField.name, 'operator']} label={conditionIndex === 0 ? t('editor.operator') : undefined} rules={[{ required: true }]}>
                                    <Select style={{ width: 155 }} options={available.map((value) => ({ value, label: t(`operatorsMap.${value}`) }))} />
                                  </Form.Item>
                                )
                              }}
                            </Form.Item>
                            <Form.Item noStyle shouldUpdate>
                              {({ getFieldValue }) => {
                                const field = getFieldValue(['rules', ruleField.name, 'conditions', conditionField.name, 'field']) as string
                                if (field === 'header') return (
                                  <Form.Item name={[conditionField.name, 'key']} label={conditionIndex === 0 ? t('editor.headerName') : undefined} rules={[{ required: true }]}>
                                    <Input style={{ width: 150 }} />
                                  </Form.Item>
                                )
                                if (kind !== 'waf' || !wafKeyedFields.includes(field)) return null
                                return (
                                  <Form.Item name={[conditionField.name, 'key']} label={conditionIndex === 0 ? t('editor.wafKey') : undefined} tooltip={t('editor.wafKeyHint')}>
                                    <Input aria-label={t('editor.wafKey')} style={{ width: 150 }} />
                                  </Form.Item>
                                )
                              }}
                            </Form.Item>
                            <Form.Item noStyle shouldUpdate>
                              {({ getFieldValue }) => getFieldValue(['rules', ruleField.name, 'conditions', conditionField.name, 'field']) === 'ip_list' ? (
                                <Form.Item name={[conditionField.name, 'values']} label={conditionIndex === 0 ? t('editor.values') : undefined} rules={[{ required: true, whitespace: true }]}>
                                  <Select aria-label={t('editor.ipList')} style={{ width: 250 }} showSearch optionFilterProp="label" loading={ipLists.isLoading}
                                    options={(ipLists.data ?? []).map((list) => ({ value: list.id, label: `${list.name} (${list.entries.length})` }))} />
                                </Form.Item>
                              ) : (
                                <Form.Item name={[conditionField.name, 'values']} label={conditionIndex === 0 ? t('editor.values') : undefined} rules={[{ required: true, whitespace: true },
                                  { validator: async (_, value?: string) => {
                                    const condition = getFieldValue(['rules', ruleField.name, 'conditions', conditionField.name]) as { field?: string; operator?: string }
                                    if (kind === 'waf' && wafSetFields.includes(condition.field ?? '') && (condition.operator === 'equals' || condition.operator === 'not_equals') &&
                                      conditionValues(value ?? '').length > 1) throw new Error(t('conditionFields.singleValue'))
                                    if (condition.field !== 'ja4') return
                                    const invalid = invalidJA4Values(conditionValues(value ?? ''))
                                    if (invalid.length) throw new Error(t('conditionFields.ja4Invalid', { values: invalid.slice(0, 3).join('、') }))
                                  } }]}>
                                  <Input.TextArea autoSize={{ minRows: 1, maxRows: 6 }} style={{ width: 250 }}
                                    placeholder={conditionValuePlaceholder(t, getFieldValue(['rules', ruleField.name, 'conditions', conditionField.name, 'field']) as string)} />
                                </Form.Item>
                              )}
                            </Form.Item>
                            {kind === 'waf' ? (
                              <Form.Item noStyle shouldUpdate>
                                {({ getFieldValue }) => {
                                  const field = getFieldValue(['rules', ruleField.name, 'conditions', conditionField.name, 'field']) as string
                                  return (
                                    <>
                                      {field === 'path' || field === 'header' || wafContentFields.includes(field) ? (
                                        <Form.Item name={[conditionField.name, 'filters']} label={conditionIndex === 0 ? t('editor.filters') : undefined}>
                                          <Select mode="multiple" allowClear aria-label={t('editor.filters')} style={{ width: 190 }} options={wafFilterNames.map((value) => ({ value, label: value }))} />
                                        </Form.Item>
                                      ) : null}
                                      {wafBodyFields.includes(field) ? (
                                        <Form.Item name={[conditionField.name, 'body_overflow']} label={conditionIndex === 0 ? t('editor.bodyOverflow') : undefined}
                                          getValueProps={(value) => ({ checked: value === 'match' })} getValueFromEvent={(checked: boolean) => checked ? 'match' : undefined}>
                                          <Switch aria-label={t('editor.bodyOverflow')} />
                                        </Form.Item>
                                      ) : null}
                                    </>
                                  )
                                }}
                              </Form.Item>
                            ) : null}
                            <Tooltip title={t('actions.deleteCondition')}>
                              <Button danger type="text" aria-label={t('actions.deleteCondition')} icon={<Trash2 size={14} />} disabled={conditionFields.length === 1} onClick={() => conditionOperations.remove(conditionField.name)} />
                            </Tooltip>
                          </Space>
                        ))}
                        <Button size="small" type="dashed" icon={<Plus size={13} />} onClick={() => conditionOperations.add({ field: 'path', operator: 'prefix', values: '' })}>
                          {t('actions.addCondition')}
                        </Button>
                        {kind === 'cc' ? <div className="security-policy-condition-hint">{t('editor.ccConditionHint')}</div> : null}
                        {kind === 'waf' ? <div className="security-policy-condition-hint">{t('editor.ipListHint')}</div> : null}
                        {kind === 'waf' ? <div className="security-policy-condition-hint">{t('conditionFields.nodeHint')}</div> : null}
                      </>
                    )}
											</Form.List>
                  )}
                  </Form.Item>
                </div>
              ))}
            </>
          )}
        </Form.List>
      </Form>
    </Modal>
  )
}

// A table row: a policy, a CC system rule group, or (WAF page) a platform library not subscribed yet.
type PolicyTableRow = SecurityPolicy | OpenRestySecurityRuleGroup | WAFRuleLibrary
const isPlatformLibrary = (item: PolicyTableRow): item is WAFRuleLibrary => 'subscription' in item

function SecurityPoliciesTable({
  accessToken, principal, scopeID, sessionEpoch, kind, referenceLayout = false, onOpenChallenges, showActivation = false,
}: {
  accessToken: string
  principal: Principal
  scopeID: string
  sessionEpoch: number
  kind: SecurityPolicyKind
  referenceLayout?: boolean
  onOpenChallenges?: () => void
  showActivation?: boolean
}) {
  const { t, i18n } = useTranslation('securityPolicies')
  const accessTokenRef = useRef(accessToken)
  accessTokenRef.current = accessToken
  const isAdmin = roleForPrincipal(principal) === 'admin'
  const canManage = principal.permissions.includes('security_policies.manage') || principal.permissions.includes('platform.admin')
  // SEC-ACCOUNT-02: system CC rule groups are installation-wide; the backend
  // only lets a platform session with openresty_security.manage toggle them.
  const canManageSystemGroups = principal.scope_kind === 'platform' &&
    (principal.permissions.includes('openresty_security.manage') || principal.permissions.includes('platform.admin'))
  const [subscriptionsOpen, setSubscriptionsOpen] = useState(false)
  const queryClient = useQueryClient()
  const [messageApi, messageContext] = useFeedbackMessage()
  const feedback = useFeedback()
  const [page, setPage] = useState(1)
  const [limit, setLimit] = useState(referenceLayout || kind === 'acl' ? 10 : 20)
  // 已生效条件写进 URL（name/id/owner），打开分享链接时读回。
  const [initialParams] = useSearchParams()
  const [nameDraft, setNameDraft] = useState(() => filterParam(initialParams, 'name'))
  const [name, setName] = useState(() => filterParam(initialParams, 'name'))
  const [policyIDDraft, setPolicyIDDraft] = useState(() => filterParam(initialParams, 'id'))
  const [policyID, setPolicyID] = useState(() => filterParam(initialParams, 'id'))
  const [status, setStatus] = useState<'enabled' | 'disabled'>()
  const [owner, setOwner] = useState(() => filterParam(initialParams, 'owner'))
  // 名称/ID/用户 边输入边生效（400ms 防抖），查询按钮即立即刷新。
  const [ownerDraft, setOwnerDraft] = useState(() => filterParam(initialParams, 'owner'))
  const [display, setDisplay] = useState<'all' | 'visible' | 'hidden'>('all')
  // CC rule group 类型 pill: system rows come from the catalog/projection, custom rows from the paged list.
  const [ruleType, setRuleType] = useState<'all' | 'system' | 'custom'>('all')
  const [selectedIDs, setSelectedIDs] = useState<string[]>([])
  // SEC-ACCOUNT-04: WAF 规则范围 is filtered on the server; batch actions go
  // through POST /v1/security-policies/batch (per item CAS + per item result).
  const [scope, setScope] = useState<SecurityPolicyScope>()
  const [batchConfirm, setBatchConfirm] = useState<SecurityPolicyBatchAction | null>(null)
  const [batchResults, setBatchResults] = useState<Array<SecurityPolicyBatchResult & { name: string }> | null>(null)
  const [editor, setEditor] = useState<SecurityPolicy | 'create' | null>(null)
  // CU-SITE-04: ?new_rule=allow (a site's 新增放行规则) opens the site's library (?policy_id) with an
  // allow rule appended, or a new library with one; the parameter is consumed once.
  const [searchParams, setSearchParams] = useSearchParams()
  const allowIntent = showActivation && searchParams.get('new_rule') === 'allow'
  const intentPolicyID = searchParams.get('policy_id') ?? ''
  const [appendAllowRule, setAppendAllowRule] = useState(false)
  // D3: an allow rule started from a site returns there (its WAF tab) when the editor
  // is cancelled; only the site ID of this page's own query is used (no external return URL).
  const [allowReturn, setAllowReturn] = useState('')
  const navigate = useNavigate()
  const intentPolicyQuery = useQuery({
    queryKey: ['security-policies', scopeID, sessionEpoch, kind, 'allow-intent', intentPolicyID],
    enabled: allowIntent && Boolean(intentPolicyID) && canManage,
    queryFn: async () => (await securityPoliciesApi.list(accessTokenRef.current, { page: 1, limit: 1, kind, id: intentPolicyID })).items[0] ?? null,
    retry: false,
  })
  useEffect(() => {
    // D2: only a successful read routes the intent; a failed read keeps it (no new
    // library, no publish) and the page offers a retry in place.
    if (!allowIntent || !canManage || intentPolicyID && !intentPolicyQuery.isSuccess) return
    const target = intentPolicyID ? intentPolicyQuery.data : null
    // A subscribed (protected) library is the provider's: the site gets its own new library instead.
    setEditor(target && !target.protected ? target : 'create')
    setAppendAllowRule(true)
    const next = new URLSearchParams(searchParams)
    next.delete('new_rule')
    setSearchParams(next, { replace: true })
    setAllowReturn(searchParams.get('site_id') ?? '')
  }, [allowIntent, canManage, intentPolicyID, intentPolicyQuery.data, intentPolicyQuery.isSuccess, searchParams, setSearchParams])
  const intentReadError = allowIntent && intentPolicyID && intentPolicyQuery.isError ? intentPolicyQuery.error : null
  const [attempt, setAttempt] = useState<WriteAttempt | null>(null)
  const [writeError, setWriteError] = useState<ApiError | null>(null)
  const [evaluating, setEvaluating] = useState<SecurityPolicy | null>(null)
  const [deleting, setDeleting] = useState<SecurityPolicy | null>(null)
  const [evaluation, setEvaluation] = useState<{ action: string; matched: number; usedDefault: boolean } | null>(null)
  const [systemDetails, setSystemDetails] = useState<OpenRestySecurityRuleGroup | null>(null)
  const [evaluationForm] = Form.useForm<EvaluationForm>()

  const query = useQuery({
    queryKey: ['security-policies', scopeID, sessionEpoch, kind, page, limit, name, policyID, status, display, owner, scope ?? ''],
    queryFn: () => securityPoliciesApi.list(accessTokenRef.current, {
      page, limit, kind, name: name || undefined, id: policyID || undefined,
      status: status ?? (display === 'visible' ? 'enabled' : display === 'hidden' ? 'disabled' : undefined),
      owner: isAdmin && owner ? owner : undefined,
      scope: kind === 'waf' ? scope : undefined,
    }),
  })
  const wafLibraries = useWAFLibraries(accessToken, () => void query.refetch())
  const groupsQuery = useQuery({
    queryKey: ['cc-rule-groups', scopeID, sessionEpoch],
    enabled: referenceLayout && kind === 'cc',
    queryFn: () => openrestySecurityApi.listRuleGroups(accessTokenRef.current),
  })
  // Once the signed catalog has synced, its single installation-wide copy
  // replaces the legacy per-tenant projection of system rule groups.
  const catalogKey = `${scopeID}:${sessionEpoch}`
  const catalogGroups = useSystemRules(accessToken, 'cc_rule_group', catalogKey)
  const catalogActive = (catalogGroups.data ?? []).length > 0
  const systemReferencesQuery = useQuery({
    queryKey: ['cc-system-rule-references', scopeID, sessionEpoch, systemDetails?.id ?? ''],
    enabled: referenceLayout && kind === 'cc' && Boolean(systemDetails),
    queryFn: async () => {
      const [matchers, filters] = await Promise.all([
        securityPoliciesApi.listReferences(accessTokenRef.current, 'matcher', { page: 1, limit: 100 }),
        securityPoliciesApi.listReferences(accessTokenRef.current, 'filter', { page: 1, limit: 100 }),
      ])
      return { matchers: matchers.items, filters: filters.items }
    },
  })
  // 规则组胶囊 counts over every group, not the current page.
  const summaryQuery = useQuery({
    queryKey: ['cc-rule-group-summary', scopeID, sessionEpoch],
    enabled: referenceLayout && kind === 'cc',
    queryFn: () => openrestySecurityApi.ruleGroupSummary(accessTokenRef.current),
  })
  const groupStateMutation = useMutation({
    mutationFn: ({ item, enabled }: { item: OpenRestySecurityRuleGroup; enabled: boolean }) => openrestySecurityApi.setRuleGroupEnabled(accessTokenRef.current, systemRuleValue(item), enabled),
    onSuccess: (_result, variables) => {
      setSystemDetails((current) => current && systemRuleValue(current) === systemRuleValue(variables.item) ? { ...current, enabled: variables.enabled } : current)
      queryClient.setQueryData<OpenRestySecurityRuleGroup[]>(['cc-rule-groups', scopeID, sessionEpoch], (groups) => groups?.map((group) => systemRuleValue(group) === systemRuleValue(variables.item) ? { ...group, enabled: variables.enabled } : group))
      void queryClient.invalidateQueries({ queryKey: ['cc-rule-groups', scopeID, sessionEpoch] })
      void queryClient.invalidateQueries({ queryKey: ['cc-rule-group-summary', scopeID, sessionEpoch] })
    },
    onError: (error) => {
      // Never leave the switch showing a state the server refused; re-read it.
      feedback.error(errorMessage(error instanceof ApiError ? error : new ApiError(String(error), 0, 'request_failed'), t))
      void queryClient.invalidateQueries({ queryKey: ['cc-rule-groups', scopeID, sessionEpoch] })
    },
  })
  const toggleSystemGroup = (item: OpenRestySecurityRuleGroup, enabled: boolean) => {
    if (!canManageSystemGroups || groupStateMutation.isPending) return
    groupStateMutation.mutate({ item, enabled })
  }

  const [savedForSite, setSavedForSite] = useState<{ id: string, version: number } | undefined>()
  // A refused field the open editor marked under the field (no dialog then).
  const [fieldMarked, setFieldMarked] = useState(false)
  const mutation = useMutation<SecurityPolicy | void, Error, WriteAttempt>({
    mutationFn: (next: WriteAttempt) => next.kind === 'create'
      ? securityPoliciesApi.create(accessTokenRef.current, next.input, next.key)
      : next.kind === 'update'
        ? securityPoliciesApi.update(accessTokenRef.current, next.id, next.version, next.input, next.key)
        : securityPoliciesApi.remove(accessTokenRef.current, next.id, next.version, next.key),
    onSuccess: (saved, completed) => {
      setAttempt(null)
      setWriteError(null)
      setEditor(null)
      setAppendAllowRule(false)
      void queryClient.invalidateQueries({ queryKey: ['security-policies', scopeID, sessionEpoch] })
      void queryClient.invalidateQueries({ queryKey: ['cc-rule-group-summary', scopeID, sessionEpoch] })
      messageApi.success(t(`notices.${completed.kind}`))
      // Opened for one site (?site_id): saving an enabled library publishes
      // it to that site's package line-group nodes (10-22 保存即下发).
      if (showActivation && saved && completed.kind !== 'delete' && saved.enabled) {
        setSavedForSite({ id: saved.id, version: saved.version })
      }
    },
    onError: (error, failed) => {
      const apiError = error instanceof ApiError ? error : new ApiError('request failed')
      setWriteError(apiError)
      if (unknownOutcome(error)) {
        setAttempt(failed)
        return
      }
      setAttempt(null)
      if (apiError.code === 'version_conflict') {
        setEditor(null)
        setWriteError(null)
        void queryClient.invalidateQueries({ queryKey: ['security-policies', scopeID, sessionEpoch] })
        feedback.error(t('notices.conflictRefreshed'))
      }
    },
  })

  const evaluateMutation = useMutation({
    mutationFn: ({ item, facts }: { item: SecurityPolicy; facts: RequestFacts }) => securityPoliciesApi.evaluate(accessTokenRef.current, item.id, item.version, facts),
    onSuccess: (result) => setEvaluation({ action: result.action, matched: result.matched_rule_ids.length, usedDefault: result.used_default }),
  })

  const batchMutation = useMutation({
    mutationFn: ({ action, items, key }: { action: SecurityPolicyBatchAction; items: SecurityPolicy[]; key: string }) =>
      securityPoliciesApi.batch(accessTokenRef.current, action, items.map((item) => ({ id: item.id, version: item.version })), key),
    onSuccess: (result, { items }) => {
      const names = new Map(items.map((item) => [item.id, item.name]))
      setBatchResults(result.items.map((item) => ({ ...item, name: names.get(item.id) ?? item.id })))
      // Rows written are deselected; refused rows stay selected for a retry with fresh versions.
      const done = new Set(result.items.filter((item) => item.status === 'ok' || item.status === 'unchanged').map((item) => item.id))
      setSelectedIDs((ids) => ids.filter((id) => !done.has(id)))
      void queryClient.invalidateQueries({ queryKey: ['security-policies', scopeID, sessionEpoch] })
    },
    onError: (error) => {
      feedback.error(errorMessage(error instanceof ApiError ? error : new ApiError(String(error), 0, 'request_failed'), t))
      void queryClient.invalidateQueries({ queryKey: ['security-policies', scopeID, sessionEpoch] })
    },
  })
  // 名称/ID/用户 边输入边生效（四种布局共用）。
  useLiveApply({ name: nameDraft.trim(), id: policyIDDraft.trim(), owner: ownerDraft.trim() }, { name, id: policyID, owner }, (next) => {
    setPage(1); setName(next.name); setPolicyID(next.id); setOwner(next.owner)
  })
  const ownerSearch = useMemo(() => isAdmin ? userSearch(accessToken) : undefined, [accessToken, isAdmin])
  useFilterUrl({ name, id: policyID, owner: isAdmin ? owner : '', status })
  const queryError = query.error instanceof ApiError ? query.error : null
  if (queryError?.status === 403) {
    return <Result className="identity-page identity-forbidden" status="403" title={t('errors.forbiddenTitle')} subTitle={t('errors.permission_denied')} />
  }
  const uncertain = Boolean(attempt && writeError && unknownOutcome(writeError))
  const writesLocked = mutation.isPending || uncertain
  // A field refusal of a save from the open editor goes to that editor.
  const fieldError = editor !== null && writeError && !uncertain && submitErrorFields(writeError).length > 0 ? writeError : null
  const wafReference = referenceLayout && kind === 'waf'
  const aclReference = kind === 'acl'
  const siteReturnID = /^[0-9a-f-]{36}$/i.test(searchParams.get('site_id') ?? '') ? searchParams.get('site_id') : null
  // 平台 WAF 规则库 rows (tp-b4): unsubscribed platform libraries join the first page; a subscribed
  // one is already listed as its protected copy, whose 订阅 cell and actions come from the library.
  // Unsubscribed platform libraries are 系统 rows; other scopes never list them.
  const pendingLibraries = wafReference && (!scope || scope === 'system') ? wafLibraries.libraries.filter((library) => library.subscription === 'not_subscribed' &&
    (!name || library.name.toLowerCase().includes(name.toLowerCase())) &&
    (!status || (status === 'enabled' ? library.enabled : !library.enabled))) : []
  const systemGroups = (groupsQuery.data ?? []).filter((item) => item.kind === 'system' && item.system_rule)
  const filteredSystemGroups = catalogActive ? [] : systemGroups.filter((item) =>
    (!name || item.name.toLowerCase().includes(name.toLowerCase())) &&
    (!policyID || item.id.includes(policyID)) &&
    (!status || (status === 'enabled' ? item.enabled : !item.enabled)) &&
    (display === 'all' || (display === 'visible' ? item.enabled : !item.enabled)))
  const ccRows: Array<PolicyTableRow> = referenceLayout && kind === 'cc'
    ? [...(ruleType === 'custom' ? [] : filteredSystemGroups), ...(ruleType === 'system' ? [] : query.data?.items ?? [])]
    : wafReference && page === 1 ? [...pendingLibraries, ...(query.data?.items ?? [])] : (query.data?.items ?? [])
  const deletableSelected = (query.data?.items ?? []).filter((item) => selectedIDs.includes(item.id) && !item.protected)
  const runBatch = (action: SecurityPolicyBatchAction) => {
    if (batchMutation.isPending || deletableSelected.length === 0) return
    batchMutation.mutate({ action, items: deletableSelected, key: writeKey(action === 'delete' ? 'delete' : action) })
  }
  // Pill counts from the server over every group (system = signed catalog when synced, else the projection).
  const ccSummary = summaryQuery.data
  const ccPill = ruleType !== 'all' ? ruleType : display === 'visible' ? 'visible' : status === 'disabled' ? 'disabled' : display === 'all' && !status ? 'all' : null
  const selectCCPill = (next: 'all' | 'system' | 'custom' | 'visible' | 'disabled') => {
    setPage(1)
    setRuleType(next === 'system' || next === 'custom' ? next : 'all')
    setDisplay(next === 'visible' ? 'visible' : 'all')
    setStatus(next === 'disabled' ? 'disabled' : undefined)
  }
  const catalogKind = referenceLayout && kind === 'cc' ? 'cc_rule_group' as const : wafReference ? 'waf_rule_set' as const : null

  const submit = (values: PolicyForm) => {
    if (writesLocked) return
    const fieldsValue = fieldsFromForm(values)
    // The rule editor does not edit the site settings (站点 CC 防护 page does);
    // an update replaces the policy, so send them back unchanged.
    if (editor !== 'create' && editor?.kind === 'cc' && editor.cc_settings) fieldsValue.cc_settings = editor.cc_settings
    const next: WriteAttempt = editor === 'create'
      ? { kind: 'create', input: { ...fieldsValue, target_scope_id: values.target_scope_id?.trim() || undefined, owner_id: values.owner_id?.trim() || undefined }, key: writeKey('create') }
      : { kind: 'update', id: editor!.id, version: editor!.version, input: fieldsValue, key: writeKey('update') }
    setAttempt(next)
    setWriteError(null)
    mutation.mutate(next)
  }

  const applyReferenceSearch = () => {
    setPage(1)
    setName(nameDraft.trim())
    setPolicyID(policyIDDraft.trim())
    setOwner(ownerDraft.trim())
  }
  const clearReferenceFilters = () => {
    setPage(1)
    setNameDraft('')
    setName('')
    setPolicyIDDraft('')
    setPolicyID('')
    setDisplay('all')
    setStatus(undefined)
    setOwnerDraft('')
    setOwner('')
    setRuleType('all')
  }

  const referenceMoreItems = [
    { key: 'challenges', label: t('cc.actions.challengePolicies') },
  ]

  const openEvaluation = (item: SecurityPolicy) => {
    setEvaluation(null)
    evaluationForm.setFieldsValue({ client_ip: '192.0.2.1', host: '', path: '/', method: 'GET', headers: '', country: 'CN', asn: 0, ja4: '', port: 443, distinct_user_agents: 0, status_404_count: 0 })
    setEvaluating(item)
  }

  const removePolicy = (item: SecurityPolicy) => {
    if (writesLocked) return // CU-CCWAF 卡08: the more menu / confirm keep the page's write lock
    const next: WriteAttempt = { kind: 'delete', id: item.id, version: item.version, key: writeKey('delete') }
    setAttempt(next)
    setWriteError(null)
    mutation.mutate(next)
  }

  const actionCell = (_: unknown, item: PolicyTableRow) => {
    const policy = item as SecurityPolicy
    return (
    <Space size={2}>
      <Tooltip title={t('actions.evaluate')}><Button type="text" size="small" aria-label={t('actions.evaluateNamed', { name: policy.name })} icon={<FlaskConical size={15} />} onClick={() => openEvaluation(policy)} /></Tooltip>
      {canManage ? <Tooltip title={t('actions.edit')}><Button type="text" size="small" aria-label={t('actions.editNamed', { name: policy.name })} icon={<Pencil size={15} />} disabled={writesLocked} onClick={() => setEditor(policy)} /></Tooltip> : null}
      {canManage ? <Popconfirm title={t('confirm.delete')} okButtonProps={{ danger: true }} okText={t('actions.delete')} cancelText={t('actions.cancel')} onConfirm={() => removePolicy(policy)}><Tooltip title={t('actions.delete')}><Button danger type="text" size="small" aria-label={t('actions.deleteNamed', { name: policy.name })} icon={<Trash2 size={15} />} disabled={writesLocked} /></Tooltip></Popconfirm> : null}
    </Space>
    )
  }

  const ccReferenceActionCell = (_: unknown, item: PolicyTableRow) => {
    if ('system_rule' in item && item.system_rule) {
      return <Space size={8} className="cc-reference-actions">
        <Button type="link" size="small" className="cc-reference-manage" aria-label={t('cc.actions.manage')} onClick={() => setSystemDetails(item)}>{t('cc.actions.manage')}</Button>
        {canManageSystemGroups ? <Dropdown trigger={['click']} menu={{ items: [{ key: 'state', label: item.enabled ? t('cc.actions.disable') : t('cc.actions.enable'), disabled: groupStateMutation.isPending }], onClick: () => toggleSystemGroup(item, !item.enabled) }}>
          <Button type="link" size="small" className="cc-reference-more" aria-label={t('cc.actions.rowMore')}>{t('cc.actions.rowMore')}<ChevronDown size={13} aria-hidden="true" /></Button>
        </Dropdown> : null}
      </Space>
    }
    const policy = item as SecurityPolicy
    return (
    <Space size={8} className="cc-reference-actions">
      <Tooltip title={t('actions.evaluate')}>
        <Button type="text" size="small" className="cc-reference-evaluate" aria-label={t('actions.evaluateNamed', { name: policy.name })} icon={<FlaskConical size={15} />} onClick={() => openEvaluation(policy)} />
      </Tooltip>
      {canManage ? <Button type="link" size="small" className="cc-reference-manage" aria-label={t('actions.editNamed', { name: policy.name })} disabled={writesLocked} onClick={() => setEditor(policy)}>{t('cc.actions.manage')}</Button> : null}
      <Dropdown
        trigger={['click']}
        menu={{
          items: [
            { key: 'evaluate', label: t('actions.evaluate') },
            ...(canManage ? [{ key: 'delete', label: t('actions.delete'), danger: true, disabled: writesLocked }] : []),
          ],
          onClick: ({ key }) => {
            if (key === 'evaluate') openEvaluation(policy)
            if (key === 'delete' && !writesLocked) setDeleting(policy)
          },
        }}
      >
        <Button type="link" size="small" className="cc-reference-more" aria-label={t('cc.actions.rowMore')}>{t('cc.actions.rowMore')}<ChevronDown size={13} aria-hidden="true" /></Button>
      </Dropdown>
    </Space>
    )
  }

  const aclActionCell = (_: unknown, item: PolicyTableRow) => {
    const policy = item as SecurityPolicy
    return (
    <Space size={2}>
      {canManage ? <Tooltip title={t('actions.edit')}><Button type="text" size="small" aria-label={t('actions.editNamed', { name: policy.name })} icon={<Pencil size={15} />} disabled={writesLocked} onClick={() => setEditor(policy)} /></Tooltip> : null}
      {canManage ? <Popconfirm title={t('confirm.delete')} okButtonProps={{ danger: true }} okText={t('actions.delete')} cancelText={t('actions.cancel')} onConfirm={() => { const next: WriteAttempt = { kind: 'delete', id: policy.id, version: policy.version, key: writeKey('delete') }; setAttempt(next); mutation.mutate(next) }}><Tooltip title={t('actions.delete')}><Button danger type="text" size="small" aria-label={t('actions.deleteNamed', { name: policy.name })} icon={<Trash2 size={15} />} disabled={writesLocked} /></Tooltip></Popconfirm> : null}
    </Space>
    )
  }

  const wafActionCell = (_: unknown, item: PolicyTableRow) => {
    if (isPlatformLibrary(item)) return canManage ? <Space size={8} className="waf-rule-row-actions"><WAFSubscriptionActions library={item} state={wafLibraries} /></Space> : null
    const policy = item as SecurityPolicy
    // A subscribed copy is read only: update or unsubscribe through its platform library.
    if (policy.protected) {
      const library = wafLibraries.forCopy(policy.library_id)
      return canManage && library ? <Space size={8} className="waf-rule-row-actions"><WAFSubscriptionActions library={library} state={wafLibraries} /></Space> : null
    }
    return (
    <Space size={8} className="waf-rule-row-actions">
      {canManage ? <Button type="link" size="small" disabled={writesLocked} onClick={() => setEditor(policy)}>{t('actions.edit')}</Button> : null}
      {canManage ? <Popconfirm title={t('confirm.delete')} okButtonProps={{ danger: true }} okText={t('actions.delete')} cancelText={t('actions.cancel')} onConfirm={() => removePolicy(policy)}><Button danger type="link" size="small" disabled={writesLocked}>{t('actions.delete')}</Button></Popconfirm> : null}
    </Space>
    )
  }

  const columns: TableColumnsType<PolicyTableRow> = aclReference ? [
    { title: t('acl.columns.id'), dataIndex: 'id', width: 170, ellipsis: true },
    ...(isAdmin ? [{ title: t('acl.columns.owner'), dataIndex: ['owner', 'display_name'], width: 120, ellipsis: true }] : []),
    { title: t('acl.columns.name'), dataIndex: 'name', width: 220, ellipsis: true },
    { title: t('acl.columns.remark'), key: 'remark', width: 280, ellipsis: true, render: (_: unknown, item: PolicyTableRow) => { const policy = item as SecurityPolicy; return <span title={policy.description || undefined}>{policy.description || t('acl.values.unavailable')}</span> } },
    { title: t('acl.columns.status'), dataIndex: 'enabled', width: 110, render: (value: boolean) => <Tag color={value ? 'success' : 'default'}>{t(value ? 'acl.values.enabled' : 'acl.values.disabled')}</Tag> },
    { title: t('acl.columns.actions'), key: 'actions', width: 110, fixed: 'right', render: aclActionCell },
  ] : wafReference ? [
    { title: t('waf.columns.id'), key: 'id', width: 64, ellipsis: true, render: (_: unknown, item: PolicyTableRow) => isPlatformLibrary(item) ? <span className="waf-rule-table-muted">{t('waf.values.unavailable')}</span> : item.id },
    { title: t('waf.columns.name'), key: 'name', width: 220, render: (_: unknown, item: PolicyTableRow) => { const policy = item as SecurityPolicy; return (
      <div className="waf-rule-name-cell">
        <span className="waf-rule-name-text" title={policy.name}>{policy.name || t('cc.values.unavailable')}</span>
        <span className={`waf-rule-description-text${policy.description ? '' : ' is-empty'}`} title={policy.description || undefined}>{policy.description || t('cc.values.unavailable')}</span>
      </div>
    ) } },
    { title: t('waf.columns.type'), key: 'type', width: 80, render: (_: unknown, item: PolicyTableRow) => isPlatformLibrary(item) || (item as SecurityPolicy).protected
      ? <span className="waf-rule-pill waf-rule-pill--primary">{t('waf.values.platform')}</span>
      : <span className="waf-rule-pill waf-rule-pill--muted">{t('waf.values.custom')}</span> },
    { title: t('waf.columns.scope'), key: 'scope', width: 80, render: (_: unknown, item: PolicyTableRow) => <span className="waf-rule-pill waf-rule-pill--muted">{isPlatformLibrary(item) ? t('waf.values.globalScope') : t('waf.values.userScope')}</span> },
    { title: t('waf.columns.owner'), key: 'owner', width: 120, ellipsis: true, render: (_: unknown, item: PolicyTableRow) => {
      const owner = isPlatformLibrary(item) || (item as SecurityPolicy).protected ? t('waf.values.platformOwner') : (item as SecurityPolicy).owner?.display_name || principal.display_name
      return <span className="waf-rule-owner-text" title={owner}>{owner}</span>
    } },
    { title: t('waf.columns.status'), dataIndex: 'enabled', width: 80, render: (value: boolean) => <span className={`waf-rule-pill ${value ? 'waf-rule-pill--success' : 'waf-rule-pill--muted'}`}>{t(value ? 'waf.values.enabled' : 'waf.values.disabled')}</span> },
    { title: t('waf.columns.subscription'), key: 'subscription', width: 100, render: (_: unknown, item: PolicyTableRow) => isPlatformLibrary(item)
      ? <WAFSubscriptionTag library={item} />
      : (item as SecurityPolicy).protected
        ? <WAFSubscriptionTag library={wafLibraries.forCopy((item as SecurityPolicy).library_id)} subscribedCopy />
        : <span className="waf-rule-table-muted">{t('waf.values.unavailable')}</span> },
    { title: t('waf.columns.updated'), dataIndex: 'updated_at', width: 170, render: (value: string) => <span className="waf-rule-table-muted">{formatReferenceDateTime(value, i18n.resolvedLanguage) || value}</span> },
    { title: t('waf.columns.actions'), key: 'actions', width: 130, render: wafActionCell },
  ] : referenceLayout ? [
    { title: t('cc.columns.id'), dataIndex: 'id', width: 100, ellipsis: true },
    {
      title: t('columns.name'), key: 'name', width: 210,
      render: (_: unknown, item: PolicyTableRow) => (
        <div className="cc-rule-name-cell">
          <span className="cc-rule-name-primary" title={item.name}>{item.name}</span>
          <small>{t('cc.values.sortMeta', { value: 'sort' in item ? item.sort ?? t('cc.values.unavailable') : 'rules' in item ? item.rules[0]?.priority ?? t('cc.values.unavailable') : t('cc.values.unavailable') })}</small>
        </div>
      ),
    },
    ...(isAdmin ? [{ title: t('columns.owner'), key: 'owner', width: 110, ellipsis: true, render: (_: unknown, item: PolicyTableRow) => {
      if (!('owner' in item) || !item.owner) return principal.display_name
      return typeof item.owner === 'string' ? item.owner : item.owner.display_name
    } }] : []),
    { title: t('cc.columns.type'), key: 'type', width: 95, render: (_: unknown, item: PolicyTableRow) => <span className="cc-reference-type">{'system_rule' in item && item.system_rule ? t('cc.values.system') : t('cc.values.custom')}</span> },
    { title: t('cc.columns.display'), dataIndex: 'enabled', width: 90, render: (value: boolean) => referenceCheck(value, t(value ? 'cc.values.visible' : 'cc.values.hidden')) },
    { title: t('columns.status'), dataIndex: 'enabled', width: 90, render: (value: boolean) => <span className={`cc-reference-status${value ? '' : ' cc-reference-status--muted'}`}><span className="cc-reference-status-dot" aria-hidden="true" />{t(value ? 'cc.values.normal' : 'states.disabled')}</span> },
    { title: t('cc.columns.createdAt'), dataIndex: 'created_at', width: 170, render: (value: string) => value ? formatReferenceDateTime(value, i18n.resolvedLanguage) || value : t('cc.values.unavailable') },
    { title: t('columns.actions'), key: 'actions', width: 130, render: ccReferenceActionCell },
  ] : [
    ...(isAdmin ? [{ title: t('columns.owner'), dataIndex: ['owner', 'display_name'], width: 150, ellipsis: true }] : []),
    { title: t('columns.name'), dataIndex: 'name', width: 180, ellipsis: true },
    { title: t('columns.kind'), dataIndex: 'kind', width: 90, render: (value: SecurityPolicyKind) => t(`kinds.${value}`) },
    { title: t('columns.defaultAction'), dataIndex: 'default_action', width: 110, render: (value: string) => <Tag color={value === 'block' ? 'error' : 'success'}>{t(`actionsMap.${value}`)}</Tag> },
    // Subscribed libraries ("@system/" copies) come back without their rules.
    { title: t('columns.rules'), dataIndex: 'rules', width: 90, render: (value: SecurityPolicyRule[] | null) => value?.length ?? '—' },
    { title: t('columns.status'), dataIndex: 'enabled', width: 100, render: (value: boolean) => <Tag color={value ? 'success' : 'default'}>{t(value ? 'states.enabled' : 'states.disabled')}</Tag> },
    { title: t('columns.version'), dataIndex: 'version', width: 90 },
    { title: t('columns.updatedAt'), dataIndex: 'updated_at', width: 180, render: (value: string) => formatDateTime(value, i18n.resolvedLanguage) || value },
    { title: t('columns.actions'), key: 'actions', width: 150, fixed: 'right', render: actionCell },
  ]

  return (
    <section className={aclReference ? 'identity-page acl-rule-page' : wafReference ? 'waf-rule-page' : referenceLayout ? 'cc-rule-table' : 'identity-page security-policies-generic-page'} aria-labelledby="security-policies-title">
      {messageContext}
      {wafReference && isAdmin ? <WAFRuleSubscriptionsPanel accessToken={accessToken} open={subscriptionsOpen} onClose={() => setSubscriptionsOpen(false)} /> : null}
      {aclReference ? (
        <>
          <h1 id="security-policies-title" className="visually-hidden">{t('titles.acl')}</h1>
          <div className="acl-rule-toolbar">
            {canManage ? <Button type="primary" disabled={writesLocked} onClick={() => setEditor('create')}>{t('acl.actions.add')}</Button> : null}
            <Dropdown
              trigger={['click']}
              menu={{ items: [{ key: 'refresh', label: t('acl.actions.refresh') }], onClick: () => void query.refetch() }}
            >
              <Button className="acl-rule-more-button">{t('acl.actions.more')}<ChevronDown size={14} aria-hidden="true" /></Button>
            </Dropdown>
            {/* SF-SECURITY-ENTRY-01: opened from a site (?site_id) -> back to that site's WAF tab */}
            {siteReturnID ? <Link className="acl-rule-back" to={`/site/${siteReturnID}/edit?tab=waf`}>{t('acl.actions.backToSite')}</Link> : null}
          </div>
          <div className="acl-rule-filters">
            <Select aria-label={t('acl.filters.status')} value={status ?? 'all'} onChange={(value) => { setPage(1); setStatus(value === 'all' ? undefined : value as 'enabled' | 'disabled') }} options={[
              { value: 'all', label: t('acl.filters.status') },
              { value: 'enabled', label: t('acl.values.enabled') },
              { value: 'disabled', label: t('acl.values.disabled') },
            ]} />
            <Input addonBefore={t('acl.filters.name')} aria-label={t('acl.filters.name')} value={nameDraft} placeholder={t('acl.filters.namePlaceholder')} allowClear onChange={(event) => setNameDraft(event.target.value)} onPressEnter={() => { setPage(1); setName(nameDraft.trim()) }} />
            <Input addonBefore={t('acl.filters.id')} aria-label={t('acl.filters.id')} value={policyIDDraft} placeholder={t('acl.filters.idPlaceholder')} allowClear onChange={(event) => setPolicyIDDraft(event.target.value)} onPressEnter={() => { setPage(1); setPolicyID(policyIDDraft.trim()) }} />
            {isAdmin ? <IdOrNameInput addonBefore={t('acl.columns.owner')} aria-label={t('acl.columns.owner')} value={ownerDraft} placeholder={t('acl.filters.ownerPlaceholder')} freeText search={ownerSearch} onChange={setOwnerDraft} /> : null}
            <Button type="link" className="acl-rule-clear" onClick={clearReferenceFilters}>{t('acl.actions.clear')}</Button>
          </div>
        </>
      ) : wafReference ? (
        <>
          <div className="waf-rule-page-head">
            <div className="waf-rule-title-row"><h1 id="security-policies-title">{t('waf.title')}</h1><span className="waf-rule-count-pill">{t('waf.count', { count: (query.data?.total ?? 0) + pendingLibraries.length })}</span></div>
            {canManage ? <Button type="primary" icon={<Plus size={15} />} disabled={writesLocked} onClick={() => setEditor('create')}>{t('waf.actions.addRule')}</Button> : null}
          </div>
          <div className="waf-rule-toolbar">
            <div className="waf-rule-search-row">
              <div className="waf-rule-name-search">
                <Input className="waf-rule-filter-name" value={nameDraft} aria-label={t('waf.filters.name')} placeholder={t('waf.filters.namePlaceholder')} allowClear onChange={(event) => setNameDraft(event.target.value)} onPressEnter={() => { setPage(1); setName(nameDraft.trim()) }} />
                <Button type="primary" onClick={() => { setPage(1); setName(nameDraft.trim()) }}>{t('waf.actions.search')}</Button>
              </div>
              <Select<SecurityPolicyScope> className="waf-rule-filter-scope" aria-label={t('waf.filters.scope')} placeholder={t('waf.filters.scope')} allowClear value={scope}
                onChange={(value) => { setPage(1); setSelectedIDs([]); setScope(value) }}
                options={(['global', 'site', 'system'] as const).map((value) => ({ value, label: t(`waf.scopes.${value}`) }))} />
              <Select className="waf-rule-filter-enable" aria-label={t('waf.filters.enable')} allowClear placeholder={t('waf.filters.enable')} value={status} onChange={(value) => { setPage(1); setStatus(value) }} options={[{ value: 'enabled', label: t('waf.values.enabled') }, { value: 'disabled', label: t('waf.values.disabled') }]} />
            </div>
            <div className={`waf-rule-toolbar-actions${isAdmin ? ' is-admin' : ''}`}>
              {isAdmin ? <Button className="waf-rule-update-subscription" icon={<RefreshCw size={14} />} onClick={() => setSubscriptionsOpen(true)}>{t('wafSubscriptions.open')}</Button> : null}
              <Dropdown trigger={['click']} menu={{
                items: [
                  { key: 'refreshSubscriptions', label: t('wafLibraries.refresh'), disabled: !canManage || wafLibraries.refresh.isPending },
                  ...(['enable', 'disable', 'delete'] as const).map((action) => ({
                    key: action, danger: action === 'delete',
                    label: t(`waf.actions.${action}Selected`, { count: deletableSelected.length }),
                    disabled: !canManage || writesLocked || batchMutation.isPending || deletableSelected.length === 0,
                  })),
                ],
                onClick: ({ key }) => {
                  if (key === 'refreshSubscriptions') wafLibraries.refresh.mutate()
                  if (key === 'enable' || key === 'disable' || key === 'delete') setBatchConfirm(key)
                },
              }}>
                <Button className="waf-rule-batch">{t('waf.actions.batch')}<ChevronDown size={14} aria-hidden="true" /></Button>
              </Dropdown>
              <Button className="waf-rule-refresh" icon={<RefreshCw size={14} />} loading={query.isFetching} onClick={() => { void query.refetch(); void queryClient.invalidateQueries({ queryKey: ['waf-rule-libraries'] }) }}>{t('waf.actions.refresh')}</Button>
            </div>
          </div>
        </>
      ) : referenceLayout ? (
        <>
          <div className="cc-rule-toolbar">
            <div className="cc-rule-toolbar-primary">
              {canManage ? <Button type="primary" icon={<Plus size={15} />} disabled={writesLocked} onClick={() => setEditor('create')}>{t('cc.actions.addGroup')}</Button> : null}
            <Button icon={<RefreshCw size={14} />} loading={query.isFetching || groupsQuery.isFetching} onClick={() => { void query.refetch(); void groupsQuery.refetch() }}>{t('actions.refresh')}</Button>
            </div>
            <Dropdown
              trigger={['click']}
              menu={{ items: referenceMoreItems, onClick: ({ key }) => { if (key === 'challenges') onOpenChallenges?.() } }}
            >
              <Button className="cc-rule-more-button">{t('cc.actions.more')}<ChevronDown size={14} aria-hidden="true" /></Button>
            </Dropdown>
          </div>
          {/* 常显 规则组名称 + 状态，类型/显示/规则组ID/用户ID 进高级筛选；查询提交名称、ID 与用户。 */}
          <AdvancedFilters
            className="cc-rule-advfilters"
            storageKey="cc-rule-groups"
            columns={4}
            primary={<>
              <Input addonBefore={t('cc.filters.name')} aria-label={t('cc.filters.name')} value={nameDraft} placeholder={t('cc.filters.namePlaceholder')} allowClear onChange={(event) => setNameDraft(event.target.value)} onPressEnter={applyReferenceSearch} />
              <Select className="cc-rule-filter-select cc-rule-filter-status" aria-label={t('cc.filters.status')} allowClear placeholder={t('cc.values.allStatuses')} value={status} onChange={(value) => { setPage(1); setStatus(value) }} options={[{ value: 'enabled', label: t('states.enabled') }, { value: 'disabled', label: t('states.disabled') }]} />
            </>}
            items={[
              ...(isAdmin ? [{ key: 'kind', label: t('cc.filters.kind'), field: <Select aria-label={t('cc.filters.kind')} value="all" options={[{ value: 'all', label: t('cc.values.allTypes') }]} /> }] : []),
              { key: 'display', label: t('cc.filters.display'), applied: display === 'all' ? undefined : t(`cc.values.${display}`),
                field: <Select aria-label={t('cc.filters.display')} value={display} onChange={(value) => { setPage(1); setDisplay(value) }} options={[
                  { value: 'all', label: t('cc.values.allVisible') },
                  { value: 'visible', label: t('cc.values.visible') },
                  { value: 'hidden', label: t('cc.values.hidden') },
                ]} /> },
              { key: 'id', label: t('cc.filters.id'), applied: policyID || undefined,
                field: <Input aria-label={t('cc.filters.id')} value={policyIDDraft} placeholder={t('cc.filters.idPlaceholder')} allowClear onChange={(event) => setPolicyIDDraft(event.target.value)} /> },
              ...(isAdmin ? [{ key: 'owner', label: t('cc.filters.owner'), applied: owner || undefined,
                field: <IdOrNameInput aria-label={t('cc.filters.owner')} value={ownerDraft} placeholder={t('cc.filters.ownerPlaceholder')} freeText search={ownerSearch} onChange={setOwnerDraft} /> }] : []),
            ]}
            onQuery={() => { if (nameDraft.trim() === name && policyIDDraft.trim() === policyID && ownerDraft.trim() === owner) void query.refetch(); else applyReferenceSearch() }}
            onReset={clearReferenceFilters}
            onClearAdvanced={() => { setPage(1); setDisplay('all'); setPolicyIDDraft(''); setPolicyID(''); setOwnerDraft(''); setOwner(''); setName(nameDraft.trim()) }}
            onRemove={(key) => {
              setPage(1)
              if (key === 'display') setDisplay('all')
              if (key === 'id') { setPolicyIDDraft(''); setPolicyID('') }
              if (key === 'owner') { setOwnerDraft(''); setOwner('') }
            }}
          />
          <div className="cc-rule-summary" role="group" aria-label={t('cc.summary.label')}>
            {([
              ['all', ccSummary?.all ?? 0, ''],
              ['system', ccSummary?.system ?? 0, ''],
              ['custom', ccSummary?.custom ?? 0, 'cc-rule-summary--primary'],
              ['visible', ccSummary?.visible ?? 0, 'cc-rule-summary--success'],
              ['disabled', ccSummary?.disabled ?? 0, 'cc-rule-summary--warning'],
            ] as const).map(([key, count, tone]) => (
              <button key={key} type="button" className={`${tone}${ccPill === key ? ' is-active' : ''}`} aria-pressed={ccPill === key} onClick={() => selectCCPill(key)}>
                {t(`cc.summary.${key}`)} <strong>{count}</strong>
              </button>
            ))}
          </div>
        </>
      ) : (
        <>
          <div className="identity-toolbar">
            <h1 id="security-policies-title">{t(`titles.${kind}`)}</h1>
            {canManage ? <Button type="primary" icon={<Plus size={15} />} disabled={writesLocked} onClick={() => setEditor('create')}>{t('actions.create')}</Button> : null}
          </div>
          <div className="identity-filter-bar">
            <Input.Search value={nameDraft} aria-label={t('filters.name')} placeholder={t('filters.name')} allowClear style={{ width: 240 }} onChange={(event) => setNameDraft(event.target.value)} onSearch={() => { setPage(1); setName(nameDraft.trim()) }} />
            <Select allowClear aria-label={t('filters.status')} placeholder={t('filters.status')} style={{ width: 150 }} value={status} onChange={(value) => { setPage(1); setStatus(value) }} options={[{ value: 'enabled', label: t('states.enabled') }, { value: 'disabled', label: t('states.disabled') }]} />
            {isAdmin ? <IdOrNameInput value={ownerDraft} aria-label={t('filters.owner')} placeholder={t('filters.owner')} style={{ width: 250 }} freeText search={ownerSearch} onChange={setOwnerDraft} /> : null}
            <Button icon={<RefreshCw size={14} />} aria-label={t('actions.refresh')} onClick={() => void query.refetch()} />
          </div>
        </>
      )}

			{writeError ? (uncertain ? <OutcomeUnknown type="error" title={t('uncertainty.title')} detail={t('uncertainty.description')} action={<Space><Button size="small" onClick={() => { if (attempt) mutation.mutate(attempt) }}>{t('actions.retrySameRequest')}</Button><Button size="small" onClick={() => { setAttempt(null); setWriteError(null); setEditor(null); void query.refetch() }}>{t('actions.closeAndRefresh')}</Button></Space>} className="identity-alert" /> : fieldError && fieldMarked ? null : <FeedbackWhen title={errorMessage(writeError, t)} detail={importErrorDescription(writeError, t) ?? inUseDescription(writeError, kind, t, () => setWriteError(null))} />) : null}
      {query.isError ? <FeedbackWhen title={t('errors.loadFailed')} detail={queryError ? errorMessage(queryError, t) : t('errors.request_failed')} action={<Button size="small" onClick={() => void query.refetch()}>{t('actions.retry')}</Button>} /> : null}

      {(kind === 'waf' || kind === 'cc') && principal.scope_kind === 'tenant' ? <RebindStatusNotice accessToken={accessToken} kind={kind} cacheKey={catalogKey} /> : null}
      {kind === 'waf' ? <WAFPendingPublications accessToken={accessToken} policies={query.data?.items ?? []} canManage={canManage} /> : null}
      {wafReference ? wafLibraries.messageContext : null}
      {wafReference && wafLibraries.loadError ? <FeedbackWhen title={t('wafLibraries.loadFailed')}
        detail={localizedUnknownApiError(wafLibraries.loadError, t('errors.request_failed'))}
        action={<Button size="small" onClick={wafLibraries.retry}>{t('actions.retry')}</Button>} /> : null}
      {intentReadError ? <Alert className="identity-alert" type="error" showIcon role="alert" message={t('allowIntent.loadFailed')}
        description={localizedUnknownApiError(intentReadError, t('errors.request_failed'))}
        action={<Button size="small" onClick={() => void intentPolicyQuery.refetch()}>{t('actions.retry')}</Button>} /> : null}
      {showActivation ? <SecurityActivationPanel
          kind={kind}
          policies={query.data?.items ?? []}
          policiesLoading={query.isPending || query.isFetching}
          autoPublish={savedForSite}
        /> : null}

      {catalogKind && !(catalogKind === 'cc_rule_group' && ruleType === 'custom') ? <SystemRuleCatalogSection accessToken={accessToken} kind={catalogKind} cacheKey={catalogKey} isAdmin={isAdmin} canManage={canManage} /> : null}
      <div className={aclReference ? 'acl-rule-table-scroll' : wafReference ? 'waf-rule-table-scroll' : referenceLayout ? 'cc-rule-table-scroll' : 'identity-table-scroll'} data-testid="security-policy-table-scroll" aria-busy={query.isPending || query.isFetching}>
        <Table rowKey="id" size="small" rowSelection={wafReference
          ? { columnWidth: 40, selectedRowKeys: selectedIDs, onChange: (keys) => setSelectedIDs(keys.map(String)), getCheckboxProps: (item) => ({ disabled: isPlatformLibrary(item) || Boolean((item as SecurityPolicy).protected) }) }
          : aclReference || referenceLayout ? { columnWidth: 60 } : undefined} columns={columns} dataSource={ccRows} loading={query.isPending || query.isFetching || groupsQuery.isFetching} pagination={false} locale={{ emptyText: query.isPending ? ' ' : t(aclReference ? 'acl.values.empty' : 'values.empty') }} scroll={{ x: aclReference ? (isAdmin ? 1020 : 900) : wafReference ? 1097 : referenceLayout ? (isAdmin ? 1100 : 960) : (isAdmin ? 1280 : 1120) }} />
      </div>
      <div className={aclReference ? 'acl-rule-pagination' : wafReference ? 'waf-rule-pagination' : referenceLayout ? 'cc-rule-pagination' : 'identity-pagination'}>
        <Pagination current={page} pageSize={limit} total={(query.data?.total ?? 0) + pendingLibraries.length} showTotal={wafReference ? (total) => t('waf.pagination.total', { count: total }) : referenceLayout ? (total) => t('cc.pagination.total', { count: total }) : aclReference ? (total) => t('acl.pagination.total', { count: total }) : undefined} showSizeChanger={!wafReference} pageSizeOptions={referenceLayout || aclReference ? [10, 20, 50] : [10, 20, 50, 100]} onChange={(nextPage, nextLimit) => { setPage(nextLimit === limit ? nextPage : 1); setLimit(nextLimit) }} />
      </div>

      <Modal
        open={Boolean(batchConfirm)}
        title={batchConfirm ? t(`waf.actions.${batchConfirm}SelectedConfirm`, { count: deletableSelected.length }) : ''}
        okText={batchConfirm === 'delete' ? t('actions.delete') : t('actions.confirm')}
        cancelText={t('actions.cancel')}
        okButtonProps={{ danger: batchConfirm === 'delete' }}
        onCancel={() => setBatchConfirm(null)}
        onOk={() => { const action = batchConfirm; setBatchConfirm(null); if (action) runBatch(action) }}
      />
      <Modal
        open={Boolean(batchResults)}
        title={t('waf.batch.resultTitle')}
        footer={<Button type="primary" onClick={() => setBatchResults(null)}>{t('waf.batch.close')}</Button>}
        onCancel={() => setBatchResults(null)}
      >
        <Table<SecurityPolicyBatchResult & { name: string }> rowKey="id" size="small" pagination={false} dataSource={batchResults ?? []} columns={[
          { title: t('waf.columns.name'), dataIndex: 'name', ellipsis: true },
          { title: t('waf.batch.result'), dataIndex: 'status', width: 180, render: (value: SecurityPolicyBatchResult['status']) => (
            <span className={`waf-rule-pill ${value === 'ok' || value === 'unchanged' ? 'waf-rule-pill--success' : 'waf-rule-pill--muted'}`}>{t(`waf.batch.status.${value}`)}</span>
          ) },
        ]} />
      </Modal>

      <Modal
        open={Boolean(deleting)}
        title={t('confirm.delete')}
        okText={t('actions.delete')}
        cancelText={t('actions.cancel')}
        okButtonProps={{ danger: true }}
        onCancel={() => setDeleting(null)}
        onOk={() => {
          const item = deleting
          setDeleting(null)
          if (item) removePolicy(item)
        }}
      />

      <CCSystemRuleEditor
        open={Boolean(systemDetails)}
        group={systemDetails}
        matchers={systemReferencesQuery.data?.matchers ?? []}
        filters={systemReferencesQuery.data?.filters ?? []}
        loading={systemReferencesQuery.isPending || systemReferencesQuery.isFetching}
        pending={groupStateMutation.isPending}
        canToggle={canManageSystemGroups}
        onToggle={(enabled) => { if (systemDetails) toggleSystemGroup(systemDetails, enabled) }}
        onClose={() => setSystemDetails(null)}
      />

      <PolicyEditor open={editor !== null} item={editor === 'create' ? null : editor} kind={kind} isAdmin={isAdmin} pending={mutation.isPending} onCancel={() => {
        if (writesLocked) return
        setEditor(null); setAppendAllowRule(false); if (fieldError) setWriteError(null)
        if (allowReturn && /^[0-9a-f-]{36}$/i.test(allowReturn)) { setAllowReturn(''); navigate(`/site/${allowReturn}/edit?tab=waf`) }
      }} onSubmit={submit}
        submitError={fieldError} onFieldMarked={setFieldMarked} accessToken={accessToken} catalogKey={catalogKey} appendAllowRule={appendAllowRule}
        createTarget={searchParams.get('tenant_scope_id') && searchParams.get('owner_id') ? { scopeId: searchParams.get('tenant_scope_id')!, ownerId: searchParams.get('owner_id')! } : undefined} canListTenants={principal.permissions.includes('identity.users.manage') || principal.permissions.includes('platform.admin')} />

      <Modal className="security-policy-modal security-policy-evaluation-modal" title={t('evaluate.title')} open={evaluating !== null} confirmLoading={evaluateMutation.isPending} okText={t('actions.evaluate')} cancelText={t('actions.cancel')} onCancel={() => setEvaluating(null)} onOk={() => void evaluationForm.validateFields().then((values) => { if (evaluating) evaluateMutation.mutate({ item: evaluating, facts: { ...values, headers: parsePreviewHeaders(values.headers), host: values.host ?? '', country: values.country ?? '', ja4: values.ja4 ?? '' } }) }).catch(() => undefined)}>
        <Form form={evaluationForm} layout="vertical" requiredMark={false}>
          <Space wrap size={10}>
            <Form.Item name="client_ip" label={t('evaluate.clientIp')} rules={[{ required: true }]}><Input style={{ width: 190 }} /></Form.Item>
            <Form.Item name="host" label={t('evaluate.host')}><Input style={{ width: 190 }} /></Form.Item>
            <Form.Item name="path" label={t('evaluate.path')} rules={[{ required: true }]}><Input style={{ width: 190 }} /></Form.Item>
            <Form.Item name="method" label={t('evaluate.method')} rules={[{ required: true }]}><Input style={{ width: 110 }} /></Form.Item>
            <Form.Item name="country" label={t('evaluate.country')}><Input style={{ width: 90 }} /></Form.Item>
            <Form.Item name="asn" label={t('evaluate.asn')}><InputNumber min={0} precision={0} /></Form.Item>
            <Form.Item name="ja4" label={t('evaluate.ja4')}><Input placeholder={t('evaluate.ja4Placeholder')} style={{ width: 190 }} /></Form.Item>
            <Form.Item name="port" label={t('evaluate.port')} rules={[{ required: true }]}><InputNumber min={0} max={65535} precision={0} /></Form.Item>
            <Form.Item name="distinct_user_agents" label={t('evaluate.distinctUserAgents')} rules={[{ required: true }]}><InputNumber min={0} max={1024} precision={0} /></Form.Item>
            <Form.Item name="status_404_count" label={t('evaluate.status404Count')} rules={[{ required: true }]}><InputNumber min={0} max={1024} precision={0} /></Form.Item>
          </Space>
          <Form.Item name="headers" label={t('evaluate.headers')} extra={t('evaluate.headersCanonicalHint')} rules={[{
            validator: (_, value: string) => {
              try { parsePreviewHeaders(value ?? ''); return Promise.resolve() } catch { return Promise.reject(new Error(t('evaluate.headersInvalid'))) }
            },
          }]}><Input.TextArea rows={3} /></Form.Item>
        </Form>
        {evaluateMutation.isError ? <Alert type="error" showIcon message={t('errors.evaluateFailed')} /> : null}
        {evaluation ? <Alert type={evaluation.action === 'block' ? 'error' : 'success'} showIcon message={t('evaluate.result', { action: t(`actionsMap.${evaluation.action}`), count: evaluation.matched })} description={evaluation.usedDefault ? t('evaluate.defaultUsed') : t('evaluate.ruleUsed')} /> : null}
      </Modal>
    </section>
  )
}

type CCReferenceForm = {
  target_scope_id?: string
  owner_id?: string
  name: string
  description: string
  enabled: boolean
  field: string
  operator: string
  key?: string
  values: string
  type: string
  parameters: string
  within_second?: number | null
  max_req?: number | null
  max_req_per_uri?: number | null
}

function CCReferenceEditor({
  open, item, isMatcher, isAdmin, pending, onCancel, onSubmit,
}: {
  open: boolean
  item: SecurityPolicyReference | 'create' | null
  isMatcher: boolean
  isAdmin: boolean
  pending: boolean
  onCancel: () => void
  onSubmit: (values: CCReferenceForm) => void
}) {
  const { t } = useTranslation('securityPolicies')
  const [form] = Form.useForm<CCReferenceForm>()
  useEffect(() => {
    if (!open) return
    if (item === 'create' || !item) {
      form.setFieldsValue({ name: '', description: '', enabled: true, field: 'path', operator: 'equals', key: '', values: '', type: 'req_rate', parameters: '{}', within_second: null, max_req: null, max_req_per_uri: null })
      return
    }
    const { numbers, rest } = splitFilterParameters(item.parameters)
    form.setFieldsValue({
      name: item.name, description: item.description ?? '', enabled: item.status === 'enabled', field: item.field ?? 'path',
      operator: item.operator ?? 'equals', key: item.key ?? '', values: (item.values ?? []).join('\n'), type: item.type ?? 'req_rate',
      parameters: JSON.stringify(rest, null, 2),
      within_second: numbers.within_second ?? null, max_req: numbers.max_req ?? null, max_req_per_uri: numbers.max_req_per_uri ?? null,
    })
  }, [form, item, open])
  const title = item === 'create' ? t(isMatcher ? 'cc.editor.createMatcher' : 'cc.editor.createFilter') : t(isMatcher ? 'cc.editor.editMatcher' : 'cc.editor.editFilter')
  return (
    <Modal
      className="security-policy-modal"
      title={title}
      open={open}
      confirmLoading={pending}
      okText={t('actions.save')}
      cancelText={t('actions.cancel')}
      onCancel={onCancel}
      onOk={() => void form.submit()}
      destroyOnClose
    >
      <Form form={form} layout="vertical" requiredMark={false} onFinish={onSubmit}>
        {isAdmin && item === 'create' ? <Space wrap>
          <Form.Item name="target_scope_id" label={t('editor.targetScope')}><Input placeholder={t('cc.editor.targetScopePlaceholder')} /></Form.Item>
          <Form.Item name="owner_id" label={t('editor.owner')}><Input placeholder={t('cc.editor.ownerPlaceholder')} /></Form.Item>
        </Space> : null}
        <Form.Item name="name" label={t('cc.editor.name')} rules={[{ required: true, message: t('cc.editor.nameRequired') }]}><Input maxLength={128} /></Form.Item>
        <Form.Item name="description" label={t('cc.editor.description')}><Input.TextArea rows={2} maxLength={1000} /></Form.Item>
        {isMatcher ? <>
          <Space wrap>
            <Form.Item name="field" label={t('cc.editor.field')} rules={[{ required: true }]}>
              <Select
                style={{ width: 180 }}
                options={ccFields.map((field) => ({ value: field, label: t(`fields.${field}`) }))}
                onChange={(value: string) => form.setFieldValue('operator', conditionOperators('cc', value)[0])}
              />
            </Form.Item>
            <Form.Item noStyle shouldUpdate={(previous, current) => previous.field !== current.field}>
              {({ getFieldValue }) => {
                const field = getFieldValue('field') as string
                return (
                  <Form.Item name="operator" label={t('cc.editor.operator')} rules={[{ required: true }]}>
                    <Select style={{ width: 180 }} options={conditionOperators('cc', field || 'path').map((operator) => ({ value: operator, label: t(`operatorsMap.${operator}`) }))} />
                  </Form.Item>
                )
              }}
            </Form.Item>
          </Space>
          <Form.Item name="key" label={t('cc.editor.key')}><Input maxLength={128} /></Form.Item>
          <Form.Item name="values" label={t('cc.editor.values')}><Input.TextArea rows={4} placeholder={t('cc.editor.valuesPlaceholder')} /></Form.Item>
        </> : <>
          <Form.Item noStyle shouldUpdate={(previous, current) => previous.type !== current.type}>
            {({ getFieldValue }) => (
              <Form.Item name="type" label={t('cc.editor.type')} rules={[{ required: true }]}>
                <Select virtual={false} options={ccFilterTypeOptions(t, getFieldValue('type'))} />
              </Form.Item>
            )}
          </Form.Item>
          <Space wrap>
            <Form.Item name="within_second" label={t('cc.editor.withinSecond')}><InputNumber min={1} max={86_400} precision={0} style={{ width: 160 }} /></Form.Item>
            <Form.Item name="max_req" label={t('cc.editor.maxReq')}><InputNumber min={1} max={1_000_000} precision={0} style={{ width: 160 }} /></Form.Item>
            <Form.Item name="max_req_per_uri" label={t('cc.editor.maxReqPerUri')} extra={t('cc.editor.maxReqPerUriHint')}><InputNumber min={0} max={1_000_000} precision={0} style={{ width: 160 }} /></Form.Item>
          </Space>
          <Form.Item name="parameters" label={t('cc.editor.parameters')} extra={t('cc.editor.parametersHint')} rules={[{ required: true, validator: (_, value) => { try { const parsed: unknown = JSON.parse(value || '{}'); return isParameterObject(parsed) ? Promise.resolve() : Promise.reject(new Error(t('cc.editor.parametersInvalid'))) } catch { return Promise.reject(new Error(t('cc.editor.parametersInvalid'))) } } }]}><Input.TextArea rows={5} /></Form.Item>
        </>}
        <Form.Item name="enabled" label={t('cc.editor.enabled')} valuePropName="checked"><Switch /></Form.Item>
      </Form>
    </Modal>
  )
}

function CCReferenceUnavailableView({
  accessToken,
  principal,
  scopeID,
  sessionEpoch,
  kind,
  onOpenChallenges,
}: {
  accessToken: string
  principal: Principal
  scopeID: string
  sessionEpoch: number
  kind: 'matchers' | 'filters'
  onOpenChallenges: () => void
}) {
  const { t, i18n } = useTranslation('securityPolicies')
  const accessTokenRef = useRef(accessToken)
  accessTokenRef.current = accessToken
  const isAdmin = roleForPrincipal(principal) === 'admin'
  const canManage = principal.permissions.includes('security_policies.manage') || principal.permissions.includes('platform.admin')
  const isMatcher = kind === 'matchers'
  const referenceKind = isMatcher ? 'matcher' as const : 'filter' as const
  const queryClient = useQueryClient()
  const [messageApi, messageContext] = useFeedbackMessage()
  const feedback = useFeedback()
  const [page, setPage] = useState(1)
  const [limit, setLimit] = useState(10)
  // 已生效条件写进 URL，打开分享链接时读回。
  const [initialParams] = useSearchParams()
  const [nameDraft, setNameDraft] = useState(() => filterParam(initialParams, 'name'))
  const [name, setName] = useState(() => filterParam(initialParams, 'name'))
  const [idDraft, setIDDraft] = useState(() => filterParam(initialParams, 'id'))
  const [id, setID] = useState(() => filterParam(initialParams, 'id'))
  const [status, setStatus] = useState<'enabled' | 'disabled'>()
  const [owner, setOwner] = useState(() => filterParam(initialParams, 'owner'))
  const [ownerDraft, setOwnerDraft] = useState(() => filterParam(initialParams, 'owner'))
  const [editor, setEditor] = useState<SecurityPolicyReference | 'create' | null>(null)
  const [deleting, setDeleting] = useState<SecurityPolicyReference | null>(null)
  const [writeError, setWriteError] = useState<ApiError | null>(null)
  const [attempt, setAttempt] = useState<{ action: 'create' | 'update' | 'delete' | 'state'; item?: SecurityPolicyReference; values?: CCReferenceForm; enabled?: boolean; key: string } | null>(null)
  const query = useQuery({
    queryKey: ['security-policy-references', scopeID, sessionEpoch, kind, page, limit, name, id, status, owner],
    queryFn: () => securityPoliciesApi.listReferences(accessTokenRef.current, isMatcher ? 'matcher' : 'filter', {
      page, limit, name: name || undefined, id: id || undefined, status, owner: isAdmin && owner ? owner : undefined,
    }),
  })
  const catalogKey = `${scopeID}:${sessionEpoch}`
  const catalogKind = isMatcher ? 'cc_matcher' as const : 'cc_filter' as const
  const catalogRules = useSystemRules(accessToken, catalogKind, catalogKey)
  // The signed catalog's copy replaces legacy per-tenant system projections.
  const referenceRows = (catalogRules.data ?? []).length > 0
    ? (query.data?.items ?? []).filter((item) => !item.system_rule)
    : (query.data?.items ?? [])
  const queryError = query.error instanceof ApiError ? query.error : null
  const mutation = useMutation({
    mutationFn: async (next: NonNullable<typeof attempt>) => {
      if (next.action === 'create' && next.values) {
        const input = referenceInput(next.values, isMatcher)
        return securityPoliciesApi.createReference(accessTokenRef.current, referenceKind, { ...input, target_scope_id: next.values.target_scope_id?.trim() || undefined, owner_id: next.values.owner_id?.trim() || undefined }, next.key)
      }
      if (next.action === 'update' && next.item && next.values) return securityPoliciesApi.updateReference(accessTokenRef.current, referenceKind, next.item.id, next.item.version ?? 1, referenceInput(next.values, isMatcher), next.key)
      if (next.action === 'state' && next.item) return securityPoliciesApi.setReferenceEnabled(accessTokenRef.current, referenceKind, next.item.id, next.item.version ?? 1, Boolean(next.enabled), next.key)
      if (next.action === 'delete' && next.item) return securityPoliciesApi.removeReference(accessTokenRef.current, referenceKind, next.item.id, next.item.version ?? 1, next.key)
      throw new Error('invalid CC reference write')
    },
    onSuccess: (_, completed) => {
      setAttempt(null); setWriteError(null); setEditor(null)
      void queryClient.invalidateQueries({ queryKey: ['security-policy-references', scopeID, sessionEpoch, kind] })
      messageApi.success(t(`cc.notices.${completed.action}`))
    },
    onError: (error, failed) => {
      const apiError = error instanceof ApiError ? error : new ApiError('request failed')
      setWriteError(apiError)
      if (unknownOutcome(error)) setAttempt(failed)
      else if (apiError.code === 'version_conflict') { setAttempt(null); setEditor(null); void query.refetch(); feedback.error(t('notices.conflictRefreshed')) }
    },
  })
  // 名称/ID/用户 边输入边生效。
  useLiveApply({ name: nameDraft.trim(), id: idDraft.trim(), owner: ownerDraft.trim() }, { name, id, owner }, (next) => {
    setPage(1); setName(next.name); setID(next.id); setOwner(next.owner)
  })
  const ownerSearch = useMemo(() => isAdmin ? userSearch(accessToken) : undefined, [accessToken, isAdmin])
  useFilterUrl({ name, id, owner: isAdmin ? owner : '', status })
  const writesLocked = mutation.isPending || Boolean(attempt && writeError && unknownOutcome(writeError))
  if (queryError?.status === 403) {
    return (
      <section className="cc-rule-unavailable" aria-labelledby={`cc-${kind}-title`}>
        {messageContext}
        <Result className="identity-forbidden" status="403" title={t('errors.forbiddenTitle')} subTitle={t('errors.permission_denied')} />
        <span id={`cc-${kind}-title`} className="sr-only">{t(isMatcher ? 'cc.tabs.matchers' : 'cc.tabs.filters')}</span>
      </section>
    )
  }
  const applySearch = () => {
    setPage(1)
    setName(nameDraft.trim())
    setID(idDraft.trim())
    setOwner(ownerDraft.trim())
  }
  const clearFilters = () => {
    setPage(1)
    setNameDraft('')
    setName('')
    setIDDraft('')
    setID('')
    setStatus(undefined)
    setOwnerDraft('')
    setOwner('')
  }
  const typeLabel = (value: string | undefined) => {
    if (!value) return t('cc.values.unavailable')
    const known: Record<string, string> = {
      req_rate: 'cc.types.reqRate', browser_verify_auto: 'cc.types.browserVerify', five_second: 'cc.types.fiveSecond',
      click: 'cc.types.click', simple_click: 'cc.types.simpleClick', slider: 'cc.types.slider',
      simple_slider: 'cc.types.simpleSlider', captcha: 'cc.types.captcha', rotate_image: 'cc.types.rotateImage',
      '302_challenge': 'cc.types.redirect', url_auth: 'cc.types.urlAuth', challenge: 'cc.types.challenge',
    }
    return known[value] ? t(known[value]) : t('cc.values.custom')
  }
  const submit = (values: CCReferenceForm) => {
    if (writesLocked || !editor) return
    const action = editor === 'create' ? 'create' : 'update'
    const next = { action, item: editor === 'create' ? undefined : editor, values, key: writeKey(action) } as const
    setAttempt(next); setWriteError(null); mutation.mutate(next)
  }
  // CU-CCWAF 卡08: every write entry of the page keeps the same lock as 添加 — an unknown
  // result is resolved by retrying that same request (its key), never by a second new write.
  const remove = (item: SecurityPolicyReference) => {
    if (writesLocked) return
    const next = { action: 'delete' as const, item, key: writeKey('delete') }
    setAttempt(next); setWriteError(null); mutation.mutate(next)
  }
  const setEnabled = (item: SecurityPolicyReference, enabled: boolean) => {
    if (writesLocked) return
    const next = { action: 'state' as const, item, enabled, key: writeKey(enabled ? 'enable' : 'disable') }
    setAttempt(next); setWriteError(null); mutation.mutate(next)
  }
  const columns: TableColumnsType<SecurityPolicyReference> = [
    { title: t('cc.columns.id'), dataIndex: 'id', width: 170, ellipsis: true },
    ...(isAdmin ? [{ title: t('columns.owner'), dataIndex: ['owner', 'display_name'], width: 120, ellipsis: true }] : []),
    { title: t('cc.columns.name'), dataIndex: 'name', width: 180, ellipsis: true },
    ...(isAdmin || isMatcher ? [{ title: t('cc.columns.systemRule'), dataIndex: 'system_rule', width: 100, render: (value: boolean) => referenceCheck(value, value ? t('cc.values.system') : t('cc.values.custom')) }] : []),
    ...(isMatcher ? [] : [{ title: t('cc.columns.type'), dataIndex: 'type', width: 130, render: (value: string) => typeLabel(value) }]),
    { title: t('columns.status'), dataIndex: 'status', width: 90, render: (value: SecurityPolicyReference['status']) => <Tag color={value === 'enabled' ? 'success' : 'default'}>{t(value === 'enabled' ? 'states.enabled' : 'states.disabled')}</Tag> },
    { title: t('cc.columns.createdAt'), dataIndex: 'created_at', width: 170, render: (value: string) => formatReferenceDateTime(value, i18n.resolvedLanguage) || value },
    { title: t('columns.actions'), key: 'actions', width: 150, render: (_value, item) => <Space size={8} className="cc-reference-actions">
      {canManage && !item.system_rule ? <Button type="link" size="small" className="cc-reference-manage" aria-label={t('actions.editNamed', { name: item.name })} disabled={writesLocked} onClick={() => setEditor(item)}>{t('cc.actions.manage')}</Button> : null}
      <Dropdown
        trigger={['click']}
        menu={{
          items: [
            ...(canManage ? [
              { key: 'state', label: item.status === 'enabled' ? t('cc.actions.disable') : t('cc.actions.enable') },
              ...(!item.system_rule ? [{ key: 'delete', label: t('actions.delete'), danger: true }] : []),
            ] : []),
          ],
          onClick: ({ key }) => {
            if (writesLocked) return
            if (key === 'state') setEnabled(item, item.status !== 'enabled')
            if (key === 'delete') setDeleting(item)
          },
        }}
      >
        <Button type="link" size="small" className="cc-reference-more" aria-label={t('cc.actions.rowMore')} disabled={canManage && writesLocked}>{t('cc.actions.rowMore')}<ChevronDown size={13} aria-hidden="true" /></Button>
      </Dropdown>
    </Space> },
  ]
  return (
    <section className="cc-rule-unavailable" aria-labelledby={`cc-${kind}-title`}>
      {messageContext}
      <div className="cc-rule-toolbar">
        {canManage ? <Button type="primary" icon={<Plus size={15} />} disabled={writesLocked} onClick={() => setEditor('create')}>{t(isMatcher ? 'cc.actions.addMatcher' : 'cc.actions.addFilter')}</Button> : null}
        <Dropdown
          trigger={['click']}
          menu={{ items: [
            { key: 'challenge', label: t('cc.actions.challengePolicies') },
          ], onClick: onOpenChallenges }}
        >
          <Button className="cc-rule-more-button">{t('cc.actions.more')}<ChevronDown size={14} aria-hidden="true" /></Button>
        </Dropdown>
      </div>
      {writeError ? (unknownOutcome(writeError) ? <OutcomeUnknown type="error" title={t('uncertainty.title')} action={<Space><Button size="small" onClick={() => { if (attempt) mutation.mutate(attempt) }}>{t('actions.retrySameRequest')}</Button><Button size="small" onClick={() => { setAttempt(null); setWriteError(null); setEditor(null); void query.refetch() }}>{t('actions.closeAndRefresh')}</Button></Space>} className="identity-alert" /> : <FeedbackWhen title={errorMessage(writeError, t)} />) : null}
      {/* 常显 名称 + 状态，类型/ID/用户ID 进高级筛选。 */}
      <AdvancedFilters
        className="cc-rule-advfilters"
        storageKey={`cc-${kind}`}
        columns={3}
        primary={<>
          <Input addonBefore={t(isMatcher ? 'cc.filters.matcherName' : 'cc.filters.filterName')} aria-label={t(isMatcher ? 'cc.filters.matcherName' : 'cc.filters.filterName')} value={nameDraft} placeholder={t(isMatcher ? 'cc.filters.matcherNamePlaceholder' : 'cc.filters.filterNamePlaceholder')} allowClear onChange={(event) => setNameDraft(event.target.value)} onPressEnter={applySearch} />
          <Select className="cc-rule-filter-select cc-rule-filter-status" aria-label={t('cc.filters.status')} allowClear placeholder={t('cc.values.allStatuses')} value={status} onChange={(value) => { setPage(1); setStatus(value) }} options={[{ value: 'enabled', label: t('states.enabled') }, { value: 'disabled', label: t('states.disabled') }]} />
        </>}
        items={[
          ...(isAdmin ? [{ key: 'kind', label: t('cc.filters.kind'), field: <Select aria-label={t('cc.filters.kind')} value="all" disabled options={[{ value: 'all', label: t('cc.values.allTypes') }]} /> }] : []),
          { key: 'id', label: t(isMatcher ? 'cc.filters.matcherId' : 'cc.filters.filterId'), applied: id || undefined,
            field: <Input aria-label={t(isMatcher ? 'cc.filters.matcherId' : 'cc.filters.filterId')} value={idDraft} placeholder={t(isMatcher ? 'cc.filters.matcherIdPlaceholder' : 'cc.filters.filterIdPlaceholder')} allowClear onChange={(event) => setIDDraft(event.target.value)} /> },
          ...(isAdmin ? [{ key: 'owner', label: t('cc.filters.owner'), applied: owner || undefined,
            field: <IdOrNameInput aria-label={t('cc.filters.owner')} value={ownerDraft} placeholder={t('cc.filters.ownerPlaceholder')} freeText search={ownerSearch} onChange={setOwnerDraft} /> }] : []),
        ]}
        onQuery={() => { if (nameDraft.trim() === name && idDraft.trim() === id && ownerDraft.trim() === owner) void query.refetch(); else applySearch() }}
        onReset={clearFilters}
        onClearAdvanced={() => { setPage(1); setIDDraft(''); setID(''); setOwnerDraft(''); setOwner(''); setName(nameDraft.trim()) }}
        onRemove={(key) => {
          setPage(1)
          if (key === 'id') { setIDDraft(''); setID('') }
          if (key === 'owner') { setOwnerDraft(''); setOwner('') }
        }}
      />
      {query.isError ? <FeedbackWhen title={t('errors.loadFailed')} detail={queryError ? errorMessage(queryError, t) : t('errors.request_failed')} action={<Button size="small" onClick={() => void query.refetch()}>{t('actions.retry')}</Button>} /> : null}
      <SystemRuleCatalogSection accessToken={accessToken} kind={catalogKind} cacheKey={catalogKey} isAdmin={isAdmin} canManage={canManage} />
      <div className="cc-rule-table-scroll">
        <Table
          rowKey="id"
          size="small"
          rowSelection={{ columnWidth: 44 }}
          columns={columns}
          dataSource={referenceRows}
          loading={query.isPending || query.isFetching}
          pagination={false}
          locale={{ emptyText: query.isPending ? ' ' : t('cc.values.empty') }}
          scroll={{ x: isAdmin ? (isMatcher ? 1180 : 1310) : (isMatcher ? 1020 : 1150) }}
        />
      </div>
      <div className="cc-rule-pagination"><Pagination current={page} pageSize={limit} total={query.data?.total ?? 0} showTotal={(total) => t('cc.pagination.total', { count: total })} showSizeChanger pageSizeOptions={[10, 20, 50]} onChange={(nextPage, nextLimit) => { setPage(nextLimit === limit ? nextPage : 1); setLimit(nextLimit) }} /></div>
      <span id={`cc-${kind}-title`} className="sr-only">{t(isMatcher ? 'cc.tabs.matchers' : 'cc.tabs.filters')}</span>
      <Modal
        open={Boolean(deleting)}
        title={t('cc.confirm.delete')}
        okText={t('actions.delete')}
        cancelText={t('actions.cancel')}
        okButtonProps={{ danger: true }}
        onCancel={() => setDeleting(null)}
        onOk={() => {
          const item = deleting
          setDeleting(null)
          if (item) remove(item)
        }}
      />
      <CCReferenceEditor open={editor !== null} item={editor} isMatcher={isMatcher} isAdmin={isAdmin} pending={mutation.isPending} onCancel={() => { if (!writesLocked) setEditor(null) }} onSubmit={submit} />
    </section>
  )
}

function referenceInput(values: CCReferenceForm, isMatcher: boolean): SecurityPolicyMatcherFields | SecurityPolicyFilterFields {
  if (isMatcher) return { name: values.name, description: values.description, enabled: values.enabled, field: values.field, operator: values.operator, key: values.key?.trim() || undefined, values: conditionValues(values.values) }
  let parameters: Record<string, unknown> = {}
  try { parameters = JSON.parse(values.parameters || '{}') as Record<string, unknown> } catch { parameters = {} }
  // 表单里的常用参数覆盖 JSON 同名字段；留空的不写，JSON 里的原值保留。
  for (const key of ccFilterNumberParameters) {
    const value = values[key]
    if (typeof value === 'number') parameters[key] = value
  }
  return { name: values.name, description: values.description, enabled: values.enabled, type: values.type, parameters }
}

function CCRulesForbiddenView({ onOpenChallenges }: { onOpenChallenges: () => void }) {
  const { t } = useTranslation('securityPolicies')
  return (
    <section className="cc-rule-table" aria-labelledby="security-policies-title">
      <div className="cc-rule-toolbar">
        <Button type="primary" disabled>{t('cc.actions.addGroup')}</Button>
        <Dropdown
          trigger={['click']}
          menu={{ items: [{ key: 'challenge', label: t('cc.actions.challengePolicies') }], onClick: onOpenChallenges }}
        >
          <Button className="cc-rule-more-button">{t('cc.actions.more')}<ChevronDown size={14} aria-hidden="true" /></Button>
        </Dropdown>
      </div>
      <div className="cc-rule-filters">
        <Select aria-label={t('cc.filters.display')} value="all" disabled options={[{ value: 'all', label: t('cc.values.allVisible') }]} />
        <Input addonBefore={t('cc.filters.name')} placeholder={t('cc.filters.namePlaceholder')} disabled />
        <Input addonBefore={t('cc.filters.id')} placeholder={t('cc.filters.idPlaceholder')} disabled />
        <Button type="link" className="cc-rule-clear" disabled>{t('cc.actions.clear')}</Button>
      </div>
      <Result className="identity-forbidden" status="403" title={t('errors.forbiddenTitle')} subTitle={t('errors.permission_denied')} />
    </section>
  )
}

function SecurityPoliciesPageContent({
  accessToken, principal, scopeID, sessionEpoch, kind, initialView, referenceLayout = false,
}: {
  accessToken: string
  principal: Principal
  scopeID: string
  sessionEpoch: number
  kind: SecurityPolicyKind
  initialView?: CCReferenceView
  referenceLayout?: boolean
}) {
  const { t } = useTranslation('challengePolicies')
  const [searchParams, setSearchParams] = useSearchParams()
  const canReadRules = principal.permissions.includes('security_policies.read') || principal.permissions.includes('platform.admin')
  // tp-b1: CC rule statistics are an operator view; tenants do not get the tab.
  const canReadStats = canReadRules && roleForPrincipal(principal) === 'admin'
  const [activeTab, setActiveTab] = useState<CCReferenceView>(() => {
    const view = initialView ?? ccReferenceView(searchParams.get('view'))
    return view === 'stats' && !canReadStats ? 'groups' : view
  })

  const changeView = (next: CCReferenceView) => {
    setActiveTab(next)
    const params = new URLSearchParams(searchParams)
    // 筛选条件属于各自列表，切换视图不带过去。
    for (const name of ['name', 'id', 'owner', 'status']) params.delete(name)
    if (next === 'groups') params.delete('view')
    else params.set('view', next === 'matchers' ? 'matcher' : next === 'filters' ? 'filter' : next === 'stats' ? 'stats' : 'challenge')
    setSearchParams(params, { replace: true })
  }

  if (kind !== 'cc') {
    return canReadRules
      ? <>{kind === 'waf' && !referenceLayout ? <Alert className="identity-alert" type="info" showIcon role="status" message={t('securityPolicies:quickBlock.regionNotice')} /> : null}<SecurityPoliciesTable accessToken={accessToken} principal={principal} scopeID={scopeID} sessionEpoch={sessionEpoch} kind={kind} referenceLayout={referenceLayout && kind === 'waf'} showActivation={Boolean(searchParams.get('site_id'))} /></>
      : <Result className="identity-page identity-forbidden" status="403" title={t('securityPolicies:errors.forbiddenTitle')} subTitle={t('securityPolicies:errors.permission_denied')} />
  }

  return <section className="identity-page cc-rule-page">
    <h1 className="sr-only" id="security-policies-title">{t('securityPolicies:titles.cc')}</h1>
    {activeTab === 'challenges' ? <>
      <Button type="link" className="cc-challenge-back" onClick={() => changeView('groups')}>{t('securityPolicies:cc.actions.backToGroups')}</Button>
      <ChallengePoliciesPanel />
    </> : <>
    <Tabs
      className="cc-rule-tabs"
      activeKey={activeTab}
      onChange={(key) => changeView(key as CCReferenceView)}
      items={[
        { key: 'groups', label: t('securityPolicies:cc.tabs.groups') },
        { key: 'matchers', label: t('securityPolicies:cc.tabs.matchers') },
        { key: 'filters', label: t('securityPolicies:cc.tabs.filters') },
        ...(canReadStats ? [{ key: 'stats', label: t('securityPolicies:ccStats.tab') }] : []),
      ]}
    />
    {activeTab === 'stats' && canReadStats
      ? <CCStatsPanel accessToken={accessToken} siteID={searchParams.get('site_id')} tenantScopeID={searchParams.get('tenant_scope_id')}
        admin={roleForPrincipal(principal) === 'admin'} />
      : activeTab === 'groups'
      ? canReadRules
        ? <SecurityPoliciesTable accessToken={accessToken} principal={principal} scopeID={scopeID} sessionEpoch={sessionEpoch} kind="cc" referenceLayout showActivation={Boolean(searchParams.get('site_id'))} onOpenChallenges={() => changeView('challenges')} />
        : <CCRulesForbiddenView onOpenChallenges={() => changeView('challenges')} />
      : <CCReferenceUnavailableView accessToken={accessToken} principal={principal} scopeID={scopeID} sessionEpoch={sessionEpoch} kind={activeTab === 'filters' ? 'filters' : 'matchers'} onOpenChallenges={() => changeView('challenges')} />}
    </>}
  </section>
}

export default function SecurityPoliciesPage({ kind, referenceLayout = false }: { kind: SecurityPolicyKind; referenceLayout?: boolean }) {
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const identityKey = principal && sessionEpoch ? `${principal.scope_id}:${sessionEpoch}:${kind}` : ''
  const previousIdentityKey = useRef(identityKey)
  const identityChanged = Boolean(identityKey && previousIdentityKey.current && previousIdentityKey.current !== identityKey)

  useEffect(() => {
    if (identityKey) previousIdentityKey.current = identityKey
  }, [identityKey])

  if (!accessToken || !principal || !sessionEpoch) return null

  return (
    <SecurityPoliciesPageContent
    key={identityKey}
      accessToken={accessToken}
      principal={principal}
      scopeID={principal.scope_id}
      sessionEpoch={sessionEpoch}
      kind={kind}
      referenceLayout={referenceLayout}
      initialView={identityChanged ? 'groups' : undefined}
    />
  )
}
