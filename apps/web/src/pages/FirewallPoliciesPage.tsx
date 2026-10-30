import { useEffect, useRef, useState, type ReactNode } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  App,
  Alert,
  Button,
  Input,
  InputNumber,
  Modal,
  Popconfirm,
  Radio,
  Result,
  Select,
  Space,
  Spin,
  Switch,
  Table,
  Tabs,
  Tag,
} from 'antd'
import { List, Plus, RotateCcw, Save, Trash2 } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApiError, type Principal } from '../api/auth'
import {
  newOpenRestySecurityIdentity,
  openrestySecurityApi,
  type OpenRestyAutoSwitch,
  type OpenRestyLogConfig,
  type OpenRestySecurityConfig,
  type OpenRestySecurityDocument,
  type OpenRestySecurityOverrideConfig,
  type OpenRestySecurityOverrideField,
  type OpenRestySecurityOverrideScope,
  type OpenRestySecurityRuleGroup,
  type OpenRestySecurityWriteIdentity,
  type OpenRestyWAFResourceLimits,
} from '../api/openrestySecurity'
import { useSessionStore } from '../auth/session'
import '../i18n/firewall'
import './FirewallPoliciesPage.css'
import { useFeedback, OutcomeUnknown } from '@cdnca/ui'


const recommendedLimits: OpenRestyWAFResourceLimits = {
  candidate_per_param: 2048,
  candidate_per_request: 4096,
  ffi_per_request: 8192,
  json_max_leaves: 2048,
  json_max_nodes: 9216,
  json_max_depth: 64,
  json_max_string_bytes: 256 * 1024,
  json_body_bytes: 1024 * 1024,
  multipart_max_parts: 128,
  body_scan_bytes: 16 * 1024 * 1024,
}

type SecurityDraft = Required<Omit<OpenRestySecurityConfig, 'key'>>
type GlobalAttempt = {
  ownerKey: string
  revision: number
  patch: OpenRestySecurityConfig
  identity: OpenRestySecurityWriteIdentity
}
type OverrideEditor = { item?: OpenRestySecurityDocument }

const defaults: SecurityDraft = {
  cc_enable: true,
  block_time: 3600,
  white_time: 21600,
  default_block_way: 'exit',
  ipset_auto_enable: true,
  site_block_qps: 200,
  block_page_num_limit: 200,
  block_page_not_counted: true,
  tmp_white_total_limit: 400,
  tmp_white_per_limit: 50,
  custom_white: '',
  custom_black: '',
  ssl_handshake_limit: 1,
  default_page_refuse: false,
  force_default_page_cc: 'auto',
  auto_default_page_cc_qps: 100,
  default_page_rule: '10003',
  icmp_drop: false,
  auto_delete_access_log: 0,
  auto_switch: { enable: false, qps_50x: 50, qps_total: 1000, rule: '10003', seconds: 300 },
  cc_img_url_type: 'system',
  cc_img_url: '',
  at_hour: 0,
  slider_html: '',
  captcha_html: '',
  click_html: '',
  delay_jump_html: '',
  rotate_html: '',
  easy_click_html: '',
  easy_slider_html: '',
  log: { log_level: 'info', debug_ip: '' },
  well_known_auto_protect_count: 600,
  internal_qps: 50,
  internal_res_block_time: 3600,
  internal_rule: [{ period: 120, reqs: 20 }, { period: 0, reqs: 0 }, { period: 0, reqs: 0 }],
  waf_enable: false,
  waf_resource_limits: recommendedLimits,
}

const templateFields = [
  'slider_html', 'captcha_html', 'click_html', 'delay_jump_html', 'rotate_html', 'easy_click_html', 'easy_slider_html',
] as const

type TemplateField = typeof templateFields[number]

const overrideFields: OpenRestySecurityOverrideField[] = [
  'waf_enable', 'waf_resource_limits', 'cc_enable', 'block_time', 'white_time', 'tmp_white_total_limit',
  'tmp_white_per_limit', 'custom_white', 'custom_black', 'ssl_handshake_limit', 'default_page_refuse',
  'default_page_rule', 'icmp_drop', 'key', 'auto_delete_access_log', 'auto_switch', 'slider_html', 'captcha_html',
  'click_html', 'easy_click_html', 'easy_slider_html', 'delay_jump_html', 'rotate_html', 'log',
]

function normalizeConfig(config: OpenRestySecurityConfig): SecurityDraft {
  return {
    ...defaults,
    ...config,
    auto_switch: { ...defaults.auto_switch, ...config.auto_switch },
    log: { ...defaults.log, ...config.log },
    waf_resource_limits: { ...recommendedLimits, ...config.waf_resource_limits },
    internal_rule: config.internal_rule?.map((rule) => ({ ...rule })) ?? defaults.internal_rule.map((rule) => ({ ...rule })),
  }
}

function ownerFor(principal: Principal, sessionEpoch: number): readonly [string, string, null, string, number] | null {
  if (principal.scope_kind !== 'platform' || principal.tenant_id !== null || !principal.scope_id || !principal.user_id || sessionEpoch < 1) return null
  return ['platform', principal.scope_id, null, principal.user_id, sessionEpoch]
}

function principalCan(principal: Principal, permission: 'openresty_security.read' | 'openresty_security.manage'): boolean {
  return principal.scope_kind === 'platform' && (principal.permissions.includes(permission) || principal.permissions.includes('platform.admin'))
}

function currentAccess(ownerKey: string, requireManage = false): string | null {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (!accessToken || !principal || !principalCan(principal, 'openresty_security.read') ||
    requireManage && !principalCan(principal, 'openresty_security.manage')) return null
  const owner = ownerFor(principal, sessionEpoch)
  return owner && JSON.stringify(owner) === ownerKey ? accessToken : null
}

function SectionHeading({ title, description }: { title: string; description: string }) {
  return <div className="firewall-section-heading"><h2>{title}</h2><p>{description}</p></div>
}

function SettingCard({ title, description, action, wide = false, children }: {
  title: string
  description: string
  action?: ReactNode
  wide?: boolean
  children: ReactNode
}) {
  return <section className={`firewall-setting-card${wide ? ' firewall-setting-card--wide' : ''}`}>
    <div className="firewall-setting-card-heading">
      <div><h3>{title}</h3><p>{description}</p></div>
      {action}
    </div>
    {children}
  </section>
}

function NumberControl({ label, value, unit, minimum = 0, maximum = 2_147_483_647, disabled, hint, onChange, onCommit }: {
  label: string
  value: number
  unit: string
  minimum?: number
  maximum?: number
  disabled: boolean
  hint?: string
  onChange: (value: number) => void
  onCommit: (value: number) => void
}) {
  return <div className="firewall-number-field">
    <label>{label}</label>
    <div className="firewall-unit-control">
      <InputNumber aria-label={label} min={minimum} max={maximum} value={value} disabled={disabled}
        onChange={(next) => onChange(next ?? minimum)} onBlur={() => onCommit(value)} />
      <span>{unit}</span>
    </div>
    {hint ? <p>{hint}</p> : null}
  </div>
}

// useGlobalConfirm asks before a global write that publishes to every node
// at once (W4): switches and "restore recommended values" save on click.
function useGlobalConfirm() {
  const { t } = useTranslation('firewall')
  const { modal } = App.useApp()
  const ask = (title: string, content: string, onOk: () => void) => void modal.confirm({
    title, content, okText: t('openresty.confirm.ok'), cancelText: t('openresty.confirm.cancel'), onOk,
  })
  return {
    toggle: (name: string, checked: boolean, apply: () => void) => ask(
      t('openresty.confirm.toggleTitle', { action: t(checked ? 'openresty.confirm.toggleOn' : 'openresty.confirm.toggleOff'), name }),
      t('openresty.confirm.toggleContent'), apply),
    restore: (apply: () => void) => ask(t('openresty.confirm.restoreTitle'), t('openresty.confirm.restoreContent'), apply),
  }
}

function ToggleSetting({ title, description, checked, disabled, onChange }: {
  title: string
  description: string
  checked: boolean
  disabled: boolean
  onChange: (checked: boolean) => void
}) {
  const confirm = useGlobalConfirm()
  return <SettingCard title={title} description={description} action={<Switch aria-label={title} checked={checked} disabled={disabled}
    onChange={(next) => confirm.toggle(title, next, () => onChange(next))} />}>
    <span className="firewall-card-spacer" />
  </SettingCard>
}

function errorKey(error: unknown): string {
  if (!(error instanceof ApiError)) return 'errors.unknown'
  if (error.status === 412 || error.code === 'revision_conflict' || error.code === 'openresty_security_revision_conflict') return 'errors.revisionConflict'
  if (error.status === 403 || error.code === 'permission_denied') return 'errors.forbidden'
  if (error.code === 'invalid_response') return 'errors.invalidResponse'
  if (error.code === 'network_error' || error.status >= 500) return 'errors.outcomeUnknown'
  return 'errors.saveFailed'
}

function CCGlobalPanel({ draft, document, disabled, savePending, persist, setDraft, onDownloadImage, imagePending, ruleGroups, ruleGroupsLoaded }: {
  draft: SecurityDraft
  document: OpenRestySecurityDocument
  disabled: boolean
  savePending: boolean
  persist: (patch: OpenRestySecurityConfig) => void
  setDraft: (next: SecurityDraft) => void
  onDownloadImage: () => void
  imagePending: boolean
  ruleGroups: OpenRestySecurityRuleGroup[]
  ruleGroupsLoaded: boolean
}) {
  const { t } = useTranslation('firewall')
  const confirm = useGlobalConfirm()
  const [template, setTemplate] = useState<TemplateField>('slider_html')
  const [secret, setSecret] = useState('')
  const locked = disabled || savePending
  const update = <K extends keyof SecurityDraft>(key: K, value: SecurityDraft[K]) => setDraft({ ...draft, [key]: value })
  const saveField = <K extends keyof OpenRestySecurityConfig>(key: K, value: OpenRestySecurityConfig[K]) => persist({ [key]: value })
  const ruleOptions = ruleGroups.map((group) => ({ value: group.id, label: group.name, disabled: !group.enabled }))
  const selectedRule = ruleGroups.find((group) => group.id === draft.default_page_rule)
    ?? ruleGroups.find((group) => group.kind === 'system' && group.system_rule &&
      (group.system_rule_id === draft.default_page_rule || group.system_rule_key === draft.default_page_rule))
  const unknownRule = ruleGroupsLoaded && Boolean(draft.default_page_rule) && !selectedRule
  // The auto switch expands a system rule group by its legacy ID on the
  // server (securitypolicy.ResolveCCSettings); custom groups cannot be used.
  const switchRuleOptions = ruleGroups.filter((group) => group.kind === 'system' && group.system_rule && group.system_rule_id)
    .map((group) => ({ value: group.system_rule_id!, label: group.name, disabled: !group.enabled }))

  return <div className="firewall-tab-panel">
    <SectionHeading title={t('openresty.cc.section')} description={t('openresty.cc.sectionDescription')} />
    <div className="firewall-card-grid">
      <ToggleSetting title={t('openresty.cc.enable')} description={t('openresty.cc.enableDescription')}
        checked={draft.cc_enable} disabled={locked} onChange={(checked) => { update('cc_enable', checked); saveField('cc_enable', checked) }} />
      <SettingCard title={t('openresty.cc.duration')} description={t('openresty.cc.durationDescription')}>
        <div className="firewall-field-grid firewall-field-grid--stacked">
          <NumberControl label={t('openresty.cc.blockTime')} value={draft.block_time} unit={t('openresty.units.seconds')} disabled={locked}
            onChange={(value) => update('block_time', value)} onCommit={(value) => saveField('block_time', value)} />
          <NumberControl label={t('openresty.cc.whiteTime')} value={draft.white_time} unit={t('openresty.units.seconds')} minimum={600} disabled={locked}
            onChange={(value) => update('white_time', value)} onCommit={(value) => saveField('white_time', value)} />
        </div>
        <p className="firewall-help">{t('openresty.cc.whiteTimeHint')}</p>
      </SettingCard>

      <SettingCard wide title={t('openresty.cc.blockWay')} description={t('openresty.cc.blockWayDescription')}>
        <Radio.Group aria-label={t('openresty.cc.blockWay')} value={draft.default_block_way} disabled={locked}
          onChange={(event) => { update('default_block_way', event.target.value); saveField('default_block_way', event.target.value) }}>
          <Radio value="ipset">{t('openresty.cc.blockWayIPSet')}</Radio>
          <Radio value="exit">{t('openresty.cc.blockWayExit')}</Radio>
          <Radio value="page">{t('openresty.cc.blockWayPage')}</Radio>
        </Radio.Group>
        <p className="firewall-help">{t('openresty.cc.blockWayHint')}</p>
        <div className="firewall-subsection">
          <h4>{t('openresty.cc.nonIPSetTitle')}</h4>
          <div className="firewall-cc-policy-row firewall-cc-policy-row--auto">
            <span className="firewall-cc-policy-label">{t('openresty.cc.autoSwitchIPSet')}</span>
            <div className="firewall-cc-policy-inline">
              <Switch aria-label={t('openresty.cc.autoSwitchIPSet')} checked={draft.ipset_auto_enable} disabled={locked}
                onChange={(checked) => confirm.toggle(t('openresty.cc.autoSwitchIPSet'), checked, () => { update('ipset_auto_enable', checked); saveField('ipset_auto_enable', checked) })} />
              <div className="firewall-cc-policy-threshold">
                <NumberControl label={t('openresty.cc.siteBlockQPS')} value={draft.site_block_qps} unit={t('openresty.units.blocksPerSecond')}
                  disabled={locked} onChange={(value) => update('site_block_qps', value)} onCommit={(value) => saveField('site_block_qps', value)} />
              </div>
            </div>
          </div>
          <p className="firewall-help">{t('openresty.cc.autoSwitchHint')}</p>
          <NumberControl label={t('openresty.cc.blockPageLimit')} value={draft.block_page_num_limit} unit={t('openresty.units.perMinute')}
            disabled={locked} onChange={(value) => update('block_page_num_limit', value)} onCommit={(value) => saveField('block_page_num_limit', value)} />
          <div className="firewall-cc-policy-row firewall-cc-policy-row--traffic">
            <span className="firewall-cc-policy-label">{t('openresty.cc.blockPageTraffic')}</span>
            <div className="firewall-cc-policy-inline">
              <Switch aria-label={t('openresty.cc.blockPageTraffic')} checked={draft.block_page_not_counted} disabled={locked}
                onChange={(checked) => confirm.toggle(t('openresty.cc.blockPageTraffic'), checked, () => { update('block_page_not_counted', checked); saveField('block_page_not_counted', checked) })} />
              <span>{t('openresty.cc.blockPageTrafficDescription')}</span>
            </div>
          </div>
        </div>
      </SettingCard>

      <SettingCard wide title={t('openresty.cc.temporaryWhitelist')} description={t('openresty.cc.temporaryWhitelistDescription')}>
        <div className="firewall-field-grid">
          <NumberControl label={t('openresty.cc.totalRequests')} value={draft.tmp_white_total_limit} unit={t('openresty.units.perFiveSeconds')}
            disabled={locked} onChange={(value) => update('tmp_white_total_limit', value)} onCommit={(value) => saveField('tmp_white_total_limit', value)} />
          <NumberControl label={t('openresty.cc.sameURLRequests')} value={draft.tmp_white_per_limit} unit={t('openresty.units.perFiveSeconds')}
            disabled={locked} onChange={(value) => update('tmp_white_per_limit', value)} onCommit={(value) => saveField('tmp_white_per_limit', value)} />
        </div>
      </SettingCard>

      {(['custom_white', 'custom_black'] as const).map((field) => <SettingCard key={field}
        title={t(`openresty.cc.${field === 'custom_white' ? 'whiteIPs' : 'blackIPs'}`)} description={t('openresty.cc.ipListDescription')}>
        <Input.TextArea aria-label={t(`openresty.cc.${field === 'custom_white' ? 'whiteIPs' : 'blackIPs'}`)} rows={5}
          value={draft[field]} disabled={locked} placeholder={t('openresty.cc.ipPlaceholder')}
          onChange={(event) => update(field, event.target.value)} onBlur={(event) => saveField(field, event.currentTarget.value)} />
      </SettingCard>)}
    </div>

    <SectionHeading title={t('openresty.node.section')} description={t('openresty.node.sectionDescription')} />
    <div className="firewall-card-grid">
      <ToggleSetting title={t('openresty.node.tls')} description={t('openresty.node.tlsDescription')}
        checked={draft.ssl_handshake_limit > 0} disabled={locked}
        onChange={(checked) => { update('ssl_handshake_limit', checked ? 1 : 0); saveField('ssl_handshake_limit', checked ? 1 : 0) }} />
      <ToggleSetting title={t('openresty.node.rejectUnbound')} description={t('openresty.node.rejectUnboundDescription')}
        checked={draft.default_page_refuse} disabled={locked}
        onChange={(checked) => { update('default_page_refuse', checked); saveField('default_page_refuse', checked) }} />

      <SettingCard wide title={t('openresty.node.defaultPage')} description={t('openresty.node.defaultPageDescription')}>
        <div className="firewall-default-page-grid">
          <div><label>{t('openresty.node.enableMode')}</label><Radio.Group value={draft.force_default_page_cc} disabled={locked}
            onChange={(event) => { update('force_default_page_cc', event.target.value); saveField('force_default_page_cc', event.target.value) }}>
            <Radio value="force">{t('openresty.node.force')}</Radio><Radio value="auto">{t('openresty.node.auto')}</Radio>
          </Radio.Group></div>
          <NumberControl label={t('openresty.node.defaultPageQPS')} value={draft.auto_default_page_cc_qps} unit={t('openresty.units.enableAtQPS')}
            disabled={locked} onChange={(value) => update('auto_default_page_cc_qps', value)} onCommit={(value) => saveField('auto_default_page_cc_qps', value)} />
          <div className="firewall-select-field"><label>{t('openresty.node.ruleGroup')}</label><Select aria-label={t('openresty.node.ruleGroup')}
            classNames={{ popup: { root: 'firewall-rule-group-dropdown' } }} listHeight={190} virtual={false}
            value={selectedRule?.id ?? (draft.default_page_rule || undefined)} disabled={locked || unknownRule} options={ruleOptions}
            onOpenChange={(open) => {
              if (!open) return
              window.requestAnimationFrame(() => window.requestAnimationFrame(() => {
                const holder = window.document.querySelector('.firewall-rule-group-dropdown .rc-virtual-list-holder')
                if (holder instanceof HTMLElement) holder.scrollTop = 0
              }))
            }}
            onChange={(value) => { update('default_page_rule', value); saveField('default_page_rule', value) }} /></div>
        </div>
      </SettingCard>

      <ToggleSetting title={t('openresty.node.disablePing')} description={t('openresty.node.disablePingDescription')}
        checked={draft.icmp_drop} disabled={locked}
        onChange={(checked) => { update('icmp_drop', checked); saveField('icmp_drop', checked) }} />
      <SettingCard title={t('openresty.node.secret')} description={t('openresty.node.secretDescription')}>
        <Input.Password aria-label={t('openresty.node.secret')} value={secret} disabled={locked}
          placeholder={document.key_configured ? t('openresty.node.secretConfigured') : t('openresty.node.secretPlaceholder')}
          autoComplete="new-password" onChange={(event) => setSecret(event.target.value)} onBlur={() => {
            if (secret) { persist({ key: secret }); setSecret('') }
          }} />
      </SettingCard>

      <SettingCard wide title={t('openresty.node.cleanup')} description={t('openresty.node.cleanupDescription')}>
        <div className="firewall-radio-row"><label>{t('openresty.node.cleanupPolicy')}</label><Radio.Group value={draft.auto_delete_access_log} disabled={locked}
          onChange={(event) => { update('auto_delete_access_log', event.target.value); saveField('auto_delete_access_log', event.target.value) }}>
          <Radio value={0}>{t('openresty.node.cleanupNever')}</Radio>
          <Radio value={1}>{t('openresty.node.cleanupLogs')}</Radio>
          <Radio value={2}>{t('openresty.node.cleanupAll')}</Radio>
        </Radio.Group></div>
      </SettingCard>
    </div>

    <SectionHeading title={t('openresty.automation.section')} description={t('openresty.automation.sectionDescription')} />
    <div className="firewall-card-grid">
      <SettingCard title={t('openresty.automation.switch')} description={t('openresty.automation.switchDescription')}
        action={<Switch checkedChildren={t('openresty.states.enabled')} unCheckedChildren={t('openresty.states.disabled')}
          aria-label={t('openresty.automation.switch')} checked={draft.auto_switch.enable} disabled={locked}
          onChange={(checked) => confirm.toggle(t('openresty.automation.switch'), checked, () => {
            const value = { ...draft.auto_switch, enable: checked }
            update('auto_switch', value); saveField('auto_switch', value)
          })} />}>
        {draft.auto_switch.enable ? <div className="firewall-field-grid firewall-field-grid--stacked">
          <NumberControl label={t('openresty.automation.totalQPS')} value={draft.auto_switch.qps_total} unit={t('openresty.units.requestsPerSecond')}
            disabled={locked} onChange={(value) => update('auto_switch', { ...draft.auto_switch, qps_total: value })}
            onCommit={(value) => saveField('auto_switch', { ...draft.auto_switch, qps_total: value })} />
          <NumberControl label={t('openresty.automation.errorQPS')} value={draft.auto_switch.qps_50x} unit={t('openresty.units.requestsPerSecond')}
            disabled={locked} onChange={(value) => update('auto_switch', { ...draft.auto_switch, qps_50x: value })}
            onCommit={(value) => saveField('auto_switch', { ...draft.auto_switch, qps_50x: value })} />
          {/* Sites whose 自动切换 is 系统默认 run this system rule group (catalog legacy ID). */}
          <div className="firewall-number-field">
            <label>{t('openresty.automation.switchTo')}</label>
            <Select aria-label={t('openresty.automation.switchTo')} disabled={locked} value={draft.auto_switch.rule || undefined}
              placeholder={t('openresty.automation.switchToPlaceholder')}
              status={ruleGroupsLoaded && draft.auto_switch.rule && !switchRuleOptions.some((option) => option.value === draft.auto_switch.rule) ? 'warning' : undefined}
              options={switchRuleOptions}
              onChange={(rule: string) => { const value = { ...draft.auto_switch, rule }; update('auto_switch', value); saveField('auto_switch', value) }} />
          </div>
          <NumberControl label={t('openresty.automation.recoverSeconds')} value={draft.auto_switch.seconds || 300} unit={t('openresty.units.seconds')}
            minimum={60} maximum={86400} disabled={locked} hint={t('openresty.automation.recoverHint')}
            onChange={(value) => update('auto_switch', { ...draft.auto_switch, seconds: value })}
            onCommit={(value) => saveField('auto_switch', { ...draft.auto_switch, seconds: value })} />
        </div> : <span className="firewall-card-spacer" />}
      </SettingCard>
      <SettingCard title={t('openresty.automation.image')} description={t('openresty.automation.imageDescription')}>
        <div className="firewall-image-controls">
          <Radio.Group value={draft.cc_img_url_type} disabled={locked}
            onChange={(event) => { update('cc_img_url_type', event.target.value); saveField('cc_img_url_type', event.target.value) }}>
            <Radio value="system">{t('openresty.automation.system')}</Radio>
            <Radio value="custom">{t('openresty.automation.custom')}</Radio>
          </Radio.Group>
          <Button type="primary" icon={<RotateCcw size={14} />} disabled={locked || imagePending} onClick={onDownloadImage}>{t('openresty.automation.updateNow')}</Button>
        </div>
        {draft.cc_img_url_type === 'custom' ? <Input aria-label={t('openresty.automation.customURL')} value={draft.cc_img_url} disabled={locked}
          placeholder={t('openresty.automation.customURLPlaceholder')} onChange={(event) => update('cc_img_url', event.target.value)}
          onBlur={(event) => saveField('cc_img_url', event.currentTarget.value)} /> : null}
        <p className="firewall-help firewall-help--warning">{t('openresty.automation.imageHint')}</p>
      </SettingCard>
    </div>

    <SectionHeading title={t('openresty.template.section')} description={t('openresty.template.sectionDescription')} />
    <SettingCard wide title={t('openresty.template.title')} description={t('openresty.template.description')}>
      <Radio.Group className="firewall-template-options" value={template} disabled={locked} onChange={(event) => setTemplate(event.target.value)}>
        {templateFields.map((field) => <Radio key={field} value={field}>{t(`openresty.template.${field}`)}</Radio>)}
      </Radio.Group>
      <Input.TextArea className="firewall-template-editor" aria-label={t('openresty.template.editor')} rows={12}
        value={draft[template]} disabled={locked} onChange={(event) => update(template, event.target.value)}
        onBlur={(event) => saveField(template, event.currentTarget.value)} />
    </SettingCard>

    <SectionHeading title={t('openresty.diagnostics.section')} description={t('openresty.diagnostics.sectionDescription')} />
    <div className="firewall-card-grid">
      <SettingCard title={t('openresty.diagnostics.log')} description={t('openresty.diagnostics.logDescription')}
        action={<Switch aria-label={t('openresty.diagnostics.log')} checked={draft.log.log_level === 'debug'} disabled={locked}
          onChange={(checked) => confirm.toggle(t('openresty.diagnostics.log'), checked, () => {
            const value = { log_level: checked ? 'debug' as const : 'info' as const, debug_ip: checked ? draft.log.debug_ip : '' }
            update('log', value); saveField('log', value)
          })} />}>
        {draft.log.log_level === 'debug' ? <Input aria-label={t('openresty.diagnostics.debugIP')} value={draft.log.debug_ip} disabled={locked}
          placeholder={t('openresty.diagnostics.debugIPPlaceholder')} onChange={(event) => update('log', { ...draft.log, debug_ip: event.target.value })}
          onBlur={(event) => saveField('log', { ...draft.log, debug_ip: event.currentTarget.value })} /> : <span className="firewall-card-spacer" />}
      </SettingCard>
      <SettingCard title={t('openresty.diagnostics.wellKnown')} description={t('openresty.diagnostics.wellKnownDescription')}>
        <NumberControl label={t('openresty.diagnostics.threshold')} value={draft.well_known_auto_protect_count} unit={t('openresty.units.perMinute')}
          disabled={locked} onChange={(value) => update('well_known_auto_protect_count', value)}
          onCommit={(value) => saveField('well_known_auto_protect_count', value)} />
        <p className="firewall-help">{t('openresty.diagnostics.wellKnownHint')}</p>
      </SettingCard>
      <SettingCard wide title={t('openresty.diagnostics.internal')} description={t('openresty.diagnostics.internalDescription')}>
        <div className="firewall-field-grid">
          <NumberControl label={t('openresty.diagnostics.triggerQPS')} value={draft.internal_qps} unit={t('openresty.units.requestsPerSecond')}
            disabled={locked} onChange={(value) => update('internal_qps', value)} onCommit={(value) => saveField('internal_qps', value)} />
          <NumberControl label={t('openresty.diagnostics.blockDuration')} value={draft.internal_res_block_time} unit={t('openresty.units.seconds')}
            disabled={locked} onChange={(value) => update('internal_res_block_time', value)} onCommit={(value) => saveField('internal_res_block_time', value)} />
        </div>
        <div className="firewall-resource-rule-heading"><div><h4>{t('openresty.diagnostics.rules')}</h4><p>{t('openresty.diagnostics.rulesDescription')}</p></div>
          <Button type="primary" size="small" icon={<Save size={14} />} disabled={locked}
            onClick={() => saveField('internal_rule', draft.internal_rule)}>{t('openresty.actions.save')}</Button></div>
        <Table size="small" pagination={false} rowKey="key" dataSource={draft.internal_rule.map((rule, index) => ({ ...rule, key: `internal-rule-${index + 1}` }))}
          columns={[
            { title: t('openresty.diagnostics.period'), dataIndex: 'period', render: (value: number, _row, index) => <InputNumber
              aria-label={`${t('openresty.diagnostics.period')} ${index + 1}`} min={0} value={value} disabled={locked}
              placeholder={t('openresty.diagnostics.emptyDisables')} onChange={(next) => update('internal_rule', draft.internal_rule.map((rule, candidate) => candidate === index ? { ...rule, period: next ?? 0 } : rule))} /> },
            { title: t('openresty.diagnostics.maxRequests'), dataIndex: 'reqs', render: (value: number, _row, index) => <InputNumber
              aria-label={`${t('openresty.diagnostics.maxRequests')} ${index + 1}`} min={0} value={value} disabled={locked}
              placeholder={t('openresty.diagnostics.emptyDisables')} onChange={(next) => update('internal_rule', draft.internal_rule.map((rule, candidate) => candidate === index ? { ...rule, reqs: next ?? 0 } : rule))} /> },
          ]} />
      </SettingCard>
    </div>
  </div>
}

function WAFGlobalPanel({ draft, disabled, savePending, persist, setDraft }: {
  draft: SecurityDraft
  disabled: boolean
  savePending: boolean
  persist: (patch: OpenRestySecurityConfig) => void
  setDraft: (next: SecurityDraft) => void
}) {
  const { t } = useTranslation('firewall')
  const confirm = useGlobalConfirm()
  const locked = disabled || savePending
  const updateLimits = (name: keyof OpenRestyWAFResourceLimits, value: number) => setDraft({
    ...draft, waf_resource_limits: { ...draft.waf_resource_limits, [name]: value },
  })
  const saveLimits = () => persist({ waf_resource_limits: draft.waf_resource_limits })
  const fields: Array<{ name: keyof OpenRestyWAFResourceLimits; group: 'parameters' | 'json' | 'upload'; unit: string; scale?: number }> = [
    { name: 'candidate_per_param', group: 'parameters', unit: t('openresty.units.items') },
    { name: 'candidate_per_request', group: 'parameters', unit: t('openresty.units.items') },
    { name: 'ffi_per_request', group: 'parameters', unit: t('openresty.units.times') },
    { name: 'json_max_leaves', group: 'json', unit: t('openresty.units.items') },
    { name: 'json_max_nodes', group: 'json', unit: t('openresty.units.items') },
    { name: 'json_max_depth', group: 'json', unit: t('openresty.units.levels') },
    { name: 'json_max_string_bytes', group: 'json', unit: 'KB', scale: 1024 },
    { name: 'json_body_bytes', group: 'json', unit: 'KB', scale: 1024 },
    { name: 'multipart_max_parts', group: 'upload', unit: t('openresty.units.items') },
    { name: 'body_scan_bytes', group: 'upload', unit: 'MB', scale: 1024 * 1024 },
  ]

  return <div className="firewall-tab-panel">
    <ToggleSetting title={t('openresty.waf.enable')} description={t('openresty.waf.enableDescription')}
      checked={draft.waf_enable} disabled={locked}
      onChange={(checked) => { setDraft({ ...draft, waf_enable: checked }); persist({ waf_enable: checked }) }} />
    <SettingCard wide title={t('openresty.waf.limits')} description={t('openresty.waf.limitsDescription')}
      action={<Button disabled={locked} onClick={() => confirm.restore(() => { setDraft({ ...draft, waf_resource_limits: recommendedLimits }); persist({ waf_resource_limits: recommendedLimits }) })}>{t('openresty.waf.restore')}</Button>}>
      <Alert className="firewall-waf-warning" type="warning" showIcon={false} message={t('openresty.waf.warning')} />
      {(['parameters', 'json', 'upload'] as const).map((group) => <div className="firewall-limit-group" key={group}>
        <h4>{t(`openresty.waf.groups.${group}`)}</h4>
        <div className="firewall-limit-grid">
          {fields.filter((field) => field.group === group).map((field) => {
            const scale = field.scale ?? 1
            const value = draft.waf_resource_limits[field.name] / scale
            return <NumberControl key={field.name} label={t(`openresty.waf.fields.${field.name}.label`)}
              hint={t(`openresty.waf.fields.${field.name}.hint`)} value={value} unit={field.unit} disabled={locked}
              onChange={(next) => updateLimits(field.name, next * scale)} onCommit={() => saveLimits()} />
          })}
        </div>
      </div>)}
    </SettingCard>
  </div>
}

// EffectiveNodePanel (fix-fwregion): a platform node's effective auto switch
// and the layer it comes from (global / region / node).
function EffectiveNodePanel({ ownerKey }: { ownerKey: string }) {
  const { t } = useTranslation('firewall')
  const token = currentAccess(ownerKey)
  const [search, setSearch] = useState('')
  const [nodeID, setNodeID] = useState('')
  const nodes = useQuery({
    queryKey: ['openresty-security', 'targets', ownerKey, 'node', search],
    enabled: Boolean(token),
    queryFn: () => openrestySecurityApi.searchTargets(token!, { scopeType: 'node', query: search, pageSize: 20 }),
  })
  const effective = useQuery({
    queryKey: ['openresty-security', 'effective', ownerKey, nodeID],
    enabled: Boolean(token && nodeID),
    queryFn: () => openrestySecurityApi.getEffective(token!, nodeID),
  })
  const value = effective.data?.config.auto_switch
  const source = effective.data?.sources?.auto_switch ?? 'global'
  const on = Boolean(value?.enable && (value.qps_total > 0 || value.qps_50x > 0) && value.rule)
  return <section className="firewall-effective-node" aria-labelledby="firewall-effective-node-title">
    <div className="firewall-regional-copy">
      <h3 id="firewall-effective-node-title">{t('openresty.regional.effectiveTitle')}</h3>
      <p>{t('openresty.regional.effectiveDescription')}</p>
    </div>
    <Select className="firewall-effective-node-select" aria-label={t('openresty.regional.effectiveNode')} showSearch filterOption={false}
      allowClear value={nodeID || undefined} loading={nodes.isLoading} placeholder={t('openresty.regional.nodePlaceholder')}
      onSearch={setSearch} onChange={(next?: string) => setNodeID(next ?? '')}
      options={nodes.data?.items.map((item) => ({ value: item.value, label: item.label, title: item.description })) ?? []} />
    {effective.isError ? <p role="alert" className="firewall-effective-node-error">{t('openresty.regional.effectiveFailed')}</p> : null}
    {effective.data ? <dl className="firewall-effective-node-values">
      <dt>{t('openresty.regional.effectiveAutoSwitch')}</dt>
      <dd>{on && value ? t('openresty.regional.effectiveOn', {
        // a 0 threshold is not used
        trigger: [value.qps_total > 0 ? t('openresty.regional.effectiveTotal', { value: value.qps_total }) : '',
          value.qps_50x > 0 ? t('openresty.regional.effectiveErrors', { value: value.qps_50x }) : '']
          .filter(Boolean).join(t('openresty.regional.effectiveOr')),
        rule: value.rule, seconds: value.seconds || 300 })
        : t('openresty.regional.effectiveOff')}</dd>
      <dt>{t('openresty.regional.effectiveSource')}</dt>
      <dd><Tag color={source === 'global' ? 'default' : 'processing'}>{t(`openresty.regional.sources.${source}`)}</Tag></dd>
    </dl> : null}
  </section>
}

function RegionalPanel({ ownerKey, draft, disabled }: { ownerKey: string; draft: SecurityDraft; disabled: boolean }) {
  const { t } = useTranslation('firewall')
  const { message } = App.useApp()
  const feedback = useFeedback()
  const client = useQueryClient()
  const token = currentAccess(ownerKey)
  const [page, setPage] = useState(1)
  const [editor, setEditor] = useState<OverrideEditor | null>(null)
  const [scopeType, setScopeType] = useState<OpenRestySecurityOverrideScope>('node')
  const [targetSearch, setTargetSearch] = useState('')
  const [scopeID, setScopeID] = useState('')
  const [selectedFields, setSelectedFields] = useState<OpenRestySecurityOverrideField[]>([])
  const [overrideDraft, setOverrideDraft] = useState<OpenRestySecurityOverrideConfig>({})
  const [secret, setSecret] = useState('')
  const queryKey = ['openresty-security', 'overrides', ownerKey, page]
  const overrides = useQuery({ queryKey, enabled: Boolean(token), queryFn: () => openrestySecurityApi.listOverrides(token!, { page, pageSize: 20 }) })
  const targets = useQuery({
    queryKey: ['openresty-security', 'targets', ownerKey, scopeType, targetSearch],
    enabled: Boolean(token && editor && !editor.item),
    queryFn: () => openrestySecurityApi.searchTargets(token!, { scopeType, query: targetSearch, pageSize: 20 }),
  })

  const closeEditor = () => {
    setEditor(null)
    setScopeID('')
    setSelectedFields([])
    setOverrideDraft({})
    setSecret('')
    setTargetSearch('')
  }
  const copyConfig = (config: OpenRestySecurityConfig): OpenRestySecurityOverrideConfig => ({
    ...config,
    ...(config.waf_resource_limits ? { waf_resource_limits: { ...config.waf_resource_limits } } : {}),
    ...(config.auto_switch ? { auto_switch: { ...config.auto_switch } } : {}),
    ...(config.log ? { log: { ...config.log } } : {}),
  })
  const openEditor = (item?: OpenRestySecurityDocument) => {
    setEditor({ item })
    setScopeType(item?.scope_type === 'region' ? 'region' : 'node')
    setScopeID(item?.scope_id ?? '')
    setSelectedFields(item ? Object.keys(item.config) as OpenRestySecurityOverrideField[] : [])
    setOverrideDraft(item ? copyConfig(item.config) : {})
    setSecret('')
    setTargetSearch('')
  }
  const updateOverrideField = (field: OpenRestySecurityOverrideField, value: unknown) => {
    setOverrideDraft((current) => ({ ...current, [field]: value } as OpenRestySecurityOverrideConfig))
  }
  const addOverrideField = (field: OpenRestySecurityOverrideField) => {
    if (selectedFields.includes(field)) return
    setSelectedFields((current) => [...current, field])
    if (field !== 'key') {
      const value = draft[field]
      if (value !== undefined) updateOverrideField(field, value && typeof value === 'object' ? structuredClone(value) : value)
    }
  }
  const removeOverrideField = (field: OpenRestySecurityOverrideField) => {
    setSelectedFields((current) => current.filter((candidate) => candidate !== field))
    setOverrideDraft((current) => {
      const next = { ...current }
      delete next[field]
      return next
    })
    if (field === 'key') setSecret('')
  }
  const selectedConfig = (): OpenRestySecurityOverrideConfig | null => {
    const result: OpenRestySecurityOverrideConfig = {}
    for (const field of selectedFields) {
      if (field === 'key') {
        if (!secret) return null
        result.key = secret
        continue
      }
      const value = overrideDraft[field]
      if (value === undefined) return null
      Object.assign(result, { [field]: value })
    }
    return result
  }
  const write = useMutation({
    mutationFn: async () => {
      const accessToken = currentAccess(ownerKey, true)
      const config = selectedConfig()
      if (!accessToken || !config || !scopeID || selectedFields.length === 0) throw new ApiError('Invalid override', 400, 'openresty_security_invalid_request')
      if (!editor?.item) return openrestySecurityApi.createOverride(accessToken, { scopeType, scopeId: scopeID, config })
      const removedFields = (Object.keys(editor.item.config) as OpenRestySecurityOverrideField[]).filter((field) => !selectedFields.includes(field))
      return openrestySecurityApi.patchOverride(accessToken, { id: editor.item.id, revision: editor.item.revision, patch: config, removedFields })
    },
    onSuccess: () => { closeEditor(); void client.invalidateQueries({ queryKey: ['openresty-security', 'overrides', ownerKey] }); void message.success(t('openresty.notices.overrideSaved')) },
    onError: (error) => { void feedback.error(t(errorKey(error))) },
  })
  const remove = useMutation({
    mutationFn: async (item: OpenRestySecurityDocument) => {
      const accessToken = currentAccess(ownerKey, true)
      if (!accessToken) throw new ApiError('Permission denied', 403, 'permission_denied')
      return openrestySecurityApi.deleteOverride(accessToken, { id: item.id, revision: item.revision })
    },
    onSuccess: () => { void client.invalidateQueries({ queryKey: ['openresty-security', 'overrides', ownerKey] }); void message.success(t('openresty.notices.overrideDeleted')) },
    onError: (error) => { void feedback.error(t(errorKey(error))) },
  })

  const booleanFields: OpenRestySecurityOverrideField[] = ['waf_enable', 'cc_enable', 'default_page_refuse', 'icmp_drop']
  const numberFields: OpenRestySecurityOverrideField[] = ['block_time', 'white_time', 'tmp_white_total_limit', 'tmp_white_per_limit']
  const textareaFields: OpenRestySecurityOverrideField[] = [
    'custom_white', 'custom_black', 'slider_html', 'captcha_html', 'click_html', 'easy_click_html',
    'easy_slider_html', 'delay_jump_html', 'rotate_html',
  ]
  const renderOverrideControl = (field: OpenRestySecurityOverrideField) => {
    const value = overrideDraft[field]
    if (booleanFields.includes(field)) return <Radio.Group
      value={Boolean(value)}
      onChange={(event) => updateOverrideField(field, event.target.value as boolean)}
    >
      <Radio.Button value>{t('openresty.states.enabled')}</Radio.Button>
      <Radio.Button value={false}>{t('openresty.states.disabled')}</Radio.Button>
    </Radio.Group>
    if (field === 'ssl_handshake_limit') return <Radio.Group
      value={Number(value ?? 0) > 0}
      onChange={(event) => updateOverrideField(field, event.target.value ? 1 : 0)}
    >
      <Radio.Button value>{t('openresty.states.enabled')}</Radio.Button>
      <Radio.Button value={false}>{t('openresty.states.disabled')}</Radio.Button>
    </Radio.Group>
    if (numberFields.includes(field)) return <InputNumber
      aria-label={t(`openresty.overrideFields.${field}`)}
      min={field === 'white_time' ? 600 : 0}
      value={Number(value ?? 0)}
      onChange={(next) => updateOverrideField(field, next ?? 0)}
    />
    if (textareaFields.includes(field)) return <Input.TextArea
      aria-label={t(`openresty.overrideFields.${field}`)}
      rows={field.endsWith('_html') ? 10 : 5}
      value={String(value ?? '')}
      onChange={(event) => updateOverrideField(field, event.target.value)}
    />
    if (field === 'default_page_rule') return <Input
      aria-label={t(`openresty.overrideFields.${field}`)}
      value={String(value ?? '')}
      onChange={(event) => updateOverrideField(field, event.target.value)}
    />
    if (field === 'auto_delete_access_log') return <Radio.Group
      value={Number(value ?? 0)}
      onChange={(event) => updateOverrideField(field, event.target.value as 0 | 1 | 2)}
    >
      <Radio.Button value={0}>{t('openresty.node.cleanupNever')}</Radio.Button>
      <Radio.Button value={1}>{t('openresty.node.cleanupLogs')}</Radio.Button>
      <Radio.Button value={2}>{t('openresty.node.cleanupAll')}</Radio.Button>
    </Radio.Group>
    if (field === 'auto_switch') {
      const current = value && typeof value === 'object' ? value as OpenRestyAutoSwitch : defaults.auto_switch
      const update = (patch: Partial<OpenRestyAutoSwitch>) => updateOverrideField(field, { ...current, ...patch })
      return <div className="firewall-override-composite">
        <Switch aria-label={t('openresty.automation.switch')} checked={current.enable} onChange={(enable) => update({ enable })} />
        <InputNumber aria-label={t('openresty.automation.errorQPS')} min={0} value={current.qps_50x} onChange={(next) => update({ qps_50x: next ?? 0 })} />
        <InputNumber aria-label={t('openresty.automation.totalQPS')} min={0} value={current.qps_total} onChange={(next) => update({ qps_total: next ?? 0 })} />
        <Input aria-label={t('openresty.node.ruleGroup')} value={current.rule} onChange={(event) => update({ rule: event.target.value })} />
        <InputNumber aria-label={t('openresty.units.seconds')} min={0} value={current.seconds} onChange={(next) => update({ seconds: next ?? 0 })} />
      </div>
    }
    if (field === 'log') {
      const current = value && typeof value === 'object' ? value as OpenRestyLogConfig : defaults.log
      const update = (patch: Partial<OpenRestyLogConfig>) => updateOverrideField(field, { ...current, ...patch })
      return <div className="firewall-override-composite">
        <Radio.Group value={current.log_level} onChange={(event) => update({ log_level: event.target.value })}>
          <Radio.Button value="info">info</Radio.Button><Radio.Button value="debug">debug</Radio.Button>
        </Radio.Group>
        <Input aria-label={t('openresty.diagnostics.debugIP')} value={current.debug_ip}
          placeholder={t('openresty.diagnostics.debugIPPlaceholder')} onChange={(event) => update({ debug_ip: event.target.value })} />
      </div>
    }
    if (field === 'waf_resource_limits') {
      const current = value && typeof value === 'object' ? value as OpenRestyWAFResourceLimits : recommendedLimits
      return <div className="firewall-override-limit-grid">
        {(Object.keys(recommendedLimits) as Array<keyof OpenRestyWAFResourceLimits>).map((name) => <label key={name}>
          <span>{t(`openresty.waf.fields.${name}.label`)}</span>
          <InputNumber aria-label={t(`openresty.waf.fields.${name}.label`)} min={0} value={current[name]}
            onChange={(next) => updateOverrideField(field, { ...current, [name]: next ?? 0 })} />
        </label>)}
      </div>
    }
    if (field === 'key') return <Input.Password value={secret} autoComplete="new-password"
      aria-label={t('openresty.node.secret')} placeholder={t('openresty.node.secretPlaceholder')}
      onChange={(event) => setSecret(event.target.value)} />
    return null
  }

  const data = overrides.data?.items ?? []
  return <div className="firewall-tab-panel firewall-regional-panel">
    <EffectiveNodePanel ownerKey={ownerKey} />
    <div className="firewall-regional-summary">
      <div className="firewall-regional-copy">
        <h3>{t('openresty.regional.title')}</h3>
        <p>{t('openresty.regional.description')}</p>
        <Tag color="processing" icon={<List size={13} />}>{t('openresty.regional.count', { count: overrides.data?.total ?? 0 })}</Tag>
      </div>
      <Button type="primary" icon={<Plus size={15} />} disabled={disabled} onClick={() => openEditor()}>{t('openresty.regional.add')}</Button>
    </div>
    {overrides.isError ? <Result status="error" title={t('openresty.errors.loadFailed')} extra={<Button onClick={() => void overrides.refetch()}>{t('openresty.actions.retry')}</Button>} /> :
      <Table className="firewall-regional-table" loading={overrides.isLoading} size="small" rowKey="id" dataSource={data}
        tableLayout="fixed"
        rowSelection={{ columnWidth: 70, selections: false, getCheckboxProps: () => ({ disabled: true }) }}
        columns={[
          { title: t('openresty.regional.scope'), key: 'scope', width: 360, render: (_value, item: OpenRestySecurityDocument) => <div><strong>{item.scope_type === 'region' ? t('openresty.regional.region') : t('openresty.regional.node')}</strong><span>{item.scope_label || item.scope_id}</span></div> },
          { title: t('openresty.regional.items'), key: 'items', width: 360, render: (_value, item: OpenRestySecurityDocument) => <Space size={[4, 4]} wrap>{Object.keys(item.config).map((field) => <Tag key={field}>{t(`openresty.overrideFields.${field}`)}</Tag>)}</Space> },
          { title: t('openresty.regional.actions'), key: 'actions', width: 310, render: (_value, item: OpenRestySecurityDocument) => <Space>
            <Button type="link" size="small" disabled={disabled} onClick={() => openEditor(item)}>{t('openresty.actions.edit')}</Button>
            <Popconfirm title={t('openresty.regional.deleteConfirm')} onConfirm={() => remove.mutate(item)}><Button type="link" size="small" danger disabled={disabled || remove.isPending} icon={<Trash2 size={14} />}>{t('openresty.actions.delete')}</Button></Popconfirm>
          </Space> },
        ]}
        locale={{ emptyText: <span className="firewall-regional-empty">{t('openresty.regional.empty')}</span> }}
        pagination={{ current: page, pageSize: 20, total: overrides.data?.total ?? 0, hideOnSinglePage: true, onChange: setPage }} />}

    <Modal className="firewall-override-modal" width={780} open={Boolean(editor)} title={editor?.item ? t('openresty.regional.edit') : t('openresty.regional.add')}
      onCancel={closeEditor} destroyOnHidden footer={<Space><Button type="primary" loading={write.isPending}
        disabled={disabled}
        onClick={() => write.mutate()}>{t('openresty.actions.confirm')}</Button><Button onClick={closeEditor}>{t('openresty.actions.cancel')}</Button></Space>}>
      <div className="firewall-override-form">
        <label>{t('openresty.regional.scopeType')}{t('openresty.regional.labelSuffix')}</label>
        <Radio.Group value={scopeType} disabled={Boolean(editor?.item)} onChange={(event) => { setScopeType(event.target.value); setScopeID(''); setTargetSearch('') }}>
          <Radio.Button value="node">{t('openresty.regional.node')}</Radio.Button><Radio.Button value="region">{t('openresty.regional.region')}</Radio.Button>
        </Radio.Group>
        <label>{scopeType === 'node' ? t('openresty.regional.nodeSelect') : t('openresty.regional.regionSelect')}{t('openresty.regional.labelSuffix')}</label>
        <Select className="firewall-override-target" aria-label={scopeType === 'node' ? t('openresty.regional.nodeSelect') : t('openresty.regional.regionSelect')} showSearch filterOption={false} value={scopeID || undefined} disabled={Boolean(editor?.item)} loading={targets.isLoading}
          placeholder={scopeType === 'node' ? t('openresty.regional.nodePlaceholder') : t('openresty.regional.regionPlaceholder')}
          onSearch={setTargetSearch} onChange={setScopeID} options={editor?.item
            ? [{ value: editor.item.scope_id, label: editor.item.scope_label || editor.item.scope_id, title: undefined }]
            : targets.data?.items.map((item) => ({ value: item.value, label: item.label, title: item.description })) ?? []} />
        <label>{t('openresty.regional.configItems')}{t('openresty.regional.labelSuffix')}</label>
        <Select key={selectedFields.join('|') || 'empty'} aria-label={t('openresty.regional.configItems')} value={undefined} placeholder={t('openresty.regional.configItemsPlaceholder')} virtual={false} listHeight={284}
          classNames={{ popup: { root: 'firewall-override-config-popup' } }}
          onChange={addOverrideField} options={overrideFields
            .filter((field) => !selectedFields.includes(field))
            .map((field) => ({ value: field, label: t(`openresty.overrideFields.${field}`) }))} />
        {selectedFields.map((field) => <div className="firewall-override-field" key={field}>
          <label>{t(`openresty.overrideFields.${field}`)}{t('openresty.regional.labelSuffix')}</label>
          <div className="firewall-override-field-control">
            {renderOverrideControl(field)}
            <p>{t('openresty.regional.copyGlobalHint')}</p>
          </div>
          <button type="button" className="firewall-override-field-remove"
            aria-label={t('openresty.regional.removeItem', { item: t(`openresty.overrideFields.${field}`) })}
            onClick={() => removeOverrideField(field)}>×</button>
        </div>)}
      </div>
    </Modal>
  </div>
}

export default function FirewallPoliciesPage() {
  const { t } = useTranslation('firewall')
  const { message } = App.useApp()
  const feedback = useFeedback()
  const client = useQueryClient()
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const owner = principal ? ownerFor(principal, sessionEpoch) : null
  const ownerKey = owner ? JSON.stringify(owner) : ''
  const canRead = Boolean(principal && principalCan(principal, 'openresty_security.read'))
  const canManage = Boolean(principal && principalCan(principal, 'openresty_security.manage'))
  const token = ownerKey ? currentAccess(ownerKey) : null
  const queryKey = ['openresty-security', 'global', ownerKey]
  const global = useQuery({ queryKey, enabled: Boolean(token && canRead), queryFn: () => openrestySecurityApi.getGlobal(token!) })
  const groups = useQuery({ queryKey: ['openresty-security', 'rule-groups', ownerKey], enabled: Boolean(token && canRead), queryFn: () => openrestySecurityApi.listRuleGroups(token!) })
  const [draft, setDraft] = useState<SecurityDraft | null>(null)
  const [failedAttempt, setFailedAttempt] = useState<GlobalAttempt | null>(null)
  const tabsRef = useRef<HTMLElement>(null)

  useEffect(() => {
    if (global.data) setDraft(normalizeConfig(global.data.config))
  }, [global.data])

  const save = useMutation({
    mutationFn: async (attempt: GlobalAttempt) => {
      const accessToken = currentAccess(attempt.ownerKey, true)
      if (!accessToken) throw new ApiError('Permission denied', 403, 'permission_denied')
      return openrestySecurityApi.patchGlobal(accessToken, attempt.revision, attempt.patch, attempt.identity)
    },
    onSuccess: (next, attempt) => {
      if (!currentAccess(attempt.ownerKey)) return
      client.setQueryData(queryKey, next)
      setDraft(normalizeConfig(next.config))
      setFailedAttempt(null)
      void message.success(t('openresty.notices.saved'))
    },
    onError: (error, attempt) => {
      if (!currentAccess(attempt.ownerKey)) return
      if (error instanceof ApiError && (error.status === 412 || error.code.includes('revision_conflict'))) {
        setFailedAttempt(null)
        void global.refetch()
      } else if (error instanceof ApiError && (error.code === 'network_error' || error.status >= 500)) {
        setFailedAttempt(attempt)
      }
      void feedback.error(t(errorKey(error)))
    },
  })

  const downloadImage = useMutation({
    mutationFn: async () => {
      const accessToken = currentAccess(ownerKey, true)
      if (!accessToken) throw new ApiError('Permission denied', 403, 'permission_denied')
      return openrestySecurityApi.queueCCImageDownload(accessToken)
    },
    onSuccess: () => { void message.success(t('openresty.notices.imageQueued')) },
    onError: (error) => { void feedback.error(t(errorKey(error))) },
  })

  const persist = (patch: OpenRestySecurityConfig) => {
    if (!global.data || save.isPending || !currentAccess(ownerKey, true)) return
    save.mutate({ ownerKey, revision: global.data.revision, patch, identity: newOpenRestySecurityIdentity('openresty-global') })
  }

  const scrollTabs = (direction: -1 | 1) => {
    tabsRef.current?.querySelector<HTMLElement>('.ant-tabs-nav-wrap')?.scrollBy({
      left: direction * 116,
      behavior: 'smooth',
    })
  }

  const alignActiveTab = () => {
    if (!window.matchMedia('(max-width: 767px)').matches) return
    window.requestAnimationFrame(() => window.requestAnimationFrame(() => {
      const wrap = tabsRef.current?.querySelector<HTMLElement>('.ant-tabs-nav-wrap')
      const active = tabsRef.current?.querySelector<HTMLElement>('.ant-tabs-tab-active')
      if (!wrap || !active) return
      const wrapRect = wrap.getBoundingClientRect()
      const activeRect = active.getBoundingClientRect()
      wrap.scrollTo({ left: wrap.scrollLeft + activeRect.left - wrapRect.left - 5 })
    }))
  }

  if (!principal || !owner || !canRead) return <Result status="403" title={t('openresty.errors.forbidden')} />
  if (global.isLoading || !draft && !global.isError) return <Spin />
  if (global.isError || !global.data || !draft) return <Result status="error" title={t('openresty.errors.loadFailed')}
    extra={<Button onClick={() => void global.refetch()}>{t('openresty.actions.retry')}</Button>} />

  const disabled = !canManage
  return <section ref={tabsRef} className="firewall-settings-page" aria-labelledby="firewall-settings-title">
    <h1 id="firewall-settings-title" className="firewall-reference-visually-hidden">{t('title')}</h1>
    {failedAttempt ? <OutcomeUnknown title={t('openresty.uncertainty.title')} detail={t('openresty.uncertainty.description')} action={<Space wrap>
        <Button size="small" type="primary" disabled={save.isPending} onClick={() => save.mutate(failedAttempt)}>{t('openresty.actions.retryExact')}</Button>
        <Button size="small" disabled={save.isPending} onClick={() => { setFailedAttempt(null); void global.refetch() }}>{t('openresty.actions.discardAndRefresh')}</Button>
      </Space>} className="firewall-uncertain-alert" /> : null}
    <Tabs
      className="firewall-reference-tabs"
      defaultActiveKey="ccGlobal"
      destroyOnHidden={false}
      onChange={alignActiveTab}
      tabBarExtraContent={{
        left: <button type="button" className="firewall-tabs-scroll firewall-tabs-scroll--previous" aria-label={t('reference.tabs.previous')} onClick={() => scrollTabs(-1)} />,
        right: <button type="button" className="firewall-tabs-scroll firewall-tabs-scroll--next" aria-label={t('reference.tabs.next')} onClick={() => scrollTabs(1)} />,
      }}
      items={[
      { key: 'ccGlobal', label: t('reference.tabs.ccGlobal'), children: <CCGlobalPanel draft={draft} document={global.data}
        disabled={disabled} savePending={save.isPending} persist={persist} setDraft={setDraft}
        onDownloadImage={() => downloadImage.mutate()} imagePending={downloadImage.isPending}
        ruleGroups={groups.data ?? []} ruleGroupsLoaded={groups.isSuccess} /> },
      { key: 'wafGlobal', label: t('reference.tabs.wafGlobal'), children: <WAFGlobalPanel draft={draft} disabled={disabled}
        savePending={save.isPending} persist={persist} setDraft={setDraft} /> },
      { key: 'regional', label: t('reference.tabs.regional'), children: <RegionalPanel ownerKey={ownerKey} draft={draft} disabled={disabled} /> },
    ]}
    />
  </section>
}
