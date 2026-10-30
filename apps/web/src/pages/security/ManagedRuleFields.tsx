import { useState } from 'react'
import { Alert, Button, Form, Input, InputNumber, Select, Space, Switch, type FormInstance } from 'antd'
import { useTranslation } from 'react-i18next'

import {
  type CatalogRuleSet, type CRSProfilePack, type SecurityPolicyKind, type SecurityPolicyManagedWAF,
} from '../../api/securityPolicies'
import type { SystemRule } from '../../api/securitySystemRules'
import '../../i18n/managedRules'
import '../../i18n/securityPoliciesCountBy'
import { CRSTierDetails, orderedProfiles, useTierName } from './CRSTierDetails'

/** How many system CC rule groups one import may combine (securitypolicy.MaxCCRuleGroups). */
const maxCCRuleGroups = 8

// Ranges are the server's validation ranges (securitypolicy.checkChallengeConfig,
// edgeconfig.normalizeManagedWAF). Defaults prefill a new challenge with the
// server's default CC challenge (libs/rulepack/params.go DefaultCCChallenge,
// ban DefaultCCChallengeBanSeconds; 5秒盾 wait 5 s as the catalog's
// delay_jump_filter, libs/entitlement/rulecatalog/seed.go); imported or saved
// values are kept.
const challengeFields = [
  ['failure_window_seconds', 1, 86400, 60], ['max_failures', 1, 1000, 5], ['ban_seconds', 1, 86400, 600],
  ['pass_seconds', 60, 604800, 3600], ['pow_bits', 8, 26, 16], ['delay_seconds', 1, 30, 5], ['challenge_seconds', 30, 3600, 120],
  ['bind_ipv4_prefix', 8, 32, 24], ['bind_ipv6_prefix', 32, 128, 64], ['key_rotate_seconds', 60, 2592000, 86400],
] as const

export function challengeFieldsFor(type: string | undefined, logOnly: boolean) {
  return challengeFields.filter(([field]) => (field !== 'delay_seconds' || type === 'five_second') &&
    (field !== 'pow_bits' || type !== 'redirect') && (field !== 'ban_seconds' || !logOnly))
}

// Optional trigger (securitypolicy.checkChallengeConfig): both empty challenges
// every unpassed request; both set challenges only a client over the limit.
const triggerFields = [['trigger_window_seconds', 1, 3600], ['trigger_max_requests', 1, 1_000_000]] as const

/** Challenge parameters of one CC rule (Form.List item `ruleName`). */
export function ChallengeFields({ ruleName, form }: { ruleName: number; form: FormInstance }) {
  const { t } = useTranslation('managedRules')
  const challengePath = (field: string) => ['rules', ruleName, 'action_config', 'challenge', field]
  return (
    <Form.Item noStyle shouldUpdate>
      {() => {
        const type = form.getFieldValue(['rules', ruleName, 'action_config', 'challenge', 'type']) as string | undefined
        const logOnly = Boolean(form.getFieldValue(['rules', ruleName, 'action_config', 'challenge', 'log_only']))
        return (
          <Space size={10} wrap align="start">
            <Form.Item name={[ruleName, 'action_config', 'challenge', 'log_only']} label={t('challenge.log_only')} valuePropName="checked">
              <Switch />
            </Form.Item>
            {/* preserve={false}: a field hidden by the type / log-only switch must
                be omitted (the server requires 0 there) and is prefilled again
                when it comes back. */}
            {challengeFieldsFor(type, logOnly).map(([field, min, max, initial]) => (
              <Form.Item key={field} name={[ruleName, 'action_config', 'challenge', field]} label={t(`challenge.${field}`)}
                tooltip={t(`challenge.${field}Help`)} initialValue={initial} preserve={false}
                rules={[{ required: true, type: 'number', min, max }]}>
                <InputNumber aria-label={t(`challenge.${field}`)} min={min} max={max} precision={0} style={{ width: 130 }} />
              </Form.Item>
            ))}
            {triggerFields.map(([field, min, max], index) => {
              const other = triggerFields[1 - index][0]
              return (
                <Form.Item key={field} name={[ruleName, 'action_config', 'challenge', field]} label={t(`challenge.${field}`)}
                  tooltip={t('challenge.triggerHelp')} dependencies={[challengePath(other)]}
                  rules={[{ type: 'number', min, max }, {
                    validator: (_, value: number | null | undefined) => {
                      const otherValue = form.getFieldValue(challengePath(other)) as number | null | undefined
                      return (value == null) && otherValue != null
                        ? Promise.reject(new Error(t('challenge.triggerPair'))) : Promise.resolve()
                    },
                  }]}>
                  <InputNumber aria-label={t(`challenge.${field}`)} min={min} max={max} precision={0} placeholder={t('challenge.triggerEmpty')} style={{ width: 130 }} />
                </Form.Item>
              )
            })}
          </Space>
        )
      }}
    </Form.Item>
  )
}

const engineFields = [
  ['request_body_limit', 1024, 134217728], ['request_body_no_files_limit', 1024, 134217728],
  ['arguments_limit', 10, 100000], ['json_depth_limit', 4, 10000], ['pcre_match_limit', 1000, 10000000],
] as const

/** Rule IDs typed as text: six-digit CRS IDs starting with 9, comma or space separated. */
export const crsRuleIdsPattern = /^\s*(9\d{5}(\s*[,\s]\s*9\d{5})*)?\s*$/

/** "941160, 941310" -> [941160, 941310] (sorted, unique). */
export function parseCRSRuleIds(text: string): number[] {
  return [...new Set(text.split(/[\s,]+/).filter(Boolean).map(Number))].sort((left, right) => left - right)
}

/**
 * Managed WAF (OWASP CRS) settings of one WAF rule (PA-12): a CRS profile
 * pack (its rule sets, paranoia, threshold and action are the pack's) and
 * the rules its sites do not evaluate (from the profile's exports; applied
 * per request, no node reload). A site may pick another profile or its own
 * exclusions (站点“防护”页 CRS 档位).
 */
export function ManagedWAFFields({ ruleName, form, profiles }: {
  ruleName: number
  form: FormInstance
  profiles: CRSProfilePack[] | undefined
}) {
  const { t } = useTranslation('managedRules')
  const tierName = useTierName()
  const base = [ruleName, 'action_config', 'managed_waf'] as const
  const exclusionsPath = ['rules', ruleName, 'action_config', 'managed_waf', 'exclusions']
  return (
    <div className="managed-waf-fields">
      <Space size={10} wrap align="start">
        <Form.Item name={[...base, 'profile']} label={t('waf.profile')} tooltip={t('waf.profileHelp')} rules={[{ required: true }]}>
          <Select aria-label={t('waf.profile')} style={{ width: 240 }} loading={profiles === undefined}
            notFoundContent={t('waf.noProfiles')}
            options={orderedProfiles(profiles ?? []).map((profile) => ({ value: profile.pack_id, label: tierName(profile) }))} />
        </Form.Item>
        {engineFields.map(([field, min, max]) => (
          <Form.Item key={field} name={[...base, field]} label={t(`waf.${field}`)} rules={[{ required: true, type: 'number', min, max }]}>
            <InputNumber aria-label={t(`waf.${field}`)} min={min} max={max} precision={0} style={{ width: 150 }} />
          </Form.Item>
        ))}
        <Form.Item name={[...base, 'request_body_limit_action']} label={t('waf.request_body_limit_action')} rules={[{ required: true }]}>
          <Select style={{ width: 180 }} options={['reject', 'partial'].map((value) => ({ value, label: t(`waf.bodyActions.${value}`) }))} />
        </Form.Item>
        <Form.Item name={[...base, 'inspection_limit_action']} label={t('waf.inspection_limit_action')} tooltip={t('waf.inspection_limit_actionHelp')}>
          <Select aria-label={t('waf.inspection_limit_action')} style={{ width: 180 }} options={['log', 'block'].map((value) => ({ value, label: t(`waf.limitActions.${value}`) }))} />
        </Form.Item>
      </Space>
      <Form.Item noStyle shouldUpdate>
        {() => {
          const selected = form.getFieldValue(['rules', ruleName, 'action_config', 'managed_waf', 'profile']) as string | undefined
          const profile = profiles?.find((item) => item.pack_id === selected)
          return (
            <>
              {profile ? <CRSTierDetails profile={profile} profiles={profiles ?? []}
                exclusions={crsRuleIdsPattern.test(exclusionText(form.getFieldValue(exclusionsPath)))
                  ? parseCRSRuleIds(exclusionText(form.getFieldValue(exclusionsPath))) : undefined}
                onExclusions={(ids) => {
                  form.setFieldValue(exclusionsPath, ids.join(', '))
                  void form.validateFields([exclusionsPath]).catch(() => undefined)
                }} /> : null}
              <Form.Item name={[...base, 'exclusions']} label={t('waf.exclusions')} tooltip={t('waf.exclusionsHelp')}
                rules={[{ pattern: crsRuleIdsPattern, message: t('waf.ruleIdsInvalid') }, {
                  validator: async (_, value: string | undefined) => {
                    const unknown = parseCRSRuleIds(value ?? '').filter((id) => profile && !profile.exports.includes(id))
                    if (unknown.length) throw new Error(t('waf.notExported', { ids: unknown.join(', ') }))
                  },
                }]}>
                <Input aria-label={t('waf.exclusions')} placeholder="941160, 941310" style={{ maxWidth: 520 }} />
              </Form.Item>
            </>
          )
        }}
      </Form.Item>
    </div>
  )
}

function exclusionText(value: unknown): string {
  return Array.isArray(value) ? value.join(', ') : typeof value === 'string' ? value : ''
}

type ManagedWAFForm = Omit<SecurityPolicyManagedWAF, 'exclusions'> & { exclusions?: string | number[] }

/** Form value -> API value (rule IDs typed as text). */
export function managedWAFFromForm(value: SecurityPolicyManagedWAF): SecurityPolicyManagedWAF {
  const exclusions = (value as ManagedWAFForm).exclusions
  const ids = Array.isArray(exclusions) ? exclusions : parseCRSRuleIds(exclusions ?? '')
  return { ...value, exclusions: ids.length ? ids : undefined }
}

/** API value -> form value. */
export function managedWAFToForm(value: SecurityPolicyManagedWAF): SecurityPolicyManagedWAF {
  return { ...value, inspection_limit_action: value.inspection_limit_action ?? 'log',
    exclusions: (value.exclusions ?? []).join(', ') as unknown as number[] }
}

/**
 * "Import from the system rule catalog": WAF rule sets, or up to 8 CC rule
 * groups merged in the order chosen (#16; the server drops rules an earlier
 * group already has and reports same-match rules that act differently).
 */
export function CatalogImport({ kind, catalog, onImport }: {
  kind: SecurityPolicyKind
  catalog: SystemRule[]
  onImport: (keys: string[]) => Promise<Pick<CatalogRuleSet, 'rules' | 'duplicates' | 'conflicts'>>
}) {
  const { t } = useTranslation('managedRules')
  const { t: tp } = useTranslation('securityPolicies')
  const [keys, setKeys] = useState<string[]>([])
  const [imported, setImported] = useState<string[]>([])
  const [pending, setPending] = useState(false)
  const [merge, setMerge] = useState<Pick<CatalogRuleSet, 'duplicates' | 'conflicts'> | null>(null)
  const usable = catalog.filter((rule) => rule.status === 'active' && rule.selectable)
  // WAF: self-developed detection (default) and OWASP CRS sit side by side; a
  // policy may import either, both or neither. Hidden engine settings / rule
  // text are not rule sets.
  const wafGroup = (engine: boolean) => usable.filter((rule) => rule.kind === 'waf_rule_set' &&
    Boolean(rule.body.waf_rule_set?.engine) === engine && Boolean(engine || rule.body.waf_rule_set?.rules))
    .map((rule) => ({ value: rule.system_key, label: rule.name }))
  type Option = { value: string; label: string }
  const options: Array<Option | { label: string; options: Option[] }> = kind === 'waf'
    ? [{ label: t('import.groups.self'), options: wafGroup(false) }, { label: t('import.groups.crs'), options: wafGroup(true) }]
      .filter((group) => group.options.length > 0)
    : usable.filter((rule) => rule.kind === 'cc_rule_group').map((rule) => ({ value: rule.system_key, label: rule.name }))
  if (kind === 'acl') return null
  const conflicts = merge?.conflicts ?? []
  return (
    <Space direction="vertical" size={6}>
      <Space size={8} wrap>
        <Select
          aria-label={t('import.select')} mode="multiple" maxCount={kind === 'cc' ? maxCCRuleGroups : undefined} style={{ minWidth: 320 }}
          placeholder={t(`import.placeholder.${kind}`)} value={keys} options={options}
          // Every set, scrollable and searchable: the default virtual list
          // showed about 8 and hid the CRS sets (live-waf P4).
          // Search by name or key, ignoring case and spaces: "sql 注入", "SQL注入"
          // and "sqli" all find waf_set:sqli (live-waf P12: at 276d058ff antd
          // searched the value "waf_set:sqli" only, so typing the name found nothing).
          showSearch virtual={false} listHeight={360}
          filterOption={(input, option) => {
            const needle = input.replace(/\s+/gu, '').toLowerCase()
            const value = option && 'value' in option ? String(option.value ?? '') : ''
            const label = option && 'label' in option ? String(option.label ?? '') : ''
            return `${label}\n${value}`.replace(/[ \t]+/gu, '').toLowerCase().includes(needle)
          }}
          onChange={(value: string[]) => setKeys(value)}
        />
        <Button type="primary" disabled={keys.length === 0} loading={pending} onClick={() => {
          setPending(true)
          setMerge(null)
          const next = keys
          void onImport(next).then((result) => { setMerge(result); setImported(next) }).catch(() => undefined).finally(() => setPending(false))
        }}>{t('import.button')}</Button>
      </Space>
      {keys.length > 0 && keys.some((key) => !imported.includes(key))
        ? <Alert type="warning" showIcon role="status" message={t('import.pendingHint', { count: keys.filter((key) => !imported.includes(key)).length })} />
        : null}
      {merge?.duplicates?.length ? <Alert type="info" showIcon role="status" message={tp('catalogMerge.duplicates', { count: merge.duplicates.length })} /> : null}
      {conflicts.length ? <Alert type="warning" showIcon role="status"
        message={tp('catalogMerge.conflicts', { rules: conflicts.map((conflict) => conflict.rule).join('、') })} /> : null}
    </Space>
  )
}
