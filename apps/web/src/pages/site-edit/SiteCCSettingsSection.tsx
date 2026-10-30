import { useIsMutating, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Input, InputNumber, Radio, Select, Space, Switch } from 'antd'
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import {
  securityPoliciesApi,
  type SecurityPolicy,
  type SecurityPolicyCCAutoSwitch,
  type SecurityPolicyCCDuration,
  type SecurityPolicyCCSettings,
  type SecurityPolicyCCTrustedCrawler,
} from '../../api/securityPolicies'
import { securitySystemRulesApi } from '../../api/securitySystemRules'
import '../../i18n/siteCCSettings'
import { FeedbackWhen, fieldReasonText, submitErrorFields } from '@cdnca/ui'
import { useInstantDraft, useInstantFeedback } from './instantSave'

type DurationMode = 'rule' | 'system' | 'custom'
type SwitchMode = 'off' | 'system' | 'custom'

const qpsPresets = [20, 50, 100, 200, 500, 1000] as const
const defaultRecoverSeconds = 300

/** One trusted crawler as edited: lists are one value per line. */
interface CrawlerDraft {
  name: string
  tokens: string
  networks: string
  suffixes: string
}

interface Draft {
  ban: DurationMode
  banSeconds: number
  pass: DurationMode
  passSeconds: number
  switchMode: SwitchMode
  qpsTotal: number
  qps5xx: number
  group?: string
  recover: number
  crawlers: CrawlerDraft[]
  cookieDomain: string
}

function durationMode(value: SecurityPolicyCCDuration | undefined): DurationMode {
  return value ? value.mode : 'rule'
}

const lines = (value: string) => value.split(/[\n,]/).map((item) => item.trim()).filter(Boolean)

function draftFromSettings(settings: SecurityPolicyCCSettings | undefined): Draft {
  const auto = settings?.auto_switch
  const custom = auto?.mode === 'custom'
  const qpsTotal = custom ? auto!.qps_total : 20
  return {
    ban: durationMode(settings?.ban_seconds), banSeconds: settings?.ban_seconds?.seconds ?? 360,
    pass: durationMode(settings?.pass_seconds), passSeconds: settings?.pass_seconds?.seconds ?? 21600,
    switchMode: auto ? auto.mode : 'off', qpsTotal,
    qps5xx: custom ? auto!.qps_5xx : 0, group: custom ? auto!.rule_groups[0] : undefined,
    recover: custom ? auto!.recover_seconds : defaultRecoverSeconds,
    crawlers: (settings?.trusted_crawlers ?? []).map((crawler) => ({ name: crawler.name,
      tokens: crawler.user_agent_tokens.join('\n'), networks: (crawler.networks ?? []).join('\n'),
      suffixes: (crawler.rdns_suffixes ?? []).join('\n') })),
    cookieDomain: settings?.challenge_cookie_domain ?? '',
  }
}

function crawlersFromDraft(crawlers: CrawlerDraft[]): SecurityPolicyCCTrustedCrawler[] | undefined {
  if (crawlers.length === 0) return undefined
  return crawlers.map((crawler) => {
    const value: SecurityPolicyCCTrustedCrawler = { name: crawler.name.trim(), user_agent_tokens: lines(crawler.tokens) }
    if (lines(crawler.networks).length) value.networks = lines(crawler.networks)
    if (lines(crawler.suffixes).length) value.rdns_suffixes = lines(crawler.suffixes)
    return value
  })
}

function durationFromDraft(mode: DurationMode, seconds: number): SecurityPolicyCCDuration | undefined {
  if (mode === 'rule') return undefined
  return { mode, seconds: mode === 'system' ? 0 : seconds }
}

/**
 * 站点 CC 防护：自动切换（网站编辑「自动防御」标签）与高级设置（黑/白名单时间，「CC防护」标签）。The settings belong to
 * the site's CC rule set (policy.cc_settings); saving writes a new version of
 * it, which reaches the nodes when published.
 * fix-siteprot: with `publish` (the site tab) the saved version is published to the site right away.
 * fix-siteautodef: `part` shows only 自动切换 (the site's 自动防御 tab) or only the advanced settings (CC防护 tab);
 * either part still saves the whole cc_settings built from its draft, as before.
 */
export function SiteCCSettingsSection({ policy, accessToken, isAdmin, canManage, onPublish, publish, part }: {
  policy: SecurityPolicy | undefined
  accessToken: string
  isAdmin: boolean
  canManage: boolean
  onPublish: () => void
  /** Publishes the saved version to the site; resolves false when the publish was refused. */
  publish?: (saved: SecurityPolicy) => Promise<boolean>
  part?: 'autoSwitch' | 'advanced'
}) {
  const { t, i18n } = useTranslation('siteCCSettings')
  const queryClient = useQueryClient()
  const [savedVersion, setSavedVersion] = useState<number | null>(null)
  const [published, setPublished] = useState<boolean | null>(null)
  const feedback = useInstantFeedback()
  // fix-siteinstant: switches and selects save at once, numbers and lists on blur; incomplete rows wait.
  const storedDraft = useMemo(() => draftFromSettings(policy?.cc_settings), [policy?.id, policy?.version, policy?.cc_settings]) // eslint-disable-line react-hooks/exhaustive-deps
  const instantKey = ['site-instant', 'cc-settings', policy?.id]
  const instant = useInstantDraft(storedDraft, {
    busy: useIsMutating({ mutationKey: instantKey }) > 0,
    isValid: (value) => Boolean(policy) && canManage && !customInvalidOf(value) && !crawlerProblemOf(value),
    submit: (value) => save.mutate(value),
  })
  const draft = instant.draft
  // fix-cfl-b (10-27 #8): 自定义 only opens the number box. It is view
  // state, not a setting: kept in the draft it was saved as an unchanged
  // version and the reloaded value (a preset) closed the box again.
  const [qpsCustomOpen, setQpsCustomOpen] = useState(false)
  const qpsCustom = qpsCustomOpen || !qpsPresets.includes(draft.qpsTotal as typeof qpsPresets[number])
  const groups = useQuery({
    queryKey: ['site-cc-settings', 'rule-groups'],
    enabled: Boolean(policy),
    queryFn: () => securitySystemRulesApi.list(accessToken, 'cc_rule_group'),
  })
  // The platform's default crawlers (search engines, AI and social
  // crawlers with their official IP ranges or rDNS verification).
  const defaultCrawlers = useQuery({
    queryKey: ['site-cc-settings', 'default-crawlers'],
    enabled: Boolean(policy),
    queryFn: () => securitySystemRulesApi.defaultCrawlers(accessToken),
  })
  const crawlerPresets = useMemo<CrawlerDraft[]>(() => (defaultCrawlers.data ?? [])
    .filter((crawler) => crawler.ready)
    .map((crawler) => ({ name: crawler.name, tokens: crawler.user_agent_tokens.join('\n'),
      networks: crawler.networks.join('\n'), suffixes: crawler.rdns_suffixes.join('\n') })), [defaultCrawlers.data])
  const groupOptions = useMemo(() => (groups.data ?? [])
    .filter((rule) => rule.status === 'active' && rule.selectable !== false && (rule.body.cc_rule_group?.entries.length ?? 0) > 0)
    .sort((left, right) => left.sort - right.sort)
    .map((rule) => ({ value: rule.system_key, label: rule.name })), [groups.data])
  const groupName = (key: string | undefined) => groupOptions.find((option) => option.value === key)?.label ?? key ?? ''

  const save = useMutation({
    mutationKey: instantKey,
    mutationFn: async (draft: Draft) => {
      if (!policy) throw new Error('no policy')
      const settings: SecurityPolicyCCSettings = {
        ban_seconds: durationFromDraft(draft.ban, draft.banSeconds),
        pass_seconds: durationFromDraft(draft.pass, draft.passSeconds),
        trusted_crawlers: crawlersFromDraft(draft.crawlers),
        challenge_cookie_domain: draft.cookieDomain.trim() || undefined,
      }
      if (draft.switchMode === 'system') {
        settings.auto_switch = { mode: 'system', qps_total: 0, qps_5xx: 0, recover_seconds: 0, rule_groups: [], rules: [] }
      } else if (draft.switchMode === 'custom') {
        const stored = policy.cc_settings?.auto_switch
        let rules: SecurityPolicyCCAutoSwitch['rules']
        if (stored?.mode === 'custom' && stored.rule_groups[0] === draft.group) {
          rules = stored.rules
        } else {
          const expanded = await securityPoliciesApi.catalogRules(accessToken, 'cc', [draft.group!], ...(isAdmin ? [policy.scope_id] as const : [] as const))
          rules = expanded.rules
        }
        settings.auto_switch = { mode: 'custom', qps_total: draft.qpsTotal, qps_5xx: draft.qps5xx,
          recover_seconds: draft.recover, rule_groups: [draft.group!], rules }
      }
      const cleaned = Object.fromEntries(Object.entries(settings).filter(([, value]) => value !== undefined)) as SecurityPolicyCCSettings
      const saved = await securityPoliciesApi.update(accessToken, policy.id, policy.version, {
        kind: policy.kind, name: policy.name, description: policy.description, enabled: policy.enabled,
        default_action: policy.default_action, rules: policy.rules,
        cc_settings: Object.keys(cleaned).length ? cleaned : undefined,
      }, `site-cc-settings-${policy.id}-${policy.version}-${crypto.randomUUID()}`)
      return { saved, published: publish ? await publish(saved) : null }
    },
    onSuccess: ({ saved: updated, published: result }) => {
      setSavedVersion(updated.version)
      setPublished(result)
      if (result !== false) feedback.success()
      void queryClient.invalidateQueries({ queryKey: ['site-protection'] })
    },
    // fix-fielderr-be4: a refused field keeps the typed value (marked below);
    // any other failure goes back to the stored settings.
    onError: (error) => { if (!refusedField(error)) instant.revert() },
  })
  function refusedField(error: unknown) {
    return submitErrorFields(error).find((item) => item.field.startsWith('cc_settings.'))
  }
  function customInvalidOf(value: Draft): boolean {
    return value.switchMode === 'custom' && (value.qpsTotal <= 0 && value.qps5xx <= 0 || !value.group)
  }
  function crawlerProblemOf(value: Draft): string | null | undefined {
    return value.crawlers.map((crawler) => !crawler.name.trim() || lines(crawler.tokens).length === 0
      ? t('crawlers.needName')
      : lines(crawler.networks).length === 0 && lines(crawler.suffixes).length === 0
        ? t('crawlers.needVerify', { name: crawler.name.trim() }) : null).find(Boolean)
  }

  if (!policy) return <Alert type="info" showIcon message={t(part === 'autoSwitch' ? 'noPolicyAutoSwitch' : 'noPolicy')} />
  const showAutoSwitch = part !== 'advanced'
  const showAdvanced = part !== 'autoSwitch'
  const stored = policy.cc_settings
  const set = (patch: Partial<Draft>) => { setSavedVersion(null); save.reset(); instant.set(patch) }
  const refused = refusedField(save.error)
  const refusedText = refused ? fieldReasonText(refused.reason, i18n.resolvedLanguage === 'en-US' ? 'en' : i18n.resolvedLanguage === 'zh-TW' ? 'zh-tw' : 'zh-cn') : ''
  // The control a refused path belongs to; trusted_crawlers[n].x is row n.
  const isRefused = (path: string) => refused?.field === `cc_settings.${path}` ||
    Boolean(refused?.field.startsWith(`cc_settings.${path}.`) || refused?.field.startsWith(`cc_settings.${path}[`))
  const statusOf = (path: string) => isRefused(path) ? 'error' as const : undefined
  const refusedLine = (path: string, label?: string) => isRefused(path)
    ? <div className="site-cc-field-error" role="alert">{label ? `${label}：${refusedText}` : refusedText}</div> : null
  const crawlerColumn = (index: number) => {
    const match = refused ? /^cc_settings\.trusted_crawlers\[(\d+)\](?:\.([a-z_]+))?/.exec(refused.field) : null
    return match && Number(match[1]) === index ? match[2] ?? 'name' : null
  }
  const customInvalid = customInvalidOf(draft)
  const crawlerProblem = crawlerProblemOf(draft)
  const disabled = !canManage
  const setCrawler = (index: number, patch: Partial<CrawlerDraft>) => set({
    crawlers: draft.crawlers.map((crawler, candidate) => candidate === index ? { ...crawler, ...patch } : crawler) })
  const addPresets = () => set({ crawlers: [...draft.crawlers,
    ...crawlerPresets.filter((preset) => !draft.crawlers.some((crawler) => crawler.name.trim() === preset.name))]
    .slice(0, 32) })
  const durationRow = (kind: 'ban' | 'pass') => {
    const mode = kind === 'ban' ? draft.ban : draft.pass
    const seconds = kind === 'ban' ? draft.banSeconds : draft.passSeconds
    const storedValue = kind === 'ban' ? stored?.ban_seconds : stored?.pass_seconds
    return <div className="site-protection-setting-row" key={kind}>
      <span className="site-protection-label">{t(`advanced.${kind}`)}</span>
      <div className="site-protection-control">
        <Space wrap>
          <Select aria-label={t(`advanced.${kind}`)} value={mode} disabled={disabled} style={{ minWidth: 160 }} status={statusOf(`${kind}_seconds.mode`)}
            onChange={(value: DurationMode) => set(kind === 'ban' ? { ban: value } : { pass: value })}
            options={(['rule', 'system', 'custom'] as const).map((value) => ({ value, label: value === 'system' && storedValue?.mode === 'system'
              ? t('advanced.systemValue', { seconds: storedValue.seconds }) : t(`advanced.modes.${value}`) }))} />
          {mode === 'custom' ? <InputNumber aria-label={`${t(`advanced.${kind}`)} ${t('advanced.modes.custom')}`} min={kind === 'ban' ? 1 : 60}
            max={kind === 'ban' ? 86400 : 604800} value={seconds} disabled={disabled} addonAfter={t('autoSwitch.seconds')} status={statusOf(`${kind}_seconds.seconds`)}
            onChange={(value) => { if (value !== null) set(kind === 'ban' ? { banSeconds: value } : { passSeconds: value }) }} /> : null}
        </Space>
        {refusedLine(`${kind}_seconds`)}
        <p>{t(`advanced.${kind}Hint`)}</p>
      </div>
    </div>
  }

  return <div className="site-cc-settings" aria-busy={save.isPending} {...instant.typingProps}>
    {showAutoSwitch ? <div className="site-protection-setting-row">
    <span className="site-protection-label" id="site-cc-auto-switch-label">{t('autoSwitch.label')}</span>
    <div className="site-protection-control site-cc-auto-switch">
      <Space align="center">
        <Switch aria-labelledby="site-cc-auto-switch-label" checked={draft.switchMode !== 'off'} disabled={disabled}
          onChange={(checked) => set({ switchMode: checked ? (stored?.auto_switch?.mode ?? 'system') : 'off' })} />
        <span>{draft.switchMode !== 'off' ? t('autoSwitch.enabled') : t('autoSwitch.disabled')}</span>
      </Space>
      <p>{t('autoSwitch.hint')}</p>
      {draft.switchMode !== 'off' ? <div className="site-cc-auto-switch-fields">
        <Radio.Group aria-label={t('autoSwitch.source')} value={draft.switchMode} disabled={disabled}
          onChange={(event) => set({ switchMode: event.target.value as SwitchMode })}
          options={[{ value: 'system', label: t('autoSwitch.system') }, { value: 'custom', label: t('autoSwitch.custom') }]} />
        {draft.switchMode === 'system'
          ? <p className="site-cc-auto-switch-summary">{stored?.auto_switch?.mode === 'system' && stored.auto_switch.rules.length > 0
            ? t('autoSwitch.systemActive', { qps: stored.auto_switch.qps_total, errors: stored.auto_switch.qps_5xx,
              group: groupName(stored.auto_switch.rule_groups[0]), seconds: stored.auto_switch.recover_seconds })
            : stored?.auto_switch?.mode === 'system' ? t('autoSwitch.systemOff') : null}</p>
          : <Space direction="vertical" size="small">
            <Space wrap>
              <label>{t('autoSwitch.qps')}
                <Select aria-label={t('autoSwitch.qps')} disabled={disabled} style={{ minWidth: 180, marginInlineStart: 8 }}
                  value={qpsCustom ? 'custom' : draft.qpsTotal}
                  onChange={(value: number | 'custom') => { setQpsCustomOpen(value === 'custom'); if (value !== 'custom') set({ qpsTotal: value }) }}
                  options={[...qpsPresets.map((value) => ({ value, label: t(`autoSwitch.presets.${value}`) })),
                    { value: 'custom', label: t('autoSwitch.presetCustom') }]} />
              </label>
              {qpsCustom ? <InputNumber aria-label={`${t('autoSwitch.qps')} ${t('autoSwitch.presetCustom')}`} min={0} max={1000000}
                value={draft.qpsTotal} disabled={disabled} status={statusOf('auto_switch.qps_total')} onChange={(value) => { if (value !== null) set({ qpsTotal: value }) }} /> : null}
              <label>{t('autoSwitch.qps5xx')}
                <InputNumber aria-label={t('autoSwitch.qps5xx')} min={0} max={1000000} value={draft.qps5xx} disabled={disabled} status={statusOf('auto_switch.qps_5xx')}
                  style={{ marginInlineStart: 8 }} onChange={(value) => { if (value !== null) set({ qps5xx: value }) }} />
              </label>
            </Space>
            <span className="site-cc-hint">{t('autoSwitch.zeroDisabled')}</span>
            <Space wrap>
              <label>{t('autoSwitch.ruleGroup')}
                <Select aria-label={t('autoSwitch.ruleGroup')} disabled={disabled} loading={groups.isLoading} style={{ minWidth: 200, marginInlineStart: 8 }}
                  placeholder={t('autoSwitch.ruleGroupPlaceholder')} value={draft.group} options={groupOptions} status={statusOf('auto_switch.rule_groups')}
                  onChange={(value: string) => set({ group: value })} />
              </label>
              <label>{t('autoSwitch.recover')}
                <InputNumber aria-label={t('autoSwitch.recover')} min={60} max={86400} value={draft.recover} disabled={disabled} status={statusOf('auto_switch.recover_seconds')}
                  addonAfter={t('autoSwitch.seconds')} style={{ marginInlineStart: 8 }} onChange={(value) => { if (value !== null) set({ recover: value }) }} />
              </label>
            </Space>
            {refusedLine('auto_switch')}
            {customInvalid ? <Alert type="warning" showIcon message={!draft.group ? t('autoSwitch.needGroup') : t('autoSwitch.needThreshold')} /> : null}
          </Space>}
        <Alert type="info" showIcon message={t('capability')} />
      </div> : null}
    </div>
    </div> : null}
    {showAdvanced ? <>
    <h3 className="site-cc-advanced-title">{t('advanced.title')}</h3>
    {durationRow('ban')}
    {durationRow('pass')}
    <div className="site-protection-setting-row">
      <span className="site-protection-label">{t('crawlers.title')}</span>
      <div className="site-protection-control">
        <p>{t('crawlers.hint')}</p>
        {draft.crawlers.length === 0 ? <p>{t('crawlers.empty')}</p> : null}
        <Space direction="vertical" size="small" style={{ width: '100%' }}>
          {draft.crawlers.map((crawler, index) => <Space key={index} align="start" wrap>
            <Input aria-label={`${t('crawlers.name')} ${index + 1}`} placeholder={t('crawlers.name')} value={crawler.name}
              disabled={disabled} status={crawlerColumn(index) === 'name' ? 'error' : undefined} style={{ width: 120 }} onChange={(event) => setCrawler(index, { name: event.target.value })} />
            <Input.TextArea aria-label={`${t('crawlers.tokens')} ${index + 1}`} placeholder={t('crawlers.tokens')} value={crawler.tokens}
              disabled={disabled} status={crawlerColumn(index) === 'user_agent_tokens' ? 'error' : undefined} autoSize={{ minRows: 1, maxRows: 4 }} style={{ width: 180 }}
              onChange={(event) => setCrawler(index, { tokens: event.target.value })} />
            <Input.TextArea aria-label={`${t('crawlers.networks')} ${index + 1}`} placeholder={t('crawlers.networks')} value={crawler.networks}
              disabled={disabled} status={crawlerColumn(index) === 'networks' ? 'error' : undefined} autoSize={{ minRows: 1, maxRows: 4 }} style={{ width: 200 }}
              onChange={(event) => setCrawler(index, { networks: event.target.value })} />
            <Input.TextArea aria-label={`${t('crawlers.suffixes')} ${index + 1}`} placeholder={t('crawlers.suffixes')} value={crawler.suffixes}
              disabled={disabled} status={crawlerColumn(index) === 'rdns_suffixes' ? 'error' : undefined} autoSize={{ minRows: 1, maxRows: 4 }} style={{ width: 200 }}
              onChange={(event) => setCrawler(index, { suffixes: event.target.value })} />
            <Button danger type="text" aria-label={`${t('crawlers.remove')} ${index + 1}`} disabled={disabled}
              onClick={() => set({ crawlers: draft.crawlers.filter((_, candidate) => candidate !== index) })}>{t('crawlers.remove')}</Button>
          </Space>)}
          <Space wrap>
            <Button disabled={disabled || draft.crawlers.length >= 32 || crawlerPresets.length === 0} onClick={addPresets}>{t('crawlers.presets')}</Button>
            <Button disabled={disabled || draft.crawlers.length >= 32}
              onClick={() => set({ crawlers: [...draft.crawlers, { name: '', tokens: '', networks: '', suffixes: '' }] })}>{t('crawlers.add')}</Button>
          </Space>
          {refused?.field.startsWith('cc_settings.trusted_crawlers') ? refusedLine('trusted_crawlers',
            { name: t('crawlers.name'), user_agent_tokens: t('crawlers.tokens'), networks: t('crawlers.networks'), rdns_suffixes: t('crawlers.suffixes') }[
              /^cc_settings\.trusted_crawlers\[\d+\]\.([a-z_]+)/.exec(refused.field)?.[1] ?? ''] ?? t('crawlers.title')) : null}
          {crawlerProblem ? <Alert type="warning" showIcon message={crawlerProblem} /> : null}
        </Space>
      </div>
    </div>
    <div className="site-protection-setting-row">
      <span className="site-protection-label" id="site-cc-cookie-domain-label">{t('cookieDomain.label')}</span>
      <div className="site-protection-control">
        <Input aria-labelledby="site-cc-cookie-domain-label" placeholder={t('cookieDomain.placeholder')} value={draft.cookieDomain}
          disabled={disabled} maxLength={253} style={{ maxWidth: 360 }} status={statusOf('challenge_cookie_domain')}
          onChange={(event) => set({ cookieDomain: event.target.value })} />
        {refusedLine('challenge_cookie_domain')}
        <p>{t('cookieDomain.hint')}</p>
      </div>
    </div>
    {draft.crawlers.length > 0 || draft.cookieDomain.trim() ? <Alert type="info" showIcon message={t('v6Capability')} /> : null}
    </> : null}
    {savedVersion !== null && published === null ? <Alert type="success" showIcon message={t('saved', { version: savedVersion })}
      action={<Button size="small" onClick={onPublish}>{t('publish')}</Button>} /> : null}
    {savedVersion !== null && published === false ? <Alert type="warning" showIcon role="status" message={t('publishFailed')} /> : null}
    {save.isError && !refused ? <FeedbackWhen title={t('saveFailed', {
      message: save.error instanceof ApiError ? save.error.code : (save.error as Error).message })} /> : null}
  </div>
}
