import { useEffect, useMemo, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Empty, Input, Popconfirm, Switch, Tag, Tooltip } from 'antd'
import { Plus, RefreshCw } from 'lucide-react'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'

import { ApiError } from '../../api/auth'
import { challengePoliciesApi, type ChallengePolicy } from '../../api/challengePolicies'
import {
  isQuickBlockRuleID,
  securityPoliciesApi,
  systemDefaultWAFKey,
  type SecurityActivationStatus,
  type SecurityPolicy,
  type SecurityPolicyRule,
  type SecurityPolicyWAFSettings,
} from '../../api/securityPolicies'
import { securitySystemRulesApi } from '../../api/securitySystemRules'
import '../../i18n/siteProtection'
import { activationErrorCodes } from '../../i18n/securityPoliciesActivationAuto'
import { SiteCCSettingsSection } from './SiteCCSettingsSection'
import { SiteQuickBlockCard } from './SiteQuickBlockCard'
import { SiteCRSOverrideCard } from './SiteCRSOverrideCard'
import { SiteQuickBlockOverrideCard } from './SiteQuickBlockOverrideCard'
import { SiteOfficialPacksCard } from './SiteOfficialPacksCard'
import { orderedProfiles, useTierName } from '../security/CRSTierDetails'
import '../../i18n/wafRuleSubscriptions'
import { wafModuleCatalogSuffix, wafModuleStates, type WAFModuleKey, type WAFModuleState } from './wafModuleStates'
import {
  ccPresetGroups, crsCatalogDefaultsKey, currentCCPreset, detachSiteLibrary, editCCRules, editWAFSourceRules, fieldsOf, ipLines, managedRuleNames,
  managedRuleValues, managedWAFProfile, proxyBlocked, publishAutoResumes, publishToSite, regionPreset, saveSiteLibrary, setManagedWAFTier, toggleWAFSet, type CCEdit, type CCPreset,
} from './sitePolicyEdits'
import './SiteProtectionTabs.css'
import './SiteAutoDefenseTab.css'
import { FeedbackWhen } from '@cdnca/ui'
import SiteEditState from './SiteEditState'
import { SiteTabSummary } from './SiteTabSummary'
import { rebaseDraft, useCommitRequest, useInstantFeedback } from './instantSave'

export type SiteProtectionProps = {
  siteId: string
  host: string
  scopeKind: 'platform' | 'tenant'
  scopeId: string
  accessToken: string
  permissions: readonly string[]
  locked: boolean
  /** The site's tenant scope; administrators need it for the CC statistics view. */
  siteScopeId?: string
  /** The site's current CNAME (attack escalation CNAME split hint). */
  cname?: string
  /** The site's owner: administrators create the site's own library for them (tenants: the server fills it). */
  siteOwnerId?: string
}

type CCMode = 'off' | 'loose' | 'js' | 'fiveSecond' | 'click' | 'slider' | 'captcha' | 'rotate' | 'simpleClick' | 'simpleSlider' | 'custom'
type CrawlerMode = 'none' | 'allow' | 'block'
type RegionMode = 'none' | 'abroad' | 'abroadHmt' | 'chinaHmt' | 'china' | 'custom'

const ccModes: CCMode[] = ['off', 'loose', 'js', 'fiveSecond', 'click', 'slider', 'captcha', 'rotate', 'simpleClick', 'simpleSlider', 'custom']
const regionModes: RegionMode[] = ['none', 'abroad', 'abroadHmt', 'chinaHmt', 'china', 'custom']
const challengeModeMap: Record<string, CCMode> = {
  js: 'js',
  five_second: 'fiveSecond',
  click: 'click',
  simple_click: 'simpleClick',
  slider: 'slider',
  simple_slider: 'simpleSlider',
  captcha: 'captcha',
  rotate_image: 'rotate',
}

/** A11: every link out of the site's CC/WAF tabs names the site, its host and,
 * for administrators, the site's tenant scope, so the target page does not ask
 * for them again. The server still checks ownership. */
function siteRuleLink(path: string, context: { siteId: string; host?: string; scopeKind: 'platform' | 'tenant'; siteScopeId?: string },
  extra: Record<string, string | undefined> = {}): string {
  const params = new URLSearchParams({ site_id: context.siteId })
  if (context.host) params.set('host', context.host)
  if (context.scopeKind === 'platform' && context.siteScopeId) params.set('tenant_scope_id', context.siteScopeId)
  for (const [key, value] of Object.entries(extra)) if (value) params.set(key, value)
  return `${path}?${params.toString()}`
}

export function hasPermission(permissions: readonly string[], permission: string): boolean {
  return permissions.includes(permission) || permissions.includes('platform.admin')
}

function policyRules(policy: SecurityPolicy | undefined): SecurityPolicyRule[] {
  return policy?.rules?.filter((rule) => rule.enabled) ?? []
}

function fallbackMode(policy: SecurityPolicy | undefined, challenge: ChallengePolicy | undefined): CCMode {
  const fallback = policyRules(policy).find((rule) => rule.conditions.length === 0 && rule.action === 'challenge')
  const type = fallback?.action_config.challenge?.type
  if (type && challengeModeMap[type]) return challengeModeMap[type]
  if (!challenge?.enabled) return 'off'
  if (challenge.mode === 'delay') return 'fiveSecond'
  if (challenge.mode === 'click' || challenge.mode === 'slider' || challenge.mode === 'captcha') return challenge.mode
  return 'custom'
}

// 放行 = the CC library's trusted crawlers (蜘蛛白名单); 拦截 = the managed crawler block rule.
function crawlerMode(policy: SecurityPolicy | undefined): CrawlerMode {
  if (policyRules(policy).some((rule) => rule.name === managedRuleNames.crawlerBlock)) return 'block'
  return policy?.cc_settings?.trusted_crawlers?.length ? 'allow' : 'none'
}

function ProtectionLoading() {
  const { t } = useTranslation('siteProtection')
  return <SiteEditState status="loading" className="site-protection-loading" label={t('common.loading')} />
}

function ProtectionError({ onRetry }: { onRetry: () => void }) {
  const { t } = useTranslation('siteProtection')
  return <FeedbackWhen title={t('common.loadFailed')} action={<Button size="small" onClick={onRetry}>{t('common.retry')}</Button>} />
}

function IPListCard({
  title,
  badge,
  badgeClass,
  value,
  disabled,
  onChange,
}: {
  title: string
  badge: string
  badgeClass: string
  value: string
  disabled: boolean
  onChange: (value: string) => void
}) {
  const { t } = useTranslation('siteProtection')
  // 整理 trims and drops blank lines, 去重 drops repeated addresses (comments kept), 清空 empties;
  // each is a change of the list and saves at once (typing saves on blur).
  const lines = value.split('\n')
  const tidy = () => lines.map((line) => line.trim()).filter(Boolean).join('\n')
  const dedupe = () => {
    const seen = new Set<string>()
    return lines.filter((line) => {
      const address = line.replace(/#.*$/, '').trim()
      if (!address) return true
      if (seen.has(address)) return false
      seen.add(address)
      return true
    }).join('\n')
  }
  const tool = (key: 'tidy' | 'dedupe' | 'clear', next: () => string) => <Button size="small" disabled={disabled || !value}
    aria-label={`${t(`cc.listTools.${key}`)} ${title}`} onClick={() => { const text = next(); if (text !== value) onChange(text) }}>{t(`cc.listTools.${key}`)}</Button>
  return <article className="site-protection-ip-card">
    <div className="site-protection-ip-card-head">
      <div><strong>{title}</strong><span className={badgeClass}>{badge}</span></div>
      <div className="site-protection-ip-card-tools">{tool('tidy', tidy)}{tool('dedupe', dedupe)}{tool('clear', () => '')}</div>
    </div>
    <Input.TextArea aria-label={title} value={value} readOnly={disabled} rows={6} placeholder={t('cc.listPlaceholder')}
      onChange={(event) => onChange(event.target.value)} />
    <div className="site-protection-ip-card-foot"><span>{t('cc.lineHint')}</span><span>{t('cc.count', { count: ipLines(value).length })}</span></div>
  </article>
}

// CU-SITE-04: a refused publish keeps the saved library (republished in place, no second library) and its error.
type SaveOutcome = { published: boolean; saved?: SecurityPolicy; publishError?: unknown }

/** The reason of a refused save or publish: the activation codes the rules page explains, else the code. */
function refusalText(error: unknown, t: TFunction<'siteProtection'>): string {
  if (!(error instanceof ApiError)) return (error as Error)?.message ?? ''
  const known = activationErrorCodes.includes(error.code) ? t(`securityPolicies:activation.errors.${error.code}`) : error.code
  return error.requestId ? `${known} ${t('save.requestId', { id: error.requestId })}` : known
}

/** Where the automatic items of this tab went (?tab=autodefense of the site edit page). */
function AutoDefenseMovedNote({ kind }: { kind: 'cc' | 'waf' }) {
  const { t } = useTranslation('siteProtection')
  const [, setSearchParams] = useSearchParams()
  const open = () => setSearchParams((current) => { const next = new URLSearchParams(current); next.set('tab', 'autodefense'); return next })
  return <div className="site-protection-order-note site-protection-moved-note" role="note">
    <span>{t(`autodefense.movedFrom.${kind}`)}</span>
    <Button size="small" type="link" onClick={open}>{t('autodefense.openTab')}</Button>
  </div>
}

// Success is the 操作成功 toast; a refused publish and a failure stay in the page.
function SaveResult({ result, error, onRepublish, republishing }: { result: SaveOutcome | undefined; error: unknown
  onRepublish?: (saved: SecurityPolicy) => void; republishing?: boolean }) {
  const { t } = useTranslation('siteProtection')
  if (error) return <FeedbackWhen title={t('save.failed', { message: refusalText(error, t) })} />
  if (!result || result.published) return null
  // CU-SITE-04: saved but not running; only a refusal the server keeps is retried by itself.
  const autoResume = publishAutoResumes(result.publishError)
  return <Alert type="warning" showIcon role="status" message={t(autoResume ? 'save.publishWaiting' : 'save.publishFailed')}
    description={result.publishError ? refusalText(result.publishError, t) : undefined}
    action={!autoResume && result.saved && onRepublish ? <Button size="small" loading={republishing} disabled={republishing}
      onClick={() => onRepublish(result.saved!)}>{t('save.republish')}</Button> : undefined} />
}

/** The site's WAF/CC policies and binding (the same queries and keys for the CC, WAF and 自动防御 tabs). */
export function useSiteLibrary(kind: 'cc' | 'waf', { siteId, scopeId, accessToken, enabled }: { siteId: string; scopeId: string; accessToken: string; enabled: boolean }) {
  const policiesQuery = useQuery({
    queryKey: ['site-protection', scopeId, siteId, `${kind}-policies`],
    enabled,
    queryFn: () => securityPoliciesApi.list(accessToken, { page: 1, limit: 100, kind }),
  })
  const activationQuery = useQuery({
    queryKey: ['site-protection', scopeId, siteId, `${kind}-activation`],
    enabled,
    retry: false,
    queryFn: ({ signal }) => securityPoliciesApi.getActivationStatus(accessToken, siteId, kind, signal),
  })
  const policies = policiesQuery.data?.items ?? []
  const boundPolicyID = activationQuery.data?.binding?.policy_id
  const activePolicy = policies.find((policy) => policy.id === boundPolicyID)
  return { policiesQuery, activationQuery, policies, boundPolicyID, activePolicy }
}

/** A new library made for the site (unique per site, at most 128 characters). */
function siteLibraryName(host: string, siteId: string) {
  return `本站防护 · ${host.slice(0, 80)}-${siteId.slice(28)}`
}

/** CU-SITE-04: publishes a saved library version to the site, keeping a refusal's error. */
async function publishOutcome(accessToken: string, siteId: string, saved: SecurityPolicy,
  status: SecurityActivationStatus | undefined): Promise<SaveOutcome> {
  try {
    await publishToSite(accessToken, siteId, saved, status)
    return { published: true }
  } catch (publishError) {
    return { published: false, saved, publishError }
  }
}

/** CU-SITE-04: the system default WAF has no rule to publish; the switch stays off (no empty library is sent). */
class WAFDefaultEmptyError extends Error {
  constructor() { super('system default WAF has no rules') }
}

/** Publishes a saved library version to the site (the rules page's site-context save); false when refused. */
export function sitePublisher(accessToken: string, siteId: string, status: SecurityActivationStatus | undefined) {
  return (saved: SecurityPolicy) => publishToSite(accessToken, siteId, saved, status).then(() => true, () => false)
}

/** 运行模式 and 命中自动封禁 of the site's WAF library (the rules page's 策略设置, waf_settings). */
export interface WAFSettingsDraft { observe: boolean; autoBlock: boolean; window: number; hits: number; seconds: number }
// The rules page's defaults for a new auto block.
const defaultAutoBlock = { window_seconds: 60, hit_threshold: 10, block_seconds: 600 }

export function wafSettingsDraft(settings: SecurityPolicyWAFSettings | undefined): WAFSettingsDraft {
  const block = settings?.auto_block ?? defaultAutoBlock
  return { observe: settings?.mode === 'observe', autoBlock: Boolean(settings?.auto_block),
    window: block.window_seconds, hits: block.hit_threshold, seconds: block.block_seconds }
}

/** As the rules page writes them: absent when defending without auto block. */
export function wafSettingsFromDraft(draft: WAFSettingsDraft): SecurityPolicyWAFSettings | undefined {
  const mode = draft.observe ? 'observe' as const : '' as const
  if (!mode && !draft.autoBlock) return undefined
  return draft.autoBlock ? { mode, auto_block: { window_seconds: draft.window, hit_threshold: draft.hits, block_seconds: draft.seconds } } : { mode }
}

interface CCDraft {
  preset: CCMode | undefined
  crawler: CrawlerMode
  whitelist: string
  blacklist: string
  proxy: boolean
  region: RegionMode
}

export function SiteCCTab({ siteId, host, scopeKind, scopeId, accessToken, permissions, locked, siteScopeId, siteOwnerId }: SiteProtectionProps) {
  const { t } = useTranslation('siteProtection')
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const canReadPolicies = hasPermission(permissions, 'security_policies.read')
  // site-parity3b: a platform administrator reads the site's tenant scope directly.
  const targetScopeId = scopeKind === 'platform' ? siteScopeId : scopeId
  const canReadChallenges = Boolean(targetScopeId) && hasPermission(permissions, 'challenge_policies.read')
  const canWrite = !locked && hasPermission(permissions, 'security_policies.manage')
  const isAdmin = scopeKind === 'platform'
  const cc = useSiteLibrary('cc', { siteId, scopeId, accessToken, enabled: canReadPolicies })
  const waf = useSiteLibrary('waf', { siteId, scopeId, accessToken, enabled: canReadPolicies })
  const challengeQuery = useQuery({
    queryKey: ['site-protection', scopeId, siteId, host, 'challenges'],
    enabled: canReadChallenges,
    retry: false,
    queryFn: ({ signal }) => challengePoliciesApi.list(accessToken, targetScopeId ?? '', { limit: 20, site_id: siteId, host }, signal),
  })
  // The system CC rule groups behind the presets (the same query as the auto switch section).
  const groupsQuery = useQuery({
    queryKey: ['site-cc-settings', 'rule-groups'],
    enabled: canReadPolicies,
    queryFn: () => securitySystemRulesApi.list(accessToken, 'cc_rule_group'),
  })
  const crawlersQuery = useQuery({
    queryKey: ['site-cc-settings', 'default-crawlers'],
    enabled: canReadPolicies,
    queryFn: () => securitySystemRulesApi.defaultCrawlers(accessToken),
  })
  const groupNames = useMemo(() => Object.fromEntries((Object.keys(ccPresetGroups) as CCPreset[]).map((preset) =>
    [preset, groupsQuery.data?.find((rule) => rule.system_key === ccPresetGroups[preset])?.name])) as Partial<Record<CCPreset, string>>,
  [groupsQuery.data])

  const ccPolicy = cc.activePolicy
  const wafPolicy = waf.activePolicy
  // C27: the default protection is only known when both the CC binding and the
  // site's challenge policies were read; otherwise no preset is shown as chosen.
  const protectionKnown = cc.activationQuery.isSuccess && (challengeQuery.isSuccess || !canReadChallenges) && groupsQuery.isSuccess
  const stored = useMemo((): CCDraft => ({
    preset: protectionKnown ? currentCCPreset(ccPolicy, groupNames) ?? fallbackMode(ccPolicy, challengeQuery.data?.items[0]) : undefined,
    crawler: crawlerMode(ccPolicy),
    whitelist: managedRuleValues(ccPolicy, managedRuleNames.whitelist).join('\n'),
    blacklist: managedRuleValues(ccPolicy, managedRuleNames.blacklist).join('\n'),
    proxy: proxyBlocked(wafPolicy),
    region: regionPreset(wafPolicy),
  }), [protectionKnown, ccPolicy, wafPolicy, groupNames, challengeQuery.data])
  const [draft, setDraft] = useState<CCDraft>(stored)
  const sentRef = useRef<CCDraft | null>(null)
  // Reset the draft only when the stored values change (not on every re-read); fields edited
  // while a save ran stay and are saved next.
  const storedKey = JSON.stringify(stored)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { setDraft((current) => rebaseDraft(stored, current, sentRef.current)); sentRef.current = null }, [storedKey])
  const changedOf = (value: CCDraft) => (Object.keys(value) as (keyof CCDraft)[]).filter((key) => key === 'whitelist' || key === 'blacklist'
    ? ipLines(value[key]).join('\n') !== ipLines(stored[key]).join('\n') : value[key] !== stored[key])
  const changed = changedOf(draft)
  const target = isAdmin ? (siteScopeId && siteOwnerId ? { scopeId: siteScopeId, ownerId: siteOwnerId } : undefined) : undefined
  // Writing needs the bindings read (bound library updated, else a new one created for the site).
  const writable = canWrite && cc.activationQuery.isSuccess && waf.activationQuery.isSuccess && (!isAdmin || Boolean(target))

  const feedback = useInstantFeedback()
  const save = useMutation({
    mutationFn: async (draft: CCDraft): Promise<SaveOutcome> => {
      const changed = changedOf(draft)
      let outcome: SaveOutcome = { published: true }
      // CU-SITE-04: the first refused publish is the one reported (its library is republished in place).
      const merge = (next: SaveOutcome) => { if (outcome.published && !next.published) outcome = next }
      const ccChanged = changed.some((key) => key === 'preset' || key === 'crawler' || key === 'whitelist' || key === 'blacklist')
      if (ccChanged) {
        const edit: CCEdit = {}
        if (changed.includes('preset') && draft.preset && draft.preset !== 'custom') {
          const preset = draft.preset as CCPreset
          edit.presetNames = Object.values(groupNames).filter((name): name is string => Boolean(name))
          edit.presetRules = preset === 'off' ? [] : (await securityPoliciesApi.catalogRules(accessToken, 'cc', [ccPresetGroups[preset]],
            ...(isAdmin && siteScopeId ? [siteScopeId] as const : [] as const))).rules
        }
        let settings = ccPolicy?.cc_settings
        if (changed.includes('crawler')) {
          const crawlers = (crawlersQuery.data ?? []).filter((crawler) => crawler.ready)
          edit.crawler = { mode: draft.crawler, tokens: [...new Set(crawlers.flatMap((crawler) => crawler.user_agent_tokens))] }
          // 放行 = the site's trusted crawlers (spider whitelist, verified by IP range or rDNS); 不处理/拦截 clear them.
          const trusted = draft.crawler === 'allow' ? (settings?.trusted_crawlers?.length ? settings.trusted_crawlers
            : crawlers.slice(0, 32).map((crawler) => ({ name: crawler.name, user_agent_tokens: crawler.user_agent_tokens,
              ...(crawler.networks.length ? { networks: crawler.networks } : {}), ...(crawler.rdns_suffixes.length ? { rdns_suffixes: crawler.rdns_suffixes } : {}) })))
            : undefined
          settings = { ...settings, trusted_crawlers: trusted }
          if (!trusted) delete settings.trusted_crawlers
          if (Object.keys(settings).length === 0) settings = undefined
        }
        if (changed.includes('whitelist')) edit.whitelist = ipLines(draft.whitelist)
        if (changed.includes('blacklist')) edit.blacklist = ipLines(draft.blacklist)
        const rules = editCCRules(ccPolicy?.rules ?? [], edit)
        const fields = ccPolicy ? { ...fieldsOf(ccPolicy), rules, cc_settings: settings }
          : { kind: 'cc' as const, name: siteLibraryName(host, siteId), description: '', enabled: true, default_action: 'allow' as const, rules, cc_settings: settings }
        merge(await saveSiteLibrary({ accessToken, siteId, policy: ccPolicy, fields, status: cc.activationQuery.data, target }))
      }
      if (changed.includes('proxy') || changed.includes('region')) {
        const rules = editWAFSourceRules(wafPolicy ? fieldsOf(wafPolicy).rules : [], {
          proxy: changed.includes('proxy') ? draft.proxy : undefined,
          region: changed.includes('region') && draft.region !== 'custom' ? draft.region : undefined })
        const fields = wafPolicy ? { ...fieldsOf(wafPolicy), rules }
          : { kind: 'waf' as const, name: siteLibraryName(host, siteId), description: '', enabled: true, default_action: 'allow' as const, rules }
        merge(await saveSiteLibrary({ accessToken, siteId, policy: wafPolicy, fields, status: waf.activationQuery.data, target }))
      }
      return outcome
    },
    // CU-SITE-04: 操作成功 only when it runs; a refused publish stays on the page.
    onSuccess: (result) => { if (result.published) feedback.success() },
    // A failed save puts the controls back to the stored values.
    onError: () => { sentRef.current = null; setDraft(stored) },
    onSettled: () => { void queryClient.invalidateQueries({ queryKey: ['site-protection'] }) },
  })
  // Choices save at once, the IP lists on blur; a running save sends the latest draft after it.
  const commits = useCommitRequest(() => {
    if (!writable || changed.length === 0) return
    sentRef.current = draft
    save.mutate(draft)
  }, save.isPending || cc.policiesQuery.isFetching || waf.policiesQuery.isFetching || cc.activationQuery.isFetching || waf.activationQuery.isFetching)
  const set = (patch: Partial<CCDraft>) => { save.reset(); republish.reset(); setDraft((current) => ({ ...current, ...patch })); commits.requestUnlessTyping() }
  // CU-SITE-04: 重新下发 the saved library after a refused publish (no second library is made).
  const republish = useMutation({
    mutationFn: (saved: SecurityPolicy) => publishOutcome(accessToken, siteId, saved, (saved.kind === 'cc' ? cc : waf).activationQuery.data),
    onSuccess: (result) => { if (result.published) feedback.success() },
    onSettled: () => { void queryClient.invalidateQueries({ queryKey: ['site-protection'] }) },
  })
  const republishSaved = (saved: SecurityPolicy) => { save.reset(); republish.mutate(saved) }

  if (!canReadPolicies && !canReadChallenges) return <SiteEditState status="forbidden" title={t('common.readOnly')} />
  if (canReadPolicies && cc.policiesQuery.isPending) return <ProtectionLoading />
  if (cc.policiesQuery.isError) return <ProtectionError onRetry={() => void cc.policiesQuery.refetch()} />

  const workingPolicy = ccPolicy ?? (cc.policies.length === 1 && !cc.activationQuery.isSuccess ? cc.policies[0] : undefined)
  const managed = new Set<string>(Object.values(managedRuleNames))
  const presetNames = Object.values(groupNames)
  const customRules = policyRules(ccPolicy).filter((rule) => !managed.has(rule.name) && !presetNames.some((name) => name && rule.name.startsWith(`${name} · `)))
  const linkContext = { siteId, host, scopeKind, siteScopeId }
  const openRules = (view = 'groups') => navigate(siteRuleLink('/site/cc-rule', linkContext, { view: view === 'groups' ? undefined : view }))
  const openWAFRules = () => navigate(siteRuleLink('/site/waf-rule', linkContext))
  // CC rule statistics: the "统计" tab of the CC page, administrators only (tp-b1); they name the site's tenant.
  const openStats = () => navigate(siteRuleLink('/site/cc-rule', { siteId, scopeKind, siteScopeId }, { view: 'stats' }))
  const disabled = !writable
  const choosePreset = (mode: CCMode) => {
    // 自定义 is the full rule editor; every other preset is applied here.
    if (mode === 'custom') openRules('groups')
    else set({ preset: mode })
  }
  const chooseRegion = (mode: RegionMode) => {
    if (mode === 'custom') openWAFRules()
    else set({ region: mode })
  }
  const libraryName = (policy: SecurityPolicy | undefined, kind: 'cc' | 'waf') => policy ? policy.name
    : t(cc.activationQuery.isSuccess ? `save.newLibrary.${kind}` : 'common.unconfirmed')

  return <div className="site-edit-tab-panel site-protection-page site-cc-protection" aria-labelledby="site-cc-protection-title" aria-busy={save.isPending} {...commits.typingProps}>
    <SiteTabSummary items={[
      { key: 'mode', label: t('cc.defaultProtection'), target: 'site-cc-protection-title',
        value: stored.preset ? t(`cc.modes.${stored.preset}`) : t('common.unconfirmed'),
        tone: !stored.preset ? 'warn' : stored.preset === 'off' ? 'off' : 'on' },
      { key: 'rules', label: t('cc.customRules'), target: 'site-cc-protection-title', value: t('cc.ruleCount', { count: customRules.length }) },
      { key: 'black', label: t('cc.blacklist'), target: 'site-cc-ip-lists-title', value: t('cc.count', { count: ipLines(stored.blacklist).length }) },
      { key: 'white', label: t('cc.whitelist'), target: 'site-cc-ip-lists-title', value: t('cc.count', { count: ipLines(stored.whitelist).length }) },
      { key: 'region', label: t('cc.region'), target: 'site-cc-source-title', value: t(`cc.regionModes.${stored.region}`),
        tone: stored.region === 'none' ? 'off' : 'on' },
    ]} />
    {cc.activationQuery.isError ? <FeedbackWhen title={t('common.bindingLoadFailed')} action={<Button size="small" onClick={() => void cc.activationQuery.refetch()}>{t('common.retry')}</Button>} /> : null}
    <section className="site-protection-section site-protection-section--plain">
      <h2 id="site-cc-protection-title">{t('cc.title')}</h2>
      <p className="site-protection-library-note" role="note">{t('save.libraryNote', { name: libraryName(ccPolicy, 'cc') })}</p>
      <div className="site-protection-setting-row">
        <span className="site-protection-label">{t('cc.defaultProtection')}</span>
        <div className="site-protection-control">
          <div className="site-protection-choice-list" role="radiogroup" aria-label={t('cc.defaultProtection')}>
            {ccModes.map((mode) => <Button key={mode} role="radio" aria-checked={draft.preset === mode} className={draft.preset === mode ? 'is-active' : undefined}
              disabled={mode === 'custom' ? !canWrite : disabled || !protectionKnown} onClick={() => choosePreset(mode)}>{t(`cc.modes.${mode}`)}</Button>)}
          </div>
          <p>{protectionKnown ? t('cc.defaultHint') : t('cc.defaultUnknown')}</p>
        </div>
      </div>
      <div className="site-protection-setting-row">
        <span className="site-protection-label">{t('cc.customRules')}</span>
        <div className="site-protection-control">
          <div className="site-protection-rule-summary"><strong>{t('cc.ruleCount', { count: customRules.length })}</strong><span>{t('cc.ruleHint')}</span>{canReadPolicies && scopeKind === 'platform' ? <Button size="small" onClick={openStats}>{t('cc.viewStats')}</Button> : null}</div>
          {customRules.length === 0 ? <div className="site-protection-empty-action"><Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('cc.emptyRules')} /><Button type="primary" icon={<Plus size={14} />} disabled={!canWrite} onClick={() => openRules('groups')}>{t('cc.addFirstRule')}</Button></div> : <div className="site-protection-rule-list">{customRules.slice(0, 5).map((rule) => <button key={rule.id ?? `${rule.name}-${rule.priority}`} type="button" onClick={() => openRules('groups')}><strong>{rule.name}</strong><span>{rule.priority}</span></button>)}</div>}
        </div>
      </div>
      <div className="site-protection-setting-row">
        <span className="site-protection-label">{t('cc.crawler')}</span>
        <div className="site-protection-control"><div className="site-protection-choice-list site-protection-choice-list--short" role="radiogroup" aria-label={t('cc.crawler')}>{(['none', 'allow', 'block'] as CrawlerMode[]).map((mode) => <Button key={mode} role="radio" aria-checked={draft.crawler === mode} className={draft.crawler === mode ? 'is-active' : undefined} disabled={disabled || mode !== 'none' && !crawlersQuery.data?.some((crawler) => crawler.ready)} onClick={() => set({ crawler: mode })}>{t(`cc.crawlerModes.${mode}`)}</Button>)}</div><p>{t('cc.crawlerHint')}</p></div>
      </div>
    </section>

    {/* 黑/白名单时间 are settings of the site's CC rule set (G1-e); 自动切换, 攻击自动升级 and 智能自动 are on the 自动防御 tab. */}
    <section className="site-protection-section site-protection-section--plain">
      <SiteCCSettingsSection part="advanced" policy={workingPolicy} accessToken={accessToken} isAdmin={isAdmin}
        canManage={canWrite} onPublish={() => openRules('groups')}
        publish={ccPolicy && workingPolicy?.id === ccPolicy.id ? sitePublisher(accessToken, siteId, cc.activationQuery.data) : undefined} />
    </section>

    <section className="site-protection-section">
      <h2 id="site-cc-ip-lists-title">{t('cc.ipLists')}</h2>
      <div className="site-protection-ip-grid">
        <IPListCard title={t('cc.blacklist')} badge={t('cc.blocked')} badgeClass="is-danger" value={draft.blacklist} disabled={disabled} onChange={(value) => set({ blacklist: value })} />
        <IPListCard title={t('cc.whitelist')} badge={t('cc.allowed')} badgeClass="is-success" value={draft.whitelist} disabled={disabled} onChange={(value) => set({ whitelist: value })} />
      </div>
    </section>

    <section className="site-protection-section">
      <h2 id="site-cc-source-title">{t('cc.sourceLimit')}</h2>
      <p className="site-protection-library-note" role="note">{t('save.wafLibraryNote', { name: libraryName(wafPolicy, 'waf') })}</p>
      <div className="site-protection-setting-row">
        <span className="site-protection-label" id="site-cc-proxy-label">{t('cc.proxy')}</span>
        <div className="site-protection-toggle-card"><span><strong>{t('cc.proxyTitle')}</strong><small>{t('cc.proxyHint')}</small></span><Switch aria-labelledby="site-cc-proxy-label" checked={draft.proxy} disabled={disabled} onChange={(checked) => set({ proxy: checked })} /></div>
      </div>
      <div className="site-protection-setting-row">
        <span className="site-protection-label">{t('cc.region')}</span>
        <div className="site-protection-region-grid" role="radiogroup" aria-label={t('cc.region')}>{regionModes.map((mode) => <button key={mode} type="button" role="radio" aria-checked={draft.region === mode} className={draft.region === mode ? 'is-active' : undefined} disabled={mode === 'custom' ? !canWrite : disabled} onClick={() => chooseRegion(mode)}><span className="site-protection-radio-dot" /><strong>{t(`cc.regionModes.${mode}`)}</strong><small>{t(`cc.regionHints.${mode}`)}</small></button>)}</div>
      </div>
    </section>
    <AutoDefenseMovedNote kind="cc" />
    <SaveResult result={republish.data} error={republish.error} onRepublish={republishSaved} republishing={republish.isPending} />
    <SaveResult result={save.data} error={save.error} onRepublish={republishSaved} republishing={republish.isPending} />
  </div>
}

export function SiteWAFTab({ siteId, host, scopeKind, scopeId, accessToken, permissions, locked, siteScopeId, siteOwnerId }: SiteProtectionProps) {
  const { t } = useTranslation('siteProtection')
  const { t: tV4 } = useTranslation('siteEditV4')
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const canReadPolicies = hasPermission(permissions, 'security_policies.read')
  const canManage = !locked && hasPermission(permissions, 'security_policies.manage')
  const isAdmin = scopeKind === 'platform'
  const [librarySearch, setLibrarySearch] = useState('')
  const tierName = useTierName()
  const { policiesQuery, activationQuery, policies, boundPolicyID, activePolicy } = useSiteLibrary('waf', { siteId, scopeId, accessToken, enabled: canReadPolicies })
  // Catalog set names identify the self-developed rules of each module.
  const catalogQuery = useQuery({
    queryKey: ['site-protection', scopeId, 'waf-catalog-names'],
    enabled: canReadPolicies,
    retry: false,
    queryFn: async () => Object.fromEntries((await securitySystemRulesApi.list(accessToken, 'waf_rule_set'))
      .map((rule) => [rule.system_key, rule.name])) as Record<string, string>,
  })
  // C27: only a successfully read activation status says "no library bound".
  const bindingKnown = activationQuery.isSuccess
  const knownModuleStates = wafModuleStates(activePolicy, catalogQuery.isSuccess ? catalogQuery.data : catalogQuery.isError ? null : {})
  const moduleStates = bindingKnown ? knownModuleStates : {
    modules: knownModuleStates.modules.map((module) => ({ ...module, state: 'unknown' as const, self: 'unknown' as const, crs: 'unknown' as const })),
    inspectionLimitAction: null, reason: null,
  }
  // A subscribed (protected) library's rules are the platform's; its modules are not edited here.
  const editableLibrary = !activePolicy?.protected
  const storedLibrary = Boolean(activePolicy)
  const storedModules = useMemo(() => moduleStates.modules.filter((module) => module.self === 'protect' || module.self === 'log').map((module) => module.key),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [activePolicy?.id, activePolicy?.version, bindingKnown, catalogQuery.data])
  const [libraryOn, setLibraryOn] = useState(storedLibrary)
  const [modulesOn, setModulesOn] = useState<WAFModuleKey[]>(storedModules)
  useEffect(() => { setLibraryOn(storedLibrary) }, [storedLibrary])
  useEffect(() => { setModulesOn(storedModules) }, [storedModules])
  const storedSettings = useMemo(() => wafSettingsDraft(activePolicy?.waf_settings), [activePolicy?.waf_settings])
  const [settings, setSettings] = useState<WAFSettingsDraft>(storedSettings)
  useEffect(() => { setSettings(storedSettings) }, [storedSettings])
  // 托管 WAF 防护档位：本站规则库的 managed_waf 规则（'' = 关闭），与规则页同一条规则。
  const crsProfilesQuery = useQuery({
    queryKey: ['site-protection', 'crs-profiles'],
    enabled: canReadPolicies,
    retry: false,
    queryFn: ({ signal }) => securityPoliciesApi.listCRSProfiles(accessToken, signal),
  })
  const crsProfiles = orderedProfiles(crsProfilesQuery.data?.items ?? [])
  const storedTier = managedWAFProfile(activePolicy?.enabled ? activePolicy.rules : undefined)
  const [tier, setTier] = useState(storedTier)
  useEffect(() => { setTier(storedTier) }, [storedTier])
  const tierChanged = tier !== storedTier
  // 运行模式 is edited here; 命中自动封禁 (the rest of waf_settings) on the 自动防御 tab keeps its stored value.
  const settingsChangeCount = settings.observe !== storedSettings.observe ? 1 : 0
  const settingsChanged = settingsChangeCount > 0
  const modulesChanged = Object.keys(wafModuleCatalogSuffix).filter((key) =>
    modulesOn.includes(key as WAFModuleKey) !== storedModules.includes(key as WAFModuleKey)) as WAFModuleKey[]
  const libraryChangeCount = (libraryOn !== storedLibrary ? 1 : 0) + (libraryOn ? modulesChanged.length + settingsChangeCount + (tierChanged ? 1 : 0) : 0)
  const changeCount = libraryChangeCount
  const target = isAdmin ? (siteScopeId && siteOwnerId ? { scopeId: siteScopeId, ownerId: siteOwnerId } : undefined) : undefined
  const writable = canManage && bindingKnown && catalogQuery.isSuccess && (!isAdmin || Boolean(target))
  const scopeArgs = isAdmin && siteScopeId ? [siteScopeId] as const : [] as const

  const feedback = useInstantFeedback()
  const save = useMutation({
    mutationFn: async (): Promise<SaveOutcome> => {
      if (libraryChangeCount === 0) return { published: true }
      return saveLibrary()
    },
    onSuccess: (result) => { if (result.published) feedback.success() },
    // A failed save puts the controls back to the stored values.
    onError: () => { setLibraryOn(storedLibrary); setModulesOn(storedModules); setSettings(storedSettings); setTier(storedTier) },
    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: ['site-protection'] })
      // 灰区挑战等依赖档位的提示按新档位重读。
      void queryClient.invalidateQueries({ queryKey: ['waf-adapt', siteId] })
    },
  })
  // Switches, modules and tiers save at once, numbers on blur; a running save sends the latest state after it.
  const commits = useCommitRequest(() => {
    if (changeCount === 0 || !writable) return
    save.mutate()
  }, save.isPending || policiesQuery.isFetching || activationQuery.isFetching)
  // 托管 WAF 档位：选档位 upsert managed_waf 规则（新建时取目录 CRS 引擎默认值），关闭移除。
  const applyTier = async (rules: SecurityPolicyRule[]): Promise<SecurityPolicyRule[]> => {
    if (!tierChanged) return rules
    if (!tier) return setManagedWAFTier(rules, null)
    const exports = crsProfiles.find((profile) => profile.pack_id === tier)?.exports ?? []
    const defaults = rules.some((rule) => rule.action === 'managed_waf') ? undefined
      : (await securityPoliciesApi.catalogRules(accessToken, 'waf', [crsCatalogDefaultsKey], ...scopeArgs)).rules
        .find((rule) => rule.action === 'managed_waf')?.action_config.managed_waf
    return setManagedWAFTier(rules, { profile: tier, exports }, defaults)
  }
  async function saveLibrary(): Promise<SaveOutcome> {
    const status = activationQuery.data!
    if (!libraryOn) {
      await detachSiteLibrary(accessToken, siteId, status)
      return { published: true }
    }
    const names = catalogQuery.data ?? {}
    const applyModules = async (rules: SecurityPolicyRule[], keys: WAFModuleKey[]) => {
      let next = rules
      for (const key of keys) {
        const setKey = `waf_set:${wafModuleCatalogSuffix[key]}`
        const added = modulesOn.includes(key) ? (await securityPoliciesApi.catalogRules(accessToken, 'waf', [setKey], ...scopeArgs)).rules : null
        next = toggleWAFSet(next, names[setKey] ?? setKey, added)
      }
      return next
    }
    if (activePolicy) {
      const fields = { ...fieldsOf(activePolicy), rules: await applyTier(await applyModules(activePolicy.rules.filter((rule) => !isQuickBlockRuleID(rule.id)), modulesChanged)),
        ...(settingsChanged ? { waf_settings: wafSettingsFromDraft(settings) } : {}) }
      return saveSiteLibrary({ accessToken, siteId, policy: activePolicy, fields, status, target })
    }
    // 一键启用：the system default WAF (系统设置 > 网站默认 > 安全设置), as the rules page's 使用系统默认.
    // CU-SITE-04: the default is the base; only the modules switched here change it (an unbound
    // site shows every module off, which is no choice to remove the default's).
    const defaults = (await securityPoliciesApi.catalogRules(accessToken, 'waf', [systemDefaultWAFKey], ...scopeArgs)).default
    const base = defaults?.rules ?? []
    const rules = await applyTier(await applyModules(base, modulesChanged))
    // A library needs a rule (securitypolicy.Service): with none, nothing is sent and the switch stays off.
    if (rules.length === 0) throw new WAFDefaultEmptyError()
    const fields = { kind: 'waf' as const, name: siteLibraryName(host, siteId), description: '', enabled: true, default_action: 'allow' as const,
      rules: rules.map((rule, index) => ({ ...rule, priority: index + 1 })),
      ...(settingsChanged ? { waf_settings: wafSettingsFromDraft(settings) } : defaults?.waf_settings ? { waf_settings: defaults.waf_settings } : {}) }
    return saveSiteLibrary({ accessToken, siteId, policy: undefined, fields, status, target })
  }
  // 应用: publish another library to the site in place (the rules page's site-context publish).
  const apply = useMutation({
    mutationFn: (policy: SecurityPolicy) => publishOutcome(accessToken, siteId, policy, activationQuery.data),
    onSuccess: (result) => { if (result.published) feedback.success() },
    onSettled: () => { void queryClient.invalidateQueries({ queryKey: ['site-protection'] }) },
  })

  if (!canReadPolicies) return <SiteEditState status="forbidden" title={t('common.readOnly')} />
  if (policiesQuery.isPending) return <ProtectionLoading />
  if (policiesQuery.isError) return <ProtectionError onRetry={() => void policiesQuery.refetch()} />

  const searchText = librarySearch.trim().toLowerCase()
  const shownPolicies = searchText ? policies.filter((policy) => policy.name.toLowerCase().includes(searchText)) : policies
  // Quick block crawler exemptions are the quick block card's, not allow rules.
  const allowRules = policyRules(activePolicy).filter((rule) => rule.action === 'allow' && !isQuickBlockRuleID(rule.id))
  const stateLabel = (state: WAFModuleState) => state === 'unknown' ? (bindingKnown ? t('common.notConfigured') : t('common.unconfirmed')) : t(`wafModules.states.${state}`)
  const linkContext = { siteId, host, scopeKind, siteScopeId }
  const openWAF = () => navigate(siteRuleLink('/site/waf-rule', linkContext))
  const openWAFPolicy = (policyID: string) => navigate(siteRuleLink('/site/waf-rule', linkContext, { policy_id: policyID }))
  // CU-SITE-04: 新增放行规则 opens the rule editor of the site's library with an allow rule added
  // (a subscribed library or none: a new library for the site; administrators name its owner).
  const openAddAllowRule = () => navigate(siteRuleLink('/site/waf-rule', linkContext, { new_rule: 'allow',
    policy_id: activePolicy && !activePolicy.protected ? activePolicy.id : undefined, owner_id: isAdmin ? siteOwnerId : undefined }))
  // A subscribed library (protected copy) updated after this site's release:
  // the new version runs only after the site is published again.
  const binding = activationQuery.data?.binding
  const pendingSubscription = activePolicy && activePolicy.protected && binding &&
    binding.active_policy_version > 0 && binding.active_policy_version < activePolicy.version
    ? { active: binding.active_policy_version, latest: activePolicy.version } : null
  // The subscribed library's latest version is published here (as 应用).
  const publishPending = () => apply.mutate(activePolicy!)
  const libraryOff = bindingKnown && !libraryOn
  const modulesOnCount = moduleStates.modules.filter((module) => module.state === 'protect' || module.state === 'log').length
  const disabled = !writable
  const changeNow = () => { save.reset(); commits.requestUnlessTyping() }
  // CU-SITE-04: 重新下发 the saved library after a refused publish (no second library is made).
  const republishSaved = (saved: SecurityPolicy) => { save.reset(); apply.mutate(saved) }
  const toggleModule = (key: WAFModuleKey) => { setModulesOn((current) => current.includes(key) ? current.filter((item) => item !== key) : [...current, key]); changeNow() }
  const setSetting = (patch: Partial<WAFSettingsDraft>) => { setSettings((current) => ({ ...current, ...patch })); changeNow() }
  const settingsDisabled = disabled || !libraryOn || !editableLibrary
  const tierDisabled = disabled || !editableLibrary || !crsProfilesQuery.isSuccess
  // A tier on a site without a library switches the library on (system default library, as the switch above).
  const chooseTier = (value: string) => { setTier(value); if (value) setLibraryOn(true); changeNow() }

  return <div className="site-edit-tab-panel site-protection-page site-waf-protection" aria-labelledby="site-waf-protection-title" aria-busy={save.isPending} {...commits.typingProps}>
    <h2 id="site-waf-protection-title" className="visually-hidden">{t('waf.title')}</h2>
    <SiteTabSummary items={[
      { key: 'library', label: t('waf.totalSwitch'), target: 'site-waf-library-title',
        value: activePolicy ? activePolicy.name : bindingKnown ? t('waf.libraryOff') : t('common.unconfirmed'),
        tone: activePolicy ? 'on' : 'warn' },
      { key: 'modules', label: t('waf.builtin'), target: 'site-waf-builtin-title',
        value: bindingKnown ? tV4('summary.waf.modulesOn', { on: modulesOnCount, total: moduleStates.modules.length }) : t('common.unconfirmed'),
        tone: !bindingKnown ? 'warn' : modulesOnCount ? 'on' : 'off' },
      { key: 'allow', label: t('waf.allowRules'), target: 'site-waf-allow-title', value: tV4('summary.count', { count: allowRules.length }) },
    ]} />
    {activationQuery.isError ? <FeedbackWhen title={t('common.bindingLoadFailed')} action={<Button size="small" onClick={() => void activationQuery.refetch()}>{t('common.retry')}</Button>} /> : null}
    {/* The switch binds the system default library to the site, or withdraws the bound one. */}
    <section className={`site-protection-feature-card site-waf-library-card${libraryOff ? ' is-warn' : ''}`} aria-labelledby="site-waf-library-title">
      <div><strong id="site-waf-library-title">{t('waf.totalSwitch')}</strong><small>{activePolicy ? t('waf.totalHintOn') : t('waf.totalHint')}</small></div>
      <span className="site-protection-feature-state">
        <Tag color={activePolicy ? 'success' : bindingKnown ? 'default' : 'warning'}>{activePolicy ? t('waf.libraryOn', { name: activePolicy.name }) : bindingKnown ? t('waf.libraryOff') : t('common.unconfirmed')}</Tag>
        <Switch aria-label={t('waf.totalSwitch')} checked={libraryOn} disabled={disabled || !libraryOn && !bindingKnown} onChange={(checked) => { setLibraryOn(checked); changeNow() }} />
        <Button disabled={!canManage} onClick={activePolicy ? () => openWAFPolicy(activePolicy.id) : openWAF}>{t('waf.advancedEdit')}</Button>
      </span>
    </section>

    {pendingSubscription ? <Alert type="warning" showIcon role="status" message={t('wafPending.siteHint', pendingSubscription)}
      action={<Button size="small" type="primary" disabled={!canManage || apply.isPending} loading={apply.isPending} onClick={publishPending}>{t('waf.publishLatest')}</Button>} /> : null}

    {/* 防御级别：运行模式（本站 WAF 规则库 waf_settings）；命中自动封禁在「自动防御」标签。 */}
    <section className="site-protection-section site-protection-section--waf" aria-labelledby="site-waf-level-title">
      <div className="site-protection-section-head"><div><h2 id="site-waf-level-title">{t('waf.level')}</h2><span>{t('waf.levelHint')}</span></div></div>
      <div className="site-protection-setting-row">
        <span className="site-protection-label" id="site-waf-mode-label">{t('waf.mode')}</span>
        <div className="site-protection-control">
          <div className="site-protection-choice-list site-protection-choice-list--short" role="radiogroup" aria-labelledby="site-waf-mode-label">
            {([false, true] as const).map((observe) => <Button key={String(observe)} role="radio" aria-checked={settings.observe === observe}
              className={settings.observe === observe ? 'is-active' : undefined} disabled={settingsDisabled}
              onClick={() => setSetting({ observe })}>{t(observe ? 'waf.modes.observe' : 'waf.modes.defend')}</Button>)}
          </div>
          <p>{t('waf.modeHint')}</p>
        </div>
      </div>
    </section>

    {/* 托管 WAF 防护档位：写本站规则库的 managed_waf 规则（规则库写接口），随底部保存下发。 */}
    <section className="site-protection-section site-protection-section--waf" aria-labelledby="site-waf-tier-title">
      <div className="site-protection-section-head"><div><h2 id="site-waf-tier-title">{t('waf.tier.title')}</h2><span>{t('waf.tier.hint')}</span></div></div>
      <div className="site-protection-setting-row">
        <span className="site-protection-label" id="site-waf-tier-label">{t('waf.tier.label')}</span>
        <div className="site-protection-control">
          <div className="site-protection-choice-list" role="radiogroup" aria-labelledby="site-waf-tier-label">
            {['', ...crsProfiles.map((profile) => profile.pack_id)].map((value) => <Button key={value || 'off'} role="radio" aria-checked={tier === value}
              className={tier === value ? 'is-active' : undefined} disabled={tierDisabled}
              onClick={() => chooseTier(value)}>{value ? tierName(crsProfiles.find((profile) => profile.pack_id === value), value) : t('waf.tier.off')}</Button>)}
          </div>
          <p>{crsProfilesQuery.isError ? t('waf.tier.profilesFailed') : crsProfilesQuery.isSuccess && crsProfiles.length === 0 ? t('waf.tier.noProfiles')
            : !editableLibrary ? t('waf.tier.protected') : t('waf.tier.help')}</p>
        </div>
      </div>
    </section>

    <SiteOfficialPacksCard siteId={siteId} accessToken={accessToken} />

    {/* 防御级别：本站 OWASP CRS 档位（PA-12 站点覆盖，PUT /v1/sites/{id}/crs），就地保存。 */}
    <SiteCRSOverrideCard siteId={siteId} accessToken={accessToken} canManage={canManage} onOpenLibraries={openWAF} />

    <section className="site-protection-section site-protection-section--waf">
      <div className="site-protection-section-head"><div><h2 id="site-waf-builtin-title">{t('waf.builtin')}</h2><span>{t('waf.builtinHintEdit')}</span></div><div><Button disabled={!canManage} onClick={openWAF}>{t('waf.advancedEdit')}</Button></div></div>
      {moduleStates.reason && moduleStates.reason !== 'noPolicy' ? <Alert type="info" showIcon message={t(`wafModules.${moduleStates.reason}`)} /> : null}
      <div className="site-protection-module-grid" role="group" aria-label={t('wafModules.title')}>{moduleStates.modules.map((module) => {
        const on = modulesOn.includes(module.key)
        return <Tooltip key={module.key} title={<span>{t('wafModules.engineState', { engine: t('wafModules.engines.self'), state: stateLabel(module.self) })}<br />{t('wafModules.engineState', { engine: t('wafModules.engines.crs'), state: stateLabel(module.crs) })}</span>}>
          <button type="button" role="switch" aria-checked={on} disabled={disabled || !libraryOn || !editableLibrary} onClick={() => toggleModule(module.key)}
            data-module-state={module.state}><strong>{t(`waf.modules.${module.key}`)}</strong><Tag color={!bindingKnown ? 'warning' : on ? 'success' : 'default'}>{!bindingKnown ? t('common.unconfirmed') : on ? t('waf.moduleOn') : t('waf.moduleOff')}</Tag></button></Tooltip>
      })}</div>
      {moduleStates.inspectionLimitAction ? <div className="site-protection-order-note">{t('wafModules.inspectionLimit', { action: t(`wafModules.inspectionLimitActions.${moduleStates.inspectionLimitAction}`) })}</div> : null}
    </section>

    <SiteQuickBlockOverrideCard siteId={siteId} accessToken={accessToken} canManage={canManage} onOpenLibraries={openWAF} />

    <SiteQuickBlockCard policy={activePolicy} activeVersion={binding?.active_policy_version} accessToken={accessToken}
      canManage={canManage} onPublish={openWAFPolicy}
      onOpenLibraries={openWAF} publish={sitePublisher(accessToken, siteId, activationQuery.data)} />

    <div className="site-protection-order-note">{t('waf.executionOrder')}</div>

    <section className="site-protection-section site-protection-section--waf">
      <div className="site-protection-section-head"><div><h2>{t('waf.libraries')}</h2><span>{t('waf.librariesHint')}</span></div></div>
      <div className="site-protection-library-grid">
        <div className="site-protection-library-column"><div className="site-protection-library-head"><strong>{t('waf.available')}</strong><span>{policies.length}</span><div><Input allowClear aria-label={t('waf.search')} placeholder={t('waf.search')} value={librarySearch} onChange={(event) => setLibrarySearch(event.target.value)} /><Button icon={<RefreshCw size={14} />} onClick={() => void policiesQuery.refetch()}>{t('waf.refresh')}</Button></div></div>{shownPolicies.length === 0 ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('waf.noPolicies')} /> : shownPolicies.map((policy) => <article key={policy.id}><div><span className="site-protection-policy-index">{policy.rules?.length ?? 0}</span><span><strong>{policy.name}</strong><small>{t('waf.rules', { count: policy.rules?.length ?? 0 })}{policy.description ? ` · ${policy.description}` : ''}</small></span></div>{policy.id === boundPolicyID ? <Button disabled>{t('common.current')}</Button> : <Popconfirm title={t('waf.applyConfirm', { name: policy.name })} okText={t('waf.apply')} cancelText={t('waf.applyCancel')}
          disabled={!canManage || !bindingKnown || apply.isPending} onConfirm={() => apply.mutate(policy)}><Button type="primary" loading={apply.isPending && apply.variables?.id === policy.id}
          disabled={!canManage || !bindingKnown || apply.isPending}>{t('waf.apply')}</Button></Popconfirm>}</article>)}</div>
        <div className="site-protection-library-column"><div className="site-protection-library-head"><strong>{t('waf.active')}</strong><span>{activePolicy ? 1 : 0}</span></div>{activePolicy ? <article><div><span className="site-protection-policy-index">{activePolicy.rules?.length ?? 0}</span><span><strong>{activePolicy.name}</strong><small>{t('waf.rules', { count: activePolicy.rules?.length ?? 0 })}</small></span></div><Tag color="success">{t('common.current')}</Tag></article> : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={bindingKnown ? t('waf.noActivePolicy') : t('common.unconfirmed')} />}</div>
      </div>
    </section>

    <section className="site-protection-section site-protection-section--waf">
      <div className="site-protection-section-head"><div><h2 id="site-waf-allow-title">{t('waf.allowRules')} <span>{allowRules.length}</span></h2><span>{t('waf.allowRulesHint')}</span></div></div>
      {allowRules.length === 0 ? <div className="site-protection-empty-action"><Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('waf.noAllowRules')} /><Button type="primary" icon={<Plus size={14} />} disabled={!canManage} onClick={openAddAllowRule}>{t('waf.addAllowRule')}</Button></div> : <div className="site-protection-rule-list">{allowRules.map((rule) => <Tooltip key={rule.id ?? rule.name} title={rule.comment}><button type="button" onClick={openWAF}><strong>{rule.name}</strong><span>{rule.priority}</span></button></Tooltip>)}</div>}
    </section>
    {/* SF-SECURITY-ENTRY-01: the site's other access rules, with this site's context */}
    <nav className="site-protection-section site-protection-more-rules" aria-label={t('waf.moreRules')}>
      <span>{t('waf.moreRulesHint')}</span>
      <Link to={siteRuleLink('/site/acl', linkContext)}>{t('waf.aclEntry')}</Link>
      {hasPermission(permissions, 'url_auth_policies.read') ? <Link to={siteRuleLink('/site/url-auth', linkContext)}>{t('waf.urlAuthEntry')}</Link> : null}
    </nav>
    <AutoDefenseMovedNote kind="waf" />
    <SaveResult result={apply.data} error={apply.error} onRepublish={republishSaved} republishing={apply.isPending} />
    {save.error instanceof WAFDefaultEmptyError
      ? <Alert type="warning" showIcon role="status" message={t('save.wafDefaultEmpty')} description={t(isAdmin ? 'save.wafDefaultEmptyAdmin' : 'save.wafDefaultEmptyTenant')} />
      : <SaveResult result={save.data} error={save.error} onRepublish={republishSaved} republishing={apply.isPending} />}
  </div>
}
