import { useIsMutating, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Input, Radio, Select, Tag } from 'antd'
import { useMemo, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import {
  quickBlockCarriers,
  securityPoliciesApi,
  type QuickBlockCarrier,
  type SecurityPolicyQuickBlock,
  type SiteQuickBlockOverride,
  type SiteQuickBlockState,
} from '../../api/securityPolicies'
import { ipIntelTagKey } from '../../i18n/ipIntel'
import '../../i18n/siteQuickBlock'
import { crawlersToText, maxQuickBlockCrawlerNetworks, parseCrawlers, quickBlockActive } from './quickBlock'
import { FeedbackWhen } from '@cdnca/ui'
import { useInstantDraft, useInstantFeedback } from './instantSave'

type Mode = 'inherit' | 'on' | 'off'

interface Draft {
  idcCN: Mode
  idcGlobal: Mode
  carriers: Mode
  carrierList: QuickBlockCarrier[]
  crawlers: Mode
  crawlerText: string
}

const switchMode = (value: boolean | null): Mode => value === null ? 'inherit' : value ? 'on' : 'off'
const listMode = (value: unknown[] | null): Mode => value === null ? 'inherit' : value.length > 0 ? 'on' : 'off'

/** The stored override as the card's draft; an "on" list starts from the library's. */
function draftFromState(state: SiteQuickBlockState | undefined): Draft {
  const override = state?.override
  const library = state?.library?.quick_block
  return {
    idcCN: switchMode(override?.block_idc_cn ?? null),
    idcGlobal: switchMode(override?.block_idc_global ?? null),
    carriers: listMode(override?.carriers ?? null),
    carrierList: [...(override?.carriers?.length ? override.carriers : library?.carriers ?? [])],
    crawlers: listMode(override?.allowed_crawlers ?? null),
    crawlerText: crawlersToText(override?.allowed_crawlers?.length ? override.allowed_crawlers : library?.allowed_crawlers),
  }
}

const knownErrors = ['quick_block_ip_intel_unavailable', 'quick_block_unsupported_policy', 'quick_block_last_rules',
  'quick_block_rule_budget', 'quick_block_no_library', 'version_conflict', 'idempotency_conflict', 'site_locked',
  'validation_error'] as const

/**
 * 站点“防护”页“本站快速屏蔽”：每一项可选“跟随规则库 /
 * 开启 / 关闭”。Only this site changes (site_quick_block_overrides); other
 * sites bound to the library keep following it. Saving advances the site
 * version: an automatic scope publishes it, a manual one shows it pending.
 */
export function SiteQuickBlockOverrideCard({ siteId, accessToken, canManage, onOpenLibraries }: {
  siteId: string
  accessToken: string
  canManage: boolean
  onOpenLibraries: () => void
}) {
  const { t } = useTranslation('siteQuickBlock')
  const { t: tagT } = useTranslation('ipIntel')
  const queryClient = useQueryClient()
  const stateQuery = useQuery({
    queryKey: ['site-protection', siteId, 'site-quick-block'],
    retry: false,
    queryFn: ({ signal }) => securityPoliciesApi.getSiteQuickBlock(accessToken, siteId, signal),
  })
  const intel = useQuery({
    queryKey: ['site-protection', 'ip-intel-status'],
    retry: false,
    queryFn: ({ signal }) => securityPoliciesApi.ipIntelStatus(accessToken, signal),
  })
  const state = stateQuery.data
  const ready = intel.data?.ready === true
  const feedback = useInstantFeedback()
  // Choices save at once, the crawler list on blur; invalid or not-yet-ready values are not sent.
  const storedDraft = useMemo(() => draftFromState(state), [state?.version, state?.library?.version]) // eslint-disable-line react-hooks/exhaustive-deps
  const instantKey = ['site-instant', 'quick-block-override', siteId]
  const instant = useInstantDraft(storedDraft, {
    busy: useIsMutating({ mutationKey: instantKey }) > 0 || stateQuery.isFetching,
    isValid: (value) => Boolean(state?.library) && overrideOf(value) !== null && crawlerProblem(value) === null &&
      !(value.carriers === 'on' && value.carrierList.length === 0) && !(turnsOnOf(value) && !ready),
    submit: (value) => { const next = overrideOf(value); if (next) save.mutate(next) },
  })
  const draft = instant.draft
  function overrideOf(value: Draft): SiteQuickBlockOverride | null {
    const crawlers = parseCrawlers(value.crawlerText)
    if (value.crawlers === 'on' && 'invalidLine' in crawlers) return null
    const toggle = (mode: Mode) => mode === 'inherit' ? null : mode === 'on'
    return {
      block_idc_cn: toggle(value.idcCN),
      block_idc_global: toggle(value.idcGlobal),
      carriers: value.carriers === 'inherit' ? null : value.carriers === 'on' ? value.carrierList : [],
      allowed_crawlers: value.crawlers === 'inherit' ? null : value.crawlers === 'on' && 'crawlers' in crawlers ? crawlers.crawlers : [],
    }
  }
  function crawlerProblem(value: Draft): string | null {
    if (value.crawlers !== 'on') return null
    const crawlers = parseCrawlers(value.crawlerText)
    return 'invalidLine' in crawlers ? t('crawlersInvalid', { line: crawlers.invalidLine })
      : crawlers.networks === 0 ? t('override.crawlersEmpty')
        : crawlers.networks > maxQuickBlockCrawlerNetworks ? t('errors.quick_block_rule_budget') : null
  }
  // As on the server: the override itself turns a block on (inherited items never need the library here).
  function turnsOnOf(value: Draft): boolean {
    return value.idcCN === 'on' || value.idcGlobal === 'on' || value.carriers === 'on' && value.carrierList.length > 0
  }
  const save = useMutation({
    mutationKey: instantKey,
    mutationFn: (override: SiteQuickBlockOverride) => {
      if (!state) throw new Error('invalid site quick block')
      return securityPoliciesApi.setSiteQuickBlock(accessToken, siteId, state.version, override,
        `site-quick-block-override-${siteId}-${state.version}-${crypto.randomUUID()}`)
    },
    onSuccess: (updated) => {
      feedback.success()
      queryClient.setQueryData(['site-protection', siteId, 'site-quick-block'], updated)
      void queryClient.invalidateQueries({ queryKey: ['site-protection'] })
    },
    onError: (error) => {
      instant.revert()
      if (error instanceof ApiError && error.code === 'version_conflict') void stateQuery.refetch()
    },
  })

  if (stateQuery.isPending) return null
  if (stateQuery.isError || !state) {
    return <FeedbackWhen title={t('override.loadFailed')} action={<Button size="small" onClick={() => void stateQuery.refetch()}>{t('override.retry')}</Button>} />
  }
  const library = state.library
  if (!library) {
    return <Alert type="info" showIcon message={t('override.noLibrary')}
      action={<Button size="small" disabled={!canManage} onClick={onOpenLibraries}>{t('openLibraries')}</Button>} />
  }

  const set = (patch: Partial<Draft>) => { save.reset(); instant.set(patch) }
  const disabled = !canManage
  const turnsOn = turnsOnOf(draft)
  const crawlerError = crawlerProblem(draft)
  const carrierError = draft.carriers === 'on' && draft.carrierList.length === 0 ? t('override.carriersEmpty') : null
  const effective: SecurityPolicyQuickBlock = {
    block_idc_cn: draft.idcCN === 'inherit' ? library.quick_block.block_idc_cn : draft.idcCN === 'on',
    block_idc_global: draft.idcGlobal === 'inherit' ? library.quick_block.block_idc_global : draft.idcGlobal === 'on',
    carriers: draft.carriers === 'inherit' ? library.quick_block.carriers : draft.carriers === 'on' ? draft.carrierList : [],
    allowed_crawlers: [],
  }
  const errorCode = save.error instanceof ApiError ? save.error.code : ''
  const errorMessage = save.isError
    ? (knownErrors as readonly string[]).includes(errorCode) ? t(`overrideErrors.${errorCode}`)
      : t('errors.unknown', { code: errorCode || (save.error as Error).message })
    : null
  const onOff = (value: boolean) => value ? t('status.on') : t('status.off')
  const listSummary = (count: number) => count > 0 ? t('override.listCount', { count }) : t('status.off')
  const libraryNetworks = library.quick_block.allowed_crawlers.reduce((sum, crawler) => sum + crawler.networks.length, 0)

  const modeGroup = (key: 'idcCN' | 'idcGlobal' | 'carriers' | 'crawlers', labelID: string, inherited: string) =>
    <div role="radiogroup" aria-labelledby={labelID}><Radio.Group name={labelID} optionType="button" size="small" value={draft[key]} disabled={disabled}
      onChange={(event) => set({ [key]: event.target.value as Mode } as Partial<Draft>)}
      options={[
        { value: 'inherit', label: t('override.inherit', { value: inherited }) },
        // Turning a block on needs the IP intelligence library; crawlers allow, so never.
        { value: 'on', label: t('override.on'), disabled: key !== 'crawlers' && (!ready || !library.supported) && draft[key] !== 'on' },
        { value: 'off', label: t('override.off') },
      ]} /></div>

  const row = (key: 'idcCN' | 'idcGlobal' | 'carriers' | 'crawlers', label: string, hint: string, inherited: string,
    extra?: ReactNode) => {
    const id = `site-quick-block-override-${key}`
    return <div className="site-protection-setting-row">
      <span className="site-protection-label" id={id}>{label}</span>
      <div className="site-protection-control">
        {modeGroup(key, id, inherited)}
        {extra}
        <p>{hint}</p>
      </div>
    </div>
  }

  return <section className="site-protection-section site-protection-section--waf site-quick-block site-quick-block-override"
    aria-labelledby="site-quick-block-override-title" aria-busy={save.isPending} {...instant.typingProps}>
    <div className="site-protection-section-head">
      <div><h2 id="site-quick-block-override-title">{t('override.title')} <Tag color={quickBlockActive(effective) ? 'success' : 'default'}>
        {quickBlockActive(effective) ? t('status.on') : t('status.off')}</Tag></h2><span>{t('override.hint')}</span></div>
    </div>
    {intel.isSuccess && !ready ? <Alert type="warning" showIcon role="status" message={t('libraryNotReady')} /> : null}
    {!library.supported ? <Alert type="info" showIcon message={t('override.unsupported')} /> : null}
    {row('idcCN', t('blockIDCCN'), t('blockIDCCNHint'), onOff(library.quick_block.block_idc_cn))}
    {row('idcGlobal', t('blockIDCGlobal'), t('blockIDCGlobalHint'), onOff(library.quick_block.block_idc_global))}
    {row('carriers', t('carriers'), carrierError ?? t('override.carriersHint'), listSummary(library.quick_block.carriers.length),
      draft.carriers === 'on' ? <Select<QuickBlockCarrier[]> mode="multiple" aria-label={t('override.carrierList')}
        style={{ width: '100%', maxWidth: 520 }} allowClear placeholder={t('carriersPlaceholder')} value={draft.carrierList}
        disabled={disabled} status={carrierError ? 'error' : undefined} onChange={(value) => set({ carrierList: value })}
        options={quickBlockCarriers.map((value) => ({ value, label: tagT(ipIntelTagKey(value)) }))} /> : null)}
    {row('crawlers', t('crawlers'), crawlerError ?? t('override.crawlersHint'), listSummary(libraryNetworks),
      draft.crawlers === 'on' ? <Input.TextArea aria-label={t('override.crawlerList')} value={draft.crawlerText} disabled={disabled}
        rows={4} placeholder={t('crawlersPlaceholder')} status={crawlerError ? 'error' : undefined}
        onChange={(event) => set({ crawlerText: event.target.value })} /> : null)}
    {turnsOn ? <Alert type="info" showIcon message={t('nodesNotice')} /> : null}
    {errorMessage ? <FeedbackWhen title={errorMessage} /> : null}
  </section>
}
