import { useIsMutating, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Input, Select, Switch, Tag } from 'antd'
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import {
  quickBlockCarriers,
  securityPoliciesApi,
  type QuickBlockCarrier,
  type SecurityPolicy,
} from '../../api/securityPolicies'
import { ipIntelTagKey } from '../../i18n/ipIntel'
import '../../i18n/siteQuickBlock'
import { crawlersToText, maxQuickBlockCrawlerNetworks, parseCrawlers, quickBlockActive } from './quickBlock'
import { FeedbackWhen } from '@cdnca/ui'
import { useInstantDraft, useInstantFeedback } from './instantSave'

interface Draft {
  idcCN: boolean
  idcGlobal: boolean
  carriers: QuickBlockCarrier[]
  crawlers: string
}

function draftFromPolicy(policy: SecurityPolicy | undefined): Draft {
  const block = policy?.quick_block
  return { idcCN: Boolean(block?.block_idc_cn), idcGlobal: Boolean(block?.block_idc_global),
    carriers: [...(block?.carriers ?? [])], crawlers: crawlersToText(block?.allowed_crawlers) }
}

const knownErrors = ['quick_block_ip_intel_unavailable', 'quick_block_unsupported_policy', 'quick_block_last_rules',
  'quick_block_rule_budget', 'quick_block_site_override_conflict', 'version_conflict', 'validation_error'] as const

/**
 * 站点“防护”页“规则库快速屏蔽（默认值）”卡片：一键屏蔽国内 / 境外 IDC 和指定运营商，
 * 可放行搜索引擎蜘蛛。The switches belong to the site's active WAF rule
 * library (policy.quick_block, system-managed rules ahead of its own);
 * saving appends a version, which reaches the nodes once published. Every
 * site of the library without its own setting follows it
 * (SiteQuickBlockOverrideCard sets this site's own).
 */
export function SiteQuickBlockCard({ policy, activeVersion, accessToken, canManage, onPublish, onOpenLibraries, publish }: {
  policy: SecurityPolicy | undefined
  activeVersion: number | undefined
  accessToken: string
  canManage: boolean
  onPublish: (policyID: string) => void
  onOpenLibraries: () => void
  /** Publishes the saved version to the site right away; resolves false when refused. */
  publish?: (saved: SecurityPolicy) => Promise<boolean>
}) {
  const { t } = useTranslation('siteQuickBlock')
  const { t: tagT } = useTranslation('ipIntel')
  const queryClient = useQueryClient()
  const [savedVersion, setSavedVersion] = useState<number | null>(null)
  const [published, setPublished] = useState<boolean | null>(null)
  const library = useQuery({
    queryKey: ['site-protection', 'ip-intel-status'],
    enabled: Boolean(policy),
    retry: false,
    queryFn: ({ signal }) => securityPoliciesApi.ipIntelStatus(accessToken, signal),
  })
  const feedback = useInstantFeedback()
  // Switches and carriers save at once, the crawler list on blur; turning a block on waits for the IP library.
  const storedDraft = useMemo(() => draftFromPolicy(policy), [policy?.id, policy?.version, policy?.quick_block]) // eslint-disable-line react-hooks/exhaustive-deps
  const instantKey = ['site-instant', 'quick-block', policy?.id]
  const instant = useInstantDraft(storedDraft, {
    busy: useIsMutating({ mutationKey: instantKey }) > 0,
    isValid: (value) => {
      const crawlers = parseCrawlers(value.crawlers)
      if ('invalidLine' in crawlers || crawlers.networks > maxQuickBlockCrawlerNetworks) return false
      return library.data?.ready === true || !quickBlockActive({ block_idc_cn: value.idcCN, block_idc_global: value.idcGlobal, carriers: value.carriers })
    },
    submit: (value) => save.mutate(value),
  })
  const draft = instant.draft
  const parsed = useMemo(() => parseCrawlers(draft.crawlers), [draft.crawlers])
  const save = useMutation({
    mutationKey: instantKey,
    mutationFn: async (draft: Draft) => {
      const parsed = parseCrawlers(draft.crawlers)
      if (!policy || 'invalidLine' in parsed) throw new Error('invalid quick block')
      const saved = await securityPoliciesApi.setQuickBlock(accessToken, policy.id, policy.version, {
        block_idc_cn: draft.idcCN, block_idc_global: draft.idcGlobal, carriers: draft.carriers, allowed_crawlers: parsed.crawlers,
      }, `site-quick-block-${policy.id}-${policy.version}-${crypto.randomUUID()}`)
      return { saved, published: publish ? await publish(saved) : null }
    },
    onSuccess: ({ saved: updated, published: result }) => {
      setSavedVersion(updated.version)
      setPublished(result)
      if (result !== false) feedback.success()
      void queryClient.invalidateQueries({ queryKey: ['site-protection'] })
    },
    onError: () => instant.revert(),
  })

  if (!policy) {
    return <Alert type="info" showIcon message={t('noPolicy')}
      action={<Button size="small" disabled={!canManage} onClick={onOpenLibraries}>{t('openLibraries')}</Button>} />
  }
  if (policy.protected || policy.kind !== 'waf' || policy.default_action !== 'allow') {
    return <Alert type="info" showIcon message={t('unsupported')} />
  }
  const ready = library.data?.ready === true
  const set = (patch: Partial<Draft>) => { setSavedVersion(null); save.reset(); instant.set(patch) }
  const disabled = !canManage
  // Turning a block on needs the library; turning it off never does.
  const lockOn = (current: boolean) => !ready && !current
  const turningOn = quickBlockActive({ block_idc_cn: draft.idcCN, block_idc_global: draft.idcGlobal, carriers: draft.carriers })
  const crawlerError = 'invalidLine' in parsed ? t('crawlersInvalid', { line: parsed.invalidLine })
    : parsed.networks > maxQuickBlockCrawlerNetworks ? t('errors.quick_block_rule_budget') : null
  const errorCode = save.error instanceof ApiError ? save.error.code : ''
  const errorMessage = save.isError
    ? (knownErrors as readonly string[]).includes(errorCode) ? t(`errors.${errorCode}`) : t('errors.unknown', { code: errorCode || (save.error as Error).message })
    : null
  const pending = savedVersion === null && activeVersion !== undefined && activeVersion > 0 && activeVersion < policy.version
    ? { active: activeVersion, latest: policy.version } : null

  const switchRow = (key: 'idcCN' | 'idcGlobal', label: string, hint: string) => {
    const id = `site-quick-block-${key}`
    return <div className="site-protection-setting-row">
      <span className="site-protection-label" id={id}>{label}</span>
      <div className="site-protection-control">
        <Switch aria-labelledby={id} checked={draft[key]} disabled={disabled || lockOn(draft[key])}
          onChange={(checked) => set({ [key]: checked } as Partial<Draft>)} />
        <p>{hint}</p>
      </div>
    </div>
  }

  return <section className="site-protection-section site-protection-section--waf site-quick-block" aria-labelledby="site-quick-block-title"
    aria-busy={save.isPending} {...instant.typingProps}>
    <div className="site-protection-section-head">
      <div><h2 id="site-quick-block-title">{t('title')} <Tag color={quickBlockActive(policy.quick_block) ? 'success' : 'default'}>
        {quickBlockActive(policy.quick_block) ? t('status.on') : t('status.off')}</Tag></h2><span>{t('hint')}</span></div>
    </div>
    {library.isSuccess && !ready ? <Alert type="warning" showIcon role="status" message={t('libraryNotReady')} /> : null}
    {pending ? <Alert type="warning" showIcon role="status" message={t('pending', pending)}
      action={<Button size="small" type="primary" disabled={!canManage} onClick={() => onPublish(policy.id)}>{t('publish')}</Button>} /> : null}
    {switchRow('idcCN', t('blockIDCCN'), t('blockIDCCNHint'))}
    {switchRow('idcGlobal', t('blockIDCGlobal'), t('blockIDCGlobalHint'))}
    <div className="site-protection-setting-row">
      <span className="site-protection-label">{t('carriers')}</span>
      <div className="site-protection-control">
        <Select<QuickBlockCarrier[]> mode="multiple" aria-label={t('carriers')} style={{ width: '100%', maxWidth: 520 }} allowClear
          placeholder={t('carriersPlaceholder')} value={draft.carriers} disabled={disabled}
          onChange={(value) => set({ carriers: value })}
          options={quickBlockCarriers.map((value) => ({ value, label: tagT(ipIntelTagKey(value)),
            disabled: lockOn(draft.carriers.includes(value)) }))} />
      </div>
    </div>
    <div className="site-protection-setting-row">
      <span className="site-protection-label">{t('crawlers')}</span>
      <div className="site-protection-control">
        <Input.TextArea aria-label={t('crawlers')} value={draft.crawlers} disabled={disabled} rows={4}
          placeholder={t('crawlersPlaceholder')} status={crawlerError ? 'error' : undefined}
          onChange={(event) => set({ crawlers: event.target.value })} />
        <p>{crawlerError ?? t('crawlersHint')}</p>
      </div>
    </div>
    {turningOn ? <Alert type="info" showIcon message={t('nodesNotice')} /> : null}
    {savedVersion !== null && published === null ? <Alert type="success" showIcon message={t('saved', { version: savedVersion })}
      action={<Button size="small" onClick={() => onPublish(policy.id)}>{t('publish')}</Button>} /> : null}
    {savedVersion !== null && published === false ? <Alert type="warning" showIcon role="status" message={t('publishFailed')} /> : null}
    {errorMessage ? <FeedbackWhen title={errorMessage} /> : null}
  </section>
}
