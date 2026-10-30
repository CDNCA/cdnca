import { useIsMutating, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Input, Radio, Select } from 'antd'
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import { securityPoliciesApi, type SiteCRSOverride, type SiteCRSState } from '../../api/securityPolicies'
import '../../i18n/siteCRS'
import { CRSTierDetails, orderedProfiles, useTierName } from '../security/CRSTierDetails'
import { crsRuleIdsPattern, parseCRSRuleIds } from '../security/ManagedRuleFields'
import { FeedbackWhen } from '@cdnca/ui'
import { useInstantDraft, useInstantFeedback } from '../site-edit/instantSave'

type Mode = 'inherit' | 'custom'

interface Draft {
  profileMode: Mode
  profile: string
  exclusionsMode: Mode
  exclusions: string
  apps: string[]
}

function draftFromState(state: SiteCRSState | undefined): Draft {
  const override = state?.override
  return {
    profileMode: override?.profile ? 'custom' : 'inherit',
    profile: override?.profile ?? state?.library?.profile ?? '',
    exclusionsMode: override?.exclusions ? 'custom' : 'inherit',
    exclusions: (override?.exclusions ?? state?.library?.exclusions ?? []).join(', '),
    apps: override?.apps ?? [],
  }
}

const knownErrors = ['crs_app_unavailable', 'crs_profile_unavailable', 'crs_exclusion_not_exported', 'crs_no_managed_waf', 'version_conflict',
  'idempotency_conflict', 'site_locked', 'validation_error'] as const

/**
 * 站点“防护”页“本站 OWASP CRS 档位”（PA-12）：档位与排除规则各自“跟随规则库 /
 * 本站单独设置”。Only this site changes (site_crs_overrides); saving advances
 * the site version (an automatic scope publishes it).
 */
export function SiteCRSOverrideCard({ siteId, accessToken, canManage, onOpenLibraries }: {
  siteId: string
  accessToken: string
  canManage: boolean
  onOpenLibraries: () => void
}) {
  const { t } = useTranslation('siteCRS')
  const tierName = useTierName()
  const queryClient = useQueryClient()
  const queryKey = ['site-protection', siteId, 'site-crs']
  const stateQuery = useQuery({
    queryKey, retry: false,
    queryFn: ({ signal }) => securityPoliciesApi.getSiteCRS(accessToken, siteId, signal),
  })
  // A response without the site CRS shape is treated as unreadable.
  const state = stateQuery.data && Array.isArray(stateQuery.data.profiles) && stateQuery.data.override ? stateQuery.data : undefined
  const [saved, setSaved] = useState(false)
  const feedback = useInstantFeedback()
  // fix-siteinstant: choices save at once, the exclusion list on blur / Enter.
  const storedDraft = useMemo(() => draftFromState(state), [state?.version, state?.library?.version]) // eslint-disable-line react-hooks/exhaustive-deps
  const instantKey = ['site-instant', 'crs', siteId]
  const instant = useInstantDraft(storedDraft, {
    busy: useIsMutating({ mutationKey: instantKey }) > 0 || stateQuery.isFetching,
    isValid: (value) => Boolean(state) && !(value.profileMode === 'custom' && !value.profile) && exclusionProblem(value) === null,
    submit: (value) => save.mutate(overrideOf(value)),
  })
  const draft = instant.draft
  const selectedProfile = draft.profileMode === 'custom' ? draft.profile : state?.library?.profile
  const profile = state?.profiles.find((item) => item.pack_id === selectedProfile)
  function exclusionProblem(value: Draft): string | null {
    if (value.exclusionsMode !== 'custom') return null
    if (!crsRuleIdsPattern.test(value.exclusions)) return t('exclusionsInvalid')
    const chosen = state?.profiles.find((item) => item.pack_id === (value.profileMode === 'custom' ? value.profile : state?.library?.profile))
    const ids = parseCRSRuleIds(value.exclusions).filter((id) => chosen && !chosen.exports.includes(id))
    return ids.length ? t('notExported', { ids: ids.join(', ') }) : null
  }
  const exclusionError = exclusionProblem(draft)
  const overrideOf = (value: Draft): SiteCRSOverride => ({
    profile: value.profileMode === 'custom' && value.profile ? value.profile : null,
    exclusions: value.exclusionsMode === 'custom' ? parseCRSRuleIds(value.exclusions) : null,
    apps: [...value.apps].sort(),
  })
  const save = useMutation({
    mutationKey: instantKey,
    mutationFn: (override: SiteCRSOverride) => {
      if (!state) throw new Error('site CRS not loaded')
      return securityPoliciesApi.setSiteCRS(accessToken, siteId, state.version, override,
        `site-crs-${siteId}-${state.version}-${crypto.randomUUID()}`)
    },
    onSuccess: (updated) => {
      setSaved(true)
      feedback.success()
      queryClient.setQueryData(queryKey, updated)
      void queryClient.invalidateQueries({ queryKey: ['site-protection'] })
    },
    onError: (error) => {
      instant.revert()
      if (error instanceof ApiError && error.code === 'version_conflict') void stateQuery.refetch()
    },
  })

  if (stateQuery.isPending) return null
  if (stateQuery.isError || !state) {
    return <FeedbackWhen title={t('loadFailed')} action={<Button size="small" onClick={() => void stateQuery.refetch()}>{t('retry')}</Button>} />
  }
  const library = state.library
  if (!library) {
    return <Alert type="info" showIcon message={t('noManagedWAF')}
      action={<Button size="small" disabled={!canManage} onClick={onOpenLibraries}>{t('openLibraries')}</Button>} />
  }
  const disabled = !canManage
  const set = (patch: Partial<Draft>) => { setSaved(false); save.reset(); instant.set(patch) }
  const profileName = (packID: string) => tierName(state.profiles.find((item) => item.pack_id === packID), packID)
  const listText = (ids: number[]) => ids.length ? ids.join(', ') : t('none')
  const apps = state.apps ?? []
  const appName = (packID: string) => apps.find((item) => item.pack_id === packID)?.name ?? packID
  const errorCode = save.error instanceof ApiError ? save.error.code : ''
  const errorMessage = save.isError
    ? (knownErrors as readonly string[]).includes(errorCode) ? t(`errors.${errorCode}`)
      : t('errors.unknown', { code: errorCode || (save.error as Error).message })
    : null
  const effectiveExclusions = draft.exclusionsMode === 'custom' ? parseCRSRuleIds(draft.exclusions) : library.exclusions
  const packNames = (items: { pack_id: string; version: string }[] | undefined) =>
    (items ?? []).map((item) => `${item.pack_id}@${item.version}`).join('、')
  const change = saved ? save.data?.rule_pack_change : undefined
  const suspendedNow = packNames(state.rule_pack_suspensions)

  return <section className="site-protection-section site-protection-section--waf site-crs" aria-labelledby="site-crs-title" aria-busy={save.isPending} {...instant.typingProps}>
    <div className="site-protection-section-head">
      <div><h2 id="site-crs-title">{t('title')}</h2><span>{t('hint')}</span></div>
    </div>
    <div className="site-protection-setting-row">
      <span className="site-protection-label" id="site-crs-profile">{t('profile')}</span>
      <div className="site-protection-control">
        <div role="radiogroup" aria-labelledby="site-crs-profile"><Radio.Group name="site-crs-profile" optionType="button" size="small" value={draft.profileMode}
          disabled={disabled} onChange={(event) => set({ profileMode: event.target.value as Mode })}
          options={[{ value: 'inherit', label: t('inherit', { value: profileName(library.profile) }) }, { value: 'custom', label: t('custom') }]} /></div>
        {draft.profileMode === 'custom' ? <Select aria-label={t('profile')} style={{ width: 280 }} value={draft.profile || undefined}
          disabled={disabled} onChange={(value: string) => set({ profile: value })}
          options={orderedProfiles(state.profiles).map((item) => ({ value: item.pack_id, label: tierName(item) }))} /> : null}
        {profile ? <CRSTierDetails profile={profile} profiles={state.profiles} disabled={disabled}
          exclusions={crsRuleIdsPattern.test(draft.exclusions) ? (draft.exclusionsMode === 'custom'
            ? parseCRSRuleIds(draft.exclusions) : library.exclusions) : undefined}
          onExclusions={(ids) => set({ exclusionsMode: 'custom', exclusions: ids.join(', ') })} /> : null}
      </div>
    </div>
    <div className="site-protection-setting-row">
      <span className="site-protection-label" id="site-crs-exclusions">{t('exclusions')}</span>
      <div className="site-protection-control">
        <div role="radiogroup" aria-labelledby="site-crs-exclusions"><Radio.Group name="site-crs-exclusions" optionType="button" size="small" value={draft.exclusionsMode}
          disabled={disabled} onChange={(event) => set({ exclusionsMode: event.target.value as Mode })}
          options={[{ value: 'inherit', label: t('inherit', { value: library.exclusions.length ? t('count', { count: library.exclusions.length }) : t('none') }) },
            { value: 'custom', label: t('custom') }]} /></div>
        {draft.exclusionsMode === 'custom' ? <Input aria-label={t('exclusions')} value={draft.exclusions} disabled={disabled}
          placeholder="941160, 941310" status={exclusionError ? 'error' : undefined} style={{ maxWidth: 520 }}
          onChange={(event) => set({ exclusions: event.target.value })} /> : null}
        <p>{exclusionError ?? t('exclusionsHint')}</p>
      </div>
    </div>
    <div className="site-protection-setting-row">
      <span className="site-protection-label" id="site-crs-apps">{t('apps')}</span>
      <div className="site-protection-control">
        {apps.length || draft.apps.length ? <Select mode="multiple" aria-labelledby="site-crs-apps" style={{ maxWidth: 520, width: '100%' }}
          allowClear placeholder={t('appsPlaceholder')} value={draft.apps} disabled={disabled}
          onChange={(value: string[]) => set({ apps: value })}
          options={apps.map((item) => ({ value: item.pack_id, label: item.name, title: item.description }))} /> : null}
        <p>{apps.length || draft.apps.length ? t('appsHint') : t('appsUnavailable')}</p>
      </div>
    </div>
    <p role="status">{t('effective', { profile: profileName(selectedProfile ?? library.profile), exclusions: listText(effectiveExclusions) })}
      {draft.apps.length ? <>；{t('appsEffective', { apps: draft.apps.map(appName).join('、') })}</> : null}</p>
    {change?.suspended.length ? <Alert type="warning" showIcon role="alert"
      message={t('packsSuspended', { packs: packNames(change.suspended) })} /> : null}
    {change?.restored.length ? <Alert type="info" showIcon message={t('packsRestored', { packs: packNames(change.restored) })} /> : null}
    {!change?.suspended.length && suspendedNow ? <Alert type="warning" showIcon
      message={t('packsSuspendedNow', { packs: suspendedNow })} /> : null}
    {errorMessage ? <FeedbackWhen title={errorMessage} /> : null}
  </section>
}
