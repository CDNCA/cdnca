import { Alert, Switch, Tag } from 'antd'
import { useTranslation } from 'react-i18next'

import type { CRSProfilePack, CRSTierSet } from '../../api/securityPolicies'
import '../../i18n/wafTiers'

/** The tier's display name: its Chinese/English friendly name, else the pack's own. */
export function useTierName() {
  const { t, i18n } = useTranslation('wafTiers')
  return (profile: Pick<CRSProfilePack, 'pack_id' | 'name'> | undefined, packID?: string) => {
    const id = profile?.pack_id ?? packID ?? ''
    return i18n.exists(`wafTiers:tiers.${id}`) ? t(`tiers.${id}`) : profile?.name ?? id
  }
}

/** Profiles ordered as tiers (narrowest first); packs without a tier last. */
export function orderedProfiles(profiles: CRSProfilePack[]): CRSProfilePack[] {
  return [...profiles].sort((left, right) => (left.tier?.order ?? 1000) - (right.tier?.order ?? 1000) ||
    left.pack_id.localeCompare(right.pack_id))
}

/** A rule group is off when every one of its rules is excluded. */
export function setEnabled(set: CRSTierSet, exclusions: number[]): boolean {
  return !set.rules.every((id) => exclusions.includes(id))
}

/** Exclusions with the group's rules removed (on) or added (off), sorted and unique. */
export function toggleSet(set: CRSTierSet, exclusions: number[], enabled: boolean): number[] {
  const next = new Set(exclusions)
  for (const id of set.rules) {
    if (enabled) next.delete(id)
    else next.add(id)
  }
  return [...next].sort((left, right) => left - right)
}

/**
 * One protection tier: what it does, its attack types (with rule counts), what
 * it adds to the previous tier and, when exclusions are editable, a switch per
 * rule group (off = exclude all its rules). All numbers come from the server
 * (counted from the CRS rule text).
 */
export function CRSTierDetails({ profile, profiles, exclusions, disabled, onExclusions }: {
  profile: CRSProfilePack
  profiles: CRSProfilePack[]
  exclusions?: number[]
  disabled?: boolean
  onExclusions?: (exclusions: number[]) => void
}) {
  const { t, i18n } = useTranslation('wafTiers')
  const tierName = useTierName()
  const tier = profile.tier
  if (!tier) return <p className="crs-tier-description">{profile.description}</p>
  // Set keys contain ":" (waf_set:crs_sqli): without nsSeparator:false it is read as a namespace and never matches.
  const setName = (key: string, fallback: string) =>
    i18n.exists(`sets.${key}`, { ns: 'wafTiers', nsSeparator: false }) ? t(`sets.${key}`, { nsSeparator: false }) : fallback
  const previous = profiles.find((item) => item.pack_id === tier.previous)
  const previousName = tierName(previous, tier.previous)
  return (
    <div className="crs-tier" data-testid="crs-tier">
      <p className="crs-tier-summary">
        {t('summary', { action: t(`action.${tier.action}`), paranoia: tier.paranoia, count: tier.sets.length })}
      </p>
      <div className="crs-tier-classes" role="group" aria-label={t('classes')}>
        <span>{t('classes')}：</span>
        {tier.sets.map((set) => <Tag key={set.key}>{setName(set.key, set.name)} · {t('rules', { count: set.rules.length })}</Tag>)}
      </div>
      <div className="crs-tier-added">
        <span>{tier.previous ? t('added', { previous: previousName }) : t('addedNone')}</span>
        {tier.added.length ? <ul>
          {tier.added.map((item) => <li key={`${item.kind}:${item.key ?? ''}`}>{
            item.kind === 'set' ? t('addedSet', { name: setName(item.key ?? '', item.name ?? ''), rules: item.rules })
              : item.kind === 'paranoia' ? t('addedParanoia', { name: setName(item.key ?? '', item.name ?? ''),
                from: item.from_paranoia, to: item.to_paranoia, rules: item.rules })
                : t('addedBlock', { previous: previousName, rules: item.rules })
          }</li>)}
        </ul> : null}
      </div>
      {tier.paranoia >= 3 ? <Alert type="warning" showIcon message={t('falsePositive')} />
        : tier.paranoia === 2 ? <Alert type="info" showIcon message={t('strictHint')} /> : null}
      {exclusions && onExclusions ? <div className="crs-tier-switches" role="group" aria-label={t('setSwitches')}>
        <span title={t('setSwitchesHint')}>{t('setSwitches')}：</span>
        {tier.sets.map((set) => {
          const on = setEnabled(set, exclusions)
          const name = setName(set.key, set.name)
          return <label key={set.key} className="crs-tier-switch">
            <Switch size="small" checked={on} disabled={disabled} aria-label={on ? t('setOn', { name }) : t('setOff', { name })}
              onChange={(checked) => onExclusions(toggleSet(set, exclusions, checked))} />
            <span>{name}</span>
          </label>
        })}
        <p>{t('setSwitchesHint')}</p>
      </div> : null}
    </div>
  )
}
