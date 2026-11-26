import { useQuery } from '@tanstack/react-query'
import { ExternalLink } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { securityPoliciesApi } from '../../api/securityPolicies'
import '../../i18n/securityPoliciesConditionFields'
import { conditionCapability, isStringSetOperator } from './conditionFields'

/**
 * under a WAF condition that needs a node capability (JA4, IP
 * intelligence, WAF v4/v6 matches) what is known about it right there: the control plane's IP intelligence
 * library, and, opened from a site, the site's nodes a release waits on to be upgraded (with the way to
 * upgrade them). The version details stay in a collapsed 诊断详情. A plain condition shows nothing.
 */
export function ConditionCapabilityNote({ field, operator, accessToken, siteId, isAdmin, diagnosticsLabel }: {
  field?: string
  operator?: string
  accessToken: string
  /** The site the rules page was opened for (?site_id); its release status names the waiting nodes. */
  siteId?: string
  isAdmin: boolean
  /** The 诊断详情 name of this row (later rows add their number, as the other condition cells). */
  diagnosticsLabel: string
}) {
  const { t } = useTranslation('securityPolicies')
  const need = conditionCapability(field, operator)
  // The same queries (and keys) as the quick block card and the activation panel.
  const ipIntel = useQuery({
    queryKey: ['site-protection', 'ip-intel-status'],
    enabled: need === 'ipIntel' && Boolean(accessToken),
    retry: false,
    queryFn: ({ signal }) => securityPoliciesApi.ipIntelStatus(accessToken, signal),
  })
  const status = useQuery({
    queryKey: ['security-activation', siteId ?? '', 'waf'],
    enabled: Boolean(need && siteId && accessToken),
    retry: false,
    queryFn: ({ signal }) => securityPoliciesApi.getActivationStatus(accessToken, siteId!, 'waf', signal),
  })
  if (!need) return null
  const wait = status.data?.capability_wait
  const waiting = wait && wait.wait_kind !== 'rule_pack' ? wait.node_ids : []
  const details = need === 'wafV4' ? [t('editor.ipListHint')]
    : need === 'wafV6' ? [t('conditionFields.v6Hint')]
      : [t('conditionFields.nodeHint'), ...(isStringSetOperator(operator) ? [t('conditionFields.v6Hint')] : [])]
  return <div className="sp-editor-cond-capability" role="note">
    <p>
      {t('conditionFields.capability.needs', { need: t(`conditionFields.capability.kinds.${need}`) })}
      {need === 'ipIntel' && ipIntel.isSuccess ? <> {ipIntel.data.ready
        ? t('conditionFields.capability.ipIntelReady', { revision: ipIntel.data.revision })
        : t('conditionFields.capability.ipIntelMissing')}</> : null}
      {' '}{waiting.length ? t('conditionFields.capability.siteWaiting', { count: waiting.length, nodes: waiting.join('、') })
        : t('conditionFields.capability.onPublish')}
      {waiting.length ? isAdmin
        ? <> <a className="sp-editor-cond-link" href="/node/list" target="_blank" rel="noreferrer">
          {t('conditionFields.capability.upgrade')} <ExternalLink size={12} aria-hidden /></a></>
        : <> {t('conditionFields.capability.askAdmin')}</> : null}
    </p>
    <details>
      <summary aria-label={diagnosticsLabel}>{t('conditionFields.capability.diagnostics')}</summary>
      {details.map((text) => <p key={text}>{text}</p>)}
    </details>
  </div>
}
