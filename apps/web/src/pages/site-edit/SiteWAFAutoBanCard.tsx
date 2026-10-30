import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, InputNumber, Switch } from 'antd'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import { firewallActionApi } from '../../api/firewallAction'
import '../../i18n/siteProtection'
import { FeedbackWhen } from '@cdnca/ui'
import { useCommitRequest, useInstantFeedback } from './instantSave'
import { useSiteFirewallAction } from './siteAutoDefenseQueries'

/**
 * ② WAF 攻击自动封禁（fix-siteautodef 从 WAF防护 页移来）：阈值是本站防火墙动作策略
 * （PUT /v1/firewall-actions/policy，与防火墙动作页同一接口），失焦即生效。没有 firewall.read 不显示。
 */
export function SiteWAFAutoBanCard({ siteId, scopeKind, scopeId, siteScopeId, accessToken, permissions, locked }: {
  siteId: string
  scopeKind: 'platform' | 'tenant'
  scopeId: string
  siteScopeId?: string
  accessToken: string
  permissions: readonly string[]
  locked: boolean
}) {
  const { t } = useTranslation('siteProtection')
  const queryClient = useQueryClient()
  const { query: firewallQuery, canRead, targetScopeId } = useSiteFirewallAction({ siteId, scopeKind, scopeId, siteScopeId, accessToken, permissions })
  const canManage = !locked && Boolean(targetScopeId) && (permissions.includes('firewall.manage') || permissions.includes('platform.admin'))
  const firewall = firewallQuery.data
  const stored = useMemo(() => firewall ? { engage: firewall.engage_threshold, recover: firewall.recover_threshold, windows: firewall.recovery_windows } : null, [firewall])
  const [thresholds, setThresholds] = useState(stored)
  useEffect(() => { setThresholds(stored) }, [stored])
  const changed = Boolean(thresholds && stored && JSON.stringify(thresholds) !== JSON.stringify(stored))
  const valid = !thresholds || thresholds.engage >= 1 && thresholds.recover < thresholds.engage && thresholds.windows >= 1 && thresholds.windows <= 60

  const feedback = useInstantFeedback()
  const save = useMutation({
    mutationFn: async () => {
      if (!firewall || !thresholds) return
      // The page's policy input fields, as 防火墙动作 saves them.
      const input = { normal_action: firewall.normal_action, escalated_action: firewall.escalated_action, block_networks: firewall.block_networks,
        trusted_proxies: firewall.trusted_proxies, trusted_crawlers: firewall.trusted_crawlers, return_page: firewall.return_page }
      await firewallActionApi.put(accessToken, { scopeId: targetScopeId ?? '', siteId, expectedRevision: firewall.revision,
        policy: { ...input, engage_threshold: thresholds.engage, recover_threshold: thresholds.recover, recovery_windows: thresholds.windows } })
    },
    onSuccess: () => feedback.success(),
    // fix-siteinstant: a failed save puts the fields back to the stored values.
    onError: () => setThresholds(stored),
    onSettled: () => { void queryClient.invalidateQueries({ queryKey: ['site-protection'] }) },
  })
  // fix-siteinstant: numbers save on blur / Enter; a running save sends the latest values after it.
  const commits = useCommitRequest(() => {
    if (!changed || !valid) return
    save.mutate()
  }, save.isPending || firewallQuery.isFetching)

  if (!canRead) return null
  const disabled = !canManage || !thresholds
  const setThreshold = (key: 'engage' | 'recover' | 'windows', value: number | null) => {
    if (value === null || !thresholds) return
    save.reset(); setThresholds({ ...thresholds, [key]: value }); commits.requestUnlessTyping()
  }
  return <section className="site-protection-section site-autodefense-section" aria-labelledby="site-waf-autoban-title" aria-busy={save.isPending} {...commits.typingProps}>
    <div className="site-protection-section-head">
      <div><h2 id="site-waf-autoban-title">{t('waf.autoBan')}</h2><span>{t('waf.autoBanHint')}</span></div>
      <div><Switch aria-label={t('waf.autoBan')} checked={Boolean(firewall)} disabled /></div>
    </div>
    {firewallQuery.isError ? <FeedbackWhen title={t('common.loadFailed')} action={<Button size="small" onClick={() => void firewallQuery.refetch()}>{t('common.retry')}</Button>} /> : null}
    <div className="site-protection-auto-ban-fields">
      <label><span>{t('waf.engageThreshold')}</span><InputNumber aria-label={t('waf.engageThreshold')} min={1} precision={0} value={thresholds?.engage} disabled={disabled} onChange={(value) => setThreshold('engage', value)} /></label>
      <label><span>{t('waf.recoverThreshold')}</span><InputNumber aria-label={t('waf.recoverThreshold')} min={0} precision={0} value={thresholds?.recover} disabled={disabled} onChange={(value) => setThreshold('recover', value)} /></label>
      <label><span>{t('waf.recoveryWindows')}</span><InputNumber aria-label={t('waf.recoveryWindows')} min={1} max={60} precision={0} value={thresholds?.windows} disabled={disabled} onChange={(value) => setThreshold('windows', value)} /></label>
    </div>
    {!valid ? <Alert type="error" showIcon message={t('waf.thresholdInvalid')} /> : null}
    {save.error ? <FeedbackWhen title={t('save.failed', { message: save.error instanceof ApiError ? save.error.code : (save.error as Error).message })} /> : null}
  </section>
}
