import { useMemo } from 'react'
import { useIsMutating, useMutation, useQueryClient } from '@tanstack/react-query'
import { Alert, InputNumber, Switch } from 'antd'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import { isQuickBlockRuleID, type SecurityActivationStatus, type SecurityPolicy } from '../../api/securityPolicies'
import '../../i18n/siteProtection'
import { FeedbackWhen } from '@cdnca/ui'
import { useInstantDraft, useInstantFeedback } from './instantSave'
import { wafSettingsDraft, wafSettingsFromDraft, type WAFSettingsDraft } from './SiteProtectionTabs'
import { fieldsOf, saveSiteLibrary } from './sitePolicyEdits'

/**
 * ③ WAF 命中自动封禁（fix-siteautodef 从 WAF防护「防御级别」移来）：本站 WAF 规则库的 waf_settings.auto_block，
 * 写回同一规则库并下发（与 WAF防护 页保存同一写法；运行模式留在 WAF防护 页，这里保留其现值）。
 * 本站未启用规则库或使用订阅规则库（只读）时只读，并说明原因。
 */
export function SiteWAFHitBlockCard({ siteId, accessToken, policy, status, bindingKnown, writable }: {
  siteId: string
  accessToken: string
  /** The site's bound WAF library (undefined: none bound or not yet read). */
  policy: SecurityPolicy | undefined
  status: SecurityActivationStatus | undefined
  bindingKnown: boolean
  /** security_policies.manage, not locked, binding read (and the administrator target known). */
  writable: boolean
}) {
  const { t } = useTranslation('siteProtection')
  const queryClient = useQueryClient()
  const stored = useMemo(() => wafSettingsDraft(policy?.waf_settings), [policy?.waf_settings])
  const instantKey = ['site-instant', 'waf-hit-block', siteId]
  const feedback = useInstantFeedback()
  const save = useMutation({
    mutationKey: instantKey,
    mutationFn: async (draft: WAFSettingsDraft) => {
      const current = policy!
      // The rules as the WAF tab saves them (quick block rules are the server's), waf_settings with the new auto ban.
      const fields = { ...fieldsOf(current), rules: current.rules.filter((rule) => !isQuickBlockRuleID(rule.id)),
        waf_settings: wafSettingsFromDraft({ ...draft, observe: stored.observe }) }
      return saveSiteLibrary({ accessToken, siteId, policy: current, fields, status, target: undefined })
    },
    onSuccess: () => feedback.success(),
    onError: () => instant.revert(),
    onSettled: () => { void queryClient.invalidateQueries({ queryKey: ['site-protection'] }) },
  })
  const editable = writable && Boolean(policy) && !policy?.protected
  const instant = useInstantDraft(stored, {
    busy: useIsMutating({ mutationKey: instantKey }) > 0,
    isChanged: (draft, base) => (draft.autoBlock ? `${draft.window}/${draft.hits}/${draft.seconds}` : '') !== (base.autoBlock ? `${base.window}/${base.hits}/${base.seconds}` : ''),
    isValid: () => editable,
    submit: (draft) => save.mutate(draft),
  })
  const draft = instant.draft
  const disabled = !editable
  const set = (patch: Partial<WAFSettingsDraft>) => { save.reset(); instant.set(patch) }
  const reason = !bindingKnown ? t('common.unconfirmed') : !policy ? t('autodefense.hitBlockNoLibrary') : policy.protected ? t('autodefense.hitBlockProtected') : null

  return <section className="site-protection-section site-autodefense-section" aria-labelledby="site-waf-autoblock-title" aria-busy={save.isPending} {...instant.typingProps}>
    <div className="site-protection-section-head">
      <div><h2 id="site-waf-autoblock-title">{t('waf.autoBlock')}</h2><span>{t('waf.autoBlockHint')}</span></div>
      <div><Switch aria-label={t('waf.autoBlock')} checked={draft.autoBlock} disabled={disabled} onChange={(checked) => set({ autoBlock: checked })} /></div>
    </div>
    {reason ? <Alert type="info" showIcon message={reason} /> : null}
    {draft.autoBlock ? <div className="site-protection-auto-ban-fields">
      <label><span>{t('waf.autoBlockWindow')}</span><InputNumber aria-label={t('waf.autoBlockWindow')} min={1} max={86_400} precision={0} value={draft.window} disabled={disabled}
        onChange={(value) => { if (value !== null) set({ window: value }) }} /></label>
      <label><span>{t('waf.autoBlockHits')}</span><InputNumber aria-label={t('waf.autoBlockHits')} min={1} max={1_000_000} precision={0} value={draft.hits} disabled={disabled}
        onChange={(value) => { if (value !== null) set({ hits: value }) }} /></label>
      <label><span>{t('waf.autoBlockSeconds')}</span><InputNumber aria-label={t('waf.autoBlockSeconds')} min={1} max={604_800} precision={0} value={draft.seconds} disabled={disabled}
        onChange={(value) => { if (value !== null) set({ seconds: value }) }} /></label>
    </div> : null}
    {save.data && !save.data.published ? <Alert type="warning" showIcon role="status" message={t('save.publishFailed')} /> : null}
    {save.error ? <FeedbackWhen title={t('save.failed', { message: save.error instanceof ApiError ? save.error.code : (save.error as Error).message })} /> : null}
  </section>
}
