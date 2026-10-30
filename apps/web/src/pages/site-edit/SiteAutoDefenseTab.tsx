import { useTranslation } from 'react-i18next'

import '../../i18n/siteProtection'
import '../../i18n/siteEditV4'
import { SiteCCSettingsSection } from './SiteCCSettingsSection'
import { SiteTabSummary, type SummaryItem } from './SiteTabSummary'
import { SiteWAFAutoBanCard } from './SiteWAFAutoBanCard'
import { SiteWAFHitBlockCard } from './SiteWAFHitBlockCard'
import { hasPermission, sitePublisher, useSiteLibrary, type SiteProtectionProps } from './SiteProtectionTabs'
import { useSiteFirewallAction } from './siteAutoDefenseQueries'
import SiteEditState from './SiteEditState'
import './SiteProtectionTabs.css'
import './SiteAutoDefenseTab.css'

/**
 * 网站编辑「自动防御」标签：CC/WAF 页里的自动类功能集中在这里，
 * CC/WAF 页只留规则本身。顶部一行状态总览，下面按 ① CC 自动切换 ② WAF 攻击自动封禁 ③ WAF 命中自动封禁（社区版：攻击自动升级、智能自动防御与保底链属于商业版）。接口与数据不变：各分区用原卡片的接口、查询键与即改即生效写法。
 * 管理端与用户端共用；无权限或未开通的分区不显示，总览也不列。
 */
export function SiteAutoDefenseTab(props: SiteProtectionProps) {
  const { siteId, scopeKind, scopeId, accessToken, permissions, locked, siteScopeId, siteOwnerId } = props
  const { t } = useTranslation('siteProtection')
  const { t: tSummary } = useTranslation('siteEditV4')
  const canRead = hasPermission(permissions, 'security_policies.read')
  const canWrite = !locked && hasPermission(permissions, 'security_policies.manage')
  const isAdmin = scopeKind === 'platform'
  const cc = useSiteLibrary('cc', { siteId, scopeId, accessToken, enabled: canRead })
  const waf = useSiteLibrary('waf', { siteId, scopeId, accessToken, enabled: canRead })
  const scope = { siteId, scopeKind, scopeId, siteScopeId, accessToken, permissions }
  const firewall = useSiteFirewallAction(scope)

  if (!canRead && !firewall.canRead) return <SiteEditState status="forbidden" title={t('common.readOnly')} />

  // ① as the CC tab wrote it: the bound library, or the only one while the binding cannot be read.
  const ccPolicy = cc.activePolicy
  const workingPolicy = ccPolicy ?? (cc.policies.length === 1 && !cc.activationQuery.isSuccess ? cc.policies[0] : undefined)
  const wafTarget = !isAdmin || Boolean(siteScopeId && siteOwnerId)
  const onOff = (on: boolean | undefined): Pick<SummaryItem, 'value' | 'tone'> => on === undefined
    ? { value: t('common.unconfirmed'), tone: 'warn' } : { value: tSummary(on ? 'summary.on' : 'summary.off'), tone: on ? 'on' : 'off' }
  const switchMode = workingPolicy?.cc_settings?.auto_switch?.mode
  const items: SummaryItem[] = []
  if (canRead) {
    items.push({ key: 'autoSwitch', label: t('autodefense.autoSwitch'), target: 'site-autodefense-autoswitch-title',
      ...onOff(cc.policiesQuery.isSuccess ? Boolean(switchMode) : undefined) })
  }
  if (firewall.canRead) {
    items.push({ key: 'autoBan', label: t('waf.autoBan'), target: 'site-waf-autoban-title', ...onOff(firewall.query.isSuccess ? Boolean(firewall.query.data) : undefined) })
  }
  if (canRead) {
    items.push({ key: 'hitBlock', label: t('waf.autoBlock'), target: 'site-waf-autoblock-title',
      ...onOff(waf.activationQuery.isSuccess && waf.policiesQuery.isSuccess ? Boolean(waf.activePolicy?.waf_settings?.auto_block) : undefined) })
  }
  return <div className="site-edit-tab-panel site-protection-page site-autodefense-page" aria-labelledby="site-autodefense-title">
    <h2 id="site-autodefense-title" className="visually-hidden">{t('autodefense.title')}</h2>
    <SiteTabSummary items={items} />
    {canRead ? <section className="site-protection-section site-autodefense-section" aria-labelledby="site-autodefense-autoswitch-title">
      <div className="site-protection-section-head"><div><h2 id="site-autodefense-autoswitch-title">{t('autodefense.autoSwitch')}</h2><span>{t('autodefense.autoSwitchHint')}</span></div></div>
      <SiteCCSettingsSection part="autoSwitch" policy={workingPolicy} accessToken={accessToken} isAdmin={isAdmin} canManage={canWrite}
        onPublish={() => undefined}
        publish={ccPolicy && workingPolicy?.id === ccPolicy.id ? sitePublisher(accessToken, siteId, cc.activationQuery.data) : undefined} />
    </section> : null}
    <SiteWAFAutoBanCard siteId={siteId} scopeKind={scopeKind} scopeId={scopeId} siteScopeId={siteScopeId} accessToken={accessToken}
      permissions={permissions} locked={locked} />
    {canRead ? <SiteWAFHitBlockCard siteId={siteId} accessToken={accessToken} policy={waf.activePolicy} status={waf.activationQuery.data}
      bindingKnown={waf.activationQuery.isSuccess} writable={canWrite && waf.activationQuery.isSuccess && wafTarget} /> : null}
  </div>
}

export default SiteAutoDefenseTab
