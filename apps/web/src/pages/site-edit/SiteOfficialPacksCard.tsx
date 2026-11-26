import { useId, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Button, Collapse, Empty, Tag } from 'antd'
import { useTranslation } from 'react-i18next'

import { rulePacksApi } from '../../api/rulePacks'
import '../../i18n/rulePacks'
import '../../i18n/siteProtection'
import './SiteOfficialPacksCard.css'

/**
 * 官方系统规则包（rule_packs layer=system）及其对本站的实际生效状态（平台→租户→站点继承后），只读说明。
 * 与规则包页同一接口 GET /v1/rule-packs?level=site&object_id=<站点>。
 * 独立于本站 WAF 规则库，组头只写“对本站生效 x/y”，逐包列表默认收起。
 */
export function SiteOfficialPacksCard({ siteId, accessToken }: { siteId: string; accessToken: string }) {
  const { t } = useTranslation('siteProtection')
  const [open, setOpen] = useState(false)
  const listID = useId()
  const query = useQuery({
    queryKey: ['site-protection', siteId, 'official-rule-packs'],
    retry: false,
    queryFn: () => rulePacksApi.view(accessToken, 'site', siteId),
  })
  // 每个官方包按本站实际生效状态（effect.enabled，三态继承解析后）显示；inherit 到系统默认关闭的包即“未生效”。
  const packs = (query.data?.packs ?? []).filter((pack) => pack.layer === 'system')
  const activeCount = packs.filter((pack) => pack.effect?.enabled).length
  // 组头给出 已生效/总数；条目只标出与多数不同的状态，两者各半时没有多数，逐条标出。
  const majority = activeCount * 2 === packs.length ? null : activeCount * 2 > packs.length
  // 默认每包一行（名称、当前动作、差异状态），完整说明（匹配条件、阈值、误报、来源与许可证）在展开详情里。
  const items = packs.map((pack) => {
    const enabled = Boolean(pack.effect?.enabled)
    const action = pack.effect?.params.action ?? pack.defaults?.action
    return {
      key: pack.pack_id,
      label: <strong className="site-official-pack-name">{pack.name}</strong>,
      extra: <span className="site-official-pack-meta">
        {typeof action === 'string' ? <span>{t('waf.officialPacks.action', { action: t(`params.values.${action}`, { ns: 'rulePacks', defaultValue: action }) })}</span> : null}
        {enabled === majority ? null : <Tag color={enabled ? 'success' : 'default'}>{t(enabled ? 'waf.officialPacks.active' : 'waf.officialPacks.inactive')}</Tag>}
      </span>,
      children: <p className="site-official-pack-desc">{pack.description}</p>,
      ...(pack.description ? {} : { collapsible: 'disabled' as const, showArrow: false }),
    }
  })
  return <section className="site-protection-section site-protection-section--waf" aria-labelledby="site-waf-official-packs-title">
    <div className="site-protection-section-head"><div><h2 id="site-waf-official-packs-title">{t('waf.officialPacks.title')}</h2><span>{t('waf.officialPacks.hint')}</span></div>
      {packs.length > 0 ? <div className="site-official-packs-head"><Tag className="site-official-packs-summary">{t('waf.officialPacks.summary', { active: activeCount, total: packs.length })}</Tag>
        <Button size="small" type="link" aria-expanded={open} aria-controls={listID} onClick={() => setOpen((value) => !value)}>
          {open ? t('waf.officialPacks.hide') : t('waf.officialPacks.show', { count: packs.length })}</Button></div> : null}</div>
    {query.isPending ? null : query.isError ? <p role="status">{t('waf.officialPacks.loadFailed')}</p>
      : packs.length === 0 ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('waf.officialPacks.none')} />
        : <div id={listID} hidden={!open}><Collapse className="site-official-packs" size="small" aria-label={t('waf.officialPacks.title')} items={items} /></div>}
  </section>
}
