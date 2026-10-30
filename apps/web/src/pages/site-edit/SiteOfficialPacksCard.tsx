import { useQuery } from '@tanstack/react-query'
import { Empty, Tag, Tooltip } from 'antd'
import { useTranslation } from 'react-i18next'

import { rulePacksApi } from '../../api/rulePacks'
import '../../i18n/siteProtection'
import './SiteOfficialPacksCard.css'

/**
 * 官方系统规则包（rule_packs layer=system）及其对本站的实际生效状态（平台→租户→站点继承后），只读说明。
 * 与规则包页同一接口 GET /v1/rule-packs?level=site&object_id=<站点>。
 */
export function SiteOfficialPacksCard({ siteId, accessToken }: { siteId: string; accessToken: string }) {
  const { t } = useTranslation('siteProtection')
  const query = useQuery({
    queryKey: ['site-protection', siteId, 'official-rule-packs'],
    retry: false,
    queryFn: () => rulePacksApi.view(accessToken, 'site', siteId),
  })
  // 每个官方包按本站实际生效状态（effect.enabled，三态继承解析后）显示；inherit 到系统默认关闭的包即“未生效”。
  const packs = (query.data?.packs ?? []).filter((pack) => pack.layer === 'system')
  const activeCount = packs.filter((pack) => pack.effect?.enabled).length
  // 等宽卡片网格：名称+状态一行，说明最多两行，全文悬浮看。
  return <section className="site-protection-section site-protection-section--waf" aria-labelledby="site-waf-official-packs-title">
    <div className="site-protection-section-head"><div><h2 id="site-waf-official-packs-title">{t('waf.officialPacks.title')}</h2><span>{t('waf.officialPacks.hint')}</span></div>
      {packs.length > 0 ? <Tag className="site-official-packs-summary">{t('waf.officialPacks.summary', { active: activeCount, total: packs.length })}</Tag> : null}</div>
    {query.isPending ? null : query.isError ? <p role="status">{t('waf.officialPacks.loadFailed')}</p>
      : packs.length === 0 ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('waf.officialPacks.none')} />
        : <ul className="site-official-packs-grid" aria-label={t('waf.officialPacks.title')}>{packs.map((pack) => <li key={pack.pack_id} className="site-official-pack">
          <div className="site-official-pack-head"><strong>{pack.name}</strong>
            <Tag color={pack.effect?.enabled ? 'success' : 'default'}>{t(pack.effect?.enabled ? 'waf.officialPacks.active' : 'waf.officialPacks.inactive')}</Tag></div>
          {pack.description ? <Tooltip title={pack.description} placement="topLeft"><p className="site-official-pack-desc">{pack.description}</p></Tooltip> : null}
        </li>)}</ul>}
  </section>
}
