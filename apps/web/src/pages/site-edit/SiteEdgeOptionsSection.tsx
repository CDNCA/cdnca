import { useState } from 'react'
import { Input, Radio, Select, Switch } from 'antd'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'

import { l2TopologyApi } from '../../api/nodeScheduling'
import { originForwarding, type SiteBasicConfig, type SiteOriginPool } from '../../api/sites'
import '../../i18n/siteEdgeOptions'
import { FormRow, SettingGroup } from './SiteEditFields'

export interface SiteEdgeOptionsSectionProps {
  pool: SiteOriginPool
  basic: SiteBasicConfig
  // admin: platform operators set the default site and the site L2
  // (competitor: 仅管理员可设; the competitor user console has neither).
  admin: boolean
  accessToken: string
  readOnly?: boolean
  basicReadOnly?: boolean
  // performance: 高级设置 → 性能与协议 cards (WebSocket, 搜索引擎回源);
  // other: 高级设置 → 其它 cards. AdvancedSiteTab places both.
  part?: 'performance' | 'other'
  onChange: (value: SiteOriginPool) => void
  onBasicChange: (value: SiteBasicConfig) => void
}

function lines(value: string): string[] {
  return value.split(/[\s,]+/u).map((item) => item.trim()).filter(Boolean)
}

// SiteEdgeOptionsSection: the edge options of the competitor's 高级设置
// (site-backend6, tp-b3c): one card per option, a switch on the right of
// the card title. Bound to the page's basic/origin drafts, saved with the
// page's save button.
export default function SiteEdgeOptionsSection({
  pool, basic, admin, accessToken, readOnly = false, basicReadOnly = false, part = 'other', onChange, onBasicChange,
}: SiteEdgeOptionsSectionProps) {
  const { t } = useTranslation('siteEdgeOptions')
  const update = (changes: Partial<SiteOriginPool>) => onChange({ ...pool, ...changes })
  const l2Mode = pool.l2_mode ?? 'package'
  const configs = useQuery({
    queryKey: ['site-edge-options', 'l2-configs'],
    queryFn: () => l2TopologyApi.configs(accessToken),
    enabled: admin && part === 'other' && l2Mode === 'custom',
  })
  // 搜索引擎回源 is on while it has an origin ('' is off on the wire); the
  // switch opens the address field, switching it off clears the address.
  const searchEngine = pool.search_engine_origin ?? ''
  const [searchEngineOpen, setSearchEngineOpen] = useState(false)
  const searchEngineOn = searchEngine !== '' || searchEngineOpen
  if (part === 'performance') {
    const websocket = originForwarding(pool).websocket
    return <>
      <SettingGroup title={t('fields.websocket')} help={t('short.websocket')} tip={t('help.websocket')}
        extra={<Switch aria-label={t('fields.websocket')} disabled={readOnly} checked={websocket.enabled}
          onChange={(enabled) => update({ websocket: { enabled, allowed_origins: enabled ? websocket.allowed_origins : [] } })} />}>
        {websocket.enabled ? (
          <FormRow label={t('fields.websocketOrigins')} tip={t('help.websocketOrigins')}>
            <Input.TextArea aria-label={t('fields.websocketOrigins')} disabled={readOnly} autoSize={{ minRows: 2, maxRows: 6 }}
              value={websocket.allowed_origins.join('\n')}
              onChange={(event) => update({ websocket: { enabled: true, allowed_origins: lines(event.target.value) } })} />
          </FormRow>
        ) : null}
      </SettingGroup>
      <SettingGroup title={t('fields.searchEngineOrigin')} help={t('short.searchEngineOrigin')} tip={t('help.searchEngineOrigin')}
        extra={<Switch aria-label={t('fields.searchEngineOrigin')} disabled={readOnly} checked={searchEngineOn}
          onChange={(checked) => { setSearchEngineOpen(checked); if (!checked) update({ search_engine_origin: '' }) }} />}>
        {searchEngineOn ? (
          <FormRow label={t('fields.searchEngineAddress')}>
            <Input aria-label={t('fields.searchEngineAddress')} disabled={readOnly} placeholder="192.0.2.10:80"
              value={searchEngine} onChange={(event) => update({ search_engine_origin: event.target.value })} />
          </FormRow>
        ) : null}
      </SettingGroup>
    </>
  }
  return <>
    <SettingGroup title={t('fields.acmePassthrough')} help={t('short.acmePassthrough')} tip={t('help.acmePassthrough')}
      extra={<Switch aria-label={t('fields.acmePassthrough')} disabled={readOnly} checked={pool.acme_passthrough ?? false}
        onChange={(checked) => update({ acme_passthrough: checked })} />} />
    <SettingGroup title={t('fields.responseRealtime')} help={t('short.responseRealtime')} tip={t('help.responseRealtime')}
      extra={<Switch aria-label={t('fields.responseRealtime')} disabled={readOnly} checked={pool.response_buffering === false}
        onChange={(checked) => update({ response_buffering: !checked })} />} />
    <SettingGroup title={t('fields.requestRealtime')} help={t('short.requestRealtime')} tip={t('help.requestRealtime')}
      extra={<Switch aria-label={t('fields.requestRealtime')} disabled={readOnly} checked={pool.request_buffering === false}
        onChange={(checked) => update({ request_buffering: !checked })} />} />
    {admin ? <>
      <SettingGroup title={t('fields.defaultSite')} help={t('short.defaultSite')} tip={t('help.defaultSite')}
        extra={<Switch aria-label={t('fields.defaultSite')} disabled={basicReadOnly} checked={basic.is_default}
          onChange={(checked) => onBasicChange({ ...basic, is_default: checked })} />} />
      <SettingGroup title={t('fields.l2')} tip={t('help.l2')}>
        <FormRow label={t('fields.l2Mode')}>
          <Radio.Group aria-label={t('fields.l2')} disabled={readOnly} value={l2Mode} optionType="button"
            options={(['package', 'off', 'custom'] as const).map((value) => ({ value, label: t(`options.${value}`) }))}
            onChange={(event) => update({ l2_mode: event.target.value, l2_config_id: event.target.value === 'custom' ? pool.l2_config_id ?? null : null })} />
        </FormRow>
        {l2Mode === 'custom' ? (
          <FormRow label={t('fields.l2Config')}>
            <Select aria-label={t('fields.l2Config')} disabled={readOnly} loading={configs.isLoading} style={{ width: 'min(320px, 100%)' }}
              value={pool.l2_config_id ?? undefined} placeholder={t('fields.l2Config')}
              options={(configs.data?.items ?? []).map((config) => ({ value: config.id, label: config.name }))}
              onChange={(id) => update({ l2_config_id: id })} />
          </FormRow>
        ) : null}
      </SettingGroup>
    </> : null}
  </>
}
