import { useQuery } from '@tanstack/react-query'
import { Modal, Select } from 'antd'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { dnsPlatformApi } from '../api/dnsPlatform'
import { regionsApi } from '../api/nodes'
import { nodeSchedulingApi } from '../api/nodeScheduling'
import type { BatchStreamActionValue } from '../api/streams'
import { useSessionStore } from '../auth/session'

export type StreamOverrideAction = 'cname_domain' | 'cname_mode' | 'line_group'

// 更多操作（平台）三个弹窗：修改CNAME域名（域名）、修改CNAME生成模式（模式）、
// 修改线路分组（区域 / 线路分组 / 备用线路组）。选项来自 DNS配置的 CNAME 域名、平台区域与
// 平台线路组；「跟随套餐」清除转发自己的值。
// fix-smallbatch 5：frozen = 结果未知的那次请求。弹窗回显它的选值并禁用输入（与设置状态弹窗一致），
// 确定即按原请求重试（onSubmit 原样交回 frozen）。
export default function StreamOverrideModal({ action, busy, frozen, onCancel, onSubmit }: {
  action: StreamOverrideAction | null
  busy: boolean
  frozen?: BatchStreamActionValue | null
  onCancel: () => void
  onSubmit: (value: BatchStreamActionValue) => void
}) {
  const { t } = useTranslation('streams')
  const principal = useSessionStore((state) => state.principal)
  const [domain, setDomain] = useState<string>()
  const [mode, setMode] = useState<'' | 'site' | 'package'>()
  const [region, setRegion] = useState<string>()
  const [group, setGroup] = useState<string>()
  const [backup, setBackup] = useState<string>()
  const held = frozen && frozen.action === action ? frozen : null
  const shown = held?.action === 'cname_domain' ? { domain: held.cname_domain }
    : held?.action === 'cname_mode' ? { mode: held.cname_mode }
      : held?.action === 'line_group' ? { region: held.region_id, group: held.node_group_id, backup: held.backup_node_group_id }
        : { domain, mode, region, group, backup }
  const resources = useQuery({
    queryKey: ['stream-override-resources', principal?.scope_id, action],
    queryFn: async () => {
      const token = useSessionStore.getState().accessToken ?? ''
      if (action === 'cname_domain') {
        const domains: string[] = []
        for (let page = 1; ; page += 1) {
          const result = await dnsPlatformApi.zones(token, { page, limit: 100, search: '' })
          domains.push(...result.items.map((zone) => zone.name.toLowerCase()))
          if (page * 100 >= result.total || result.items.length === 0) break
        }
        return { cname_domains: [...new Set(domains)].sort(), regions: [], node_groups: [] }
      }
      const regions: Array<{ id: string; name: string }> = []
      for (let page = 1; ; page += 1) {
        const result = await regionsApi.list(token, { page, page_size: 300 })
        regions.push(...result.data.map((item) => ({ id: item.id, name: item.name })))
        if (page * 300 >= result.count || result.data.length === 0) break
      }
      const groups = await nodeSchedulingApi.list(token, { kind: 'platform', targetScopeId: principal?.scope_id ?? '' })
      // A line group's region is a region name or ID; an ambiguous one is not filtered by region.
      const node_groups = groups.items.map((item) => {
        const matches = regions.filter((region) => region.id === item.region || region.name === item.region)
        return { id: item.id, name: item.name, region_id: matches.length === 1 ? matches[0]!.id : null }
      })
      return { cname_domains: [], regions, node_groups }
    },
    enabled: (action === 'cname_domain' || action === 'line_group') && Boolean(principal),
    retry: false,
  })
  const inherit = { value: '', label: t('overrideModal.inherit') }
  const groups = (resources.data?.node_groups ?? []).filter((item) => !shown.region || item.region_id === shown.region)
    .map((item) => ({ value: item.id, label: item.name }))
  const notFound = resources.isError ? t('errors.requestFailed') : undefined
  const ready = held ? true : action === 'cname_domain' ? domain !== undefined
    : action === 'cname_mode' ? mode !== undefined
      : !backup || Boolean(group)
  const submit = () => {
    if (held) onSubmit(held)
    else if (action === 'cname_domain') onSubmit({ action, cname_domain: domain ?? '' })
    else if (action === 'cname_mode') onSubmit({ action, cname_mode: mode ?? '' })
    else if (action === 'line_group') {
      onSubmit({ action, ...(region ? { region_id: region } : {}), ...(group ? { node_group_id: group } : {}),
        ...(group && backup ? { backup_node_group_id: backup } : {}) })
    }
  }
  return (
    <Modal
      className="identity-modal stream-status-modal"
      title={action ? t(`overrideModal.${action}Title`) : ''}
      open={action !== null}
      width={420}
      okText={t('form.confirm')}
      cancelText={t('actions.cancel')}
      confirmLoading={busy}
      okButtonProps={{ disabled: !ready }}
      onOk={submit}
      onCancel={() => { if (!busy) onCancel() }}
      afterClose={() => { setDomain(undefined); setMode(undefined); setRegion(undefined); setGroup(undefined); setBackup(undefined) }}
      destroyOnHidden
    >
      {action === 'cname_domain' ? <label className="stream-status-field">{t('overrideModal.domain')}
        <Select aria-label={t('overrideModal.domain')} placeholder={t('filters.selectPlaceholder')} value={shown.domain} onChange={setDomain} disabled={Boolean(held)}
          loading={resources.isFetching} notFoundContent={notFound}
          options={[inherit, ...(resources.data?.cname_domains ?? []).map((item) => ({ value: item, label: item }))]} />
      </label> : null}
      {action === 'cname_mode' ? <label className="stream-status-field">{t('overrideModal.mode')}
        <Select aria-label={t('overrideModal.mode')} placeholder={t('filters.selectPlaceholder')} value={shown.mode} onChange={setMode} disabled={Boolean(held)}
          options={[inherit, { value: 'site', label: t('overrideModal.modeSite') }, { value: 'package', label: t('overrideModal.modePackage') }]} />
      </label> : null}
      {action === 'line_group' ? <>
        <label className="stream-status-field">{t('overrideModal.region')}
          <Select aria-label={t('overrideModal.region')} placeholder={t('filters.selectPlaceholder')} allowClear value={shown.region} disabled={Boolean(held)}
            loading={resources.isFetching} notFoundContent={notFound} onChange={(value) => { setRegion(value); setGroup(undefined); setBackup(undefined) }}
            options={(resources.data?.regions ?? []).map((item) => ({ value: item.id, label: item.name }))} />
        </label>
        <label className="stream-status-field">{t('overrideModal.lineGroup')}
          <Select aria-label={t('overrideModal.lineGroup')} placeholder={t('overrideModal.inherit')} allowClear value={shown.group} disabled={Boolean(held)}
            loading={resources.isFetching} notFoundContent={notFound} options={groups}
            onChange={(value) => { setGroup(value); if (value === backup) setBackup(undefined) }} />
        </label>
        <label className="stream-status-field">{t('overrideModal.backupLineGroup')}
          <Select aria-label={t('overrideModal.backupLineGroup')} placeholder={t('filters.selectPlaceholder')} allowClear value={shown.backup}
            disabled={Boolean(held) || !shown.group} options={groups.filter((item) => item.value !== group)} onChange={setBackup} />
        </label>
      </> : null}
    </Modal>
  )
}
