import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Card, List, Space, Table, Tag, Typography, type TableColumnsType } from 'antd'
import { useFeedbackMessage, useFeedback } from '@cdnca/ui'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import {
  RulePackConflictError, disableInput, rulePacksApi,
  type Conflict, type NodeRule, type Remedy, type Resolution,
} from '../../api/rulePacks'
import { localizedUnknownApiError } from '../../i18n/apiError'
import '../../i18n/rulePacks'

function ruleAction(rule: NodeRule): string {
  if (rule.waf) return `${rule.waf.action} / ${rule.waf.flow}`
  if (rule.cc) return rule.cc.action.kind
  if (rule.crs) return `crs ${rule.crs.action} PL${rule.crs.paranoia}`
  return '—'
}

// RulePackSitePanel shows a site's live resolution (final order, conflicts
// with "disable at level" remedies, warnings) next to what is published,
// and publishes it. endUser: a customer's own account (no "租户" wording).
export default function RulePackSitePanel({ accessToken, siteID, canManage, onChanged, endUser = false }: {
  accessToken: string
  siteID: string
  canManage: boolean
  onChanged: () => void
  endUser?: boolean
}) {
  const { t } = useTranslation('rulePacks')
  const queryClient = useQueryClient()
  const [messageApi, messageContext] = useFeedbackMessage()
  const feedback = useFeedback()
  const query = useQuery({ queryKey: ['rule-pack-site', siteID], queryFn: () => rulePacksApi.site(accessToken, siteID) })
  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ['rule-pack-site', siteID] })
    onChanged()
  }
  const publish = useMutation({
    mutationFn: () => rulePacksApi.publish(accessToken, siteID),
    onSuccess: () => { void messageApi.success(t('notices.published')); refresh() },
    onError: (error) => {
      if (error instanceof RulePackConflictError) {
        void feedback.error(t('notices.conflict'))
        queryClient.setQueryData(['rule-pack-site', siteID], (old: typeof query.data) => old && { ...old, resolution: error.resolution })
        return
      }
      void feedback.error(localizedUnknownApiError(error, t('notices.failed')))
    },
  })
  const remedy = useMutation({
    mutationFn: (item: Remedy) => rulePacksApi.putOverride(accessToken, disableInput(item)),
    onSuccess: () => { void messageApi.success(t('notices.saved')); refresh() },
    onError: (error) => void feedback.error(error instanceof ApiError && error.code === 'rule_pack_locked'
      ? t('notices.locked') : localizedUnknownApiError(error, t('notices.failed'))),
  })
  const data = query.data
  const resolution: Resolution | undefined = data?.resolution
  const levelName = (level: string) => t(`${endUser ? 'tenantLevels' : 'levels'}.${level}`)
  const columns: TableColumnsType<NodeRule> = [
    { title: t('site.position'), key: 'position', width: 56, render: (_, __, index) => index + 1 },
    { title: t('columns.layer'), dataIndex: 'layer', width: 90, render: (value: string) => <Tag>{t(`layers.${value}`)}</Tag> },
    { title: t('columns.priority'), dataIndex: 'priority', width: 80 },
    { title: t('columns.pack'), dataIndex: 'pack_id', render: (value: string, rule) => <span><code>{value}</code> <small>{rule.version}</small></span> },
    { title: t('site.rule'), dataIndex: 'rule_id', render: (value: string, rule) => <span>{rule.name} <small><code>{value}</code></small></span> },
    { title: t('columns.engine'), dataIndex: 'engine', width: 110 },
    { title: t('site.action'), key: 'action', render: (_, rule) => ruleAction(rule) },
  ]
  const conflictItem = (item: Conflict, actions: boolean) => <List.Item>
    <Space direction="vertical" size={4} style={{ width: '100%' }}>
      <Typography.Text strong>{t(`conflictCodes.${item.code}`, { defaultValue: item.code })}</Typography.Text>
      <Space wrap>{item.sides.map((side) => <Tag key={`${side.pack_id}/${side.rule_id ?? ''}`}>
        {side.pack_id}{side.rule_id ? ` / ${side.rule_id}` : ''} · {t('values.from', { level: levelName(side.enabled_at.level) })}
      </Tag>)}</Space>
      {actions && canManage ? <Space wrap>{item.remedies.map((entry) => <Button key={`${entry.action}-${entry.at.level}-${entry.pack_id}-${entry.rule_id ?? ''}`}
        size="small" danger loading={remedy.isPending} onClick={() => remedy.mutate(entry)}>
        {t(endUser ? 'site.switchOffAt' : 'site.disableAt', { level: levelName(entry.at.level), target: entry.rule_id ? `${entry.pack_id} / ${entry.rule_id}` : entry.pack_id })}
      </Button>)}</Space> : null}
    </Space>
  </List.Item>
  return <Card size="small" title={t('site.order')} loading={query.isPending} extra={canManage
    ? <Button type="primary" disabled={!resolution?.security || data?.up_to_date} loading={publish.isPending} onClick={() => publish.mutate()}>{t('site.publish')}</Button>
    : null}>
    {messageContext}
    {data ? <Space direction="vertical" style={{ width: '100%' }}>
      <Typography.Text type="secondary">{t('site.orderHint')}</Typography.Text>
      <Space wrap>
        <Tag color={data.published ? 'blue' : 'default'}>{data.published ? t('site.published', { revision: data.published.revision }) : t('site.unpublished')}</Tag>
        <Tag color={data.up_to_date ? 'success' : 'warning'}>{t(data.up_to_date ? 'site.upToDate' : 'site.pending')}</Tag>
        {resolution?.security ? <Typography.Text code>{t('site.digest', { digest: resolution.security.resolved_sha256.slice(0, 16) })}</Typography.Text> : null}
        {resolution ? <Typography.Text type="secondary">{t('values.cost', resolution.cost)}</Typography.Text> : null}
      </Space>
      {resolution && resolution.conflicts.length > 0 ? <Alert type="error" showIcon message={t('site.conflicts', { count: resolution.conflicts.length })}
        description={<List size="small" dataSource={resolution.conflicts} renderItem={(item) => conflictItem(item, true)} />} /> : null}
      {resolution && resolution.warnings.length > 0 ? <Alert type="warning" showIcon message={t('site.warnings', { count: resolution.warnings.length })}
        description={<List size="small" dataSource={resolution.warnings} renderItem={(item) => conflictItem(item, false)} />} /> : null}
      <Table rowKey="node_id" size="small" columns={columns} dataSource={resolution?.rules ?? []} pagination={false} />
    </Space> : null}
  </Card>
}
