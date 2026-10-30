import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, App, Button, Space, Switch, Table, Tag, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

import { marketSupplierApi, type SitePause } from '../../../api/marketSupplier'
import { LoadFailure, Short } from './shared'
import { useErrorText, useTime, useToken, useWrite } from './hooks'

// ADR 0012 §19.4 (ML-24): same-site automatic pauses. Suppliers (canResume)
// see a resume button; the market answers 403 to one that did not switch it on.
// Subscribers see the notice that some of their sites were paused.
export function SitePausesPanel({ canResume }: { canResume: boolean }) {
  const { t } = useTranslation('marketSupplier')
  const { modal } = App.useApp()
  const token = useToken()
  const time = useTime()
  const errorText = useErrorText()
  const [openOnly, setOpenOnly] = useState(true)
  const query = useQuery({ queryKey: ['nodeMarket', 'sitePauses', openOnly], enabled: !!token, retry: false,
    queryFn: () => marketSupplierApi.sitePauses(token, openOnly) })
  const resume = useWrite((p: SitePause) => marketSupplierApi.resumeSitePause(token, p.id), 'sitePauses.resumed')
  const open = (query.data ?? []).filter((p) => !p.released_at)
  return (
    <Space direction="vertical" style={{ width: '100%' }}>
      <Typography.Title level={5}>{t('sitePauses.title')}</Typography.Title>
      <Typography.Text type="secondary">{t('sitePauses.help')}</Typography.Text>
      {!canResume && open.length ? <Alert type="warning" showIcon message={t('sitePauses.buyerNotice')} /> : null}
      <Space><Switch size="small" checked={openOnly} onChange={setOpenOnly} aria-label={t('sitePauses.openOnly')} />{t('sitePauses.openOnly')}</Space>
      {query.error ? <LoadFailure scope={canResume ? 'sell' : 'market'} error={query.error} title={errorText(query.error)} /> : null}
      <Table<SitePause> size="small" rowKey="id" loading={query.isLoading} dataSource={query.data ?? []} pagination={{ pageSize: 20 }}
        locale={{ emptyText: t('sitePauses.empty') }}
        columns={[
          { title: t('sitePauses.site'), dataIndex: 'leaf_site_id', render: (v: string) => <Short value={v} /> },
          { title: t('holds.subscription'), dataIndex: 'root_subscription', render: (v: string) => <Short value={v} /> },
          { title: t('sitePauses.slot'), dataIndex: 'node_pool_ref', render: (v: string) => <Typography.Text code>{v}</Typography.Text> },
          { title: t('sitePauses.count'), key: 'count', render: (_: unknown, p) => `${p.count} / ${p.after_actions}` },
          { title: t('sitePauses.since'), dataIndex: 'since', render: time },
          { key: 'state', render: (_: unknown, p) => p.released_at ? <Tag>{t('sitePauses.released')} {time(p.released_at)}</Tag>
            : canResume ? <Button size="small" type="primary" loading={resume.isPending}
              onClick={() => modal.confirm({ title: t('sitePauses.resumeConfirm'), onOk: () => resume.mutateAsync(p).catch(() => undefined) })}>{t('sitePauses.resume')}</Button>
              : <Tag color="warning">{t('states.paused')}</Tag> },
        ]} />
    </Space>
  )
}
