import { useMemo, useState } from 'react'
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App as AntApp, Button, Collapse, Form, Input, Radio, Select, Space, Table, Tag, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../api/auth'
import { nodesApi } from '../api/nodes'
import {
  createGatewayAddressStepUp, gatewayAddressChangeComplete, nodeGatewayAddressApi, validGatewayAddress, validServerName,
  type GatewayAddressChange, type GatewayAddressNodeStatus, type GatewayAddressTargetKind,
} from '../api/nodeGatewayAddress'
import { formatDateTime } from '../i18n/formatters'
import {
  gatewayAddressErrorMessage, gatewayAddressRequestMessage, gatewayAddressStateMessage, maintenanceUpgradeFormat,
  maintenanceUpgradeMessage,
} from '../i18n/maintenanceUpgrade'

interface FormValues {
  address: string
  server_name: string
  target_kind: GatewayAddressTargetKind
  region?: string
  node_ids?: string[]
  code: string
}

const stateColor: Record<string, string> = {
  pending: 'default', delivered: 'default', probing: 'processing', switched: 'success', failed: 'error', superseded: 'default',
}

const totpPattern = /^[0-9]{6}$/

function requestError(error: unknown, language: string): string {
  return gatewayAddressRequestMessage(language, error instanceof ApiError ? error.code : '')
}

// 维护升级 → 节点设置「更换主控连接地址」(fix-nodegw): the form sends one
// signed change per node; the history lists each node's state and lets an
// administrator retry the failed ones.
export default function NodeGatewayAddressPanel({ accessToken, canRead, canManage }: {
  accessToken: string
  canRead: boolean
  canManage: boolean
}) {
  const { i18n } = useTranslation()
  const language = i18n.resolvedLanguage ?? 'zh-CN'
  const mt = (key: Parameters<typeof maintenanceUpgradeMessage>[1]) => maintenanceUpgradeMessage(language, key)
  const { message } = AntApp.useApp()
  const queryClient = useQueryClient()
  const [form] = Form.useForm<FormValues>()
  const targetKind = Form.useWatch('target_kind', form) ?? 'all'
  const [retryCodes, setRetryCodes] = useState<Record<string, string>>({})

  const changesQuery = useQuery({
    queryKey: ['node-gateway-address-changes', accessToken],
    queryFn: () => nodeGatewayAddressApi.list(accessToken),
    enabled: canRead,
    refetchInterval: 15000,
    retry: false,
  })
  const nodesQuery = useInfiniteQuery({
    queryKey: ['node-gateway-address-nodes', accessToken],
    queryFn: ({ pageParam }) => nodesApi.list(accessToken, { limit: 100, cursor: pageParam }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last, _pages, _lastParam, pageParams) =>
      last.next_cursor && !pageParams.includes(last.next_cursor) ? last.next_cursor : undefined,
    enabled: canRead && canManage,
    retry: false,
  })
  const nodes = useMemo(() => (nodesQuery.data?.pages ?? []).flatMap((page) => page.items), [nodesQuery.data])
  const regions = useMemo(() => [...new Set(nodes.map((node) => node.region).filter(Boolean))].sort(), [nodes])

  const refresh = () => queryClient.invalidateQueries({ queryKey: ['node-gateway-address-changes'] })
  const create = useMutation({
    mutationFn: async (values: FormValues) => {
      const stepUp = await createGatewayAddressStepUp(accessToken, values.code)
      return nodeGatewayAddressApi.create(accessToken, {
        address: values.address.trim(), server_name: (values.server_name ?? '').trim(), target_kind: values.target_kind,
        ...(values.target_kind === 'region' ? { region: values.region } : {}),
        ...(values.target_kind === 'nodes' ? { node_ids: values.node_ids } : {}),
      }, stepUp)
    },
    onSuccess: (change) => {
      message.success(maintenanceUpgradeFormat(language, 'gatewayAddressSubmitted', { count: change.node_count }))
      form.resetFields(['code'])
      void refresh()
    },
    onError: (error) => message.error(requestError(error, language)),
  })
  const retry = useMutation({
    mutationFn: async ({ id, code }: { id: string; code: string }) =>
      nodeGatewayAddressApi.retry(accessToken, id, await createGatewayAddressStepUp(accessToken, code)),
    onSuccess: (result, { id }) => {
      message.success(maintenanceUpgradeFormat(language, 'gatewayAddressRetried', { count: result.retried }))
      setRetryCodes((codes) => ({ ...codes, [id]: '' }))
      void refresh()
      void queryClient.invalidateQueries({ queryKey: ['node-gateway-address-change', id] })
    },
    onError: (error) => message.error(requestError(error, language)),
  })

  const changes = changesQuery.data?.items ?? []
  const open = changes.find((change) => !gatewayAddressChangeComplete(change.counts))
  const latest = changes[0]

  return <section className="maintenance-gateway-address" aria-labelledby="gateway-address-title">
    <h3 id="gateway-address-title">{mt('gatewayAddressTitle')}</h3>
    <p className="maintenance-gateway-address-intro">{mt('gatewayAddressIntro')}</p>
    {open
      ? <Alert type="warning" showIcon message={mt('gatewayAddressKeepOld')} />
      : latest && <Alert type="success" showIcon message={mt('gatewayAddressAllDone')} />}
    {canManage ? <Form<FormValues> form={form} layout="vertical" className="maintenance-gateway-address-form" requiredMark={false}
      initialValues={{ target_kind: 'all', address: '', server_name: '', code: '' }}
      onFinish={(values) => create.mutate(values)}>
      <div className="maintenance-gateway-address-fields">
        <Form.Item name="address" label={mt('gatewayAddressAddress')} extra={mt('gatewayAddressAddressHelp')}
          rules={[{ validator: (_, value: string) => validGatewayAddress(value ?? '') ? Promise.resolve() : Promise.reject(new Error(mt('gatewayAddressAddressInvalid'))) }]}>
          <Input autoComplete="off" spellCheck={false} placeholder={mt('gatewayAddressPlaceholder')} />
        </Form.Item>
        <Form.Item name="server_name" label={mt('gatewayAddressServerName')} extra={mt('gatewayAddressServerNameHelp')}
          rules={[{ validator: (_, value: string) => validServerName(value ?? '') ? Promise.resolve() : Promise.reject(new Error(mt('gatewayAddressServerNameInvalid'))) }]}>
          <Input autoComplete="off" spellCheck={false} placeholder={mt('gatewayAddressServerNamePlaceholder')} />
        </Form.Item>
      </div>
      <Form.Item name="target_kind" label={mt('gatewayAddressTarget')}>
        <Radio.Group optionType="button" options={[
          { value: 'all', label: mt('gatewayAddressTargetAll') },
          { value: 'region', label: mt('gatewayAddressTargetRegion') },
          { value: 'nodes', label: mt('gatewayAddressTargetNodes') },
        ]} />
      </Form.Item>
      {targetKind === 'region' && <Form.Item name="region" label={mt('gatewayAddressRegion')}
        rules={[{ required: true, message: mt('gatewayAddressRegionRequired') }]}>
        <Select aria-label={mt('gatewayAddressRegion')} loading={nodesQuery.isLoading} options={regions.map((region) => ({ value: region, label: region }))} />
      </Form.Item>}
      {targetKind === 'nodes' && <Form.Item name="node_ids" label={mt('gatewayAddressNodes')}
        rules={[{ required: true, type: 'array', min: 1, message: mt('gatewayAddressNodesRequired') }]}>
        <Select aria-label={mt('gatewayAddressNodes')} mode="multiple" loading={nodesQuery.isLoading} optionFilterProp="label"
          options={nodes.map((node) => ({ value: node.id, label: `${node.display_id} ${node.name}${node.region ? ` · ${node.region}` : ''}` }))} />
      </Form.Item>}
      <div className="maintenance-gateway-address-submit">
        <Form.Item name="code" label={mt('gatewayAddressCode')} extra={mt('gatewayAddressCodeHelp')}
          rules={[{ pattern: totpPattern, required: true, message: mt('gatewayAddressCodeInvalid') }]}>
          <Input inputMode="numeric" autoComplete="one-time-code" maxLength={6} />
        </Form.Item>
        <Button type="primary" htmlType="submit" loading={create.isPending}>{mt('gatewayAddressSubmit')}</Button>
      </div>
    </Form> : <Typography.Paragraph type="secondary">{mt('gatewayAddressReadOnly')}</Typography.Paragraph>}

    <h4 className="maintenance-gateway-address-history-title">{mt('gatewayAddressHistory')}</h4>
    {changesQuery.isError ? <Alert type="error" showIcon message={requestError(changesQuery.error, language)} />
      : changes.length === 0 ? <Typography.Paragraph type="secondary">{mt('gatewayAddressEmpty')}</Typography.Paragraph>
        : <Collapse className="maintenance-gateway-address-history" items={changes.map((change) => ({
          key: change.id,
          label: <ChangeSummary change={change} language={language} />,
          children: <ChangeNodes accessToken={accessToken} change={change} language={language} canManage={canManage}
            code={retryCodes[change.id] ?? ''} onCode={(code) => setRetryCodes((codes) => ({ ...codes, [change.id]: code }))}
            retrying={retry.isPending && retry.variables?.id === change.id}
            onRetry={() => retry.mutate({ id: change.id, code: retryCodes[change.id] ?? '' })} />,
        }))} />}
  </section>
}

function ChangeSummary({ change, language }: { change: GatewayAddressChange; language: string }) {
  const mt = (key: Parameters<typeof maintenanceUpgradeMessage>[1]) => maintenanceUpgradeMessage(language, key)
  const total = change.node_count - change.counts.superseded
  const target = change.target_kind === 'region' ? `${mt('gatewayAddressTargetRegion')} ${change.region ?? ''}`
    : change.target_kind === 'nodes' ? mt('gatewayAddressTargetNodes') : mt('gatewayAddressTargetAll')
  return <span className="maintenance-gateway-address-summary">
    <code>{change.address}</code>
    {change.server_name !== change.address.replace(/:[0-9]+$/, '') && <span>SNI {change.server_name}</span>}
    <span>{target}</span>
    <span>{total === 0 ? gatewayAddressStateMessage(language, 'superseded')
      : maintenanceUpgradeFormat(language, 'gatewayAddressSummary', { switched: change.counts.switched, total })}</span>
    {change.counts.failed > 0 && <Tag color="error">{gatewayAddressStateMessage(language, 'failed')} {change.counts.failed}</Tag>}
    <span className="maintenance-gateway-address-time">{formatDateTime(change.created_at, language)}</span>
  </span>
}

function ChangeNodes({ accessToken, change, language, canManage, code, onCode, retrying, onRetry }: {
  accessToken: string
  change: GatewayAddressChange
  language: string
  canManage: boolean
  code: string
  onCode: (code: string) => void
  retrying: boolean
  onRetry: () => void
}) {
  const mt = (key: Parameters<typeof maintenanceUpgradeMessage>[1]) => maintenanceUpgradeMessage(language, key)
  const detail = useQuery({
    queryKey: ['node-gateway-address-change', change.id],
    queryFn: () => nodeGatewayAddressApi.get(accessToken, change.id),
    refetchInterval: gatewayAddressChangeComplete(change.counts) ? false : 10000,
    retry: false,
  })
  if (detail.isError) return <Alert type="error" showIcon message={requestError(detail.error, language)} />
  return <>
    {canManage && change.counts.failed > 0 && <Space className="maintenance-gateway-address-retry" wrap>
      <Input aria-label={mt('gatewayAddressRetryCode')} placeholder={mt('gatewayAddressRetryCode')} inputMode="numeric"
        autoComplete="one-time-code" maxLength={6} value={code} onChange={(event) => onCode(event.target.value)} />
      <Button onClick={onRetry} loading={retrying} disabled={!totpPattern.test(code)}>{mt('gatewayAddressRetry')}</Button>
    </Space>}
    <Table<GatewayAddressNodeStatus> size="small" rowKey="node_id" scroll={{ x: 720 }} loading={detail.isLoading} pagination={{ pageSize: 20, hideOnSinglePage: true }}
      dataSource={detail.data?.nodes ?? []} columns={[
        { title: mt('gatewayAddressColumnNode'), key: 'node', render: (_, node) => `${node.display_id} ${node.name}` },
        { title: mt('gatewayAddressColumnRegion'), dataIndex: 'region' },
        {
          title: mt('gatewayAddressColumnState'), key: 'state', render: (_, node) => <Space direction="vertical" size={2}>
            <Tag color={stateColor[node.state]}>{gatewayAddressStateMessage(language, node.state)}</Tag>
            {node.state === 'failed' && node.error_code && <Typography.Text type="danger">{gatewayAddressErrorMessage(language, node.error_code)}</Typography.Text>}
          </Space>,
        },
        { title: mt('gatewayAddressColumnActive'), key: 'active', render: (_, node) => node.active_address ? <code>{node.active_address}</code> : '—' },
        { title: mt('gatewayAddressColumnUpdated'), key: 'updated', render: (_, node) => formatDateTime(node.updated_at, language) },
      ]} />
  </>
}
