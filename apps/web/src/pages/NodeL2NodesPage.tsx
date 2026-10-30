import { useEffect, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  Button,
  Dropdown,
  Form,
  Input,
  InputNumber,
  Modal,
  Result,
  Select,
  Switch,
  Table,
  Tag,
  type TableColumnsType,
} from 'antd'
import { useFeedbackMessage, FeedbackWhen, OutcomeUnknown } from '@cdnca/ui'
import {
  ArrowLeft,
  CheckCircle2,
  ChevronDown,
  CircleHelp,
  Pause,
  Play,
  Plus,
  Trash2,
} from 'lucide-react'
import { useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../api/auth'
import {
  l2TopologyApi,
  type L2Node,
  type L2NodeCandidate,
  type L2NodeInput,
} from '../api/nodeScheduling'
import { useSessionStore } from '../auth/session'
import { ResourceID } from '../components/ResourceID'
import '../i18n/nodeL2Topology'
import './node-scheduling/messages'
import {
  outcomeUnknown,
  revisionMetadata,
  schedulingError,
  uuidPattern,
} from './node-scheduling/shared'
import {
  clearL2Retry,
  persistL2Retry,
  restoreL2Retry,
  type L2NodesAttempt as NodeAttempt,
  type L2RetryOwner,
} from './l2RetryRecord'
import './NodeSchedulingPage.css'
import './NodeL2TopologyPage.css'

export default function NodeL2NodesPage() {
  const { t } = useTranslation('nodeScheduling')
  const principal = useSessionStore((state) => state.principal)
  const token = useSessionStore((state) => state.accessToken)
  const epoch = useSessionStore((state) => state.sessionEpoch)
  const { id = '' } = useParams<{ id: string }>()
  const [params] = useSearchParams()
  if (!token) return null
  if (
    !principal ||
    !uuidPattern.test(principal.scope_id) ||
    !principal.user_id ||
    epoch <= 0 ||
    (principal.scope_kind === 'tenant'
      ? !principal.tenant_id
      : principal.tenant_id !== null) ||
    !principal.permissions.some((permission) =>
      ['node_scheduling.read', 'platform.admin'].includes(permission),
    ) ||
    (params.has('target_scope_id') && params.get('target_scope_id') !== principal.scope_id)
  ) {
    return (
      <Result
        status="403"
        title={t('errors.forbiddenTitle')}
        subTitle={t('errors.forbiddenDescription')}
      />
    )
  }
  if (!uuidPattern.test(id))
    return (
      <Result
        status="error"
        title={t('errors.loadFailed')}
        subTitle={t('errors.node_scheduling_invalid_request')}
      />
    )
  const ownerKey = JSON.stringify([
    principal.scope_kind,
    principal.scope_id,
    principal.tenant_id,
    principal.user_id,
    epoch,
  ])
  return (
    <L2NodesContent
      key={`${ownerKey}:${id}`}
      id={id}
      scopeID={principal.scope_id}
      ownerKey={ownerKey}
    />
  )
}

function L2NodesContent({
  id,
  scopeID,
  ownerKey,
}: {
  id: string
  scopeID: string
  ownerKey: string
}) {
  const { t } = useTranslation('nodeScheduling')
  const { t: l2T } = useTranslation('nodeL2Topology')
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [messageApi, messageContext] = useFeedbackMessage()
  const active = useRef(true)
  const retryOwner = useRef<L2RetryOwner>([
    JSON.parse(ownerKey)[0], scopeID, JSON.parse(ownerKey)[3],
  ]).current
  const [restored] = useState(() => restoreL2Retry<NodeAttempt>(retryOwner, id))
  const stickyUnknown = useRef(Boolean(restored.record))
  const sending = useRef(false)
  const [storageBlocked, setStorageBlocked] = useState(restored.blocked)
  const [readbackAttempt, setReadbackAttempt] = useState<NodeAttempt | null>(
    restored.record?.phase === 'readback' ? restored.record.attempt : null,
  )
  const [readingBack, setReadingBack] = useState(false)
  const queryKey = useRef(['l2-nodes', ownerKey, id] as const).current
  const [denied, setDenied] = useState(false)
  const [availableSearch, setAvailableSearch] = useState('')
  const [configuredSearch, setConfiguredSearch] = useState('')
  const [availableIDs, setAvailableIDs] = useState<string[]>([])
  const [selectedIDs, setSelectedIDs] = useState<string[]>([])
  const [dialog, setDialog] = useState<
    | { kind: 'add' }
    | { kind: 'edit'; item: L2Node }
    | { kind: 'delete' | 'enable' | 'disable'; items: L2Node[] }
    | null
  >(null)
  const [form] = Form.useForm<L2NodeInput>()
  const [attempt, setAttempt] = useState<NodeAttempt | null>(
    restored.record?.phase === 'unknown' ? restored.record.attempt : null,
  )
  const [error, setError] = useState<unknown>(null)
  const access = (manage = false) => {
    const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
    if (
      !active.current ||
      !accessToken ||
      !principal ||
      JSON.stringify([
        principal.scope_kind,
        principal.scope_id,
        principal.tenant_id,
        principal.user_id,
        sessionEpoch,
      ]) !== ownerKey ||
      !principal.permissions.some((permission) =>
        ['node_scheduling.read', 'platform.admin'].includes(permission),
      ) ||
      (manage &&
        !principal.permissions.some((permission) =>
          ['node_scheduling.manage', 'platform.admin'].includes(permission),
        ))
    )
      throw new Error('L2 node session is no longer current')
    return accessToken
  }
  const canManage = Boolean(
    useSessionStore((state) =>
      state.principal?.permissions.some((permission) =>
        ['node_scheduling.manage', 'platform.admin'].includes(permission),
      ),
    ),
  )
  const validResource = (resource: { id: string; tenant_scope_id: string; revision: number }) => {
    if (
      !resource ||
      !uuidPattern.test(resource.id) ||
      resource.tenant_scope_id !== scopeID ||
      !Number.isInteger(resource.revision) ||
      resource.revision < 1
    )
      throw new ApiError('Invalid L2 resource', 200, 'invalid_response')
  }
  const denyCurrentOwner = () => {
    active.current = false
    setDenied(true)
    setDialog(null)
    queueMicrotask(() => queryClient.removeQueries({ queryKey }))
  }
  const readNodes = async () => {
    try {
      const config = await l2TopologyApi.config(access(), id)
      access()
      validResource(config)
      if (config.id !== id) throw new ApiError('Invalid L2 resource', 200, 'invalid_response')
      const [configured, available, conditions, configs] = await Promise.all([
        l2TopologyApi.nodes(access(), id),
        l2TopologyApi.availableNodes(access(), id),
        l2TopologyApi.conditions(access()),
        l2TopologyApi.configs(access()),
      ])
      access()
      if (
        ![configured.items, available.items, conditions.items, configs.items].every(Array.isArray)
      )
        throw new ApiError('Invalid L2 resources', 200, 'invalid_response')
      configured.items.forEach((node) => {
        validResource(node)
        if (node.config_id !== id) throw new ApiError('Invalid L2 node', 200, 'invalid_response')
      })
      conditions.items.forEach(validResource)
      configs.items.forEach(validResource)
      if (available.items.some((node) => !uuidPattern.test(node.node_id)))
        throw new ApiError('Invalid L2 candidate', 200, 'invalid_response')
      return {
        config,
        configured: configured.items,
        available: available.items,
        conditions: conditions.items,
        configs: configs.items,
      }
    } catch (failure) {
      access()
      if (failure instanceof ApiError && failure.status === 403) denyCurrentOwner()
      throw failure
    }
  }
  const query = useQuery({
    queryKey,
    queryFn: readNodes,
    enabled: !denied,
    retry: false,
    refetchOnReconnect: false,
    refetchOnWindowFocus: false,
  })
  useEffect(() => {
    active.current = true
    return () => {
      active.current = false
      queueMicrotask(() => {
        if (active.current) return
        queryClient.removeQueries({ queryKey })
        for (const mutation of queryClient.getMutationCache().findAll({ mutationKey: queryKey }))
          queryClient.getMutationCache().remove(mutation)
      })
    }
  }, [queryClient, queryKey])
  useEffect(() => {
    if (query.error instanceof ApiError && query.error.status === 403) {
      active.current = false
      setDenied(true)
      setDialog(null)
      queryClient.removeQueries({ queryKey })
    }
  }, [query.error, queryClient, queryKey])
  const reconcileSaved = async (write: NodeAttempt) => {
    if (readingBack) return
    try { access() } catch { return }
    setReadingBack(true)
    try {
      const result = await readNodes()
      access()
      queryClient.setQueryData(queryKey, result)
      if (!clearL2Retry(retryOwner, id, write)) {
        setStorageBlocked(true)
        return
      }
      setReadbackAttempt(null)
      setAttempt(null)
      setError(null)
      setAvailableIDs([])
      setSelectedIDs([])
      stickyUnknown.current = false
      messageApi.success(l2T('notices.saved'))
    } catch (failure) {
      try { access(); setError(failure) } catch { /* A stale or denied owner cannot publish results. */ }
    } finally {
      try { access(); setReadingBack(false) } catch { /* Keep the departed owner untouched. */ }
    }
  }
  const mutation = useMutation({
    mutationKey: queryKey,
    mutationFn: async (write: NodeAttempt) => {
      if (write.kind === 'add') {
        const result = await l2TopologyApi.addNodes(
          access(true),
          { config_id: id, node_ids: write.nodeIDs, condition_id: write.conditionID },
          write.metadata,
        )
        access(true)
        if (!Array.isArray(result.items) || result.items.length !== write.nodeIDs.length)
          throw new ApiError('Invalid L2 add result', 200, 'invalid_response')
        result.items.forEach((node) => {
          validResource(node)
          if (node.config_id !== id || !write.nodeIDs.includes(node.node_id))
            throw new ApiError('Invalid L2 node', 200, 'invalid_response')
        })
      } else if (write.kind === 'update' || write.kind === 'batchUpdate') {
        for (const target of write.kind === 'update' ? [write] : write.targets) {
          const result = await l2TopologyApi.saveNode(
            access(true),
            target.id,
            target.input,
            target.metadata,
          )
          access(true)
          validResource(result)
          if (result.id !== target.id || result.config_id !== id)
            throw new ApiError('Invalid L2 node', 200, 'invalid_response')
          stickyUnknown.current = true
        }
      } else {
        for (const target of write.targets) {
          await l2TopologyApi.removeNode(access(true), target.id, target.metadata)
          access(true)
          stickyUnknown.current = true
        }
      }
      access(true)
    },
    onSuccess: async (_, write) => {
      try {
        access(true)
      } catch {
        return
      }
      setDialog(null)
      if (!persistL2Retry(retryOwner, id, write, 'readback')) {
        setStorageBlocked(true)
        return
      }
      setAttempt(null)
      setReadbackAttempt(write)
      setError(null)
      await reconcileSaved(write)
    },
    onError: (failure, write) => {
      if (!active.current) return
      try {
        access(true)
      } catch {
        return
      }
      if (failure instanceof ApiError && failure.status === 403) {
        denyCurrentOwner()
        return
      }
      setError(failure)
      setDialog(null)
      if (outcomeUnknown(failure) || stickyUnknown.current) {
        stickyUnknown.current = true
        setAttempt(write)
      } else if (clearL2Retry(retryOwner, id, write)) setAttempt(null)
      else setStorageBlocked(true)
      void queryClient.invalidateQueries({ queryKey })
    },
    onSettled: () => { sending.current = false },
    retry: false,
  })
  const write = (value: NodeAttempt) => {
    try { access(true) } catch { return }
    if (canManage && !mutation.isPending && !sending.current && !attempt && !readbackAttempt && !storageBlocked) {
      if (!persistL2Retry(retryOwner, id, value, 'unknown')) {
        setDialog(null)
        setStorageBlocked(true)
        return
      }
      stickyUnknown.current = false
      sending.current = true
      setError(null)
      mutation.mutate(value)
    }
  }
  const search = (node: L2NodeCandidate, term: string) =>
    [node.name, node.ip_address, node.display_id].some((value) =>
      value.toLocaleLowerCase().includes(term.trim().toLocaleLowerCase()),
    )
  const available = (query.data?.available ?? []).filter((node) => search(node, availableSearch))
  const configured = (query.data?.configured ?? []).filter((node) => search(node, configuredSearch))
  const selected = configured.filter((node) => selectedIDs.includes(node.id))
  const busy = mutation.isPending || Boolean(attempt) || Boolean(readbackAttempt) || storageBlocked
  const configs = query.data?.configs ?? []
  const region = query.data?.config.region ?? ''
  const columns: TableColumnsType<L2NodeCandidate> = [
    { title: l2T('columns.name'), dataIndex: 'name' },
    { title: l2T('nodes.ip'), dataIndex: 'ip_address' },
  ]
  if (denied)
    return (
      <Result
        status="403"
        title={t('errors.forbiddenTitle')}
        subTitle={t('errors.forbiddenDescription')}
      />
    )
  return (
    <section className="node-scheduling-page node-l2-topology-page node-l2-nodes-page">
      {messageContext}
      <header className="node-l2-nodes-header">
        <Button
          type="text"
          icon={<ArrowLeft size={16} />}
          onClick={() => navigate('/node/l2-config')}
        >
          {t('actions.back')}
        </Button>
        <label>
          {l2T('filters.region')}
          <Select
            aria-label={l2T('filters.region')}
            value={region}
            options={[...new Set(configs.map((item) => item.region))].map((value) => ({
              value,
              label: value || l2T('values.defaultRegion'),
            }))}
            onChange={(value) => {
              const first = configs.find((item) => item.region === value)
              if (first) navigate(`/node/l2-config/node/${first.id}`)
            }}
          />
        </label>
        <label>
          {l2T('nodes.configuration')}
          <Select
            aria-label={l2T('nodes.configuration')}
            value={id}
            options={configs
              .filter((item) => item.region === region)
              .map((item) => ({ value: item.id, label: item.name }))}
            onChange={(value) => navigate(`/node/l2-config/node/${value}`)}
          />
        </label>
      </header>
      {query.error ? (
        <FeedbackWhen title={t('errors.loadFailed')} detail={schedulingError(query.error, t)} action={<Button onClick={() => void query.refetch()}>{t('actions.retry')}</Button>} />
      ) : null}
      {storageBlocked ? (
        <Alert type="error" message={l2T('retry.storageBlocked')}
          description={l2T('retry.storageBlockedDescription')} />
      ) : readbackAttempt ? (
        <Alert type="warning" message={l2T('retry.readbackPending')}
          description={l2T('retry.readbackDescription')}
          action={
            <Button loading={readingBack} onClick={() => void reconcileSaved(readbackAttempt)}>
              {l2T('retry.read')}
            </Button>
          } />
      ) : attempt ? (
        <OutcomeUnknown title={t('errors.outcomeUnknown')} action={
            <Button
              disabled={!canManage}
              loading={mutation.isPending}
              onClick={() => {
                try { access(true) } catch { return }
                if (sending.current || storageBlocked || readbackAttempt) return
                if (!persistL2Retry(retryOwner, id, attempt, 'unknown')) {
                  setStorageBlocked(true)
                  return
                }
                sending.current = true
                mutation.mutate(attempt)
              }}
            >
              {t('actions.retrySame')}
            </Button>
          } />
      ) : error ? (
        <FeedbackWhen title={t('errors.writeFailed')} detail={schedulingError(error, t)} />
      ) : null}
      <div className="node-l2-nodes-panes">
        <section>
          <h2>
            <CircleHelp size={16} />
            {l2T('nodes.available')}
          </h2>
          <div className="node-scheduling-toolbar">
            <Button
              type="primary"
              icon={<Plus size={14} />}
              disabled={!canManage || !availableIDs.length || availableIDs.length > 512 || busy}
              onClick={() => {
                form.setFieldsValue({ condition_id: null })
                setDialog({ kind: 'add' })
              }}
            >
              {l2T('nodes.add')}
            </Button>
            <Input.Search
              aria-label={l2T('nodes.availableSearch')}
              placeholder={l2T('nodes.search')}
              value={availableSearch}
              onChange={(event) => {
                setAvailableSearch(event.target.value)
                setAvailableIDs([])
                if (dialog?.kind === 'add') setDialog(null)
              }}
            />
          </div>
          <Table<L2NodeCandidate>
            rowKey="node_id"
            columns={columns}
            dataSource={available}
            loading={query.isLoading}
            pagination={false}
            scroll={{ x: 480 }}
            rowSelection={{
              selectedRowKeys: availableIDs,
              onChange: (keys) => setAvailableIDs(keys.map(String)),
              getCheckboxProps: () => ({ disabled: !canManage || busy }),
            }}
            locale={{ emptyText: l2T('empty.topology') }}
          />
        </section>
        <section>
          <h2>
            <CheckCircle2 size={16} />
            {l2T('nodes.configured')}
          </h2>
          <div className="node-scheduling-toolbar">
            <Button
              type="primary"
              className="l2-enable"
              icon={<Play size={12} />}
              disabled={!canManage || !selected.length || busy}
              onClick={() => setDialog({ kind: 'enable', items: selected })}
            >
              {l2T('nodes.enable')}
            </Button>
            <Button
              type="primary"
              className="l2-disable"
              icon={<Pause size={12} />}
              disabled={!canManage || !selected.length || busy}
              onClick={() => setDialog({ kind: 'disable', items: selected })}
            >
              {l2T('nodes.disable')}
            </Button>
            <Button
              type="primary"
              danger
              icon={<Trash2 size={14} />}
              disabled={!canManage || !selected.length || busy}
              onClick={() => setDialog({ kind: 'delete', items: selected })}
            >
              {l2T('actions.delete')}
            </Button>
            <Dropdown
              trigger={['click']}
              disabled={!canManage || selected.length !== 1 || busy}
              menu={{
                items: [{ key: 'edit', label: l2T('nodes.edit') }],
                onClick: () => {
                  const item = selected[0]
                  if (item) {
                    form.setFieldsValue(item)
                    setDialog({ kind: 'edit', item })
                  }
                },
              }}
            >
              <Button>
                {t('lineDetail.actions.more')}
                <ChevronDown size={12} />
              </Button>
            </Dropdown>
            <Input.Search
              aria-label={l2T('nodes.configuredSearch')}
              placeholder={l2T('nodes.search')}
              value={configuredSearch}
              onChange={(event) => {
                setConfiguredSearch(event.target.value)
                setSelectedIDs([])
                if (dialog && dialog.kind !== 'add') setDialog(null)
              }}
            />
          </div>
          <Table<L2Node>
            rowKey="id"
            dataSource={configured}
            loading={query.isLoading}
            pagination={false}
            scroll={{ x: 600 }}
            rowSelection={{
              selectedRowKeys: selectedIDs,
              onChange: (keys) => setSelectedIDs(keys.map(String)),
              getCheckboxProps: () => ({ disabled: !canManage || busy }),
            }}
            locale={{ emptyText: l2T('empty.topology') }}
            columns={[
              {
                title: l2T('columns.id'),
                render: (_, node) => (
                  <ResourceID internalId={node.id} displayId={node.display_id} />
                ),
              },
              {
                title: l2T('nodes.conditionColumn'),
                render: (_, node) => node.condition_name ?? l2T('nodes.allRequests'),
              },
              {
                title: l2T('nodes.node'),
                render: (_, node) => (
                  <div className="node-l2-node-name">
                    {canManage ? (
                      <Button
                        type="link"
                        aria-label={`${l2T('actions.edit')} ${node.name}`}
                        disabled={busy}
                        onClick={() => {
                          form.setFieldsValue(node)
                          setDialog({ kind: 'edit', item: node })
                        }}
                      >
                        {node.name}
                      </Button>
                    ) : (
                      node.name
                    )}
                    <small>{node.ip_address}</small>
                  </div>
                ),
              },
              {
                title: l2T('nodes.state'),
                render: (_, node) => (
                  <Tag
                    color={node.enabled && node.online_status === 'online' ? 'success' : 'default'}
                  >
                    {l2T(node.enabled ? `nodes.${node.online_status}` : 'nodes.no')}
                  </Tag>
                ),
              },
              { title: l2T('nodes.weight'), dataIndex: 'weight' },
              { title: l2T('nodes.sort'), dataIndex: 'sort' },
            ]}
          />
        </section>
      </div>
      <Modal
        title={l2T(
          dialog?.kind === 'add'
            ? 'nodes.selectCondition'
            : dialog?.kind === 'delete'
              ? 'remove.title'
              : dialog?.kind === 'edit'
                ? 'nodes.edit'
                : 'line.confirmTitle',
        )}
        open={Boolean(dialog)}
        confirmLoading={mutation.isPending}
        okText={l2T('actions.confirm')}
        cancelText={l2T('actions.cancel')}
        onCancel={() => {
          if (!mutation.isPending) setDialog(null)
        }}
        onOk={() => {
          if (!dialog) return
          if (dialog.kind === 'delete') {
            write({
              kind: 'delete',
              targets: dialog.items.map((node) => ({
                id: node.id,
                metadata: revisionMetadata('l2-node-delete', node.revision),
              })),
            })
            return
          }
          if (dialog.kind === 'enable' || dialog.kind === 'disable') {
            write({
              kind: 'batchUpdate',
              targets: dialog.items.map((node) => ({
                id: node.id,
                input: {
                  condition_id: node.condition_id,
                  enabled: dialog.kind === 'enable',
                  weight: node.weight,
                  sort: node.sort,
                },
                metadata: revisionMetadata('l2-node-status', node.revision),
              })),
            })
            return
          }
          void form
            .validateFields()
            .then((values) => {
              if (dialog.kind === 'add')
                write({
                  kind: 'add',
                  nodeIDs: availableIDs.filter((nodeID) =>
                    query.data?.available.some((node) => node.node_id === nodeID),
                  ),
                  conditionID: values.condition_id ?? null,
                  metadata: revisionMetadata('l2-node-add', 0),
                })
              else if (dialog.kind === 'edit')
                write({
                  kind: 'update',
                  id: dialog.item.id,
                  input: {
                    condition_id: values.condition_id ?? null,
                    enabled: values.enabled,
                    weight: values.weight,
                    sort: values.sort,
                  },
                  metadata: revisionMetadata('l2-node-edit', dialog.item.revision),
                })
            })
            .catch(() => undefined)
        }}
      >
        {dialog && ['delete', 'enable', 'disable'].includes(dialog.kind) && 'items' in dialog ? (
          <p>
            {l2T(dialog.kind === 'delete' ? 'remove.confirmation' : 'nodes.confirm', {
              names: dialog.items.map((node) => node.name).join('、'),
            })}
          </p>
        ) : (
          <Form form={form} layout="vertical">
            <Form.Item name="condition_id" label={l2T('nodes.condition')}>
              <Select
                allowClear
                placeholder={l2T('nodes.allRequests')}
                options={(query.data?.conditions ?? []).map((condition) => ({
                  value: condition.id,
                  label: condition.name,
                }))}
              />
            </Form.Item>
            {dialog?.kind === 'add' ? (
              <p className="node-l2-condition-help">{l2T('nodes.conditionHelp')}</p>
            ) : null}
            {dialog?.kind === 'edit' ? (
              <>
                <Form.Item name="enabled" valuePropName="checked" label={l2T('nodes.enabled')}>
                  <Switch />
                </Form.Item>
                <Form.Item
                  name="weight"
                  label={l2T('nodes.weight')}
                  rules={[
                    {
                      required: true,
                      type: 'number',
                      min: 1,
                      max: 100,
                      message: l2T('nodes.weightValidation'),
                    },
                  ]}
                >
                  <InputNumber min={1} max={100} precision={0} />
                </Form.Item>
                <Form.Item
                  name="sort"
                  label={l2T('nodes.sort')}
                  rules={[
                    {
                      required: true,
                      type: 'number',
                      min: 0,
                      max: 999999,
                      message: l2T('nodes.sortValidation'),
                    },
                  ]}
                >
                  <InputNumber min={0} max={999999} precision={0} />
                </Form.Item>
              </>
            ) : null}
          </Form>
        )}
      </Modal>
    </section>
  )
}
