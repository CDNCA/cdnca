import { useCallback, useEffect, useRef, useState, type Key } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  Button,
  Form,
  Input,
  Modal,
  Radio,
  Result,
  Select,
  Table,
  type TableColumnsType,
} from 'antd'
import { useFeedbackMessage, useFeedback, FeedbackWhen, OutcomeUnknown } from '@cdnca/ui'
import { Check, ChevronLeft, ChevronRight, Plus, Trash2 } from 'lucide-react'
import { Link, useNavigate } from 'react-router-dom'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'

import { ApiError, type Principal } from '../api/auth'
import {
  l2TopologyApi,
  type L2Config,
  type L2ConfigInput,
  type L2Condition,
  type L2ConditionInput,
  type L2Rule,
} from '../api/nodeScheduling'
import { regionsApi } from '../api/nodes'
import { useSessionStore } from '../auth/session'
import { ResourceID } from '../components/ResourceID'
import '../i18n/nodeL2Topology'
import './node-scheduling/messages'
import {
  outcomeUnknown,
  revisionMetadata,
  schedulingError,
  uuidPattern,
  validCodePointLength,
} from './node-scheduling/shared'
import {
  clearL2Retry,
  persistL2Retry,
  restoreL2Retry,
  type L2InventoryAttempt as WriteAttempt,
  type L2RetryOwner,
} from './l2RetryRecord'
import './NodeSchedulingPage.css'
import './NodeL2TopologyPage.css'

type L2Owner = readonly [Principal['scope_kind'], string, string | null, string, number]
type L2Permission = 'read' | 'manage' | 'regions'
type Inventory = 'configuration' | 'conditions'
type L2Item = L2Config | L2Condition
const staleL2Read = new Error('L2 topology session owner changed during read')
const staleL2Write = new Error('L2 topology session owner changed during write')
const ruleFields: L2Rule['field'][] = [
  'host',
  'request_uri',
  'uri',
  'node_country',
  'node_isp',
  'node_province',
  'node_city',
  'node_id',
  'protocol',
]
const ruleOperators: L2Rule['operator'][] = [
  'eq',
  'neq',
  'contains',
  'not_contains',
  'prefix',
  'suffix',
  'regex',
  'not_regex',
]

function l2Owner(principal: Principal, sessionEpoch: number): L2Owner | null {
  if (!uuidPattern.test(principal.scope_id) || !principal.user_id || sessionEpoch <= 0) return null
  if (principal.scope_kind === 'tenant') {
    if (!principal.tenant_id) return null
  } else if (principal.tenant_id !== null) return null
  return [
    principal.scope_kind,
    principal.scope_id,
    principal.tenant_id,
    principal.user_id,
    sessionEpoch,
  ]
}

function l2CanRead(principal: Principal): boolean {
  return (
    principal.permissions.includes('node_scheduling.read') ||
    principal.permissions.includes('platform.admin')
  )
}

function l2CanManage(principal: Principal): boolean {
  return (
    l2CanRead(principal) &&
    (principal.permissions.includes('node_scheduling.manage') ||
      principal.permissions.includes('platform.admin'))
  )
}

function currentL2Access(ownerKey: string, permission: L2Permission): string | null {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (!accessToken || !principal) return null
  const owner = l2Owner(principal, sessionEpoch)
  if (!owner || JSON.stringify(owner) !== ownerKey || !l2CanRead(principal)) return null
  if (permission === 'manage' && !l2CanManage(principal)) return null
  if (
    permission === 'regions' &&
    !principal.permissions.some((value) => ['regions.read', 'platform.admin'].includes(value))
  )
    return null
  return accessToken
}

/** UX-L2-RULE-01: rules read as one sentence, e.g. 域名 等于「a.example」 且 协议 等于「https」. */
function ruleSummary(rules: L2Rule[], l2T: TFunction): string {
  return rules.map((rule) => l2T('conditions.ruleText', {
    field: l2T(`conditions.fields.${rule.field}`), operator: l2T(`conditions.operators.${rule.operator}`), value: rule.value,
  })).join(l2T('conditions.and'))
}

/** A regex rule's value must compile; lookaround and backreferences are refused like the server's RE2. */
function validRulePattern(rule: L2Rule): boolean {
  if (rule.operator !== 'regex' && rule.operator !== 'not_regex') return true
  if (/\(\?<?[=!]|\\[1-9]/.test(rule.value)) return false
  try {
    new RegExp(rule.value)
    return true
  } catch {
    return false
  }
}

function invalidResponse(): ApiError {
  return new ApiError('Invalid API response', 200, 'invalid_response')
}

function validateWriteScope<T extends L2Item>(item: T, expectedScopeID: string): T {
  if (
    !item ||
    !uuidPattern.test(item.id) ||
    item.tenant_scope_id !== expectedScopeID ||
    !Number.isInteger(item.revision) ||
    item.revision < 1
  )
    throw invalidResponse()
  return item
}

function validatePageScope<T extends L2Item>(
  page: { items: T[] },
  expectedScopeID: string,
): { items: T[] } {
  if (!page || !Array.isArray(page.items)) throw invalidResponse()
  page.items.forEach((item) => validateWriteScope(item, expectedScopeID))
  return page
}

const l2IntroKey = 'cdnca.nodeL2Intro'

function readIntroCollapsed(): boolean {
  try {
    return window.localStorage.getItem(l2IntroKey) === 'collapsed'
  } catch {
    return false
  }
}

/** fix-nodehint: what L2 does and how to set it up, expanded the first time, then remembered collapsed. */
function L2Intro() {
  const { t: l2T } = useTranslation('nodeL2Topology')
  // the first view shows it expanded and records that it was seen; later views start collapsed
  const [expanded, setExpanded] = useState(() => !readIntroCollapsed())
  useEffect(() => {
    try {
      window.localStorage.setItem(l2IntroKey, 'collapsed')
    } catch {
      // storage unavailable: the card simply opens expanded again next time
    }
  }, [])
  const list = (group: 'benefits' | 'options' | 'steps', keys: string[]) => (
    <ul className={`node-l2-intro-list node-l2-intro-${group}`}>
      {keys.map((key) => <li key={key}>{l2T(`intro.${group}.${key}`)}</li>)}
    </ul>
  )
  return (
    <section className="node-l2-intro" aria-labelledby="node-l2-intro-title">
      <div className="node-l2-intro-head">
        <h2 id="node-l2-intro-title">{l2T('intro.title')}</h2>
        <Button type="link" size="small" aria-expanded={expanded} aria-controls="node-l2-intro-body"
          onClick={() => setExpanded((value) => !value)}>
          {l2T(expanded ? 'intro.collapse' : 'intro.expand')}
        </Button>
      </div>
      {expanded ? (
        <div id="node-l2-intro-body" className="node-l2-intro-body">
          <div className="node-l2-intro-flow" role="img" aria-label={l2T('intro.flowLabel')}>
            {(['user', 'l1', 'l2', 'origin'] as const).map((hop, index) => (
              <span key={hop} className="node-l2-intro-hop-wrap">
                {index > 0 ? <ChevronRight className="node-l2-intro-arrow" size={16} aria-hidden="true" /> : null}
                <span className={`node-l2-intro-hop node-l2-intro-hop-${hop}`}>{l2T(`intro.flow.${hop}`)}</span>
              </span>
            ))}
            <span className="node-l2-intro-fallback" aria-hidden="true">{l2T('intro.flow.fallback')}</span>
          </div>
          <p>{l2T('intro.what')}</p>
          <div className="node-l2-intro-grid">
            <div>
              <h3>{l2T('intro.benefitsTitle')}</h3>
              {list('benefits', ['share', 'route', 'fallback'])}
            </div>
            <div>
              <h3>{l2T('intro.optionsTitle')}</h3>
              {list('options', ['mode', 'load', 'condition'])}
            </div>
          </div>
          <h3>{l2T('intro.stepsTitle')}</h3>
          <ol className="node-l2-intro-list node-l2-intro-steps">
            {(['node', 'config', 'lineGroup', 'site'] as const).map((key) => <li key={key}>{l2T(`intro.steps.${key}`)}</li>)}
          </ol>
          <p className="node-l2-intro-effect">
            {l2T('intro.effect')} <Link to="/node/line-group">{l2T('intro.stepsLink')}</Link>
          </p>
        </div>
      ) : null}
    </section>
  )
}

export default function NodeL2TopologyPage() {
  const { t } = useTranslation('nodeScheduling')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  if (!accessToken) return null
  const owner = principal ? l2Owner(principal, sessionEpoch) : null
  if (!principal || !owner || !l2CanRead(principal))
    return (
      <Result
        status="403"
        title={t('errors.forbiddenTitle')}
        subTitle={t('errors.forbiddenDescription')}
      />
    )
  const ownerKey = JSON.stringify(owner)
  return (
    <NodeL2TopologyContent
      key={ownerKey}
      principal={principal}
      owner={owner}
      ownerKey={ownerKey}
      canManage={l2CanManage(principal)}
    />
  )
}

function NodeL2TopologyContent({
  principal,
  owner,
  ownerKey,
  canManage,
}: {
  principal: Principal
  owner: L2Owner
  ownerKey: string
  canManage: boolean
}) {
  const { t } = useTranslation('nodeScheduling')
  const { t: l2T } = useTranslation('nodeL2Topology')
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [messageApi, messageContext] = useFeedbackMessage()
  const feedback = useFeedback()
  const active = useRef(true)
  const retryOwner = useRef<L2RetryOwner>([owner[0], owner[1], owner[3]]).current
  const [restored] = useState(() => restoreL2Retry<WriteAttempt>(retryOwner, 'inventory'))
  const stickyUnknown = useRef(Boolean(restored.record))
  const sending = useRef(false)
  const [storageBlocked, setStorageBlocked] = useState(restored.blocked)
  const [readbackAttempt, setReadbackAttempt] = useState<WriteAttempt | null>(
    restored.record?.phase === 'readback' ? restored.record.attempt : null,
  )
  const [readingBack, setReadingBack] = useState(false)
  const queryPrefix = useRef(['node-l2-topology', ...owner] as const).current
  const mutationPrefix = useRef(['node-l2-topology-write', ...owner] as const).current
  const [inventory, setInventory] = useState<Inventory>('configuration')
  const [regionFilter, setRegionFilter] = useState<string | undefined>()
  const [pageSize, setPageSize] = useState(10)
  const [pageIndex, setPageIndex] = useState(0)
  const [selectedKeys, setSelectedKeys] = useState<Key[]>([])
  const [editor, setEditor] = useState<{ inventory: Inventory; item: L2Item | null } | null>(null)
  const [deleteTargets, setDeleteTargets] = useState<L2Item[]>([])
  const [writeAttempt, setWriteAttempt] = useState<WriteAttempt | null>(
    restored.record?.phase === 'unknown' ? restored.record.attempt : null,
  )
  const [writeError, setWriteError] = useState<unknown>(null)
  const [terminalForbidden, setTerminalForbidden] = useState(false)
  const [regionsForbidden, setRegionsForbidden] = useState(false)
  const regionsDenied = useRef(false)
  const [form] = Form.useForm<L2ConfigInput & L2ConditionInput>()
  const [ruleDraft, setRuleDraft] = useState<Partial<L2Rule>>({ value: '' })
  const [rules, setRules] = useState<L2Rule[]>([])
  const [ruleError, setRuleError] = useState(false)
  const [regexError, setRegexError] = useState(false)
  const currentSessionAccess = useCallback(
    (permission: L2Permission) => (active.current ? currentL2Access(ownerKey, permission) : null),
    [ownerKey],
  )
  const clearCache = useCallback(() => {
    queryClient.removeQueries({ queryKey: queryPrefix })
    for (const item of queryClient.getMutationCache().findAll({ mutationKey: mutationPrefix }))
      queryClient.getMutationCache().remove(item)
  }, [mutationPrefix, queryClient, queryPrefix])
  useEffect(() => {
    active.current = true
    return () => {
      active.current = false
      queueMicrotask(() => {
        if (!active.current) clearCache()
      })
    }
  }, [clearCache])
  const denyCurrentOwner = useCallback(() => {
    active.current = false
    setTerminalForbidden(true)
    setEditor(null)
    setDeleteTargets([])
    setWriteAttempt(null)
    setWriteError(null)
    queueMicrotask(clearCache)
  }, [clearCache])
  const readWithAccess = async <T,>(read: (token: string) => Promise<T>): Promise<T> => {
    const token = currentSessionAccess('read')
    if (!token) throw staleL2Read
    try {
      const result = await read(token)
      if (!currentSessionAccess('read')) throw staleL2Read
      return result
    } catch (error) {
      if (!currentSessionAccess('read')) throw staleL2Read
      if (error instanceof ApiError && error.status === 403) denyCurrentOwner()
      throw error
    }
  }
  const configsQuery = useQuery({
    queryKey: [...queryPrefix, 'configuration'],
    queryFn: async () => {
      const result = await readWithAccess(l2TopologyApi.configs)
      return validatePageScope(result, owner[1])
    },
    enabled: !terminalForbidden,
    retry: false,
    refetchOnReconnect: false,
    refetchOnWindowFocus: false,
  })
  const conditionsQuery = useQuery({
    queryKey: [...queryPrefix, 'conditions'],
    queryFn: async () => {
      const result = await readWithAccess(l2TopologyApi.conditions)
      return validatePageScope(result, owner[1])
    },
    enabled: inventory === 'conditions' && !terminalForbidden,
    retry: false,
    refetchOnReconnect: false,
    refetchOnWindowFocus: false,
  })
  const regionsQuery = useQuery({
    queryKey: [...queryPrefix, 'regions'],
    queryFn: async () => {
      const names: string[] = []
      for (let page = 1; ; page += 1) {
        const token = currentSessionAccess('regions')
        if (!token) throw staleL2Read
        try {
          const result = await regionsApi.list(token, { page, page_size: 300 })
          if (!currentSessionAccess('regions')) throw staleL2Read
          names.push(...result.data.map((region) => region.name))
          if (page * 300 >= result.count) return names
        } catch (error) {
          if (!currentSessionAccess('regions')) throw staleL2Read
          if (error instanceof ApiError && error.status === 403) {
            regionsDenied.current = true
            setRegionsForbidden(true)
          }
          throw error
        }
      }
    },
    enabled:
      (editor?.inventory === 'configuration' || (writeAttempt?.kind === 'config' && writeAttempt.input.region !== '')) &&
      !terminalForbidden &&
      !regionsForbidden &&
      principal.permissions.some((permission) =>
        ['regions.read', 'platform.admin'].includes(permission),
      ),
    retry: false,
    refetchOnReconnect: false,
    refetchOnWindowFocus: false,
  })
  const activeQuery = inventory === 'configuration' ? configsQuery : conditionsQuery
  const canReadRegions = principal.permissions.some((permission) =>
    ['regions.read', 'platform.admin'].includes(permission),
  )
  const availableRegionNames = canReadRegions && !regionsForbidden && !regionsQuery.isError
    ? [...new Set((regionsQuery.data ?? []).filter((value) => validCodePointLength(value, 1, 64)))].sort()
    : []
  const canUseRegion = (region: string, id: string | null): boolean => {
    if (typeof region !== 'string' || (region !== '' && !validCodePointLength(region, 1, 64))) return false
    const existing = id ? configsQuery.data?.items.find((item) => item.id === id) : undefined
    if (id && !existing) return false
    if (existing) {
      if (region === existing.region) return true
      if (existing.region && (!currentSessionAccess('regions') || regionsDenied.current || !availableRegionNames.includes(existing.region))) return false
    }
    return region === '' || Boolean(currentSessionAccess('regions') && !regionsDenied.current && availableRegionNames.includes(region))
  }
  useEffect(() => {
    if (!canReadRegions || regionsForbidden)
      queryClient.removeQueries({ queryKey: [...queryPrefix, 'regions'] })
  }, [canReadRegions, regionsForbidden, queryClient, queryPrefix])
  useEffect(() => {
    if (
      [configsQuery.error, conditionsQuery.error].some(
        (error) => error instanceof ApiError && error.status === 403,
      ) &&
      currentSessionAccess('read')
    )
      denyCurrentOwner()
  }, [configsQuery.error, conditionsQuery.error, currentSessionAccess, denyCurrentOwner])
  const reconcileSaved = async (attempt: WriteAttempt) => {
    if (!currentSessionAccess('read') || readingBack) return
    setReadingBack(true)
    try {
      const target = attempt.kind === 'delete'
        ? attempt.inventory
        : attempt.kind === 'condition' ? 'conditions' : 'configuration'
      const result = target === 'configuration'
        ? await readWithAccess(l2TopologyApi.configs)
        : await readWithAccess(l2TopologyApi.conditions)
      if (!currentSessionAccess('read')) return
      validatePageScope<L2Item>(result, owner[1])
      queryClient.setQueryData([...queryPrefix, target], result)
      if (!clearL2Retry(retryOwner, 'inventory', attempt)) {
        setStorageBlocked(true)
        return
      }
      setReadbackAttempt(null)
      setWriteAttempt(null)
      setWriteError(null)
      setSelectedKeys([])
      stickyUnknown.current = false
      messageApi.success(l2T(attempt.kind === 'delete' ? 'notices.deleted' : 'notices.saved'))
    } catch (error) {
      if (currentSessionAccess('read')) setWriteError(error)
    } finally {
      if (currentSessionAccess('read')) setReadingBack(false)
    }
  }
  const writeMutation = useMutation({
    mutationKey: mutationPrefix,
    mutationFn: async (attempt: WriteAttempt) => {
      const token = currentSessionAccess('manage')
      if (!token || (attempt.kind === 'config' && !canUseRegion(attempt.input.region, attempt.id))) throw staleL2Write
      if (attempt.kind === 'delete') {
        for (const target of attempt.targets) {
          const currentToken = currentSessionAccess('manage')
          if (!currentToken) throw staleL2Write
          await (
            attempt.inventory === 'configuration'
              ? l2TopologyApi.removeConfig
              : l2TopologyApi.removeCondition
          )(currentToken, target.id, target.metadata)
          if (!currentSessionAccess('manage')) throw staleL2Write
          stickyUnknown.current = true
        }
      } else {
        const result =
          attempt.kind === 'config'
            ? await l2TopologyApi.saveConfig(token, attempt.id, attempt.input, attempt.metadata)
            : await l2TopologyApi.saveCondition(token, attempt.id, attempt.input, attempt.metadata)
        if (!currentSessionAccess('manage')) throw staleL2Write
        validateWriteScope(result, owner[1])
        if (attempt.id && result.id !== attempt.id) throw invalidResponse()
      }
      if (!currentSessionAccess('manage')) throw staleL2Write
    },
    onSuccess: async (_, attempt) => {
      if (!currentSessionAccess('manage')) return
      setEditor(null)
      setDeleteTargets([])
      if (!persistL2Retry(retryOwner, 'inventory', attempt, 'readback')) {
        setStorageBlocked(true)
        return
      }
      setWriteAttempt(null)
      setReadbackAttempt(attempt)
      setWriteError(null)
      await reconcileSaved(attempt)
    },
    onError: (error, attempt) => {
      if (error === staleL2Write || !currentSessionAccess('manage')) return
      if (error instanceof ApiError && error.status === 403) {
        denyCurrentOwner()
        return
      }
      setWriteError(error)
      if (outcomeUnknown(error) || stickyUnknown.current) {
        stickyUnknown.current = true
        setWriteAttempt(attempt)
      } else if (clearL2Retry(retryOwner, 'inventory', attempt)) setWriteAttempt(null)
      else setStorageBlocked(true)
      setEditor(null)
      setDeleteTargets([])
      void queryClient.invalidateQueries({ queryKey: queryPrefix })
    },
    onSettled: () => { sending.current = false },
    retry: false,
  })
  const writeBlocked = storageBlocked || Boolean(readbackAttempt) || Boolean(writeAttempt) || writeMutation.isPending
  const beginWrite = (attempt: WriteAttempt) => {
    if (!currentSessionAccess('manage') || sending.current || writeBlocked) return
    if (attempt.kind === 'config' && !canUseRegion(attempt.input.region, attempt.id)) return
    if (!persistL2Retry(retryOwner, 'inventory', attempt, 'unknown')) {
      setEditor(null)
      setDeleteTargets([])
      setStorageBlocked(true)
      return
    }
    stickyUnknown.current = false
    sending.current = true
    setWriteError(null)
    writeMutation.mutate(attempt)
  }
  const openEditor = (item: L2Item | null) => {
    if (!currentSessionAccess('manage') || writeBlocked) return
    setEditor({ inventory, item })
    setWriteError(null)
    setRuleError(false)
    setRegexError(false)
    setRuleDraft({ value: '' })
    form.resetFields()
    form.setFieldsValue(
      item ?? { name: '', region: '', remark: '', mode: 'cache', load_method: 'rr' },
    )
    setRules(item && 'rules' in item ? item.rules.map((rule) => ({ ...rule })) : [])
  }
  const regionNames = [
    ...new Set(
      [
        ...availableRegionNames,
        ...(configsQuery.data?.items ?? []).map((item) => item.region),
      ].filter(Boolean),
    ),
  ].sort()
  const originalRegion = editor?.item && 'region' in editor.item ? editor.item.region : undefined
  const regionReadOnly = Boolean(originalRegion && !availableRegionNames.includes(originalRegion))
  const retryRegionAllowed = writeAttempt?.kind !== 'config' || canUseRegion(writeAttempt.input.region, writeAttempt.id)
  const visibleItems: L2Item[] =
    inventory === 'configuration'
      ? (configsQuery.data?.items ?? []).filter(
          (item) => regionFilter === undefined || item.region === regionFilter,
        )
      : (conditionsQuery.data?.items ?? [])
  const pageCount = Math.max(1, Math.ceil(visibleItems.length / pageSize))
  const safePageIndex = Math.min(pageIndex, pageCount - 1)
  const configColumnWidth = canManage ? 'calc((100% - 60px) * 0.16)' : '16%'
  const columns: TableColumnsType<L2Item> = [
    {
      title: l2T('columns.id'),
      width: inventory === 'configuration' ? configColumnWidth : 90,
      render: (_, item) => <ResourceID internalId={item.id} displayId={item.display_id} />,
    },
    { title: l2T('columns.name'), dataIndex: 'name', width: inventory === 'configuration' ? configColumnWidth : undefined },
    ...(inventory === 'configuration'
      ? [
          {
            title: l2T('columns.region'),
            width: configColumnWidth,
            render: (_: unknown, item: L2Item) =>
              'region' in item ? item.region || l2T('values.defaultRegion') : '',
          },
          {
            title: l2T('columns.mode'),
            width: configColumnWidth,
            render: (_: unknown, item: L2Item) =>
              'mode' in item ? l2T(`create.${item.mode}`) : '',
          },
          {
            title: l2T('columns.loadMethod'),
            width: configColumnWidth,
            render: (_: unknown, item: L2Item) =>
              'load_method' in item
                ? l2T(item.load_method === 'rr' ? 'create.roundRobin' : 'create.urlHash')
                : '',
          },
        ]
      : [
          {
            title: l2T('conditions.rules'),
            render: (_: unknown, item: L2Item) => {
              const summary = 'rules' in item ? ruleSummary(item.rules, l2T) : ''
              return <span className="node-l2-rule-summary" title={summary}>{summary}</span>
            },
          },
          { title: l2T('create.note'), dataIndex: 'remark' },
        ]),
    {
      title: l2T('columns.actions'),
      width: inventory === 'configuration' ? undefined : 210,
      align: inventory === 'configuration' ? 'center' : undefined,
      render: (_, item) => (
        <div className={`node-l2-row-actions${inventory === 'configuration' ? ' is-centered' : ''}`}>
          {inventory === 'configuration' ? (
            <Button type="link" onClick={() => navigate(`/node/l2-config/node/${item.id}`)}>
              {l2T('actions.nodes')}
            </Button>
          ) : null}
          {canManage ? (
            <>
              <Button
                type="link"
                disabled={writeBlocked}
                onClick={() => openEditor(item)}
              >
                {l2T('actions.edit')}
              </Button>
              <Button
                type="link"
                disabled={writeBlocked}
                onClick={() => setDeleteTargets([item])}
              >
                {l2T('actions.delete')}
              </Button>
            </>
          ) : null}
        </div>
      ),
    },
  ]
  const submitEditor = () =>
    void form
      .validateFields()
      .then((values) => {
        if (!editor) return
        if (editor.inventory === 'conditions' && rules.length === 0) {
          setRuleError(true)
          return
        }
        const metadata = revisionMetadata('l2-save', editor.item?.revision ?? 0)
        if (editor.inventory === 'configuration')
          beginWrite({
            kind: 'config',
            id: editor.item?.id ?? null,
            input: {
              name: values.name,
              region: values.region,
              remark: values.remark ?? '',
              mode: values.mode,
              load_method: values.load_method,
            },
            metadata,
          })
        else
          beginWrite({
            kind: 'condition',
            id: editor.item?.id ?? null,
            input: { name: values.name, remark: values.remark ?? '', rules },
            metadata,
          })
      })
      .catch(() => undefined)

  if (terminalForbidden)
    return (
      <Result
        status="403"
        title={t('errors.forbiddenTitle')}
        subTitle={t('errors.forbiddenDescription')}
      />
    )
  return (
    <section
      className="node-scheduling-page node-l2-topology-page"
      aria-labelledby="node-l2-topology-title"
    >
      {messageContext}
      <h1 id="node-l2-topology-title">{l2T('title')}</h1>
      <L2Intro />
      <p className="node-l2-topology-usage">
        {l2T('usage')} <Link to="/node/line-group">{l2T('usageLink')}</Link>
      </p>
      <div className="node-l2-topology-tab-row">
        <div className="node-l2-topology-tabs" role="tablist" aria-label={l2T('title')}>
          {(['configuration', 'conditions'] as const).map((tab) => (
            <button
              key={tab}
              type="button"
              role="tab"
              id={`node-l2-tab-${tab}`}
              aria-controls="node-l2-topology-panel"
              aria-selected={inventory === tab}
              className={`node-l2-topology-tab${inventory === tab ? ' is-active' : ''}`}
              onClick={() => {
                setInventory(tab)
                setSelectedKeys([])
                setPageIndex(0)
              }}
            >
              {l2T(`tabs.${tab}`)}
            </button>
          ))}
        </div>
        <div
          className="node-scheduling-toolbar node-l2-topology-toolbar"
          role="toolbar"
          aria-label={l2T('title')}
        >
          {canManage ? (
            <>
              <Button
                className="node-l2-topology-create"
                type="primary"
                icon={<Plus size={15} />}
                disabled={writeBlocked}
                onClick={() => openEditor(null)}
              >
                {l2T(inventory === 'configuration' ? 'actions.create' : 'conditions.create')}
              </Button>
              <Button
                className="node-l2-topology-delete"
                danger
                icon={<Trash2 size={14} />}
                disabled={writeBlocked}
                onClick={() => {
                  const targets = visibleItems.filter((item) => selectedKeys.includes(item.id))
                  if (!targets.length) {
                    feedback.warning(l2T('remove.selectRequired'))
                    return
                  }
                  setDeleteTargets(targets)
                }}
              >
                {l2T('actions.delete')}
              </Button>
            </>
          ) : null}
          {inventory === 'configuration' ? (
            <Select
              className="node-l2-topology-region-filter"
              aria-label={l2T('filters.region')}
              allowClear
              placeholder={l2T('filters.allRegions')}
              value={regionFilter}
              options={[
                { value: '', label: l2T('values.defaultRegion') },
                ...regionNames.map((value) => ({ value, label: value })),
              ]}
              virtual={false}
              listHeight={200}
              classNames={{
                popup: { root: 'node-l2-topology-select-popup node-l2-topology-region-popup' },
              }}
              onChange={(value) => {
                setRegionFilter(value)
                setSelectedKeys([])
                setPageIndex(0)
              }}
            />
          ) : null}
        </div>
      </div>
      {storageBlocked ? (
        <Alert className="node-scheduling-alert" type="error" showIcon
          message={l2T('retry.storageBlocked')} description={l2T('retry.storageBlockedDescription')} />
      ) : readbackAttempt ? (
        <Alert className="node-scheduling-alert" type="warning" showIcon
          message={l2T('retry.readbackPending')} description={l2T('retry.readbackDescription')}
          action={
            <Button loading={readingBack} onClick={() => void reconcileSaved(readbackAttempt)}>
              {l2T('retry.read')}
            </Button>
          } />
      ) : writeAttempt ? (
        <OutcomeUnknown title={t('errors.outcomeUnknown')} detail={<>{t('errors.outcomeUnknownDescription')}{!retryRegionAllowed ? <p>{l2T('retry.regionUnavailable')}</p> : null}</>} action={
            <>
              <Button
                disabled={!canManage || !retryRegionAllowed}
                loading={writeMutation.isPending}
                onClick={() => {
                  if (!currentSessionAccess('manage') || sending.current || storageBlocked || readbackAttempt) return
                  if (writeAttempt.kind === 'config' && !canUseRegion(writeAttempt.input.region, writeAttempt.id)) return
                  if (!persistL2Retry(retryOwner, 'inventory', writeAttempt, 'unknown')) {
                    setStorageBlocked(true)
                    return
                  }
                  sending.current = true
                  writeMutation.mutate(writeAttempt)
                }}
              >
                {t('actions.retrySame')}
              </Button>
              <Button onClick={() => void activeQuery.refetch()}>
                {t('actions.refreshReconcile')}
              </Button>
            </>
          } className="node-scheduling-alert" />
      ) : writeError ? (
        <FeedbackWhen title={t('errors.writeFailed')} detail={schedulingError(writeError, t)} />
      ) : null}
      {activeQuery.error ? (
        <FeedbackWhen title={t('errors.loadFailed')} detail={schedulingError(activeQuery.error, t)} action={<Button onClick={() => void activeQuery.refetch()}>{t('actions.retry')}</Button>} />
      ) : null}
      <div
        id="node-l2-topology-panel"
        role="tabpanel"
        aria-labelledby={`node-l2-tab-${inventory}`}
        className="node-scheduling-table-scroll node-l2-topology-table-scroll"
        data-testid="node-l2-topology-table"
        aria-busy={activeQuery.isLoading}
      >
        <Table<L2Item>
          rowKey="id"
          size="middle"
          className={inventory === 'configuration' ? 'node-l2-configuration-table' : undefined}
          tableLayout={inventory === 'configuration' ? 'fixed' : 'auto'}
          loading={activeQuery.isLoading}
          columns={columns}
          dataSource={visibleItems.slice(safePageIndex * pageSize, (safePageIndex + 1) * pageSize)}
          pagination={false}
          scroll={{ x: 730 }}
          rowSelection={
            canManage
              ? { columnWidth: 60, selectedRowKeys: selectedKeys, onChange: setSelectedKeys }
              : undefined
          }
          locale={{
            emptyText: l2T(regionFilter === undefined ? 'empty.topology' : 'empty.filtered'),
          }}
        />
      </div>
      <div className="node-scheduling-pagination">
        <span className="node-l2-topology-total">
          {l2T('pagination.total', { count: visibleItems.length })}
        </span>
        <Button
          aria-label={t('actions.previous')}
          icon={<ChevronLeft size={16} />}
          disabled={safePageIndex === 0}
          onClick={() => setPageIndex((page) => Math.max(0, page - 1))}
        />
        <span className="node-scheduling-page-number" aria-current="page">
          {safePageIndex + 1}
        </span>
        <span className="node-scheduling-page-label">
          {l2T('pagination.page', { page: safePageIndex + 1, pages: pageCount })}
        </span>
        <Button
          aria-label={t('actions.next')}
          icon={<ChevronRight size={16} />}
          disabled={safePageIndex + 1 >= pageCount}
          onClick={() => setPageIndex((page) => page + 1)}
        />
        <Select
          aria-label={l2T('filters.pageSizeLabel')}
          value={pageSize}
          options={[10, 20, 50].map((value) => ({
            value,
            label: l2T('filters.pageSize', { count: value }),
          }))}
          virtual={false}
          classNames={{
            popup: { root: 'node-l2-topology-select-popup node-l2-topology-page-size-popup' },
          }}
          onChange={(value) => {
            setPageSize(value)
            setPageIndex(0)
          }}
        />
      </div>
      <Modal
        className={`node-l2-topology-create-modal${editor?.inventory === 'conditions' ? ' node-l2-condition-modal' : ''}`}
        width={editor?.inventory === 'conditions' ? 850 : 520}
        open={Boolean(editor)}
        title={l2T(
          editor?.inventory === 'conditions'
            ? editor.item
              ? 'conditions.edit'
              : 'conditions.create'
            : editor?.item
              ? 'create.editTitle'
              : 'create.title',
        )}
        onCancel={() => {
          if (!writeMutation.isPending) setEditor(null)
        }}
        destroyOnHidden
        footer={[
          <Button key="cancel" disabled={writeMutation.isPending} onClick={() => setEditor(null)}>
            {l2T('actions.cancel')}
          </Button>,
          <Button
            key="save"
            type="primary"
            icon={<Check size={14} />}
            loading={writeMutation.isPending}
            onClick={submitEditor}
          >
            {l2T('actions.confirm')}
          </Button>,
        ]}
      >
        <Form
          form={form}
          layout="horizontal"
          labelCol={{ flex: editor?.inventory === 'conditions' ? '70px' : '100px' }}
          wrapperCol={{ flex: 1 }}
          requiredMark={false}
        >
          {editor?.inventory === 'configuration' ? (
            <Form.Item
              name="region"
              label={l2T('create.region')}
              extra={regionReadOnly ? l2T('create.regionReadOnly') : undefined}
              rules={[{
                validator: (_, value: string) => canUseRegion(value, editor?.item?.id ?? null)
                  ? Promise.resolve() : Promise.reject(new Error(l2T('validation.region'))),
              }]}
            >
              <Select
                loading={regionsQuery.isFetching}
                disabled={regionReadOnly}
                placeholder={l2T('create.regionPlaceholder')}
                options={regionReadOnly ? [{ value: originalRegion, label: originalRegion }] : [
                  { value: '', label: l2T('values.defaultRegion') },
                  ...availableRegionNames.map((value) => ({ value, label: value })),
                ]}
              />
            </Form.Item>
          ) : null}
          <Form.Item
            name="name"
            label={l2T('create.name')}
            rules={[
              {
                validator: (_, value: string) =>
                  validCodePointLength(value ?? '', 1, 128)
                    ? Promise.resolve()
                    : Promise.reject(new Error(l2T(
                      editor?.inventory === 'conditions' ? 'conditions.required' : 'create.required',
                    ))),
              },
            ]}
          >
            <Input
              placeholder={l2T(
                editor?.inventory === 'conditions'
                  ? 'conditions.namePlaceholder'
                  : 'create.namePlaceholder',
              )}
            />
          </Form.Item>
          <Form.Item
            name="remark"
            label={l2T('create.note')}
            rules={[
              {
                validator: (_, value: string) =>
                  validCodePointLength(value ?? '', 0, 1024)
                    ? Promise.resolve()
                    : Promise.reject(new Error(l2T('validation.remark'))),
              },
            ]}
          >
            <Input placeholder={l2T('create.notePlaceholder')} />
          </Form.Item>
          {editor?.inventory === 'configuration' ? (
            <>
              <Form.Item name="mode" label={l2T('create.mode')} extra={l2T('create.modeHelp')}>
                <Radio.Group
                  optionType="button"
                  options={[
                    { value: 'cache', label: l2T('create.cache') },
                    { value: 'global', label: l2T('create.global') },
                  ]}
                />
              </Form.Item>
              <Form.Item
                name="load_method"
                label={l2T('create.loadMethod')}
                extra={l2T('create.loadHelp')}
              >
                <Radio.Group
                  optionType="button"
                  options={[
                    { value: 'rr', label: l2T('create.roundRobin') },
                    { value: 'url_hash', label: l2T('create.urlHash') },
                  ]}
                />
              </Form.Item>
              {regionsQuery.error ? (
                <Alert type="warning" showIcon message={l2T('errors.regions')} />
              ) : null}
            </>
          ) : (
            <Form.Item label={l2T('conditions.rules')}>
              <Table<L2Rule & { key: number }>
                size="small"
                dataSource={rules.map((rule, key) => ({ ...rule, key }))}
                pagination={false}
                locale={{ emptyText: l2T('empty.topology') }}
                columns={[
                  {
                    title: l2T('conditions.field'),
                    width: '25%',
                    render: (_, rule) => l2T(`conditions.fields.${rule.field}`),
                  },
                  {
                    title: l2T('conditions.operator'),
                    width: '25%',
                    render: (_, rule) => l2T(`conditions.operators.${rule.operator}`),
                  },
                  { title: l2T('conditions.value'), dataIndex: 'value', width: '25%' },
                  {
                    title: l2T('columns.actions'),
                    width: '25%',
                    render: (_, rule) => (
                      <Button
                        type="link"
                        onClick={() =>
                          setRules((current) => current.filter((_, index) => index !== rule.key))
                        }
                      >
                        {l2T('actions.delete')}
                      </Button>
                    ),
                  },
                ]}
              />
              <div className="node-l2-condition-rule-editor">
                <Select
                  aria-label={l2T('conditions.field')}
                  placeholder={l2T('conditions.fieldPlaceholder')}
                  value={ruleDraft.field}
                  options={ruleFields.map((value) => ({
                    value,
                    label: l2T(`conditions.fields.${value}`),
                  }))}
                  onChange={(field) => setRuleDraft((draft) => ({ ...draft, field }))}
                />
                <Select
                  aria-label={l2T('conditions.operator')}
                  placeholder={l2T('conditions.operatorPlaceholder')}
                  value={ruleDraft.operator}
                  options={ruleOperators.map((value) => ({
                    value,
                    label: l2T(`conditions.operators.${value}`),
                  }))}
                  onChange={(operator) => setRuleDraft((draft) => ({ ...draft, operator }))}
                />
                <Input.TextArea
                  aria-label={l2T('conditions.value')}
                  placeholder={l2T('conditions.valuePlaceholder')}
                  value={ruleDraft.value}
                  rows={3}
                  onChange={(event) =>
                    setRuleDraft((draft) => ({ ...draft, value: event.target.value }))
                  }
                />
                <Button
                  type="link"
                  onClick={() => {
                    if (
                      !ruleDraft.field ||
                      !ruleDraft.operator ||
                      !validCodePointLength(ruleDraft.value ?? '', 1, 1024) ||
                      rules.length >= 32
                    ) {
                      setRuleError(true)
                      return
                    }
                    // L2-REGEX-01: the server (RE2, same meaning on the node's PCRE) is authoritative.
                    if (!validRulePattern(ruleDraft as L2Rule)) {
                      setRuleError(false)
                      setRegexError(true)
                      return
                    }
                    setRules((current) => [...current, ruleDraft as L2Rule])
                    setRuleDraft({ value: '' })
                    setRuleError(false)
                    setRegexError(false)
                  }}
                >
                  {l2T('conditions.add')}
                </Button>
              </div>
              <div className="node-l2-condition-help">{l2T('conditions.help')}</div>
              {rules.length > 0 ? (
                <div className="node-l2-condition-preview" data-testid="l2-condition-preview">
                  {l2T('conditions.preview', { summary: ruleSummary(rules, l2T) })}
                </div>
              ) : null}
              {regexError ? (
                <div role="alert" className="node-l2-topology-scope-error">
                  {l2T('validation.regex')}
                </div>
              ) : null}
              {ruleError ? (
                <div role="alert" className="node-l2-topology-scope-error">
                  {l2T('validation.rules')}
                </div>
              ) : null}
            </Form.Item>
          )}
        </Form>
      </Modal>
      <Modal
        title={l2T('remove.title')}
        open={deleteTargets.length > 0}
        okText={l2T('actions.confirm')}
        cancelText={l2T('actions.cancel')}
        confirmLoading={writeMutation.isPending}
        onCancel={() => {
          if (!writeMutation.isPending) setDeleteTargets([])
        }}
        onOk={() =>
          beginWrite({
            kind: 'delete',
            inventory,
            targets: deleteTargets.map((item) => ({
              id: item.id,
              metadata: revisionMetadata('l2-delete', item.revision),
            })),
          })
        }
      >
        <p>
          {l2T('remove.confirmation', { names: deleteTargets.map((item) => item.name).join('、') })}
        </p>
      </Modal>
    </section>
  )
}
