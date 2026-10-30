import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  Button,
  Checkbox,
  Descriptions,
  Drawer,
  Form,
  Input,
  Modal,
  Popconfirm,
  Result,
  Select,
  Space,
  Spin,
  Table,
  Tag,
  type TableColumnsType,
} from 'antd'
import { useFeedback, useFeedbackMessage, useFormSubmitError, FeedbackWhen, OutcomeUnknown, TimeRangeFilter, type TimeRangeValue } from '@cdnca/ui'
import { Check, ChevronLeft, ChevronRight, Clipboard, Eye, Play, Plus, RefreshCw, RotateCw, Send, ShieldOff } from 'lucide-react'
import dayjs from 'dayjs'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'
import { useSearchParams } from 'react-router-dom'

import { ApiError, type Principal } from '../../api/auth'
import {
  newPluginWebhookIdempotencyKey,
  pluginWebhookDomainEventTypes,
  pluginWebhookEventType,
  pluginWebhooksApi,
  type PluginWebhookCreateInput,
  type PluginWebhookDelivery,
  type PluginWebhookDeliveryReceipt,
  type PluginWebhookReplayRangeResult,
  type PluginWebhookRotationReceipt,
  type PluginWebhookSubscription,
  type PluginWebhookSubscriptionReceipt,
  type PluginWebhookSubscriptionResult,
} from '../../api/pluginWebhooks'
import { useSessionStore } from '../../auth/session'
import { formatDateTime } from '../../i18n/formatters'
import { localizedUnknownApiError } from '../../i18n/apiError'
import '../../i18n/pluginWebhooks'

import './PluginWebhooksPage.css'

interface CreateFormValues {
  name: string
  target_url: string
  event_types: PluginWebhookCreateInput['event_types']
  installation_authorization_id?: string
  site_ids?: string
}

interface ReplayRangeFormValues {
  failed_only?: boolean
}

// 按时间重放：默认今天（结束裁到当前时刻），后端单批最长 31 天；选定时即固定窗口，同一窗口重试复用同一幂等键。
const replayRangeMaxSpanMs = 31 * 24 * 3600 * 1000
// 今天 00:00 到当前分钟末（结束不落未来，与组件 maxDate 裁剪同口径）。
function todayUntilNow(): [dayjs.Dayjs, dayjs.Dayjs] {
  const now = dayjs()
  return [now.startOf('day'), now.startOf('minute').add(1, 'minute')]
}

// Site-bound events (a subscription with a site filter receives only these).
const siteBoundEventTypes = new Set<string>(['io.cdnca.site.v1.updated', 'io.cdnca.security.v1.incident_detected'])
const siteIDListPattern = /^\s*[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(\s*[,\s]\s*[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})*\s*$/i

function parseSiteIDs(value: string | undefined): string[] | undefined {
  const items = (value ?? '').split(/[\s,]+/).map((item) => item.trim().toLowerCase()).filter(Boolean)
  return items.length > 0 ? Array.from(new Set(items)) : undefined
}

interface CreateAttempt {
  kind: 'create'
  scopeID: string
  key: string
}

type ActionKind = 'test' | 'replay' | 'rotate' | 'activate' | 'revoke'

interface ActionAttempt {
  kind: ActionKind
  scopeID: string
  subscriptionID: string
  key: string
}

type ActionRequest =
  | { kind: 'test' }
  | { kind: 'replay'; deliveryID: string }
  | { kind: 'rotate'; revision: number }
  | { kind: 'activate' }
  | { kind: 'revoke'; revision: number }

type ActionReceipt =
  | { kind: 'test' | 'replay'; receipt: PluginWebhookDeliveryReceipt }
  | { kind: 'rotate'; receipt: PluginWebhookRotationReceipt }
  | { kind: 'activate' | 'revoke'; receipt: PluginWebhookSubscriptionResult }

type SecretReceipt =
  | { kind: 'create'; ownerKey: string; scopeID: string; subscription: PluginWebhookSubscription; secret: string }
  | { kind: 'rotate'; ownerKey: string; scopeID: string; subscriptionID: string; receipt: PluginWebhookRotationReceipt }

interface ScopedActionError {
  ownerKey: string
  scopeID: string
  text: string
}

interface OwnedSelection {
  ownerKey: string
  scopeID: string
  subscription: PluginWebhookSubscription
}

interface OwnedAttempt<T> {
  ownerKey: string
  attempt: T
}

interface PendingRotation {
  subscriptionID: string
  rotationID: string
  revision: number
}

interface CursorState {
  key: string
  cursors: string[]
}

const scopeIDPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const domainEventLabelKey: Record<typeof pluginWebhookDomainEventTypes[number], string> = {
  'io.cdnca.deployment.v1.status_changed': 'deployment',
  'io.cdnca.site.v1.updated': 'site',
  'io.cdnca.certificate.v1.status_changed': 'certificate',
  'io.cdnca.certificate.v1.expiry_reached': 'certificateExpiry',
  'io.cdnca.node.v1.status_changed': 'node',
  'io.cdnca.usage.v1.threshold_reached': 'usage',
  'io.cdnca.security.v1.incident_detected': 'security',
}

function errorText(error: unknown, t: TFunction<'pluginWebhooks'>): string {
  if (!(error instanceof ApiError)) return t('errors.requestFailed')
  switch (error.code) {
    case 'permission_denied': return t('errors.permissionDenied')
    case 'plugin_webhook_not_found': return t('errors.notFound')
    case 'plugin_webhook_target_forbidden': return t('errors.targetForbidden')
    case 'plugin_webhook_state_conflict': return t('errors.stateConflict')
    case 'plugin_webhook_rotation_pending': return t('errors.rotationPending')
    case 'plugin_webhook_validation_error': return t('errors.validationError')
    case 'idempotency_key_required': return t('errors.idempotencyKeyRequired')
    case 'precondition_required': return t('errors.preconditionRequired')
    case 'revision_conflict': return t('errors.revisionConflict')
    case 'idempotency_conflict': return t('errors.idempotencyConflict')
    case 'idempotency_expired': return t('errors.idempotencyExpired')
    case 'plugin_webhook_delivery_not_replayable': return t('errors.deliveryNotReplayable')
    case 'plugin_webhook_entitlement_denied': return t('errors.entitlementDenied')
    case 'plugin_webhook_quota_exceeded': return t('errors.quotaExceeded')
    case 'plugin_webhook_rate_limited': return t('errors.rateLimited')
    case 'plugin_webhook_secret_unavailable': return t('errors.secretUnavailable')
    case 'plugin_webhook_store_unavailable': return t('errors.storeUnavailable')
    case 'plugin_webhook_result_unknown': return t('errors.resultUnknown')
    default: return localizedUnknownApiError(error, t('errors.requestFailed'))
  }
}

function statusColor(status: PluginWebhookSubscription['status']): string {
  return status === 'active' ? 'green' : 'default'
}

function deliveryColor(status: PluginWebhookDelivery['status']): string {
  if (status === 'delivered') return 'green'
  if (status === 'dead_lettered' || status === 'revoked') return 'red'
  if (status === 'retry_scheduled') return 'orange'
  return 'blue'
}

function copyText(value: string): void {
  if (navigator.clipboard) void navigator.clipboard.writeText(value)
}

function unknownOutcome(error: unknown): boolean {
  if (!(error instanceof ApiError)) return true
  if (error.code === 'plugin_webhook_rate_limited') return false
  if (error.code === 'plugin_webhook_result_unknown') return true
  return error.status === 0 || error.status === 408 || error.status >= 500
}

function pendingRotationKey(ownerKey: string, scopeID: string, subscriptionID: string): string {
  return JSON.stringify([ownerKey, scopeID, subscriptionID])
}

function writeAttemptKey(attempt: CreateAttempt | ActionAttempt): string {
  return JSON.stringify([attempt.kind, attempt.scopeID, 'subscriptionID' in attempt ? attempt.subscriptionID : '', attempt.key])
}

function sessionOwnerKey(principal: Principal, sessionEpoch: number): string {
  return JSON.stringify([
    principal.scope_kind,
    principal.scope_id,
    principal.tenant_id,
    principal.user_id,
    sessionEpoch,
  ])
}

function currentSessionCanManage(expectedOwnerKey: string): boolean {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (!accessToken || !principal || !sessionEpoch) return false
  return sessionOwnerKey(principal, sessionEpoch) === expectedOwnerKey &&
    (principal.permissions.includes('plugin_webhooks.manage') || principal.permissions.includes('platform.admin'))
}

export default function PluginWebhooksPage() {
  const { t } = useTranslation('pluginWebhooks')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const canRead = Boolean(principal && (
    principal.permissions.includes('plugin_webhooks.read') || principal.permissions.includes('platform.admin')
  ))

  if (!accessToken || !principal || !sessionEpoch || !canRead ||
    (principal.scope_kind === 'tenant' && !scopeIDPattern.test(principal.scope_id))) {
    return <Result status="error" icon={<ShieldOff size={72} aria-hidden="true" />} title={t('forbidden.title')} subTitle={t('forbidden.description')} />
  }

  const ownerKey = sessionOwnerKey(principal, sessionEpoch)
  return (
    <PluginWebhooksPageContent
      key={ownerKey}
      accessToken={accessToken}
      principal={principal}
      ownerKey={ownerKey}
    />
  )
}

function PluginWebhooksPageContent({ accessToken, principal, ownerKey }: {
  accessToken: string
  principal: Principal
  ownerKey: string
}) {
  const { t, i18n } = useTranslation('pluginWebhooks')
  const [searchParams, setSearchParams] = useSearchParams()
  const isPlatform = principal.scope_kind === 'platform'
  const permissions = principal.permissions
  const canManage = permissions.includes('plugin_webhooks.manage') || permissions.includes('platform.admin')
  const requestedTargetScope = isPlatform ? (searchParams.get('target_scope_id') ?? '').trim().toLowerCase() : ''
  const initialTargetScope = scopeIDPattern.test(requestedTargetScope) ? requestedTargetScope : ''
  const [targetScopeDraft, setTargetScopeDraft] = useState(requestedTargetScope)
  const [targetScopeID, setTargetScopeID] = useState(initialTargetScope)
  const [targetScopeError, setTargetScopeError] = useState(Boolean(requestedTargetScope && !initialTargetScope))
  const scopeID = isPlatform ? targetScopeID : principal.scope_id
  const queryClient = useQueryClient()
  const [messageApi, messageContext] = useFeedbackMessage()
  const feedback = useFeedback()
  const messageApiRef = useRef(messageApi)
  messageApiRef.current = messageApi
  const [createOpen, setCreateOpen] = useState(false)
  const [selected, setSelected] = useState<OwnedSelection | null>(null)
  const [secretReceipt, setSecretReceipt] = useState<SecretReceipt | null>(null)
  const [pendingRotations, setPendingRotations] = useState<Record<string, PendingRotation>>({})
  const [createAttempt, setCreateAttempt] = useState<OwnedAttempt<CreateAttempt> | null>(null)
  const [attempt, setAttempt] = useState<OwnedAttempt<ActionAttempt> | null>(null)
  const [actionError, setActionError] = useState<ScopedActionError | null>(null)
  const [subscriptionPages, setSubscriptionPages] = useState<CursorState>({ key: '', cursors: [] })
  const [deliveryPages, setDeliveryPages] = useState<CursorState>({ key: '', cursors: [] })
  const [form] = Form.useForm<CreateFormValues>()
  const createResetRef = useRef<() => void>(() => undefined)
  const actionResetRef = useRef<() => void>(() => undefined)
  const accessTokenRef = useRef(accessToken)
  accessTokenRef.current = accessToken
  const mountedRef = useRef(true)
  const ownerKeyRef = useRef(ownerKey)
  const scopeIDRef = useRef(scopeID)
  ownerKeyRef.current = ownerKey
  scopeIDRef.current = scopeID
  const createInputsRef = useRef<Record<string, PluginWebhookCreateInput>>({})
  const createReceiptsRef = useRef<Record<string, PluginWebhookSubscriptionReceipt>>({})
  const actionRequestsRef = useRef<Record<string, ActionRequest>>({})
  const actionReceiptsRef = useRef<Record<string, ActionReceipt>>({})
  const pendingRotationsRef = useRef<Record<string, PendingRotation>>({})
  const writeOwnersRef = useRef<Record<string, string>>({})
  const selectedSubscription = selected?.ownerKey === ownerKey && selected.scopeID === scopeID ? selected.subscription : null
  const subscriptionCursors = subscriptionPages.key === scopeID ? subscriptionPages.cursors : []
  const subscriptionCursor = subscriptionCursors.at(-1)
  const deliveryKey = `${scopeID}:${selectedSubscription?.id ?? ''}`
  const deliveryCursors = deliveryPages.key === deliveryKey ? deliveryPages.cursors : []
  const deliveryCursor = deliveryCursors.at(-1)

  useEffect(() => {
    mountedRef.current = true
    return () => {
      mountedRef.current = false
      createInputsRef.current = {}
      createReceiptsRef.current = {}
      actionRequestsRef.current = {}
      actionReceiptsRef.current = {}
      pendingRotationsRef.current = {}
      writeOwnersRef.current = {}
      messageApiRef.current.destroy()
    }
  }, [])

  const retainPendingRotation = useCallback((targetOwnerKey: string, targetScopeID: string, rotation: PendingRotation) => {
    const next = { ...pendingRotationsRef.current, [pendingRotationKey(targetOwnerKey, targetScopeID, rotation.subscriptionID)]: rotation }
    pendingRotationsRef.current = next
    setPendingRotations(next)
  }, [])

  const clearPendingRotation = useCallback((targetOwnerKey: string, targetScopeID: string, subscriptionID: string) => {
    const key = pendingRotationKey(targetOwnerKey, targetScopeID, subscriptionID)
    if (!(key in pendingRotationsRef.current)) return
    const next = { ...pendingRotationsRef.current }
    delete next[key]
    pendingRotationsRef.current = next
    setPendingRotations(next)
  }, [])

  const subscriptionsQuery = useQuery({
    queryKey: ['plugin-webhook-subscriptions', ownerKey, scopeID, subscriptionCursor],
    queryFn: () => pluginWebhooksApi.listSubscriptions(accessTokenRef.current, scopeID, { limit: 50, cursor: subscriptionCursor }),
    enabled: Boolean(scopeID),
  })
  const detailQuery = useQuery({
    queryKey: ['plugin-webhook-subscription', ownerKey, scopeID, selectedSubscription?.id],
    queryFn: () => pluginWebhooksApi.getSubscription(accessTokenRef.current, scopeID, selectedSubscription!.id),
    enabled: Boolean(scopeID && selectedSubscription),
  })
  const deliveriesQuery = useQuery({
    queryKey: ['plugin-webhook-deliveries', ownerKey, scopeID, selectedSubscription?.id, deliveryCursor],
    queryFn: () => pluginWebhooksApi.listDeliveries(accessTokenRef.current, scopeID, selectedSubscription!.id, { limit: 50, cursor: deliveryCursor }),
    enabled: Boolean(scopeID && selectedSubscription),
  })

  // Replay by time keeps one idempotency key per opened range, so retrying an
  // unknown outcome (or a rate-limited batch) never replays a delivery twice.
  const [replayRange, setReplayRange] = useState<{ subscriptionID: string, key: string, signature: string, result?: PluginWebhookReplayRangeResult } | null>(null)
  const [replayRangeForm] = Form.useForm<ReplayRangeFormValues>()
  const markReplayRangeError = useFormSubmitError(replayRangeForm)
  const [replayWindow, setReplayWindow] = useState<TimeRangeValue>({ preset: 'today', range: null })
  const replayRangeMutation = useMutation({
    gcTime: 0,
    mutationFn: async (next: { subscriptionID: string, key: string, from: string, to: string, failedOnly: boolean }) => {
      if (!currentSessionCanManage(ownerKey)) throw new ApiError('Permission denied', 403, 'permission_denied')
      return pluginWebhooksApi.replayDeliveryRange(accessTokenRef.current, scopeID, next.subscriptionID, {
        from: next.from, to: next.to, limit: 100, ...(next.failedOnly ? { statuses: ['dead_lettered' as const] } : {}),
      }, next.key)
    },
    onSuccess: (result, next) => {
      setReplayRange((current) => current && current.key === next.key ? { ...current, result } : current)
      void queryClient.invalidateQueries({ queryKey: ['plugin-webhook-deliveries', ownerKey, scopeID, next.subscriptionID] })
    },
    onError: (error) => { markReplayRangeError(error, () => feedback.error(errorText(error, t))) },
  })

  const createMutation = useMutation({
    gcTime: 0,
    mutationFn: async (next: CreateAttempt): Promise<void> => {
      const attemptKey = writeAttemptKey(next)
      const attemptOwnerKey = writeOwnersRef.current[attemptKey]
      const input = createInputsRef.current[attemptKey]
      if (!input || !attemptOwnerKey) throw new ApiError('Create request unavailable', 409, 'plugin_webhook_state_conflict')
      if (!currentSessionCanManage(attemptOwnerKey)) throw new ApiError('Permission denied', 403, 'permission_denied')
      delete createReceiptsRef.current[attemptKey]
      const result = await pluginWebhooksApi.createSubscription(accessTokenRef.current, next.scopeID, input, next.key)
      if (mountedRef.current && attemptOwnerKey === ownerKeyRef.current) createReceiptsRef.current[attemptKey] = result
    },
    onSuccess: (_result, next) => {
      const attemptKey = writeAttemptKey(next)
      const attemptOwnerKey = writeOwnersRef.current[attemptKey]
      const receipt = createReceiptsRef.current[attemptKey]
      delete createReceiptsRef.current[attemptKey]
      delete createInputsRef.current[attemptKey]
      delete writeOwnersRef.current[attemptKey]
      setCreateAttempt((current) => current && current.ownerKey === attemptOwnerKey && writeAttemptKey(current.attempt) === attemptKey ? null : current)
      if (!attemptOwnerKey || attemptOwnerKey !== ownerKeyRef.current || !currentSessionCanManage(attemptOwnerKey)) return
      setCreateOpen(false)
      form.resetFields()
      setActionError(null)
      if (next.scopeID === scopeIDRef.current && receipt) {
        setSecretReceipt({ kind: 'create', ownerKey: attemptOwnerKey, scopeID: next.scopeID, subscription: receipt.subscription, secret: receipt.secret })
        messageApi.success(t('notices.created'))
      }
      createResetRef.current()
      actionResetRef.current()
      setSubscriptionPages({ key: next.scopeID, cursors: [] })
      void queryClient.invalidateQueries({ queryKey: ['plugin-webhook-subscriptions', attemptOwnerKey, next.scopeID] })
    },
    onError: (error, next) => {
      const attemptKey = writeAttemptKey(next)
      const attemptOwnerKey = writeOwnersRef.current[attemptKey]
      delete createReceiptsRef.current[attemptKey]
      if (!attemptOwnerKey || attemptOwnerKey !== ownerKeyRef.current) {
        delete createInputsRef.current[attemptKey]
        delete writeOwnersRef.current[attemptKey]
        return
      }
      if (!currentSessionCanManage(attemptOwnerKey)) {
        setCreateAttempt((current) => current && writeAttemptKey(current.attempt) === attemptKey ? null : current)
        delete createInputsRef.current[attemptKey]
        delete writeOwnersRef.current[attemptKey]
        createResetRef.current()
        return
      }
      setActionError({ ownerKey: attemptOwnerKey, scopeID: next.scopeID, text: errorText(error, t) })
      if (unknownOutcome(error)) {
        setCreateAttempt({ ownerKey: attemptOwnerKey, attempt: next })
        if (next.scopeID === scopeIDRef.current) setCreateOpen(false)
      } else {
        setCreateAttempt((current) => current && current.ownerKey === attemptOwnerKey && writeAttemptKey(current.attempt) === attemptKey ? null : current)
        delete createInputsRef.current[attemptKey]
        delete writeOwnersRef.current[attemptKey]
      }
      createResetRef.current()
    },
  })

  const actionMutation = useMutation({
    gcTime: 0,
    mutationFn: async (next: ActionAttempt): Promise<void> => {
      const attemptKey = writeAttemptKey(next)
      const attemptOwnerKey = writeOwnersRef.current[attemptKey]
      const request = actionRequestsRef.current[attemptKey]
      if (!request || request.kind !== next.kind || !attemptOwnerKey) throw new ApiError('Action request unavailable', 409, 'plugin_webhook_state_conflict')
      if (!currentSessionCanManage(attemptOwnerKey)) throw new ApiError('Permission denied', 403, 'permission_denied')
      delete actionReceiptsRef.current[attemptKey]
      let result: ActionReceipt
      switch (request.kind) {
        case 'test':
          result = { kind: 'test', receipt: await pluginWebhooksApi.createTestDelivery(accessTokenRef.current, next.scopeID, next.subscriptionID, next.key) }
          break
        case 'replay':
          result = { kind: 'replay', receipt: await pluginWebhooksApi.replayDelivery(accessTokenRef.current, next.scopeID, next.subscriptionID, request.deliveryID, next.key) }
          break
        case 'rotate': {
          result = { kind: 'rotate', receipt: await pluginWebhooksApi.rotateSecret(accessTokenRef.current, next.scopeID, next.subscriptionID, request.revision, next.key) }
          break
        }
        case 'activate': {
          const rotation = pendingRotationsRef.current[pendingRotationKey(attemptOwnerKey, next.scopeID, next.subscriptionID)]
          if (!rotation) throw new ApiError('Pending rotation unavailable', 409, 'plugin_webhook_state_conflict')
          result = { kind: 'activate', receipt: await pluginWebhooksApi.activateSecret(accessTokenRef.current, next.scopeID, next.subscriptionID, rotation.rotationID, rotation.revision, next.key) }
          break
        }
        case 'revoke':
          result = { kind: 'revoke', receipt: await pluginWebhooksApi.revokeSubscription(accessTokenRef.current, next.scopeID, next.subscriptionID, request.revision, next.key) }
          break
      }
      if (mountedRef.current && attemptOwnerKey === ownerKeyRef.current) actionReceiptsRef.current[attemptKey] = result
    },
    onSuccess: (_result, next) => {
      const attemptKey = writeAttemptKey(next)
      const attemptOwnerKey = writeOwnersRef.current[attemptKey]
      const result = actionReceiptsRef.current[attemptKey]
      delete actionReceiptsRef.current[attemptKey]
      delete actionRequestsRef.current[attemptKey]
      delete writeOwnersRef.current[attemptKey]
      setAttempt((current) => current && current.ownerKey === attemptOwnerKey && writeAttemptKey(current.attempt) === attemptKey ? null : current)
      if (!attemptOwnerKey || attemptOwnerKey !== ownerKeyRef.current || !currentSessionCanManage(attemptOwnerKey)) return
      setActionError(null)
      if (next.kind === 'rotate' && result?.kind === 'rotate') {
        const rotation = result.receipt
        retainPendingRotation(attemptOwnerKey, next.scopeID, { subscriptionID: next.subscriptionID, rotationID: rotation.rotation_id, revision: rotation.subscription_revision })
        if (next.scopeID === scopeIDRef.current) setSecretReceipt({ kind: 'rotate', ownerKey: attemptOwnerKey, scopeID: next.scopeID, subscriptionID: next.subscriptionID, receipt: rotation })
      } else {
        if (next.kind === 'activate' || next.kind === 'revoke') {
          setSecretReceipt(null)
          clearPendingRotation(attemptOwnerKey, next.scopeID, next.subscriptionID)
        }
        if (next.scopeID === scopeIDRef.current && result?.kind === next.kind) messageApi.success(t(`notices.${next.kind}`))
      }
      createResetRef.current()
      actionResetRef.current()
      setSubscriptionPages({ key: next.scopeID, cursors: [] })
      if (next.kind === 'test' || next.kind === 'replay') {
        setDeliveryPages({ key: `${next.scopeID}:${next.subscriptionID}`, cursors: [] })
      }
      void queryClient.invalidateQueries({ queryKey: ['plugin-webhook-subscriptions', attemptOwnerKey, next.scopeID] })
      void queryClient.invalidateQueries({ queryKey: ['plugin-webhook-subscription', attemptOwnerKey, next.scopeID, next.subscriptionID] })
      void queryClient.invalidateQueries({ queryKey: ['plugin-webhook-deliveries', attemptOwnerKey, next.scopeID, next.subscriptionID] })
    },
    onError: (error, next) => {
      const attemptKey = writeAttemptKey(next)
      const attemptOwnerKey = writeOwnersRef.current[attemptKey]
      delete actionReceiptsRef.current[attemptKey]
      if (!attemptOwnerKey || attemptOwnerKey !== ownerKeyRef.current) {
        delete actionRequestsRef.current[attemptKey]
        delete writeOwnersRef.current[attemptKey]
        return
      }
      if (!currentSessionCanManage(attemptOwnerKey)) {
        setAttempt((current) => current && writeAttemptKey(current.attempt) === attemptKey ? null : current)
        delete actionRequestsRef.current[attemptKey]
        delete writeOwnersRef.current[attemptKey]
        actionResetRef.current()
        return
      }
      setActionError({ ownerKey: attemptOwnerKey, scopeID: next.scopeID, text: errorText(error, t) })
      if ((next.kind === 'activate' || next.kind === 'revoke') && error instanceof ApiError &&
        (error.code === 'plugin_webhook_not_found' || error.code === 'plugin_webhook_state_conflict')) {
        clearPendingRotation(attemptOwnerKey, next.scopeID, next.subscriptionID)
      }
      if (unknownOutcome(error)) setAttempt({ ownerKey: attemptOwnerKey, attempt: next })
      else {
        setAttempt((current) => current && current.ownerKey === attemptOwnerKey && writeAttemptKey(current.attempt) === attemptKey ? null : current)
        delete actionRequestsRef.current[attemptKey]
        delete writeOwnersRef.current[attemptKey]
      }
      actionResetRef.current()
    },
  })
  createResetRef.current = createMutation.reset
  actionResetRef.current = actionMutation.reset

  const currentCreateAttempt = createAttempt?.ownerKey === ownerKey && createAttempt.attempt.scopeID === scopeID ? createAttempt.attempt : null
  const currentAttempt = attempt?.ownerKey === ownerKey && attempt.attempt.scopeID === scopeID ? attempt.attempt : null
  const createPending = createMutation.isPending && createMutation.variables?.scopeID === scopeID && writeOwnersRef.current[writeAttemptKey(createMutation.variables)] === ownerKey
  const actionPending = actionMutation.isPending && actionMutation.variables?.scopeID === scopeID && writeOwnersRef.current[writeAttemptKey(actionMutation.variables)] === ownerKey
  const writeInFlight = Boolean(createPending || actionPending || currentCreateAttempt || currentAttempt)
  const writeLocked = Boolean(!canManage || writeInFlight)
  const exactDetail = detailQuery.isSuccess && detailQuery.data?.id === selectedSubscription?.id && detailQuery.data.tenant_scope_id === scopeID ? detailQuery.data : null
  const detail = exactDetail ?? selectedSubscription
  const subscriptions = subscriptionsQuery.data?.items ?? []
  const activeCount = subscriptions.filter((item) => item.status === 'active').length
  const revokedCount = subscriptions.filter((item) => item.status === 'revoked').length
  const subscriptionNextCursor = subscriptionsQuery.data?.next_cursor
  const deliveryNextCursor = deliveriesQuery.data?.next_cursor
  const beginAction = useCallback((next: ActionAttempt, request: ActionRequest) => {
    if (!currentSessionCanManage(ownerKey) || !scopeIDRef.current || writeLocked || ownerKeyRef.current !== ownerKey || next.scopeID !== scopeIDRef.current || next.kind !== request.kind) return
    const attemptKey = writeAttemptKey(next)
    writeOwnersRef.current[attemptKey] = ownerKey
    actionRequestsRef.current[attemptKey] = request
    setActionError(null)
    setAttempt({ ownerKey, attempt: next })
    actionMutation.mutate(next)
  }, [actionMutation, ownerKey, writeLocked])

  const revokedSubscriptionID = exactDetail?.status === 'revoked' ? exactDetail.id : ''
  useEffect(() => {
    if (!revokedSubscriptionID) return
    clearPendingRotation(ownerKey, scopeID, revokedSubscriptionID)
  }, [clearPendingRotation, ownerKey, revokedSubscriptionID, scopeID])
  const columns = useMemo<TableColumnsType<PluginWebhookSubscription>>(() => [
    {
      title: t('columns.name'), dataIndex: 'name', key: 'name', width: 230,
      render: (value: string, item) => <Button type="link" className="plugin-webhook-name" onClick={() => setSelected({ ownerKey, scopeID, subscription: item })}>{value}</Button>,
    },
    {
      title: t('columns.target'), dataIndex: 'target_url', key: 'target_url', width: 290,
      render: (value: string) => <code className="plugin-webhook-target">{value}</code>,
    },
    {
      title: t('columns.status'), dataIndex: 'status', key: 'status', width: 120,
      render: (value: PluginWebhookSubscription['status']) => <Tag color={statusColor(value)}>{t(`states.${value}`)}</Tag>,
    },
    { title: t('columns.revision'), dataIndex: 'revision', key: 'revision', width: 100 },
    {
      title: t('columns.updatedAt'), dataIndex: 'updated_at', key: 'updated_at', width: 190,
      render: (value: string) => formatDateTime(value, i18n.resolvedLanguage ?? 'zh-CN') || value,
    },
    {
      title: t('columns.actions'), key: 'actions', width: 210,
      render: (_value, item) => <Space wrap size={2}>
        <Button type="link" size="small" icon={<Eye size={14} />} onClick={() => setSelected({ ownerKey, scopeID, subscription: item })}>{t('actions.view')}</Button>
        {canManage ? <Button type="link" size="small" icon={<Send size={14} />} disabled={writeLocked || item.status !== 'active'} onClick={() => beginAction({ kind: 'test', scopeID, subscriptionID: item.id, key: newPluginWebhookIdempotencyKey('test') }, { kind: 'test' })}>{t('actions.test')}</Button> : null}
      </Space>,
    },
  ], [beginAction, canManage, i18n.resolvedLanguage, ownerKey, scopeID, t, writeLocked])

  function openReplayRange(subscriptionID: string) {
    replayRangeForm.setFieldsValue({ failed_only: true })
    setReplayWindow({ preset: 'today', range: todayUntilNow() })
    setReplayRange({ subscriptionID, key: newPluginWebhookIdempotencyKey('replay-range'), signature: '' })
  }

  function submitReplayRange(values: ReplayRangeFormValues) {
    if (!replayRange || !replayWindow.range) return
    const from = replayWindow.range[0].toISOString()
    const to = replayWindow.range[1].toISOString()
    const failedOnly = Boolean(values.failed_only)
    const signature = `${from}|${to}|${failedOnly}`
    // A changed range is a different batch and needs its own key.
    const key = replayRange.signature === '' || replayRange.signature === signature ? replayRange.key : newPluginWebhookIdempotencyKey('replay-range')
    setReplayRange({ subscriptionID: replayRange.subscriptionID, key, signature })
    replayRangeMutation.mutate({ subscriptionID: replayRange.subscriptionID, key, from, to, failedOnly })
  }

  function submitCreate(values: CreateFormValues) {
    if (!currentSessionCanManage(ownerKey) || ownerKeyRef.current !== ownerKey || scopeIDRef.current !== scopeID || !scopeID) return
    const eventTypes = Array.from(new Set(values.event_types ?? []))
    const installationAuthorizationID = values.installation_authorization_id?.trim() || undefined
    const siteIDs = eventTypes.some((eventType) => siteBoundEventTypes.has(eventType)) ? parseSiteIDs(values.site_ids) : undefined
    const input: PluginWebhookCreateInput = {
      name: values.name, target_url: values.target_url, event_types: eventTypes,
      ...(installationAuthorizationID ? { installation_authorization_id: installationAuthorizationID } : {}),
      ...(siteIDs ? { site_ids: siteIDs } : {}),
    }
    const next: CreateAttempt = { kind: 'create', scopeID, key: newPluginWebhookIdempotencyKey('create') }
    const attemptKey = writeAttemptKey(next)
    writeOwnersRef.current[attemptKey] = ownerKey
    createInputsRef.current[attemptKey] = input
    setActionError(null)
    setCreateAttempt({ ownerKey, attempt: next })
    createMutation.mutate(next)
  }

  function retryAction() {
    if (!currentSessionCanManage(ownerKey)) return
    if (currentCreateAttempt) createMutation.mutate(currentCreateAttempt)
    else if (currentAttempt) actionMutation.mutate(currentAttempt)
  }
  function closeUnknown() {
    if (currentCreateAttempt) {
      const attemptKey = writeAttemptKey(currentCreateAttempt)
      delete createInputsRef.current[attemptKey]
      delete createReceiptsRef.current[attemptKey]
      delete writeOwnersRef.current[attemptKey]
    }
    if (currentAttempt) {
      const attemptKey = writeAttemptKey(currentAttempt)
      delete actionRequestsRef.current[attemptKey]
      delete actionReceiptsRef.current[attemptKey]
      delete writeOwnersRef.current[attemptKey]
    }
    const closedAction = currentAttempt
    setSecretReceipt((current) => current?.ownerKey === ownerKey && current.scopeID === scopeID ? null : current)
    if (closedAction && (closedAction.kind === 'activate' || closedAction.kind === 'revoke')) {
      clearPendingRotation(ownerKey, closedAction.scopeID, closedAction.subscriptionID)
    }
    setCreateAttempt((current) => current?.ownerKey === ownerKey ? null : current)
    setAttempt((current) => current?.ownerKey === ownerKey ? null : current)
    setActionError(null)
    createMutation.reset()
    actionMutation.reset()
    void queryClient.invalidateQueries({ queryKey: ['plugin-webhook-subscriptions', ownerKey, scopeID] })
    if (closedAction && ['rotate', 'activate', 'revoke'].includes(closedAction.kind)) {
      void queryClient.invalidateQueries({ queryKey: ['plugin-webhook-subscription', ownerKey, closedAction.scopeID, closedAction.subscriptionID] })
    }
    if (closedAction && (closedAction.kind === 'test' || closedAction.kind === 'replay')) {
      void queryClient.invalidateQueries({ queryKey: ['plugin-webhook-deliveries', ownerKey, closedAction.scopeID, closedAction.subscriptionID] })
    }
  }

  function applyTargetScope() {
    if (writeInFlight) return
    const value = targetScopeDraft.trim().toLowerCase()
    if (!scopeIDPattern.test(value)) {
      setTargetScopeError(true)
      setTargetScopeID('')
      setSelected(null)
      closeSecretReceipt()
      return
    }
    setTargetScopeError(false)
    setTargetScopeID(value)
    setSelected(null)
    closeSecretReceipt()
    setActionError(null)
    const next = new URLSearchParams(searchParams)
    next.set('target_scope_id', value)
    setSearchParams(next, { replace: true })
  }

  function nextSubscriptionPage() {
    if (!subscriptionNextCursor || subscriptionCursors.includes(subscriptionNextCursor)) return
    setSubscriptionPages({ key: scopeID, cursors: [...subscriptionCursors, subscriptionNextCursor] })
  }

  function previousSubscriptionPage() {
    if (subscriptionCursors.length === 0) return
    setSubscriptionPages({ key: scopeID, cursors: subscriptionCursors.slice(0, -1) })
  }

  function nextDeliveryPage() {
    if (!deliveryNextCursor || deliveryCursors.includes(deliveryNextCursor)) return
    setDeliveryPages({ key: deliveryKey, cursors: [...deliveryCursors, deliveryNextCursor] })
  }

  function previousDeliveryPage() {
    if (deliveryCursors.length === 0) return
    setDeliveryPages({ key: deliveryKey, cursors: deliveryCursors.slice(0, -1) })
  }

  function closeSecretReceipt() {
    setSecretReceipt(null)
    createMutation.reset()
    actionMutation.reset()
  }

  function activatePendingRotation(subscriptionID: string) {
    if (!currentSessionCanManage(ownerKey)) return
    if (exactDetail?.id !== subscriptionID || !pendingRotationsRef.current[pendingRotationKey(ownerKey, scopeID, subscriptionID)]) return
    const next: ActionAttempt = {
      kind: 'activate',
      scopeID,
      subscriptionID,
      key: newPluginWebhookIdempotencyKey('activate'),
    }
    closeSecretReceipt()
    beginAction(next, { kind: 'activate' })
  }

  const drawerSubscription = detail
  const lifecycleSubscription = exactDetail
  const drawerPendingRotation = lifecycleSubscription ? pendingRotations[pendingRotationKey(ownerKey, scopeID, lifecycleSubscription.id)] : null
  const visibleSecretReceipt = secretReceipt?.ownerKey === ownerKey && secretReceipt.scopeID === scopeID &&
    (secretReceipt.kind === 'create' || secretReceipt.subscriptionID === exactDetail?.id) ? secretReceipt : null
  const deliveries = deliveriesQuery.data?.items ?? []
  const deliveryColumns = useMemo<TableColumnsType<PluginWebhookDelivery>>(() => {
    const result: TableColumnsType<PluginWebhookDelivery> = [
    { title: t('deliveryColumns.id'), dataIndex: 'id', key: 'id', ellipsis: true, width: 225 },
    { title: t('deliveryColumns.status'), dataIndex: 'status', key: 'status', width: 150, render: (value: PluginWebhookDelivery['status']) => <Tag color={deliveryColor(value)}>{t(`deliveryStates.${value}`)}</Tag> },
    { title: t('deliveryColumns.attempts'), dataIndex: 'attempt_count', key: 'attempt_count', width: 90 },
    { title: t('deliveryColumns.createdAt'), dataIndex: 'created_at', key: 'created_at', width: 180, render: (value: string) => formatDateTime(value, i18n.resolvedLanguage ?? 'zh-CN') || value },
    ]
    if (canManage) result.push({
      title: t('deliveryColumns.actions'), key: 'actions', width: 130,
      render: (_value, item) => <Button type="link" size="small" icon={<Play size={14} />} disabled={writeLocked || !['delivered', 'dead_lettered'].includes(item.status)} onClick={() => beginAction({ kind: 'replay', scopeID, subscriptionID: item.subscription_id, key: newPluginWebhookIdempotencyKey('replay') }, { kind: 'replay', deliveryID: item.id })}>{t('actions.replay')}</Button>,
    })
    return result
  }, [beginAction, canManage, i18n.resolvedLanguage, scopeID, t, writeLocked])

  const forbidden = subscriptionsQuery.isError && subscriptionsQuery.error instanceof ApiError && subscriptionsQuery.error.status === 403
  const unknownAttempt = currentCreateAttempt ?? currentAttempt
  const displayedActionError = actionError?.ownerKey === ownerKey && actionError.scopeID === scopeID ? actionError.text : null

  return <div className="plugin-webhooks-page">
    {messageContext}
    <div className="plugin-webhooks-heading">
      <div>
        <h1>{t('title')}</h1>
        <p>{t('subtitle')}</p>
      </div>
      {scopeID ? <Space wrap>
        <Button icon={<RefreshCw size={15} />} loading={subscriptionsQuery.isFetching} onClick={() => void subscriptionsQuery.refetch()}>{t('actions.refresh')}</Button>
        {canManage ? <Button type="primary" icon={<Plus size={15} />} disabled={writeLocked} onClick={() => setCreateOpen(true)}>{t('actions.create')}</Button> : null}
      </Space> : null}
    </div>

    {isPlatform ? <div className="plugin-webhook-target-scope">
      <Input aria-label={t('targetScope.label')} placeholder={t('targetScope.placeholder')} value={targetScopeDraft} status={targetScopeError ? 'error' : undefined} onChange={(event) => setTargetScopeDraft(event.target.value)} onPressEnter={applyTargetScope} />
      <Button type="primary" disabled={writeInFlight} onClick={applyTargetScope}>{t('targetScope.apply')}</Button>
    </div> : null}
    {isPlatform && !scopeID ? <Alert className="plugin-webhooks-alert" type={targetScopeError ? 'error' : 'info'} showIcon message={t(targetScopeError ? 'targetScope.invalid' : 'targetScope.required')} /> : null}

    {!scopeID ? null : forbidden ? <Result status="error" icon={<ShieldOff size={72} aria-hidden="true" />} title={t('forbidden.title')} subTitle={t('forbidden.description')} /> : <>{subscriptionsQuery.isLoading ? <div className="plugin-webhook-loading"><Spin aria-label={t('accessibility.loading')} /></div> : <>
    {subscriptionsQuery.isError ? <FeedbackWhen title={t('errors.loadFailed')} detail={errorText(subscriptionsQuery.error, t)} action={<Button size="small" onClick={() => void subscriptionsQuery.refetch()}>{t('actions.retry')}</Button>} /> : null}
    {displayedActionError && !unknownAttempt ? <FeedbackWhen title={t('errors.actionFailed')} detail={displayedActionError} /> : null}
    {unknownAttempt && displayedActionError ? <OutcomeUnknown title={t('errors.unknownOutcome')} detail={displayedActionError} action={<Space>{canManage ? <Button size="small" type="primary" loading={createMutation.isPending || actionMutation.isPending} onClick={retryAction}>{t('actions.retrySameRequest')}</Button> : null}
      <Button size="small" disabled={createMutation.isPending || actionMutation.isPending} onClick={closeUnknown}>{t('actions.closeAndRefresh')}</Button></Space>} className="plugin-webhooks-alert" /> : null}

    <div className="plugin-webhook-summary" aria-label={t('summary.label')}>
      <div><span>{t('summary.total')}</span><strong>{subscriptions.length}</strong></div>
      <div><span>{t('summary.active')}</span><strong>{activeCount}</strong></div>
      <div><span>{t('summary.revoked')}</span><strong>{revokedCount}</strong></div>
      <div><span>{t('summary.eventType')}</span><code>{pluginWebhookEventType}</code></div>
    </div>

    {subscriptionsQuery.isError ? null : subscriptions.length === 0 && !subscriptionsQuery.isFetching ? <div className="plugin-webhook-empty"><Result status="info" title={t('empty.title')} subTitle={t('empty.description')} extra={canManage ? <Button type="primary" icon={<Plus size={15} />} disabled={writeLocked} onClick={() => setCreateOpen(true)}>{t('actions.create')}</Button> : null} /></div> : <Table<PluginWebhookSubscription> rowKey="id" size="middle" scroll={{ x: 1120 }} columns={columns} dataSource={subscriptions} pagination={false} />}
    {subscriptionsQuery.isError ? null : <div className="plugin-webhook-pagination" aria-label={t('pagination.subscriptions')}>
      <Button icon={<ChevronLeft size={14} />} disabled={subscriptionCursors.length === 0 || subscriptionsQuery.isFetching} onClick={previousSubscriptionPage}>{t('pagination.previous')}</Button>
      <span>{t('pagination.page', { page: subscriptionCursors.length + 1 })}</span>
      <Button icon={<ChevronRight size={14} />} disabled={!subscriptionNextCursor || subscriptionCursors.includes(subscriptionNextCursor) || subscriptionsQuery.isFetching} onClick={nextSubscriptionPage}>{t('pagination.next')}</Button>
    </div>}

    {canManage ? <Modal title={t('create.title')} open={createOpen} closable={{ 'aria-label': t('actions.close') }} okText={t('actions.create')} cancelText={t('actions.cancel')} confirmLoading={createMutation.isPending} onCancel={() => { setCreateOpen(false); form.resetFields() }} onOk={() => { void form.validateFields().then(submitCreate).catch(() => undefined) }}>
      <Alert type="info" showIcon message={t('create.notice')} />
      <Form form={form} layout="vertical" className="plugin-webhook-form" initialValues={{ event_types: [pluginWebhookEventType] }}>
        <Form.Item name="name" label={t('create.name')} rules={[{ required: true, whitespace: true, message: t('create.nameRequired') }, { max: 128, message: t('create.nameTooLong') }]}><Input maxLength={128} placeholder={t('create.namePlaceholder')} /></Form.Item>
        <Form.Item name="target_url" label={t('create.target')} rules={[{ required: true, type: 'url', message: t('create.targetInvalid') }]}><Input maxLength={2048} placeholder={t('create.targetPlaceholder')} /></Form.Item>
        <Form.Item name="event_types" label={t('create.events')} rules={[{ required: true, type: 'array', min: 1, message: t('create.eventsRequired') }]} extra={t('create.eventsDescription')}>
          <Select mode="multiple" options={[
            { value: pluginWebhookEventType, label: t('create.eventTypes.test') },
            ...pluginWebhookDomainEventTypes.map((eventType) => ({ value: eventType, label: t(`create.eventTypes.${domainEventLabelKey[eventType]}`) })),
          ]} onChange={(eventTypes: PluginWebhookCreateInput['event_types']) => {
            if (!eventTypes.some((eventType) => eventType !== pluginWebhookEventType)) form.setFieldValue('installation_authorization_id', undefined)
          }} />
        </Form.Item>
        <Form.Item noStyle shouldUpdate={(previous, current) => previous.event_types !== current.event_types}>
          {({ getFieldValue }) => {
            const eventTypes = (getFieldValue('event_types') ?? []) as PluginWebhookCreateInput['event_types']
            const requiresAuthorization = eventTypes.some((eventType) => eventType !== pluginWebhookEventType)
            if (!requiresAuthorization) return null
            return <Form.Item name="installation_authorization_id" label={t('create.installationAuthorization')} rules={[
              { required: true, message: t('create.installationAuthorizationRequired') },
              { pattern: scopeIDPattern, message: t('create.installationAuthorizationInvalid') },
            ]} extra={t('create.installationAuthorizationDescription')}>
              <Input allowClear maxLength={36} placeholder={t('create.installationAuthorizationPlaceholder')} />
            </Form.Item>
          }}
        </Form.Item>
        <Form.Item noStyle shouldUpdate={(previous, current) => previous.event_types !== current.event_types}>
          {({ getFieldValue }) => {
            const eventTypes = (getFieldValue('event_types') ?? []) as PluginWebhookCreateInput['event_types']
            if (!eventTypes.some((eventType) => siteBoundEventTypes.has(eventType))) return null
            return <Form.Item name="site_ids" label={t('create.siteFilter')} extra={t('create.siteFilterDescription')}
              rules={[{ pattern: siteIDListPattern, message: t('create.siteFilterInvalid') }]}>
              <Input.TextArea autoSize={{ minRows: 1, maxRows: 4 }} placeholder={t('create.siteFilterPlaceholder')} />
            </Form.Item>
          }}
        </Form.Item>
      </Form>
    </Modal> : null}

    <Modal title={visibleSecretReceipt?.kind === 'rotate' ? t('secret.rotateTitle') : t('secret.createTitle')} open={Boolean(visibleSecretReceipt)} closable={{ 'aria-label': t('actions.close') }} footer={null} destroyOnHidden onCancel={closeSecretReceipt}>
      {visibleSecretReceipt ? <div className="plugin-webhook-secret">
        <Alert type="warning" showIcon message={t('secret.warning')} description={t('secret.description')} />
        <Space.Compact block>
          <Input.Password role="textbox" aria-label={visibleSecretReceipt.kind === 'rotate' ? t('secret.rotateTitle') : t('secret.createTitle')} value={visibleSecretReceipt.kind === 'rotate' ? visibleSecretReceipt.receipt.secret : visibleSecretReceipt.secret} readOnly />
          <Button aria-label={t('secret.copy')} icon={<Clipboard size={15} />} onClick={() => copyText(visibleSecretReceipt.kind === 'rotate' ? visibleSecretReceipt.receipt.secret : visibleSecretReceipt.secret)} />
        </Space.Compact>
        {visibleSecretReceipt.kind === 'rotate' ? <Space className="plugin-webhook-secret-actions"><Button type="primary" icon={<Check size={15} />} disabled={writeLocked} onClick={() => activatePendingRotation(visibleSecretReceipt.subscriptionID)}>{t('actions.activate')}</Button><Button onClick={closeSecretReceipt}>{t('actions.close')}</Button></Space> : <Button className="plugin-webhook-secret-actions" onClick={closeSecretReceipt}>{t('actions.close')}</Button>}
      </div> : null}
    </Modal>

    <Modal title={t('replayRange.title')} open={Boolean(replayRange)} destroyOnHidden okText={t('actions.replayRange')} cancelText={t('actions.cancel')}
      confirmLoading={replayRangeMutation.isPending} onCancel={() => setReplayRange(null)} onOk={() => replayRangeForm.submit()}>
      <Alert type="info" showIcon message={t('replayRange.notice')} />
      <Form form={replayRangeForm} layout="vertical" className="plugin-webhook-form" onFinish={submitReplayRange}>
        <Form.Item>
          <TimeRangeFilter allowClear={false} maxSpanMs={replayRangeMaxSpanMs} maxDate={dayjs()}
            value={replayWindow} onChange={setReplayWindow} />
        </Form.Item>
        <Form.Item name="failed_only" valuePropName="checked"><Checkbox>{t('replayRange.failedOnly')}</Checkbox></Form.Item>
      </Form>
      {replayRange?.result ? <Alert type={replayRange.result.remaining ? 'warning' : 'success'} showIcon
        message={t('replayRange.result', {
          replayed: replayRange.result.items.filter((item) => item.outcome === 'replayed' || item.outcome === 'already_replayed').length,
          denied: replayRange.result.items.filter((item) => item.outcome === 'permission_denied').length,
        })} description={replayRange.result.remaining ? t('replayRange.remaining') : undefined} /> : null}
    </Modal>

    <Drawer className="plugin-webhook-drawer" title={drawerSubscription ? drawerSubscription.name : t('detail.title')} width={760} open={Boolean(selectedSubscription)} closable={{ 'aria-label': t('actions.close') }} onClose={() => setSelected(null)}>
      {detailQuery.isLoading ? <div className="plugin-webhook-loading"><Spin aria-label={t('accessibility.loading')} /></div> : null}
      {detailQuery.isError ? <Alert type="error" showIcon message={t('errors.detailLoadFailed')} description={errorText(detailQuery.error, t)} action={<Button size="small" onClick={() => void detailQuery.refetch()}>{t('actions.retry')}</Button>} /> : null}
      {drawerSubscription ? <>
        <Descriptions bordered size="small" column={2}>
          <Descriptions.Item label={t('detail.status')}><Tag color={statusColor(drawerSubscription.status)}>{t(`states.${drawerSubscription.status}`)}</Tag></Descriptions.Item>
          <Descriptions.Item label={t('detail.revision')}>{drawerSubscription.revision}</Descriptions.Item>
          <Descriptions.Item label={t('detail.target')} span={2}><code className="plugin-webhook-target">{drawerSubscription.target_url}</code></Descriptions.Item>
          <Descriptions.Item label={t('detail.events')} span={2}>{drawerSubscription.event_types.join(', ')}</Descriptions.Item>
          <Descriptions.Item label={t('detail.siteFilter')} span={2}>{drawerSubscription.site_ids?.join(', ') ?? t('detail.allSites')}</Descriptions.Item>
          <Descriptions.Item label={t('detail.createdAt')}>{formatDateTime(drawerSubscription.created_at, i18n.resolvedLanguage ?? 'zh-CN') || drawerSubscription.created_at}</Descriptions.Item>
          <Descriptions.Item label={t('detail.updatedAt')}>{formatDateTime(drawerSubscription.updated_at, i18n.resolvedLanguage ?? 'zh-CN') || drawerSubscription.updated_at}</Descriptions.Item>
        </Descriptions>
        {canManage && lifecycleSubscription ? <div className="plugin-webhook-toolbar">
          <Button icon={<Send size={15} />} disabled={writeLocked || lifecycleSubscription.status !== 'active'} onClick={() => beginAction({ kind: 'test', scopeID, subscriptionID: lifecycleSubscription.id, key: newPluginWebhookIdempotencyKey('test') }, { kind: 'test' })}>{t('actions.sendTest')}</Button>
          {drawerPendingRotation ? <Button type="primary" icon={<Check size={15} />} disabled={writeLocked || lifecycleSubscription.status !== 'active'} onClick={() => activatePendingRotation(lifecycleSubscription.id)}>{t('actions.activate')}</Button> : null}
          <Button icon={<Play size={15} />} disabled={writeLocked || lifecycleSubscription.status !== 'active'} onClick={() => openReplayRange(lifecycleSubscription.id)}>{t('actions.replayRange')}</Button>
          <Button icon={<RotateCw size={15} />} disabled={writeLocked || Boolean(drawerPendingRotation) || lifecycleSubscription.status !== 'active'} onClick={() => beginAction({ kind: 'rotate', scopeID, subscriptionID: lifecycleSubscription.id, key: newPluginWebhookIdempotencyKey('rotate') }, { kind: 'rotate', revision: lifecycleSubscription.revision })}>{t('actions.rotate')}</Button>
          <Popconfirm title={t('revoke.confirm')} okText={t('actions.revoke')} cancelText={t('actions.cancel')} disabled={lifecycleSubscription.status !== 'active'} onConfirm={() => beginAction({ kind: 'revoke', scopeID, subscriptionID: lifecycleSubscription.id, key: newPluginWebhookIdempotencyKey('revoke') }, { kind: 'revoke', revision: lifecycleSubscription.revision })}><Button danger icon={<ShieldOff size={15} />} disabled={writeLocked || lifecycleSubscription.status !== 'active'}>{t('actions.revoke')}</Button></Popconfirm>
        </div> : null}
        <div className="plugin-webhook-deliveries-heading"><h2>{t('deliveries.title')}</h2><Button size="small" icon={<RefreshCw size={14} />} loading={deliveriesQuery.isFetching} onClick={() => void deliveriesQuery.refetch()}>{t('actions.refresh')}</Button></div>
        {deliveriesQuery.isError ? <Alert type="error" showIcon message={t('errors.deliveryLoadFailed')} /> : null}
        {deliveries.length === 0 && !deliveriesQuery.isFetching ? <div className="plugin-webhook-deliveries-empty">{t('deliveries.empty')}</div> : <Table<PluginWebhookDelivery> rowKey="id" size="small" scroll={{ x: 760 }} columns={deliveryColumns} dataSource={deliveries} pagination={false} />}
        {deliveriesQuery.isError ? null : <div className="plugin-webhook-pagination" aria-label={t('pagination.deliveries')}>
          <Button icon={<ChevronLeft size={14} />} disabled={deliveryCursors.length === 0 || deliveriesQuery.isFetching} onClick={previousDeliveryPage}>{t('pagination.previous')}</Button>
          <span>{t('pagination.page', { page: deliveryCursors.length + 1 })}</span>
          <Button icon={<ChevronRight size={14} />} disabled={!deliveryNextCursor || deliveryCursors.includes(deliveryNextCursor) || deliveriesQuery.isFetching} onClick={nextDeliveryPage}>{t('pagination.next')}</Button>
        </div>}
      </> : null}
    </Drawer>
    </>}</>}
  </div>
}
