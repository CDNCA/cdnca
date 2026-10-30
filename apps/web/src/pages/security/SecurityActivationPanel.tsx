import { useEffect, useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { Alert, Button, Descriptions, Input, Modal, Result, Select, Space, Tag, Typography } from 'antd'
import { useFeedbackMessage, FeedbackWhen, OutcomeUnknown } from '@cdnca/ui'
import { ArrowLeftRight, RefreshCw, RotateCcw, ShieldCheck, ShieldOff, Upload } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { useSearchParams } from 'react-router-dom'

import { ApiError } from '../../api/auth'
import {
  newSecurityActivationWriteMetadata,
  securityPoliciesApi,
  type SecurityActivationCandidate,
  type SecurityActivationFailureReason,
  type SecurityActivationPublishInput,
  type SecurityActivationRollbackInput,
  type SecurityActivationStatus,
  type SecurityActivationWriteMetadata,
  type SecurityPolicy,
  type SecurityPolicyKind,
} from '../../api/securityPolicies'
import { useSessionStore } from '../../auth/session'
import { localizedUnknownApiError } from '../../i18n/apiError'
import { challengePolicyRefusalText } from '../../i18n/crsRepublish'
import '../../i18n/securityPoliciesCapabilityRefusal'
import '../../i18n/securityPoliciesCountBy'
import { activationErrorCodes } from '../../i18n/securityPoliciesActivationAuto'
import { rebindErrorCodes } from '../../i18n/securityPoliciesRebind'

export type SecurityActivationDisplayState =
  | 'pending'
  | 'canary'
  | 'expanding'
  | 'active'
  | 'rolling_back'
  | 'rolled_back'
  | 'detaching'
  | 'detached'
  | 'failed'

type WriteAttempt =
  | {
      kind: 'publish' | 'rebind' | 'detach'
      input: SecurityActivationPublishInput
      metadata: SecurityActivationWriteMetadata
    }
  | {
      kind: 'reconcile'
      candidateID: string
      input: { promotion_cas: ReturnType<typeof promotionCAS> }
      metadata: SecurityActivationWriteMetadata
    }
  | {
      kind: 'rollback'
      candidateID: string
      input: SecurityActivationRollbackInput
      metadata: SecurityActivationWriteMetadata
    }

const canonicalUUIDPattern = /^(?!00000000-0000-0000-0000-000000000000$)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

const stateColors: Record<SecurityActivationDisplayState, string> = {
  pending: 'default',
  canary: 'processing',
  expanding: 'cyan',
  active: 'success',
  rolling_back: 'warning',
  rolled_back: 'gold',
  detaching: 'warning',
  detached: 'default',
  failed: 'error',
}

function promotionCAS(candidate: SecurityActivationCandidate) {
  return {
    tenant_scope_id: candidate.tenant_scope_id,
    binding_id: candidate.binding_id,
    binding_revision: candidate.binding_revision,
    last_bundle_id: candidate.last_bundle_id,
    last_claimed_policy_version: candidate.last_claimed_policy_version,
    expected_active_policy_version: candidate.expected_active_policy_version,
    candidate_source_revision: candidate.candidate_source_revision,
    candidate_config_version_id: candidate.candidate_config_version_id,
    candidate_artifact_sha256: candidate.candidate_artifact_sha256,
    target_snapshot_sha256: candidate.target_snapshot_sha256,
  }
}

function securityActivationDisplayState(status: SecurityActivationStatus): SecurityActivationDisplayState {
  const candidate = status.latest_candidate
  if (!candidate) return status.binding?.active_policy_version ? 'active' : 'pending'
  if (['failed', 'cancelled', 'expired'].includes(candidate.candidate_status)) return 'failed'
  if (status.operation === 'rollback') {
    return candidate.candidate_status === 'promoted' ? 'rolled_back' : 'rolling_back'
  }
  if (status.latest_detach) {
    return candidate.candidate_status === 'promoted' ? 'detached' : 'detaching'
  }
  switch (candidate.candidate_status) {
    case 'canary':
      return 'canary'
    case 'expanding':
    case 'healthy':
      return 'expanding'
    case 'promoted':
      return 'active'
    default:
      return 'pending'
  }
}

function outcomeUnknown(error: unknown): boolean {
  return !(error instanceof ApiError) || error.status === 0 || error.status === 408 ||
    error.status === 429 || error.status >= 500 || error.code === 'invalid_response'
}

function activationError(error: unknown, fallback: string, explain?: (code: string) => string): string {
  if (!(error instanceof ApiError)) return fallback
  // 403 package_feature_denied / 400 activation_expiry_too_late / 422
  // no_target_nodes say why and what to do next (live-waf P7/P8).
  if (explain && (activationErrorCodes.includes(error.code) || rebindErrorCodes.includes(error.code))) return localizedUnknownApiError(error, explain(error.code))
  // rule_pack_unavailable names the nodes and packs (ui-errmsg-1024 N17);
  // localizedUnknownApiError reads error.rulePacks.
  return challengePolicyRefusalText(error) ?? localizedUnknownApiError(error, fallback)
}

// The control plane picks the targets (the site's package line groups) and a
// canary of 1; expires_at stays within the 15-minute candidate TTL and is
// fixed per attempt so a retry sends the same request.
const activationLifetimeMs = 10 * 60 * 1000

function activationExpiry(): string {
  return new Date(Date.now() + activationLifetimeMs).toISOString()
}

// A refusal because target nodes cannot count by network / host / URI / TLS
// fingerprint (CC v4) names every such node; the release waits for them.
// responseApiError keeps no server text, so the nodes come from the
// structured refusal (error.capability); the message match is only the
// fallback for an ApiError that carries readable text.
const ccCountByVersion = 4

function countByRefusalNodes(error: ApiError): string[] | undefined {
  const refusal = error.capability
  if (refusal) {
    if (refusal.capability !== 'CAPABILITY_NAME_CC' || refusal.required_version !== ccCountByVersion) return undefined
    return [...new Set([refusal.node_id, ...refusal.other_node_ids])]
  }
  if (!error.message.includes('counting by')) return undefined
  return [...new Set(error.message.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g) ?? [])]
}

/** Every node named by a structured capability refusal. */
// sec-ui-polish P11: a failed node by name (or IP, else short ID); the full
// ID is the title and can be copied.
function FailedNode({ reason, copyLabel }: { reason: SecurityActivationFailureReason; copyLabel: string }) {
  const name = reason.node_name.trim()
  const ip = reason.node_ip.trim()
  const label = name && ip ? `${name}（${ip}）` : name || ip || `${reason.node_id.slice(0, 8)}…`
  return (
    <Typography.Text className="security-activation-failure-node" title={reason.node_id}
      copyable={{ text: reason.node_id, tooltips: [copyLabel, '✓'] }}>{label}</Typography.Text>
  )
}

function refusedNodes(error: ApiError): string[] | undefined {
  const refusal = error.capability
  return refusal ? [...new Set([refusal.node_id, ...refusal.other_node_ids])] : undefined
}

export default function SecurityActivationPanel({
  kind,
  policies,
  policiesLoading,
  autoPublish,
}: {
  kind: SecurityPolicyKind
  policies: SecurityPolicy[]
  policiesLoading: boolean
  /** A library just saved for this site: publish it once its status is loaded (10-22 保存即下发). */
  autoPublish?: { id: string, version: number }
}) {
  const { t } = useTranslation('securityPolicies')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const canManage = Boolean(principal?.permissions.includes('security_policies.manage') || principal?.permissions.includes('platform.admin'))
  const [searchParams, setSearchParams] = useSearchParams()
  const urlSiteID = searchParams.get('site_id') ?? ''
  // "去发布" from a pending subscribed library update (WAFPendingPublications)
  // fills the library and the site's last target nodes; nothing is sent until
  // the operator clicks publish.
  const urlPolicyID = searchParams.get('policy_id') ?? ''
  const [siteDraft, setSiteDraft] = useState(urlSiteID)
  const [siteError, setSiteError] = useState(false)
  const [policyID, setPolicyID] = useState('')
  const [attempt, setAttempt] = useState<WriteAttempt | null>(null)
  const [writeError, setWriteError] = useState<unknown>(null)
  const [messageApi, messageContext] = useFeedbackMessage()
  const [modal, modalContext] = Modal.useModal()
  const canonicalSiteID = canonicalUUIDPattern.test(urlSiteID) ? urlSiteID : ''
  const eligiblePolicies = policies.filter((item) => item.kind === kind && item.enabled)
  const effectivePolicyID = policyID || (eligiblePolicies.length === 1 ? eligiblePolicies[0]!.id : '')
  const selectedPolicy = eligiblePolicies.find((item) => item.id === effectivePolicyID)
  const explain = (code: string) => t(`activation.errors.${code}`)
  // Libraries are named from the page's list; a deleted one is not in it.
  const policyLabel = (id: string) => {
    const found = policies.find((item) => item.id === id)
    return found ? found.name : t('activation.values.deletedPolicy', { id })
  }

  useEffect(() => {
    if (urlPolicyID) setPolicyID(urlPolicyID)
  }, [urlPolicyID])

  useEffect(() => {
    setSiteDraft(urlSiteID)
    setSiteError(Boolean(urlSiteID) && !canonicalUUIDPattern.test(urlSiteID))
    setAttempt(null)
    setWriteError(null)
  }, [urlSiteID])

  const statusQuery = useQuery({
    queryKey: ['security-activation', canonicalSiteID, kind],
    queryFn: ({ signal }) => securityPoliciesApi.getActivationStatus(accessToken!, canonicalSiteID, kind, signal),
    enabled: Boolean(accessToken && canManage && canonicalSiteID),
  })

  const mutation = useMutation({
    mutationFn: (next: WriteAttempt) => {
      switch (next.kind) {
        case 'reconcile':
          return securityPoliciesApi.reconcileActivation(accessToken!, next.candidateID, next.input, next.metadata)
        case 'rollback':
          return securityPoliciesApi.rollbackActivation(accessToken!, next.candidateID, next.input, next.metadata)
        default:
          return securityPoliciesApi.publishActivation(accessToken!, next.input, next.metadata)
      }
    },
    onSuccess: (_result, completed) => {
      setAttempt(null)
      setWriteError(null)
      messageApi.success(t(`activation.notices.${completed.kind}`))
      void statusQuery.refetch()
    },
    onError: (error, failed) => {
      setWriteError(error)
      setAttempt(outcomeUnknown(error) ? failed : null)
    },
  })

  const autoKey = autoPublish ? `${autoPublish.id}@${autoPublish.version}` : ''
  const [autoDone, setAutoDone] = useState('')
  const statusReady = Boolean(statusQuery.data) && !statusQuery.isFetching
  useEffect(() => {
    if (!autoPublish || !autoKey || autoDone === autoKey || !statusReady || mutation.isPending || attempt) return
    // SEC-ACCOUNT-01: skip only when this exact library@version is already
    // active; another library at the same version number must still publish.
    const active = statusQuery.data?.binding
    if (active && active.policy_id === autoPublish.id && active.active_policy_version === autoPublish.version) return
    setAutoDone(autoKey)
    setPolicyID(autoPublish.id)
    messageApi.info(t('activation.autoPublishOnSave'))
    publish(autoPublish)
    // publish reads the loaded status; run once per saved version.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoKey, autoDone, statusReady])

  if (!accessToken) return null

  const applySite = () => {
    const nextSiteID = siteDraft.trim().toLowerCase()
    if (!canonicalUUIDPattern.test(nextSiteID)) {
      setSiteError(true)
      return
    }
    const next = new URLSearchParams(searchParams)
    next.set('site_id', nextSiteID)
    setSearchParams(next, { replace: true })
  }

  const run = (next: WriteAttempt) => {
    if (!canManage || mutation.isPending || attempt) return
    setWriteError(null)
    setAttempt(next)
    mutation.mutate(next)
  }

  const publish = (policy: { id: string, version: number } | undefined = selectedPolicy,
    kind: 'publish' | 'rebind' = 'publish') => {
    if (!canonicalSiteID || !policy || !statusQuery.data) return
    run({
      kind,
      input: {
        site_id: canonicalSiteID,
        policy_id: policy.id,
        policy_version: policy.version,
        expected_binding_revision: statusQuery.data.binding?.binding_revision ?? 0,
        expected_active_policy_version: statusQuery.data.binding?.active_policy_version ?? 0,
        target_node_ids: [],
        canary_size: 0,
        expires_at: activationExpiry(),
      },
      metadata: newSecurityActivationWriteMetadata('publish'),
    })
  }

  // sec-rebind: withdraw the active library (a release like any other).
  const detach = () => {
    const binding = statusQuery.data?.binding
    if (!canonicalSiteID || !binding || binding.active_policy_version < 1) return
    run({
      kind: 'detach',
      input: {
        site_id: canonicalSiteID,
        policy_id: binding.policy_id,
        policy_version: binding.active_policy_version,
        expected_binding_revision: binding.binding_revision,
        expected_active_policy_version: binding.active_policy_version,
        target_node_ids: [],
        canary_size: 0,
        expires_at: activationExpiry(),
        detach: true,
      },
      metadata: newSecurityActivationWriteMetadata('publish'),
    })
  }

  const confirmDetach = () => {
    const binding = statusQuery.data?.binding
    if (!binding) return
    const kindLabel = t(`kinds.${kind}`)
    modal.confirm({
      title: t('activation.detachDialog.title', { kind: kindLabel }),
      content: t('activation.detachDialog.content', { kind: kindLabel, name: policyLabel(binding.policy_id) }),
      okText: t('activation.actions.detachConfirm'),
      okButtonProps: { danger: true },
      cancelText: t('activation.actions.cancel'),
      onOk: detach,
    })
  }

  const reconcile = () => {
    const candidate = statusQuery.data?.latest_candidate
    if (!candidate) return
    run({
      kind: 'reconcile',
      candidateID: candidate.id,
      input: { promotion_cas: promotionCAS(candidate) },
      metadata: newSecurityActivationWriteMetadata('reconcile'),
    })
  }

  // sec-rebind: the server names the promoted candidate and version to roll
  // back to (the library active before the latest promotion), or why not.
  const rollback = () => {
    const status = statusQuery.data
    const target = status?.rollback
    if (!status?.binding || !target?.available || !target.candidate_id || !target.source_policy_version) return
    run({
      kind: 'rollback',
      candidateID: target.candidate_id,
      input: {
        source_policy_version: target.source_policy_version,
        expected_binding_revision: status.binding.binding_revision,
        expected_active_policy_version: status.binding.active_policy_version,
        target_node_ids: [],
        canary_size: 0,
        expires_at: activationExpiry(),
      },
      metadata: newSecurityActivationWriteMetadata('rollback'),
    })
  }

  const reload = async () => {
    const result = await statusQuery.refetch()
    if (!result.error) {
      setAttempt(null)
      setWriteError(null)
    }
  }

  const uncertain = Boolean(attempt && writeError && outcomeUnknown(writeError))
  const writesLocked = mutation.isPending || uncertain
  const candidate = statusQuery.data?.latest_candidate
  const binding = statusQuery.data?.binding
  const activeBinding = binding && binding.active_policy_version > 0 ? binding : null
  const rollbackState = statusQuery.data?.rollback
  const rebindTarget = activeBinding && selectedPolicy && selectedPolicy.id !== activeBinding.policy_id ? selectedPolicy : undefined
  const displayState = statusQuery.data ? securityActivationDisplayState(statusQuery.data) : null
  const forbidden = !canManage || statusQuery.error instanceof ApiError && statusQuery.error.status === 403

  return (
    <section aria-labelledby={`security-activation-title-${kind}`} aria-busy={statusQuery.isPending && Boolean(canonicalSiteID)}>
      {messageContext}
      {modalContext}
      <div className="identity-toolbar">
        <h2 id={`security-activation-title-${kind}`}>{t('activation.title')}</h2>
        <Space wrap>
          {displayState ? <Tag color={stateColors[displayState]}>{t(`activation.states.${displayState}`)}</Tag> : null}
          <Button
            icon={<RefreshCw size={14} />}
            disabled={!canonicalSiteID || !canManage}
            loading={statusQuery.isFetching}
            onClick={() => void reload()}
          >
            {t('activation.actions.reload')}
          </Button>
        </Space>
      </div>

      <div className="identity-filter-bar">
        <Input
          aria-label={t('activation.fields.site')}
          value={siteDraft}
          status={siteError ? 'error' : undefined}
          style={{ width: 330 }}
          onChange={(event) => { setSiteDraft(event.target.value); setSiteError(false) }}
          onPressEnter={applySite}
        />
        <Button type="primary" onClick={applySite}>{t('activation.actions.applySite')}</Button>
        <Select
          aria-label={t('activation.fields.policy')}
          value={selectedPolicy?.id}
          loading={policiesLoading}
          style={{ width: 260 }}
          placeholder={t('activation.values.selectPolicy')}
          options={eligiblePolicies.map((item) => ({
            value: item.id,
            label: `${item.name} (v${item.version})`,
          }))}
          onChange={setPolicyID}
        />
      </div>

      {siteError ? <FeedbackWhen title={t('activation.errors.invalidSite')} /> : null}
      {forbidden ? (
        <Result status="403" title={t('activation.errors.forbiddenTitle')} subTitle={t('activation.errors.permission_denied')} />
      ) : !canonicalSiteID ? (
        <Alert className="identity-alert" type="info" showIcon message={t('activation.values.siteRequired')} />
      ) : statusQuery.isPending ? (
        <Alert className="identity-alert" type="info" showIcon message={t('activation.values.loading')} />
      ) : statusQuery.isError ? (
        <FeedbackWhen title={t('activation.errors.loadFailed')} detail={activationError(statusQuery.error, t('activation.errors.request_failed'))} action={<Button size="small" onClick={() => void statusQuery.refetch()}>{t('activation.actions.retry')}</Button>} />
      ) : (
        <>
          {uncertain ? (
            <OutcomeUnknown title={t('activation.uncertainty.title')} detail={t('activation.uncertainty.description')} action={<Button size="small" loading={mutation.isPending} onClick={() => { if (attempt) mutation.mutate(attempt) }}>
                {t('activation.actions.retrySame')}
              </Button>} className="identity-alert" />
          ) : writeError ? (
            <FeedbackWhen title={t('activation.errors.writeFailed')} detail={
              writeError instanceof ApiError && writeError.code === 'node_capability_unavailable'
                ? countByRefusalNodes(writeError)
                  ? <>{t('countByPublish.refusal')}<br />{t('countByPublish.refusalNodes', { nodes: countByRefusalNodes(writeError)!.join('、') })}</>
                  : refusedNodes(writeError)
                    ? <>{t('capabilityRefusal.hint')}<br />{t('countByPublish.refusalNodes', { nodes: refusedNodes(writeError)!.join('、') })}</>
                    : t('capabilityRefusal.hint')
                : activationError(writeError, t('activation.errors.request_failed'), explain)} />
          ) : null}
          {statusQuery.data?.failure_reasons?.length ? (
            <Alert className="identity-alert" type="error" showIcon role="alert" message={t('activation.errors.candidateFailedTitle')} description={
              <ul className="security-activation-failures">
                {statusQuery.data.failure_reasons.map((reason) => (
                  <li key={reason.node_id}>
                    {t('activation.errors.candidateFailedNodeLabel')}<FailedNode reason={reason} copyLabel={t('activation.actions.copyNodeId')} />
                    {t('activation.errors.candidateFailedNodeMessage', { message: reason.message || reason.code || '—' })}
                    {reason.reason === 'waf_engine_unavailable' ? <><br />{t('activation.errors.wafEngineMissing')}</> : null}
                  </li>
                ))}
              </ul>
            } />
          ) : null}
          {statusQuery.data?.capability_wait ? (
            <Alert className="identity-alert" type="info" showIcon role="status" message={t(statusQuery.data.capability_wait.wait_kind === 'rule_pack' ? 'countByPublish.waitingRulePacks' : 'countByPublish.waiting', {
              version: statusQuery.data.capability_wait.policy_version, nodes: statusQuery.data.capability_wait.node_ids.join('、'),
            })} />
          ) : null}

          <Descriptions size="small" column={{ xs: 1, sm: 2, md: 3 }}>
            <Descriptions.Item label={t('activation.facts.activePolicy')}>
              {activeBinding ? `${policyLabel(activeBinding.policy_id)} (v${activeBinding.active_policy_version})` : t('activation.values.noneActive')}
            </Descriptions.Item>
            <Descriptions.Item label={t('activation.facts.bindingRevision')}>
              {statusQuery.data?.binding?.binding_revision ?? 0}
            </Descriptions.Item>
            <Descriptions.Item label={t('activation.facts.activeVersion')}>
              {statusQuery.data?.binding?.active_policy_version ?? 0}
            </Descriptions.Item>
            <Descriptions.Item label={t('activation.facts.candidate')}>
              {candidate?.id ?? t('activation.values.none')}
            </Descriptions.Item>
          </Descriptions>

          <Typography.Paragraph type="secondary">{t('activation.autoTargets')}</Typography.Paragraph>
          {activeBinding ? <Typography.Paragraph type="secondary">{t('activation.values.rebindHint')}</Typography.Paragraph> : null}

          <Space wrap>
            {activeBinding ? (
              <Button type="primary" icon={<ArrowLeftRight size={14} />} disabled={writesLocked || !rebindTarget}
                onClick={() => publish(rebindTarget, 'rebind')}>
                {t('activation.actions.rebind')}
              </Button>
            ) : null}
            <Button type={activeBinding ? 'default' : 'primary'} icon={<Upload size={14} />}
              disabled={writesLocked || !selectedPolicy || Boolean(rebindTarget)} onClick={() => publish()}>
              {t('activation.actions.publish')}
            </Button>
            <Button icon={<ShieldCheck size={14} />} disabled={writesLocked || !candidate} onClick={reconcile}>
              {t('activation.actions.reconcile')}
            </Button>
            <Button danger icon={<RotateCcw size={14} />} disabled={writesLocked || !rollbackState?.available}
              aria-describedby={rollbackState && !rollbackState.available && rollbackState.reason ? `security-rollback-reason-${kind}` : undefined}
              onClick={rollback}>
              {t('activation.actions.rollback')}
            </Button>
            {activeBinding ? (
              <Button danger icon={<ShieldOff size={14} />} disabled={writesLocked} onClick={confirmDetach}>
                {t('activation.actions.detach')}
              </Button>
            ) : null}
          </Space>
          {rollbackState?.available && rollbackState.policy_id ? (
            <Typography.Paragraph type="secondary" className="security-activation-rollback-hint">
              {t('activation.rollbackTarget', { name: policyLabel(rollbackState.policy_id), version: rollbackState.source_policy_version })}
            </Typography.Paragraph>
          ) : rollbackState?.reason && candidate ? (
            <Typography.Paragraph type="secondary" id={`security-rollback-reason-${kind}`} className="security-activation-rollback-hint">
              {t(`activation.rollbackReasons.${rollbackState.reason}`)}
            </Typography.Paragraph>
          ) : null}
        </>
      )}
    </section>
  )
}
