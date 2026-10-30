import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { Alert, App, Button, Input, Select, Space, Switch, Tag } from 'antd'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'

import { ApiError, type Principal } from '../../api/auth'
import {
  certificatesApi,
  type CertificateAsset,
  type CertificateAssetBinding,
  type CertificateAssetVersion,
} from '../../api/certificates'
import {
  legacySiteTLSProtocols,
  siteTLSCipherPresets,
  siteTLSClientAuthModes,
  siteTLSCustomCipherSuites,
  siteTLSNeedsLegacyCiphers,
  siteTLSProtocolOrder,
  siteTLSVersionPreset,
  siteTLSVersionPresets,
  type SiteBasicConfig,
  type SiteTLSClientAuth,
  type SiteTLSVersionPreset,
} from '../../api/sites'
import '../../i18n/certificateAssets'
import '../../i18n/siteHttps'
import '../../i18n/siteTLS'
import '../../i18n/siteEditV4'
import { SiteTabSummary } from './SiteTabSummary'
import type { BasicValidationErrors } from './siteEditValidation'
import { useCommitRequest, useInstantFeedback } from './instantSave'
import { SettingRow, SettingSection } from './SiteEditFields'
import './HttpsSiteTab.css'
import { FeedbackWhen } from '@cdnca/ui'

interface CertificateChoice {
  asset: CertificateAsset
  version: CertificateAssetVersion
}

interface CertificateState {
  choices: CertificateChoice[]
  binding: CertificateAssetBinding | null
}

type BindingAttempt =
  | {
      kind: 'bind'
      assetID: string
      versionID: string
      expectedRevision: number
      idempotencyKey: string
      requestID: string
    }
  | {
      kind: 'unbind'
      assetID: string
      expectedRevision: number
      idempotencyKey: string
      requestID: string
    }

export interface HttpsWorkflowState {
  dirty: boolean
  uncertain: boolean
  pending: boolean
}

interface HttpsSiteTabProps {
  siteId: string
  siteScopeId?: string
  accessToken: string
  scopeKind: Principal['scope_kind']
  principalScopeId: string
  permissions: readonly string[]
  sessionEpoch: number
  value: SiteBasicConfig
  errors: BasicValidationErrors
  readOnly: boolean
  onChange: (value: SiteBasicConfig) => void
  onWorkflowStateChange?: (state: HttpsWorkflowState) => void
  /** be-gap-2: the site detail's https_certificate_bound (until the binding itself is read). */
  certificateBound?: boolean
  // the saved https_enabled (not the draft): warns when the draft turns a live HTTPS off
  savedHttpsEnabled?: boolean
}

function splitPorts(value: string): string[] {
  return value.split(/[\s,，]+/u).filter(Boolean)
}

function invalidCertificateResponse(): ApiError {
  return new ApiError('Invalid certificate response', 502, 'invalid_response')
}

function uncertainWrite(error: unknown): boolean {
  if (!(error instanceof ApiError)) return true
  return !(
    error.status >= 400 &&
    error.status < 500 &&
    error.status !== 408 &&
    error.status !== 429
  )
}

async function loadCertificateState(
  accessToken: string,
  siteId: string,
  expectedScopeID: string,
  targetScopeID?: string,
): Promise<CertificateState> {
  const assets: CertificateAsset[] = []
  const seen = new Set<string>()
  const limit = 100
  let page = 1
  let total = 0
  do {
    const result = await certificatesApi.listAssets(accessToken, targetScopeID, {
      page,
      limit,
      search: '',
    })
    total = result.total
    if (result.items.length === 0 && assets.length < total) throw invalidCertificateResponse()
    for (const asset of result.items) {
      if (asset.tenant_scope_id !== expectedScopeID || seen.has(asset.id)) {
        throw invalidCertificateResponse()
      }
      seen.add(asset.id)
      assets.push(asset)
    }
    page += 1
  } while (assets.length < total)

  const choices: CertificateChoice[] = []
  for (let start = 0; start < assets.length; start += 8) {
    const batch = await Promise.all(assets.slice(start, start + 8).map(async (asset) => {
      const detail = await certificatesApi.getAsset(accessToken, asset.id, targetScopeID)
      if (detail.asset.id !== asset.id || detail.asset.tenant_scope_id !== expectedScopeID) {
        throw invalidCertificateResponse()
      }
      const active = detail.versions
        .filter((version) => version.status === 'active')
        .sort((left, right) => right.version - left.version)[0]
      return active ? { asset: detail.asset, version: active } : null
    }))
    for (const choice of batch) {
      if (choice) choices.push(choice)
    }
  }

  let siteBinding: Awaited<ReturnType<typeof certificatesApi.getSiteBinding>> | null
  try {
    siteBinding = await certificatesApi.getSiteBinding(accessToken, siteId, targetScopeID)
  } catch (error) {
    if (
      error instanceof ApiError &&
      error.status === 404 &&
      error.code === 'certificate_site_binding_not_found'
    ) {
      siteBinding = null
    } else {
      throw error
    }
  }

  if (siteBinding) {
    const { binding, version } = siteBinding
    const choice = choices.find((candidate) =>
      candidate.asset.id === binding.asset_id && candidate.version.id === binding.version_id,
    )
    if (
      binding.tenant_scope_id !== expectedScopeID ||
      binding.site_id !== siteId ||
      !binding.bound ||
      version.tenant_scope_id !== expectedScopeID ||
      version.asset_id !== binding.asset_id ||
      version.id !== binding.version_id ||
      version.status !== 'active' ||
      !choice ||
      choice.version.version !== version.version ||
      choice.version.fingerprint_sha256 !== version.fingerprint_sha256
    ) {
      throw invalidCertificateResponse()
    }
  }

  choices.sort((left, right) => left.asset.name.localeCompare(right.asset.name, 'zh-CN'))
  return { choices, binding: siteBinding?.binding ?? null }
}

export default function HttpsSiteTab({
  siteId,
  siteScopeId,
  accessToken,
  scopeKind,
  principalScopeId,
  permissions,
  sessionEpoch,
  value,
  errors,
  readOnly,
  onChange,
  onWorkflowStateChange,
  certificateBound,
  savedHttpsEnabled,
}: HttpsSiteTabProps) {
  const { t } = useTranslation(['siteHttps', 'siteTLS', 'certificateAssets'])
  const { t: tV4 } = useTranslation('siteEditV4')
  const { modal } = App.useApp()
  const instant = useInstantFeedback()
  const navigate = useNavigate()
  const canReadCertificates = permissions.includes('certificates.read')
  const canManageCertificates = permissions.includes('certificates.manage')
  const effectiveScopeID = siteScopeId ?? (scopeKind === 'tenant' ? principalScopeId : undefined)
  const scopeReady = Boolean(effectiveScopeID) && (
    scopeKind !== 'tenant' || !siteScopeId || siteScopeId === principalScopeId
  )
  const targetScopeID = scopeKind === 'platform' ? effectiveScopeID : undefined
  const query = useQuery({
    queryKey: ['site-https-certificates', scopeKind, effectiveScopeID, siteId, sessionEpoch],
    queryFn: () => loadCertificateState(
      accessToken,
      siteId,
      effectiveScopeID ?? '',
      targetScopeID,
    ),
    // be-gap-2: the certificate is bound before HTTPS can be turned on, so it loads while HTTPS is off too.
    enabled: canReadCertificates && scopeReady,
    retry: false,
    refetchOnReconnect: false,
    refetchOnWindowFocus: false,
  })
  const [portsText, setPortsText] = useState(value.https_listen_ports.join(' '))
  const [portsEditing, setPortsEditing] = useState(false)
  const [selectedVersionID, setSelectedVersionID] = useState('')
  const [selectionTouched, setSelectionTouched] = useState(false)
  const [bindingAttempt, setBindingAttempt] = useState<BindingAttempt | null>(null)
  const [feedback, setFeedback] = useState<{ type: 'success' | 'warning' | 'error'; message: string } | null>(null)
  const currentVersionID = query.data?.binding?.version_id ?? ''
  const certificateDirty = selectionTouched && selectedVersionID !== currentVersionID
  // be-gap-2 WEB-C01/C05: HTTPS and forced HTTPS can only be turned on with a bound certificate (the
  // service refuses it too: validation_error certificate_required). Turning them off is always allowed.
  const bound = query.data ? query.data.binding !== null : certificateBound !== false

  useEffect(() => {
    if (!portsEditing) setPortsText(value.https_listen_ports.join(' '))
  }, [portsEditing, value.https_listen_ports])

  useEffect(() => {
    if (query.data && !selectionTouched && !bindingAttempt) {
      setSelectedVersionID(query.data.binding?.version_id ?? '')
    }
  }, [bindingAttempt, query.data, selectionTouched])

  const bindingMutation = useMutation({
    mutationFn: async (attempt: BindingAttempt) => {
      if (attempt.kind === 'bind') {
        const result = await certificatesApi.bindAsset(
          accessToken,
          attempt.assetID,
          {
            site_id: siteId,
            version_id: attempt.versionID,
            expected_revision: attempt.expectedRevision,
            default: true,
          },
          attempt.idempotencyKey,
          attempt.requestID,
          targetScopeID,
        )
        if (
          result.site_id !== siteId ||
          result.asset_id !== attempt.assetID ||
          result.version_id !== attempt.versionID ||
          !result.bound ||
          !result.default
        ) throw invalidCertificateResponse()
        return result
      }
      const result = await certificatesApi.unbindAsset(
        accessToken,
        attempt.assetID,
        siteId,
        { expected_revision: attempt.expectedRevision },
        attempt.idempotencyKey,
        attempt.requestID,
        targetScopeID,
      )
      if (result.site_id !== siteId || result.asset_id !== attempt.assetID || result.bound) {
        throw invalidCertificateResponse()
      }
      return result
    },
    onSuccess: (result, attempt) => {
      setBindingAttempt(null)
      setSelectionTouched(false)
      setSelectedVersionID(attempt.kind === 'bind' ? attempt.versionID : '')
      setFeedback(null)
      instant.success()
      // The re-read syncs the select (effect above) unless the user has chosen again meanwhile.
      void query.refetch()
      return result
    },
    onError: (error: unknown, attempt) => {
      if (error instanceof ApiError && error.status === 409) {
        setBindingAttempt(null)
        setSelectionTouched(false)
        setFeedback(null)
        instant.warning(t('feedback.conflict'))
        void query.refetch()
        return
      }
      if (uncertainWrite(error)) {
        setBindingAttempt(attempt)
        setFeedback({ type: 'warning', message: t('feedback.outcomeUnknown') })
        return
      }
      // fix-certinstant: a refused bind/unbind goes back to the server's current binding.
      setBindingAttempt(null)
      setSelectionTouched(false)
      setSelectedVersionID(query.data?.binding?.version_id ?? '')
      setFeedback(null)
      const permissionDenied = error instanceof ApiError && error.status === 403
      instant.failure(permissionDenied
        ? t('errors.permission')
        : error instanceof ApiError && error.code === 'invalid_response'
          ? t('errors.invalidResponse')
          : t('errors.request'))
    },
  })

  useEffect(() => {
    onWorkflowStateChange?.({
      dirty: certificateDirty,
      uncertain: bindingAttempt !== null,
      pending: bindingMutation.isPending,
    })
  }, [bindingAttempt, bindingMutation.isPending, certificateDirty, onWorkflowStateChange])

  useEffect(() => () => {
    onWorkflowStateChange?.({ dirty: false, uncertain: false, pending: false })
  }, [onWorkflowStateChange])

  const choicesByVersion = useMemo(
    () => new Map((query.data?.choices ?? []).map((choice) => [choice.version.id, choice])),
    [query.data?.choices],
  )
  const tlsProtocols = value.tls_protocols ?? []
  const tlsVersionPreset = siteTLSVersionPreset(value.tls_protocols)
  const legacyTLSProtocols = tlsProtocols.filter((protocol) =>
    legacySiteTLSProtocols.some((legacy) => legacy === protocol),
  )
  const unknownTLSProtocols = tlsProtocols.filter((protocol) =>
    !siteTLSProtocolOrder.some((known) => known === protocol) &&
    !legacySiteTLSProtocols.some((legacy) => legacy === protocol),
  )
  const cipherPreset = value.tls_cipher_preset ?? 'modern'
  const clientAuth: SiteTLSClientAuth = value.tls_client_auth ?? 'off'
  const chooseVersions = (preset: SiteTLSVersionPreset) => {
    if (siteConfigurationReadOnly) return
    const protocols = [...siteTLSVersionPresets[preset]]
    // TLSv1/TLSv1.1 handshakes need the legacy cipher list; leaving them
    // switches back to the modern list unless another was chosen.
    // The custom list is TLS 1.2 suites: a TLSv1.3-only site goes back to
    // modern.
    const preset_ = siteTLSNeedsLegacyCiphers(protocols)
      ? 'legacy'
      : cipherPreset === 'legacy' || cipherPreset === 'custom' && !protocols.includes('TLSv1.2') ? 'modern' : cipherPreset
    onChange({ ...value, tls_protocols: protocols, tls_cipher_preset: preset_,
      tls_cipher_suites: preset_ === 'custom' ? value.tls_cipher_suites : undefined })
  }
  // custom starts from the modern suites (a valid list) and keeps the
  // site's order; other presets send no list.
  const chooseCipherPreset = (preset: (typeof siteTLSCipherPresets)[number]) => {
    if (siteConfigurationReadOnly) return
    onChange({ ...value, tls_cipher_preset: preset,
      tls_cipher_suites: preset === 'custom' ? value.tls_cipher_suites ?? [...siteTLSCustomCipherSuites.slice(0, 6)] : undefined })
  }
  const siteConfigurationReadOnly = readOnly

  // fix-certinstant: choosing a certificate binds it, clearing the choice unbinds. useCommitRequest
  // sends once the previous write and its re-read are done, with the latest choice only.
  const commitCertificate = () => {
    if (readOnly || !canManageCertificates || !scopeReady || bindingAttempt || !query.data) return
    if (selectedVersionID === currentVersionID) {
      setSelectionTouched(false)
      return
    }
    const idempotencyKey = crypto.randomUUID()
    const requestID = crypto.randomUUID()
    if (!selectedVersionID) {
      const binding = query.data?.binding
      if (!binding) return
      bindingMutation.mutate({
        kind: 'unbind',
        assetID: binding.asset_id,
        expectedRevision: binding.revision,
        idempotencyKey,
        requestID,
      })
      return
    }
    const choice = choicesByVersion.get(selectedVersionID)
    if (!choice) return
    bindingMutation.mutate({
      kind: 'bind',
      assetID: choice.asset.id,
      versionID: choice.version.id,
      expectedRevision: query.data?.binding?.revision ?? 0,
      idempotencyKey,
      requestID,
    })
  }
  const certificateCommit = useCommitRequest(commitCertificate, bindingMutation.isPending || query.isFetching)
  const chooseCertificate = (versionID: string) => {
    if (readOnly || !canManageCertificates) return
    setSelectedVersionID(versionID)
    setSelectionTouched(true)
    setFeedback(null)
    certificateCommit.request()
  }
  const onCertificateChange = (versionID: string | undefined) => {
    // Unbinding leaves the HTTPS listener without a certificate: forced HTTPS and HSTS stop working.
    if (!versionID && query.data?.binding && (value.https_enabled || value.force_https)) {
      modal.confirm({
        title: t('certificate.unbindConfirmTitle'),
        content: t('certificate.unbindConfirm'),
        okText: t('certificate.unbindOk'),
        cancelText: t('certificate.unbindCancel'),
        okButtonProps: { danger: true },
        onOk: () => chooseCertificate(''),
      })
      return
    }
    chooseCertificate(versionID ?? '')
  }

  const certificateError = query.error instanceof ApiError && query.error.status === 403
    ? t('errors.permission')
    : query.error instanceof ApiError && query.error.code === 'invalid_response'
      ? t('errors.invalidResponse')
      : t('errors.load')

  const certificateRow = (
    <SettingRow label={t('certificate.label')} help={t('certificate.help')}>
      {!scopeReady ? (
        <Alert showIcon type="error" message={t('certificate.scopeMissing')} />
      ) : !canReadCertificates ? (
        <Alert showIcon type="info" message={t('certificate.unavailable')} />
      ) : query.isError ? (
        <FeedbackWhen title={certificateError} action={<Button size="small" onClick={() => void query.refetch()}>{t('actions.retry')}</Button>} />
      ) : (
        <>
          <Space.Compact className="site-https-certificate-control">
            <Select
              aria-label={t('certificate.label')}
              allowClear
              loading={query.isLoading || query.isFetching || bindingMutation.isPending}
              disabled={readOnly || !canManageCertificates || bindingMutation.isPending || bindingAttempt !== null}
              value={selectedVersionID || undefined}
              placeholder={t('certificate.placeholder')}
              notFoundContent={query.isLoading ? null : t('certificate.noAssets')}
              options={(query.data?.choices ?? []).map((choice) => ({
                value: choice.version.id,
                label: `${choice.asset.name} · ${choice.version.sans.join('、')}`,
              }))}
              onChange={onCertificateChange}
            />
          </Space.Compact>
          <div className="site-https-certificate-meta">
            {query.data?.binding ? (
              <Tag color="blue">{t('certificate.current')} #{query.data.binding.revision}</Tag>
            ) : null}
            {bindingMutation.isPending ? (
              <span role="status">{t(bindingMutation.variables?.kind === 'unbind' ? 'certificate.unbinding' : 'certificate.binding')}</span>
            ) : null}
            {bindingAttempt && !bindingMutation.isPending ? (
              <Button type="link" size="small" onClick={() => bindingMutation.mutate(bindingAttempt)}>
                {t('actions.retrySameRequest')}
              </Button>
            ) : null}
            <Button
              type="link"
              size="small"
              onClick={() => navigate(`/site/cert?domains=${encodeURIComponent(value.domains.join('\n'))}&site=${encodeURIComponent(siteId)}`)}
            >
              {t('certificate.manage')}
            </Button>
            {bindingAttempt ? (
              <Button
                type="link"
                size="small"
                onClick={() => {
                  setBindingAttempt(null)
                  setSelectionTouched(false)
                  setFeedback(null)
                  void query.refetch().then(() => {
                    setFeedback({ type: 'success', message: t('feedback.refreshed') })
                  })
                }}
              >
                {t('actions.refresh')}
              </Button>
            ) : null}
          </div>
        </>
      )}
      {feedback ? <Alert showIcon type={feedback.type} message={feedback.message} /> : null}
    </SettingRow>
  )

  return (
    <div className="site-edit-tab-panel site-https-tab">
      <SiteTabSummary items={[
        { key: 'https', label: t('access.label'), target: 'site-https-access', tone: value.https_enabled ? 'on' : 'off',
          value: value.https_enabled ? `${tV4('summary.on')} · ${value.https_listen_ports.join(' ') || '-'}` : tV4('summary.off') },
        { key: 'certificate', label: t('certificate.label'), target: 'site-https-access', tone: bound ? 'on' : 'warn',
          value: bound ? tV4('summary.https.bound') : tV4('summary.https.unbound') },
        ...(value.https_enabled ? [
          { key: 'force', label: t('force.label'), target: 'site-https-access', tone: (value.force_https ? 'on' : 'off') as 'on' | 'off',
            value: value.force_https ? tV4('summary.on') : tV4('summary.off') },
          { key: 'tls', label: t('tls.label'), target: 'site-https-protocol',
            value: tlsVersionPreset ? t(`siteTLS:versions.${tlsVersionPreset}`) : tlsProtocols.join(' ') || tV4('summary.none') },
          { key: 'http2', label: 'HTTP/2', target: 'site-https-versions', tone: ((value.http2_enabled ?? true) ? 'on' : 'off') as 'on' | 'off',
            value: (value.http2_enabled ?? true) ? tV4('summary.on') : tV4('summary.off') },
          { key: 'http3', label: 'HTTP/3', target: 'site-https-versions', tone: ((value.http3_enabled ?? true) ? 'on' : 'off') as 'on' | 'off',
            value: (value.http3_enabled ?? true) ? tV4('summary.on') : tV4('summary.off') },
        ] : []),
      ]} />
      <SettingSection title={t('title')} id="site-https-access">
        <SettingRow label={t('access.label')}>
          <div className="site-https-switch-line">
            <Switch
              aria-label={t('access.label')}
              checked={value.https_enabled}
              disabled={siteConfigurationReadOnly || (!bound && !value.https_enabled)}
              onChange={(checked) => {
                if (!siteConfigurationReadOnly) onChange({ ...value, https_enabled: checked })
              }}
            />
            <span>{t('access.help')}</span>
          </div>
          {!bound ? <Alert className="site-https-certificate-required" showIcon type="warning" message={t('access.certificateRequired')} /> : null}
          {/* site-parity4: turning a live HTTPS off says what stops working, next to the switch */}
          {savedHttpsEnabled && !value.https_enabled ? (
            <Alert className="site-https-off-warning" showIcon type="error" message={tV4('summary.https.offWarning')} />
          ) : null}
        </SettingRow>

        {!value.https_enabled ? (
          <>
            <div className="site-https-disabled-note" role="status">{t('access.disabled')}</div>
            {certificateRow}
          </>
        ) : (
          <>
            <SettingRow label={t('ports.label')} help={t('ports.help')}>
              <Input
                aria-label={t('ports.label')}
                status={errors.https_listen_ports ? 'error' : undefined}
                disabled={siteConfigurationReadOnly}
                value={portsText}
                placeholder={t('ports.placeholder')}
                onFocus={() => setPortsEditing(true)}
                onBlur={() => {
                  setPortsEditing(false)
                  setPortsText(value.https_listen_ports.join(' '))
                }}
                onChange={(event) => {
                  if (siteConfigurationReadOnly) return
                  setPortsText(event.target.value)
                  onChange({ ...value, https_listen_ports: splitPorts(event.target.value) })
                }}
              />
              {errors.https_listen_ports ? <span className="site-field-error">{errors.https_listen_ports}</span> : null}
            </SettingRow>

            <SettingRow label={t('force.label')} help={t('force.help')}>
              <Space wrap>
                <Switch
                  aria-label={t('force.label')}
                  checked={value.force_https ?? false}
                  disabled={siteConfigurationReadOnly || (!bound && !(value.force_https ?? false))}
                  onChange={(checked) => {
                    if (!siteConfigurationReadOnly) onChange({ ...value, force_https: checked })
                  }}
                />
                <Select
                  aria-label={t('force.port')}
                  style={{ minWidth: 160 }}
                  disabled={siteConfigurationReadOnly || !(value.force_https ?? false)}
                  value={value.https_listen_ports.includes(String(value.https_redirect_port ?? 0)) ? value.https_redirect_port : 0}
                  options={[
                    { value: 0, label: t('force.firstPort') },
                    ...value.https_listen_ports.map((port) => ({ value: Number(port), label: port })),
                  ]}
                  onChange={(port: number) => {
                    if (!siteConfigurationReadOnly) onChange({ ...value, https_redirect_port: port })
                  }}
                />
              </Space>
            </SettingRow>

            <h3 className="site-https-subsection" id="site-https-protocol">{tV4('summary.https.protocolSection')}</h3>
            <SettingRow label={t('tls.label')} help={t('siteTLS:field.help')}>
              <Select<SiteTLSVersionPreset>
                aria-label={t('tls.label')}
                status={errors.tls_protocols ? 'error' : undefined}
                disabled={siteConfigurationReadOnly}
                value={tlsVersionPreset ?? undefined}
                placeholder={tlsProtocols.join(' ')}
                options={(Object.keys(siteTLSVersionPresets) as SiteTLSVersionPreset[]).map((preset) => ({
                  value: preset,
                  label: t(`siteTLS:versions.${preset}`),
                }))}
                onChange={chooseVersions}
              />
              {legacyTLSProtocols.length > 0 ? (
                <Alert
                  showIcon
                  type="error"
                  message={t('siteTLS:legacy.title')}
                  description={t('siteTLS:legacy.description', { protocols: legacyTLSProtocols.join(', ') })}
                />
              ) : null}
              {unknownTLSProtocols.length > 0 ? (
                <Alert
                  showIcon
                  type="warning"
                  message={t('siteTLS:unknown.title')}
                  description={t('siteTLS:unknown.description', { protocols: unknownTLSProtocols.join(', ') })}
                />
              ) : null}
              {siteTLSNeedsLegacyCiphers(value.tls_protocols) ? (
                <Alert showIcon type="warning" message={t('siteTLS:versions.legacyWarning')} />
              ) : null}
              {errors.tls_protocols ? <span className="site-field-error">{errors.tls_protocols}</span> : null}
            </SettingRow>

            <SettingRow label={t('siteTLS:ciphers.label')} help={t('siteTLS:ciphers.help')}>
              <Select
                aria-label={t('siteTLS:ciphers.label')}
                disabled={siteConfigurationReadOnly}
                value={cipherPreset}
                options={siteTLSCipherPresets.map((preset) => ({
                  value: preset,
                  label: t(`siteTLS:ciphers.${preset}`),
                  // TLSv1/TLSv1.1 need the legacy list; custom is TLS 1.2 suites.
                  disabled: siteTLSNeedsLegacyCiphers(value.tls_protocols) && preset !== 'legacy' ||
                    preset === 'custom' && !(value.tls_protocols ?? ['TLSv1.2']).includes('TLSv1.2'),
                }))}
                onChange={chooseCipherPreset}
              />
            </SettingRow>
            {cipherPreset === 'custom' ? (
              <SettingRow label={t('siteTLS:ciphers.customLabel')} help={t('siteTLS:ciphers.customHelp')}>
                <Select<string[]>
                  mode="multiple"
                  aria-label={t('siteTLS:ciphers.customLabel')}
                  disabled={siteConfigurationReadOnly}
                  value={value.tls_cipher_suites ?? []}
                  options={siteTLSCustomCipherSuites.map((suite) => ({ value: suite, label: suite }))}
                  onChange={(suites) => {
                    if (!siteConfigurationReadOnly) onChange({ ...value, tls_cipher_suites: suites })
                  }}
                />
                <Alert showIcon type="info" message={t('siteTLS:ciphers.customSafeOnly')} />
                {errors.tls_cipher_suites ? <span className="site-field-error">{errors.tls_cipher_suites}</span> : null}
              </SettingRow>
            ) : null}

            <SettingRow label={t('siteTLS:ocsp.label')} help={t('siteTLS:ocsp.help')}>
              <Switch
                aria-label={t('siteTLS:ocsp.label')}
                checked={value.tls_ocsp_stapling ?? false}
                disabled={siteConfigurationReadOnly}
                onChange={(checked) => {
                  if (!siteConfigurationReadOnly) onChange({ ...value, tls_ocsp_stapling: checked })
                }}
              />
            </SettingRow>

            <SettingRow label={t('siteTLS:preferServerCiphers.label')} help={t('siteTLS:preferServerCiphers.help')}>
              <Select<'preset' | 'on' | 'off'>
                aria-label={t('siteTLS:preferServerCiphers.label')}
                disabled={siteConfigurationReadOnly}
                value={value.tls_prefer_server_ciphers == null ? 'preset' : value.tls_prefer_server_ciphers ? 'on' : 'off'}
                options={[
                  { value: 'preset', label: t('siteTLS:preferServerCiphers.preset', {
                    state: t(cipherPreset === 'modern' ? 'siteTLS:preferServerCiphers.off' : 'siteTLS:preferServerCiphers.on'),
                  }) },
                  { value: 'on', label: t('siteTLS:preferServerCiphers.on') },
                  { value: 'off', label: t('siteTLS:preferServerCiphers.off') },
                ]}
                onChange={(choice) => {
                  if (!siteConfigurationReadOnly) onChange({ ...value, tls_prefer_server_ciphers: choice === 'preset' ? null : choice === 'on' })
                }}
              />
            </SettingRow>

            <h3 className="site-https-subsection" id="site-https-versions">{tV4('summary.https.versionsSection')}</h3>
            <SettingRow label={t('siteTLS:http2.label')} help={t('siteTLS:http2.help')}>
              <Switch
                aria-label={t('siteTLS:http2.label')}
                checked={value.http2_enabled ?? true}
                disabled={siteConfigurationReadOnly}
                onChange={(checked) => {
                  if (!siteConfigurationReadOnly) onChange({ ...value, http2_enabled: checked })
                }}
              />
            </SettingRow>

            <SettingRow label={t('siteTLS:http3.label')} help={t('siteTLS:http3.help')}>
              <Switch
                aria-label={t('siteTLS:http3.label')}
                checked={value.http3_enabled ?? true}
                disabled={siteConfigurationReadOnly}
                onChange={(checked) => {
                  if (!siteConfigurationReadOnly) onChange({ ...value, http3_enabled: checked })
                }}
              />
            </SettingRow>

            <SettingRow label={t('siteTLS:clientAuth.label')} help={t('siteTLS:clientAuth.help')}>
              <Select<SiteTLSClientAuth>
                aria-label={t('siteTLS:clientAuth.label')}
                disabled={siteConfigurationReadOnly}
                value={clientAuth}
                options={siteTLSClientAuthModes.map((mode) => ({ value: mode, label: t(`siteTLS:clientAuth.${mode}`) }))}
                onChange={(mode) => {
                  if (siteConfigurationReadOnly) return
                  onChange({ ...value, tls_client_auth: mode, tls_client_ca_pem: mode === 'off' ? '' : value.tls_client_ca_pem ?? '' })
                }}
              />
              {clientAuth !== 'off' ? (
                <Input.TextArea
                  aria-label={t('siteTLS:clientAuth.ca')}
                  status={errors.tls_client_ca_pem ? 'error' : undefined}
                  disabled={siteConfigurationReadOnly}
                  autoSize={{ minRows: 4, maxRows: 12 }}
                  spellCheck={false}
                  placeholder="-----BEGIN CERTIFICATE-----"
                  value={value.tls_client_ca_pem ?? ''}
                  onChange={(event) => {
                    if (!siteConfigurationReadOnly) onChange({ ...value, tls_client_ca_pem: event.target.value })
                  }}
                />
              ) : null}
              {errors.tls_client_ca_pem ? <span className="site-field-error">{errors.tls_client_ca_pem}</span> : null}
            </SettingRow>

            {certificateRow}
          </>
        )}
      </SettingSection>
    </div>
  )
}
