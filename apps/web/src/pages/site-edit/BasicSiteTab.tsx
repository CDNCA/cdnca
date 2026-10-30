import { useEffect, useState } from 'react'
import { Button, Input, InputNumber, Modal, Popconfirm, Radio, Select, Switch, Tag, Tooltip } from 'antd'
import { CircleHelp, Clipboard, Globe2, Pencil, Plus, ShieldCheck, Trash2 } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import '../../i18n/siteTransfer'
import { useSearchParams } from 'react-router-dom'
import { MODAL_WIDTH, ModalFooter } from '@cdnca/ui'

import {
  backupOriginLines,
  canonicalSiteDomains,
  expandBackupOrigins,
  inheritedOriginPort,
  parseOriginLine,
  type OriginBalanceMethod,
  type OriginFailbackMode,
  type SiteBasicConfig,
  type SiteDetail,
  type SiteOrigin,
  type SiteOriginPool,
  type SiteStatus,
  withInheritedOriginPorts,
} from '../../api/sites'
import type { AppRole } from '../../auth/session'
import { formatDateTime } from '../../i18n/formatters'
import '../../i18n/cnameAllocations'
import '../../i18n/siteListenerDomains'
import type { BasicValidationErrors } from './siteEditValidation'
import BalanceKeyFields from './BalanceKeyFields'
import BalanceMethodChoices from './BalanceMethodChoices'
import { FormRow } from './SiteEditFields'
import { SiteTabSummary } from './SiteTabSummary'
import { SiteOriginStatusCard } from './SiteOriginStatusCard'
import CnameFailureReason from './CnameFailureReason'
import CnameFailureActions from './CnameFailureActions'
import { cnameFailureText } from './cnameFailureText'
import { SiteGroupSelect } from './SitePackageGroupSelects'
import '../../i18n/siteOriginForwarding'
import '../../i18n/originWeight'
import { weightShares } from '../originWeightShare'
import './BasicSiteTab.css'

const statusLabels: Record<SiteStatus, { color: string }> = {
  active: { color: 'success' },
  disabled: { color: 'default' },
  package_expired: { color: 'warning' },
  traffic_exceeded: { color: 'warning' },
  locked: { color: 'error' },
  syncing: { color: 'processing' },
  sync_failed: { color: 'error' },
}

// A new origin uses the pool's 回源端口 (the competitor's 源地址 without a port).
const emptyOrigin: SiteOrigin = { host: '', port: 80, weight: 1, enabled: true, level: 0, max_conns: 0, port_inherited: true }

function dateText(value: string, language: string, placeholder: string): string {
  return formatDateTime(value, language) || value || placeholder
}

// textBackups is the box's text as the backup list it saves to.
function textBackups(text: string): string {
  return backupOriginLines(expandBackupOrigins({ origins: [], backup_origins: text.split('\n') }).origins).join('\n')
}

// backupLinesError: the first malformed line, or more than 15 backups.
function backupLinesError(text: string): { key: 'backupInvalid' | 'backupTooMany'; line?: number } | null {
  const lines = text.split('\n')
  for (const [index, line] of lines.entries()) {
    if (line.trim() && !parseOriginLine(line)) return { key: 'backupInvalid', line: index + 1 }
  }
  return textBackups(text).split('\n').filter(Boolean).length > 15 ? { key: 'backupTooMany' } : null
}

function splitValues(value: string): string[] {
  return value.split(/[\s,]+/u).map((item) => item.trim()).filter(Boolean)
}

export interface BasicSiteTabProps {
  detail: SiteDetail
  role: AppRole
  value: SiteBasicConfig
  originPool: SiteOriginPool
  errors: BasicValidationErrors
  originError?: string
  readOnly?: boolean
  canManageDNS?: boolean
  originReadOnly?: boolean
  onChange: (value: SiteBasicConfig) => void
  onOriginChange: (value: SiteOriginPool) => void
  onBlockedAction: (action: string) => void
  // The origin status card (probe state, switch back); absent in tests
  // that do not cover it.
  accessToken?: string
  canManageOrigins?: boolean
  // The site's tenant scope (platform: the site's, tenant: its own) for the
  // group select; absent: it shows only the current value.
  selectScopeID?: string
  // 更换所属用户 (platform administrator): opens the transfer dialog.
  onTransfer?: () => void
}

export default function BasicSiteTab({
  detail,
  role,
  value,
  originPool,
  errors,
  originError,
  readOnly = false,
  canManageDNS = false,
  originReadOnly = false,
  onChange,
  onOriginChange,
  accessToken,
  canManageOrigins = false,
  selectScopeID,
  onTransfer,
}: BasicSiteTabProps) {
  const { t, i18n } = useTranslation(['sites', 'cnameAllocations', 'siteOriginForwarding'])
  const { t: tW } = useTranslation('originWeight')
  const { t: tCname } = useTranslation('siteCnameRegeneration')
  const { t: tV4 } = useTranslation('siteEditV4')
  const { t: tTransfer } = useTranslation('siteTransfer')
  const cnameReason = cnameFailureText(value.cname_failure_code, value.cname_domain, tCname, i18n.exists, role === 'admin')
  const [, setSearchParams] = useSearchParams()
  // Turning HTTPS off is always allowed; turning it on needs a bound certificate (the service refuses it too).
  const httpsLocked = detail.https_certificate_bound === false && !value.https_enabled
  const language = i18n.resolvedLanguage ?? i18n.language
  const [newDomain, setNewDomain] = useState('')
  const [domainsOpen, setDomainsOpen] = useState(false)
  const [domainsDraft, setDomainsDraft] = useState('')
  const [cnameOpen, setCnameOpen] = useState(false)
  const [cnameDomain, setCnameDomain] = useState('')
  const [cnameHostname, setCnameHostname] = useState('')
  const [originOpen, setOriginOpen] = useState(false)
  const [originDraft, setOriginDraft] = useState<SiteOrigin>(emptyOrigin)
  const [editingOrigin, setEditingOrigin] = useState<number | null>(null)
  // The backup box keeps what the user typed (blank lines, order); the pool
  // carries the levels it expands to.
  const savedBackups = backupOriginLines(originPool.origins).join('\n')
  const [backupText, setBackupText] = useState(savedBackups)
  useEffect(() => {
    // a reset or a saved pool replaces the box unless it already says the same
    setBackupText((current) => textBackups(current) === savedBackups ? current : savedBackups)
  }, [savedBackups])
  const primaries = originPool.origins.map((origin, index) => ({ origin, index })).filter(({ origin }) => (origin.level ?? 0) === 0)
  const backupError = backupLinesError(backupText)
  const changeBackups = (text: string) => {
    setBackupText(text)
    const primaryOrigins = originPool.origins.filter((origin) => (origin.level ?? 0) === 0)
    onOriginChange(expandBackupOrigins({ ...originPool, origins: primaryOrigins, backup_origins: text.split('\n') }))
  }
  const status = statusLabels[value.status]
  // Each origin's share within its level (backups are their own levels)
  const shares = weightShares(originPool.origins)
  const leastConn = originPool.balance_method === 'least_conn'
  const shareText = (share: number | null) => share === null ? tW('disabled') : tW(leastConn ? 'shareLeastConn' : 'share', { share })
  const draftShare = (() => {
    if (!originDraft.enabled) return tW('draftDisabled')
    const origins = originPool.origins.map((origin) => ({ ...origin }))
    const draft = { ...originDraft, level: originDraft.level ?? 0 }
    if (editingOrigin === null) origins.push(draft)
    else origins[editingOrigin] = draft
    const share = weightShares(origins)[editingOrigin ?? origins.length - 1] ?? 0
    return tW(leastConn ? 'draftShareLeastConn' : 'draftShare', { share })
  })()
  const enabledOrigins = originPool.origins.filter((origin) => origin.enabled).length
  const healthCheckEnabled = originPool.failover_tries > 1
  const changeBalance = (balanceMethod: OriginBalanceMethod) => {
    // The key fields exist only for their method; the server rejects them otherwise.
    const { hash_key: hashKey, sticky, ...rest } = originPool
    onOriginChange({
      ...rest, balance_method: balanceMethod,
      ...(balanceMethod === 'hash' ? { hash_key: hashKey || '$remote_addr' } : {}),
      ...(balanceMethod === 'sticky' ? { sticky: sticky ?? { source: 'cookie', name: 'cdnca_route' } } : {}),
    })
  }

  // TECH-04: a block's head (changes save themselves, no save button).
  const blockHead = (block: 'basic' | 'origin', id: string) => (
    <div className="site-basic-block-head">
      <h2 id={id}>{t(block === 'basic' ? 'edit.saveScope.blocks.basic' : 'edit.saveScope.blocks.origin')}</h2>
    </div>
  )

  const goToTab = (tab: 'origin' | 'https', conditional = false) => {
    setSearchParams((current) => {
      const next = new URLSearchParams(current)
      next.set('tab', tab)
      if (conditional) next.set('conditional', '1')
      return next
    })
  }

  const updateDomains = (raw: string) => {
    const draft = splitValues(raw)
    onChange({ ...value, domains: canonicalSiteDomains(draft) ?? draft })
  }

  const addDomain = () => {
    const draft = splitValues(newDomain)
    if (draft.length === 0) return
    const domains = [...value.domains, ...draft]
    onChange({ ...value, domains: canonicalSiteDomains(domains) ?? domains })
    setNewDomain('')
  }

  const closeOrigin = () => { setOriginOpen(false); setEditingOrigin(null) }

  const saveOrigin = () => {
    const nextOrigin = { ...originDraft, host: originDraft.host.trim() }
    if (!nextOrigin.host) return
    const origins = originPool.origins.map((origin) => ({ ...origin }))
    if (editingOrigin === null) origins.push(nextOrigin)
    else origins[editingOrigin] = nextOrigin
    onOriginChange(withInheritedOriginPorts({ ...originPool, origins }))
    setOriginDraft(emptyOrigin)
    setEditingOrigin(null)
    setOriginOpen(false)
  }

  return (
    <div className="site-edit-tab-panel site-basic-panel">
      <SiteTabSummary items={[
        { key: 'status', label: t('edit.basic.fields.status'), value: t(`states.${value.status}`), target: 'site-basic-settings',
          tone: value.status === 'active' ? 'on' : value.status === 'disabled' ? 'off' : 'warn' },
        { key: 'cname', label: t('edit.basic.fields.cname'), target: 'site-basic-settings', tone: value.cname_state === 'failed' ? 'error' : 'plain',
          value: value.cname || (value.cname_state === 'failed' ? tV4('summary.basic.cnameFailed') : t('values.placeholder')) },
        { key: 'domains', label: t('edit.basic.sections.domains'), target: 'site-basic-domains',
          value: value.domains.length === 1 ? value.domains[0] : t('edit.basic.counts.domains', { count: value.domains.length }) },
        { key: 'https', label: 'HTTPS', target: 'site-basic-access', tone: value.https_enabled ? 'on' : 'off',
          value: value.https_enabled ? tV4('summary.on') : tV4('summary.off') },
        { key: 'origins', label: t('edit.basic.sections.originList'), target: 'site-basic-origins',
          value: tV4('summary.basic.origins', { primary: primaries.length, backup: originPool.origins.length - primaries.length }) },
      ]} />
      <section className="site-basic-block" aria-labelledby="site-basic-block-basic">
      {blockHead('basic', 'site-basic-block-basic')}
      <section className="site-basic-section" id="site-basic-settings">
        <h3>{t('edit.basic.sections.settings')}</h3>
        <div className="site-basic-facts">
          {onTransfer ? (
            <div className="site-basic-fact">
              <span>{tTransfer('owner')}</span>
              <strong>{detail.owner?.display_name || t('values.placeholder')}</strong>
              <Button type="link" size="small" disabled={readOnly} onClick={onTransfer}>{tTransfer('action')}</Button>
            </div>
          ) : null}
          <div className="site-basic-fact">
            <span>{t('edit.basic.fields.status')}</span>
            <Tag color={status.color}>{t(`states.${value.status}`)}</Tag>
          </div>
          <div className="site-basic-fact">
            <span>{t('edit.basic.fields.createdAt')}</span>
            <strong>{dateText(detail.created_at, language, t('values.placeholder'))}</strong>
          </div>
          <div className="site-basic-fact">
            <span>{t('edit.basic.fields.updatedAt')}</span>
            <strong>{dateText(detail.updated_at, language, t('values.placeholder'))}</strong>
          </div>
          <label className="site-basic-fact">
            <span>{t('edit.basic.fields.group')}</span>
            {selectScopeID ? (
              <SiteGroupSelect accessToken={accessToken} scopeID={selectScopeID}
                value={value} readOnly={readOnly} onChange={onChange} />
            ) : (
              <Select aria-label={t('edit.basic.fields.group')} value={value.group_id} allowClear disabled={readOnly} placeholder={t('edit.basic.selectPlaceholder')} options={value.group_id ? [{ value: value.group_id, label: value.group_name || value.group_id }] : []} onChange={(groupId) => onChange({ ...value, group_id: groupId ?? null })} />
            )}
          </label>
          <div className="site-basic-fact">
            <span>{t('edit.basic.fields.cname')}</span>
            <div className="site-basic-cname">
              {value.cname || value.cname_state !== 'failed' ? <strong>{value.cname || (value.cname_state === 'pending' ? tCname('cell.pending') : t('values.placeholder'))}</strong> : null}
              {/* CNAME state next to the CNAME itself (it used to be an Alert at the bottom of the tab). */}
              {value.cname && value.cname_state === 'pending' ? <Tag color="processing">{t('cnameAllocations:states.pending')}</Tag> : null}
              {value.cname_state === 'failed' ? <CnameFailureActions code={value.cname_failure_code} reason={cnameReason} admin={role === 'admin'} siteID={detail.id} onRegenerate={canManageDNS ? () => onChange({ ...value, cname_regenerate: true }) : undefined} regenerateDisabled={readOnly} extraDetail={accessToken && (role !== 'admin' || detail.scope_id) ? <CnameFailureReason accessToken={accessToken} siteID={detail.id} audience={role === 'admin' ? { kind: 'platform', scopeID: detail.scope_id! } : { kind: 'tenant' }} /> : null} /> : null}
              {value.cname ? (
                <Tooltip title={t('edit.basic.actions.copyCname')}>
                  <Button type="text" size="small" aria-label={t('edit.basic.actions.copyCname')} icon={<Clipboard size={14} aria-hidden="true" />} onClick={() => { if (navigator.clipboard) void navigator.clipboard.writeText(value.cname) }} />
                </Tooltip>
              ) : null}
              {role === 'admin' ? (
                <Button
                  type="link"
                  size="small"
                  disabled={readOnly || !canManageDNS}
                  onClick={() => {
                    setCnameDomain(value.cname_domain ?? '')
                    setCnameHostname(value.cname_hostname ?? '')
                    setCnameOpen(true)
                  }}
                >
                  {t('edit.actions.changeCname')}
                </Button>
              ) : null}
            </div>
          </div>
        </div>
      </section>

      <section className="site-basic-section" id="site-basic-domains">
        <div className="site-basic-section-heading">
          <div>
            <div className="site-basic-title-line"><h3>{t('edit.basic.sections.domains')}</h3><span>{t('edit.basic.counts.domains', { count: value.domains.length })}</span></div>
            <p>{t('edit.basic.help.domains')}</p>
          </div>
          <Button disabled={readOnly} onClick={() => { setDomainsDraft(value.domains.join('\n')); setDomainsOpen(true) }}>
            {t('edit.basic.actions.batchDomains')}
          </Button>
        </div>
        <Input
          className="site-basic-domain-source"
          aria-label={t('edit.basic.fields.domain')}
          status={errors.domains ? 'error' : undefined}
          disabled={readOnly}
          value={value.domains.join(' ')}
          onChange={(event) => {
            const draft = splitValues(event.target.value)
            const inputType = (event.nativeEvent as InputEvent).inputType
            const partial = inputType === 'insertText' && draft.some((domain) => domain === '*' || domain.endsWith('.'))
            onChange({ ...value, domains: partial ? draft : canonicalSiteDomains(draft) ?? draft })
          }}
        />
        <div className="site-basic-domain-editor">
          <div className="site-basic-domain-tags">
            {value.domains.map((domain) => (
              <Tag key={domain} closable={!readOnly} onClose={(event) => { event.preventDefault(); onChange({ ...value, domains: value.domains.filter((item) => item !== domain) }) }}>
                <Globe2 size={13} aria-hidden="true" />
                {domain}
              </Tag>
            ))}
          </div>
          <div className="site-basic-domain-add">
            <Input aria-label={t('edit.basic.aria.newDomain')} disabled={readOnly} value={newDomain} placeholder={t('edit.basic.placeholders.domain')} onChange={(event) => setNewDomain(event.target.value)} onPressEnter={addDomain} />
            <Button type="primary" aria-label={t('edit.basic.aria.addDomain')} disabled={readOnly || !newDomain.trim()} icon={<Plus size={15} aria-hidden="true" />} onClick={addDomain} />
          </div>
        </div>
        {errors.domains ? <span className="site-field-error">{errors.domains}</span> : null}
        <div className="site-basic-ipv6-row">
          <div><strong>{t('edit.basic.fields.cacheShared')}</strong><p>{t('edit.basic.help.cacheShared')}</p></div>
          <Switch aria-label={t('edit.basic.aria.cacheShared')} checked={value.cache_shared_across_domains ?? false} disabled={readOnly} onChange={(checked) => onChange({ ...value, cache_shared_across_domains: checked })} />
        </div>
      </section>

      <section className="site-basic-section" id="site-basic-access">
        <h3>{t('edit.basic.sections.access')}</h3>
        <div className="site-basic-access-grid">
          <article className="site-basic-access-card">
            <div className="site-basic-access-icon"><Globe2 size={19} aria-hidden="true" /></div>
            <div className="site-basic-access-content">
              <div className="site-basic-access-title">
                <strong>HTTP</strong>
                {/* PJ-C03: HTTP listening is required (the service rejects http_enabled=false and every
                    site keeps at least one HTTP port), so the switch is shown on and fixed, with the reason. */}
                <Tooltip title={t('edit.basic.help.httpRequired')}><Switch aria-label={t('edit.basic.aria.httpEnabled')} checked disabled /></Tooltip>
              </div>
              <p>{t('edit.basic.status.http', { state: t('edit.basic.values.open'), ports: value.http_listen_ports.join(', ') || t('values.placeholder') })}</p>
              <div className="site-basic-access-ports">
                <span>{t('edit.basic.fields.listenPorts')}</span>
                <Input aria-label={t('edit.basic.aria.httpPorts')} status={errors.http_listen_ports ? 'error' : undefined} disabled={readOnly} value={value.http_listen_ports.join(' ')} placeholder={t('edit.basic.placeholders.ports')} onChange={(event) => onChange({ ...value, http_listen_ports: splitValues(event.target.value) })} />
              </div>
              {errors.http_listen_ports ? <span className="site-field-error">{errors.http_listen_ports}</span> : null}
              <div className="site-basic-access-ports">
                <span>IPv6</span>
                <div className="site-basic-access-ipv6">
                  <Switch aria-label={t('edit.basic.aria.ipv6Enabled')} checked={value.ipv6_enabled} disabled={readOnly} onChange={(checked) => onChange({ ...value, ipv6_enabled: checked })} />
                  <Tag color={detail.listener_state.ipv6_runtime_state === 'active' ? 'success' : detail.listener_state.ipv6_runtime_state === 'failed' ? 'error' : 'default'}>{t(`edit.basic.runtime.${detail.listener_state.ipv6_runtime_state}`)}</Tag>
                  <Tooltip title={t('edit.basic.help.ipv6')}><span className="site-form-row-tip" role="img" tabIndex={0} aria-label={t('edit.basic.help.ipv6')}><CircleHelp size={14} aria-hidden="true" /></span></Tooltip>
                </div>
              </div>
            </div>
          </article>
          <article className="site-basic-access-card">
            <div className="site-basic-access-icon is-secure"><ShieldCheck size={19} aria-hidden="true" /></div>
            <div className="site-basic-access-content">
              <div className="site-basic-access-title">
                <strong>HTTPS</strong>
                {/* be-gap-2 WEB-C01/C05: HTTPS is only turned on with a bound certificate (bound in HTTPS settings). */}
                <Tooltip title={httpsLocked ? t('edit.basic.help.httpsCertificateRequired') : undefined}>
                  <Switch aria-label={t('edit.basic.aria.httpsEnabled')} checked={value.https_enabled} disabled={readOnly || httpsLocked} onChange={(checked) => onChange({ ...value, https_enabled: checked })} />
                </Tooltip>
              </div>
              <p>{t('edit.basic.status.https', { state: value.https_enabled ? t('edit.basic.values.open') : t('edit.basic.values.closed'), ports: value.https_listen_ports.join(', ') || t('values.placeholder') })}</p>
              {value.https_enabled ? (
                <div className="site-basic-access-ports">
                  <span>{t('edit.basic.fields.listenPorts')}</span>
                  <Input aria-label={t('edit.basic.aria.httpsPorts')} status={errors.https_listen_ports ? 'error' : undefined} disabled={readOnly} value={value.https_listen_ports.join(' ')} placeholder={t('edit.basic.placeholders.ports')} onChange={(event) => onChange({ ...value, https_listen_ports: splitValues(event.target.value) })} />
                </div>
              ) : (
                <p className="site-basic-access-hint">{t(detail.https_certificate_bound === false ? 'edit.basic.help.httpsCertificateRequired' : 'edit.basic.help.httpsClosed')}</p>
              )}
              <div className="site-basic-access-actions">
                <Button size="small" onClick={() => goToTab('https')}>{t('edit.basic.actions.httpsSettings')}</Button>
              </div>
              {errors.https_listen_ports ? <span className="site-field-error">{errors.https_listen_ports}</span> : null}
            </div>
          </article>
        </div>
      </section>
      </section>

      <section className="site-basic-block" aria-labelledby="site-basic-block-origin">
      {blockHead('origin', 'site-basic-block-origin')}
      <section className="site-basic-section" id="site-basic-origins">
        {/* 源站列表与备用源两列并排（原来上下各占一整行）。 */}
        <div className="site-basic-origin-pair">
        <div className="site-basic-origin-primary">
        <div className="site-basic-section-heading">
          <div><div className="site-basic-title-line"><h3>{t('edit.basic.sections.originList')}</h3><span>{t('edit.basic.counts.origins', { count: originPool.origins.length })}</span>
            <Tooltip title={<>{tW('help')}<br />{tW(`method.${originPool.balance_method}`)}</>}><span className="site-form-row-tip" role="img" tabIndex={0} aria-label={tW('tipLabel')}><CircleHelp size={14} aria-hidden="true" /></span></Tooltip>
          </div><p>{t('edit.basic.help.originList')}</p><p id="site-origin-weight-help" className="site-basic-weight-help">{tW('help')} {tW(`method.${originPool.balance_method}`)}</p></div>
          <Button type="primary" aria-label={t('edit.actions.addOrigin')} disabled={originReadOnly} icon={<Plus size={15} aria-hidden="true" />} onClick={() => { setOriginDraft(emptyOrigin); setEditingOrigin(null); setOriginOpen(true) }}>
            {t('edit.basic.actions.addOriginShort')}
          </Button>
        </div>
        <div className={originError ? 'site-basic-origin-list has-error' : 'site-basic-origin-list'}>
          {primaries.map(({ origin, index }) => (
            <div className="site-basic-origin-row" key={`${origin.host}:${origin.port}:${index}`}>
              <div className="site-basic-origin-index">#{index + 1}</div>
              <div className="site-basic-origin-address"><strong>{origin.host.includes(':') ? `[${origin.host}]:${origin.port}` : `${origin.host}:${origin.port}`}</strong><span>{t('edit.basic.origin.meta', { weight: origin.weight })}{' · '}{shareText(shares[index])}</span></div>
              <Tag color={origin.enabled ? 'success' : 'default'}>{origin.enabled ? t('edit.basic.origin.enabled') : t('edit.basic.origin.disabled')}</Tag>
              <Tooltip title={t('actions.edit')}>
                <Button type="text" aria-label={t('actions.edit')} disabled={originReadOnly} icon={<Pencil size={15} aria-hidden="true" />} onClick={() => { setEditingOrigin(index); setOriginDraft({ ...origin }); setOriginOpen(true) }} />
              </Tooltip>
              <Popconfirm title={t('edit.confirm.deleteOrigin')} okText={t('actions.delete')} cancelText={t('actions.cancel')} disabled={originReadOnly} onConfirm={() => onOriginChange({ ...originPool, origins: originPool.origins.filter((_, itemIndex) => itemIndex !== index) })}>
                <Tooltip title={t('actions.delete')}><Button type="text" danger aria-label={t('actions.delete')} disabled={originReadOnly} icon={<Trash2 size={15} aria-hidden="true" />} /></Tooltip>
              </Popconfirm>
            </div>
          ))}
        </div>
        {originError ? <span className="site-field-error">{originError}</span> : null}
        </div>
        <div className="site-basic-backup-origins">
          <label htmlFor="site-backup-origins" className="site-basic-title-line"><h3>{t('siteOriginForwarding:fields.backupOrigins')}</h3></label>
          <Input.TextArea id="site-backup-origins" aria-describedby="site-backup-origins-help" status={backupError ? 'error' : undefined}
            autoSize={{ minRows: 3, maxRows: 15 }} disabled={originReadOnly} value={backupText}
            placeholder={t('siteOriginForwarding:failover.backupPlaceholder')} onChange={(event) => changeBackups(event.target.value)} />
          <p id="site-backup-origins-help" className="site-basic-modal-help">{t('siteOriginForwarding:failover.backupHelp')} {tW('backup')}</p>
          {backupError ? <span className="site-field-error" role="alert">{t(`siteOriginForwarding:failover.${backupError.key}`, { line: backupError.line })}</span> : null}
        <FormRow label={t('siteOriginForwarding:fields.failbackMode')} labelId="site-failback-mode-label" tip={t('siteOriginForwarding:failover.failbackHelp')}>
          <Radio.Group aria-labelledby="site-failback-mode-label" disabled={originReadOnly} value={originPool.failback_mode ?? 'auto'}
            onChange={(event) => onOriginChange({ ...originPool, failback_mode: event.target.value as OriginFailbackMode })}
            options={[{ value: 'auto', label: t('siteOriginForwarding:failover.failbackAuto') }, { value: 'manual', label: t('siteOriginForwarding:failover.failbackManual') }]} />
        </FormRow>
        </div>
        </div>
      </section>

      <section className="site-basic-section site-basic-origin-rules">
        <div className="site-basic-title-line"><h3>{t('edit.basic.sections.originRules')}</h3><span>{t('edit.basic.help.originRules')}</span></div>
        {/* 负载方式卡片占满整行一排放下；条件源站与健康检查（原「源站可用性」单独一卡）并排 */}
        <FormRow label={t('edit.basic.fields.balanceMethod')}>
          <BalanceMethodChoices disabled={originReadOnly} value={originPool.balance_method} onChange={changeBalance} />
        </FormRow>
        <BalanceKeyFields pool={originPool} readOnly={originReadOnly} onChange={onOriginChange} />
        <div className="site-form-inline-row">
          <FormRow label={t('edit.basic.fields.conditionalOrigin')} tip={t('edit.basic.help.conditionalOrigin')}>
            <Button onClick={() => goToTab('origin', true)}>{t('edit.basic.actions.configure')}</Button>
          </FormRow>
          <FormRow label={t('edit.basic.fields.healthCheck')} tip={t('edit.basic.help.healthCheck')} help={enabledOrigins < 2 ? t('edit.basic.help.healthCheckRequiresOrigins') : undefined}>
            <Switch aria-label={t('edit.basic.fields.healthCheck')} checked={healthCheckEnabled} disabled={originReadOnly || enabledOrigins < 2} onChange={(checked) => onOriginChange({ ...originPool, failover_tries: checked ? enabledOrigins : 1 })} />
          </FormRow>
        </div>
      </section>

      {accessToken ? <SiteOriginStatusCard siteId={detail.id} accessToken={accessToken} canManage={canManageOrigins} /> : null}
      </section>

      <Modal title={t('edit.basic.modals.domains')} open={domainsOpen} width={MODAL_WIDTH.S} onCancel={() => setDomainsOpen(false)}
        footer={<ModalFooter okText={t('actions.confirm')} cancelText={t('actions.cancel')} onCancel={() => setDomainsOpen(false)} onOk={() => { updateDomains(domainsDraft); setDomainsOpen(false) }} />}>
        <Input.TextArea aria-label={t('edit.basic.aria.batchDomains')} autoSize={{ minRows: 6, maxRows: 12 }} value={domainsDraft} onChange={(event) => setDomainsDraft(event.target.value)} />
        <p className="site-basic-modal-help">{t('edit.basic.help.domains')}</p>
      </Modal>

      <Modal title={t('edit.actions.changeCname')} open={cnameOpen} width={MODAL_WIDTH.S} onCancel={() => setCnameOpen(false)}
        footer={<ModalFooter okText={t('actions.confirm')} cancelText={t('actions.cancel')} okDisabled={readOnly || !canManageDNS || !cnameDomain.trim()} onCancel={() => setCnameOpen(false)}
            onOk={() => { onChange({ ...value, cname_domain: cnameDomain.trim(), cname_hostname: cnameHostname.trim(), cname_regenerate: true }); setCnameOpen(false) }} />}>
        <div className="site-basic-modal-fields">
          <label><span>{t('cnameAllocations:columns.domain')}</span><Input aria-label={t('cnameAllocations:columns.domain')} value={cnameDomain} onChange={(event) => setCnameDomain(event.target.value)} /></label>
          <label><span>{t('cnameAllocations:columns.hostname')}</span><Input aria-label={t('cnameAllocations:columns.hostname')} value={cnameHostname} onChange={(event) => setCnameHostname(event.target.value)} /></label>
        </div>
      </Modal>

      <Modal className="site-origin-modal" title={editingOrigin === null ? t('edit.basic.origin.addTitle') : t('edit.basic.origin.editTitle')} open={originOpen} width={MODAL_WIDTH.S} onCancel={closeOrigin}
        footer={<ModalFooter okText={t('actions.confirm')} cancelText={t('actions.cancel')} okDisabled={originReadOnly || !originDraft.host.trim()} onCancel={closeOrigin} onOk={saveOrigin} />}>
        <div className="site-basic-modal-fields">
          <label><span>{t('edit.basic.fields.sourceAddress')}</span><Input aria-label={t('edit.basic.fields.sourceAddress')} disabled={originReadOnly} value={originDraft.host} placeholder={t('edit.basic.origin.hostPlaceholder')} onChange={(event) => setOriginDraft({ ...originDraft, host: event.target.value })} /></label>
          <label className="site-basic-modal-switch"><span>{t('edit.basic.fields.portInherited')}</span><Switch aria-label={t('edit.basic.fields.portInherited')} disabled={originReadOnly} checked={originDraft.port_inherited ?? false} onChange={(inherited) => setOriginDraft({ ...originDraft, port_inherited: inherited, port: inherited ? inheritedOriginPort(originPool) : originDraft.port })} /></label>
          <label><span>{t('edit.basic.fields.port')}</span><InputNumber aria-label={t('edit.basic.aria.originPort')} disabled={originReadOnly || (originDraft.port_inherited ?? false)} min={1} max={65535} value={originDraft.port_inherited ? inheritedOriginPort(originPool) : originDraft.port} onChange={(port) => setOriginDraft({ ...originDraft, port: port ?? 80 })} /></label>
          {originDraft.port_inherited ? <p className="site-basic-modal-help">{t('edit.basic.help.portInherited', { port: inheritedOriginPort(originPool) })}</p> : null}
          <label><span>{t('edit.basic.fields.weight')}</span><InputNumber aria-label={t('edit.basic.aria.originWeight')} disabled={originReadOnly} min={1} max={100} value={originDraft.weight} aria-describedby="site-origin-draft-share site-origin-draft-weight-help" onChange={(weight) => setOriginDraft({ ...originDraft, weight: weight ?? 1 })} /></label>
          <p id="site-origin-draft-share" className="site-basic-weight-share" aria-live="polite">{draftShare}</p>
          <p id="site-origin-draft-weight-help" className="site-basic-modal-help">{tW('help')}</p>
          <label className="site-basic-modal-switch"><span>{t('edit.basic.fields.status')}</span><Switch aria-label={t('edit.basic.aria.originStatus')} disabled={originReadOnly} checked={originDraft.enabled} onChange={(enabled) => setOriginDraft({ ...originDraft, enabled })} /></label>
          <label><span>{t('siteOriginForwarding:fields.maxConns')}</span><InputNumber aria-label={t('siteOriginForwarding:fields.maxConns')} disabled={originReadOnly} min={0} max={100000} precision={0} value={originDraft.max_conns ?? 0} onChange={(maxConns) => setOriginDraft({ ...originDraft, max_conns: maxConns ?? 0 })} /></label>
          <p className="site-basic-modal-help">{t('siteOriginForwarding:help.maxConns')}</p>
        </div>
      </Modal>
    </div>
  )
}
