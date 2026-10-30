import { Alert, Button, Collapse, Input, InputNumber, Radio, Select, Switch } from 'antd'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'

import {
  maxFollowRedirectHops,
  originForwarding,
  originKeepalive,
  type OriginRequestHostMode,
  type OriginScheme,
  type SiteOriginPool,
  withInheritedOriginPorts,
} from '../../api/sites'
import '../../i18n/siteOriginForwarding'
import { FormRow } from './SiteEditFields'
import { SiteTabSummary } from './SiteTabSummary'

export interface OriginSettingsTabProps {
  pool: SiteOriginPool
  readOnly?: boolean
  originError?: string
  // Tenants with origin_auth.read manage per-site signing rules on their own page.
  canReadOriginAuth?: boolean
  // Our conditional origin editor (ConditionalOriginSiteTab), shown folded.
  conditional?: React.ReactNode
  conditionalOpen?: boolean
  // UX-02: unsaved basic settings hold the origin pool read-only.
  // User 10-27: the visitor certificate is not set here. Whether the site has
  // one, and the way to its HTTPS settings (or to request one).
  certificateBound?: boolean
  onOpenHttps?: () => void
  onRequestCertificate?: () => void
  onChange: (value: SiteOriginPool) => void
}

// The four 回源协议 cards; follow_port is 跟随协议和端口 (follow
// on the visitor's port), so the port follow switch has no row of its own.
type OriginProtocolChoice = OriginScheme | 'follow_port'
const protocolChoices: OriginProtocolChoice[] = ['http', 'https', 'follow', 'follow_port']

function lines(value: string): string[] {
  return value.split(/[\s,]+/u).map((item) => item.trim()).filter(Boolean)
}

// OriginSettingsTab is the 回源设置 tab in this order: protocol
// and port, origin Host, timeouts, connection reuse, origin auth; then our
// own forwarding options and the folded conditional origin editor. It edits
// the same origin pool draft the basic tab does (PATCH section=origin).
export default function OriginSettingsTab({
  pool, readOnly = false, originError, canReadOriginAuth = false, conditional, conditionalOpen = false,
  certificateBound = false, onOpenHttps, onRequestCertificate, onChange,
}: OriginSettingsTabProps) {
  const { t } = useTranslation('siteOriginForwarding')
  const { t: tV4 } = useTranslation('siteEditV4')
  const forwarding = originForwarding(pool)
  const tls = forwarding.tls
  const redirect = forwarding.follow_redirect
  const keepalive = originKeepalive(pool)
  const https = forwarding.scheme !== 'http'
  const protocol: OriginProtocolChoice = forwarding.scheme === 'follow' && forwarding.follow_port ? 'follow_port' : forwarding.scheme
  // Port-inherited origins follow the pool's port as the server stores it.
  const update = (changes: Partial<SiteOriginPool>) => onChange(withInheritedOriginPorts({ ...pool, ...changes }))
  // Each protocol keeps only its own ports (the server refuses the others):
  // HTTP 80 / HTTPS 443 when unused; 跟随协议和端口 uses neither.
  const changeProtocol = (choice: OriginProtocolChoice) => {
    const scheme: OriginScheme = choice === 'follow_port' ? 'follow' : choice
    const httpPort = choice === 'http' || choice === 'follow' ? forwarding.http_port : 80
    const httpsPort = choice === 'https' || choice === 'follow' ? forwarding.https_port : 443
    update({
      scheme, follow_port: choice === 'follow_port', http_port: httpPort, https_port: httpsPort,
      ...(scheme === 'http' ? { tls: { trust: 'system' as const } } : {}),
    })
  }
  const showHTTPPort = protocol === 'http' || protocol === 'follow'
  const showHTTPSPort = protocol === 'https' || protocol === 'follow'
  const changeHost = (mode: OriginRequestHostMode) =>
    update({ request_host: { mode, value: mode === 'custom' ? forwarding.request_host.value ?? '' : '' } })

  // 本页摘要: protocol:port, Host, timeouts, reuse, auth (DESIGN-site-edit.md §2).
  const protocolPort = protocol === 'http' ? `HTTP:${forwarding.http_port}`
    : protocol === 'https' ? `HTTPS:${forwarding.https_port}`
      : protocol === 'follow' ? `${t('options.scheme.follow')} ${forwarding.http_port}/${forwarding.https_port}`
        : t('options.scheme.follow_port')
  const hostValue = forwarding.request_host.mode === 'custom' && forwarding.request_host.value
    ? forwarding.request_host.value : t(`options.requestHost.${forwarding.request_host.mode}`)
  const seconds = (ms: number) => String(Math.round(ms / 100) / 10)

  return (
    <div className="site-edit-tab-panel site-basic-panel site-origin-settings">
      <SiteTabSummary items={[
        { key: 'protocol', label: tV4('summary.origin.protocol'), value: protocolPort, target: 'site-origin-protocol' },
        { key: 'host', label: tV4('summary.origin.host'), value: hostValue, target: 'site-origin-host' },
        { key: 'timeout', label: tV4('summary.origin.timeout'), target: 'site-origin-timeout',
          value: tV4('summary.origin.timeoutValue', { read: seconds(pool.read_timeout_ms), connect: seconds(pool.connect_timeout_ms) }) },
        { key: 'keepalive', label: tV4('summary.origin.keepalive'), target: 'site-origin-reuse', tone: keepalive.enabled ? 'on' : 'off',
          value: keepalive.enabled ? `${tV4('summary.on')} · ${Math.round(keepalive.idleTimeoutMs / 1000)}${t('units.seconds')}` : tV4('summary.off') },
        { key: 'auth', label: tV4('summary.origin.auth'), target: 'site-origin-auth', tone: forwarding.origin_auth_enabled ? 'on' : 'off',
          value: forwarding.origin_auth_enabled ? tV4('summary.on') : tV4('summary.off') },
      ]} />
      {originError ? <span className="site-field-error" role="alert">{originError}</span> : null}

      {/* 分区按网格排，协议/Host 占整行，超时/复用/鉴权/其它为小卡并排 */}
      <div className="site-origin-grid">
      <section className="site-basic-section is-wide" aria-labelledby="site-origin-protocol">
        <h2 id="site-origin-protocol">{t('sections.protocol')}</h2>
        <div role="radiogroup" aria-labelledby="site-origin-protocol">
          <Radio.Group className="site-origin-choice-grid is-two" name="site-origin-scheme" disabled={readOnly}
            value={protocol} onChange={(event) => changeProtocol(event.target.value as OriginProtocolChoice)}>
            {protocolChoices.map((value) => (
              <Radio key={value} value={value} className="site-origin-choice">
                <strong>{t(`options.scheme.${value}`)}</strong>
                <span>{t(`choices.scheme.${value}`)}</span>
              </Radio>
            ))}
          </Radio.Group>
        </div>
        <div className="site-form-inline-row">
        {showHTTPPort ? (
          <FormRow label={t('fields.httpPort')} tip={t('help.httpPort')}>
            <InputNumber aria-label={t('fields.httpPort')} disabled={readOnly} min={1} max={65535} precision={0} value={forwarding.http_port}
              onChange={(port) => port !== null && update({ http_port: port })} />
          </FormRow>
        ) : null}
        {showHTTPSPort ? (
          <FormRow label={t('fields.httpsPort')} tip={t('help.httpsPort')}>
            <InputNumber aria-label={t('fields.httpsPort')} disabled={readOnly} min={1} max={65535} precision={0} value={forwarding.https_port}
              onChange={(port) => port !== null && update({ https_port: port })} />
          </FormRow>
        ) : null}
        </div>
        {https ? (
          <>
            <Alert type="info" showIcon className="site-origin-visitor-certificate" message={t('visitorCertificate')}
              action={certificateBound || !onRequestCertificate
                ? (onOpenHttps ? <Button size="small" onClick={onOpenHttps}>{t('actions.toHttps')}</Button> : null)
                : <Button size="small" type="primary" onClick={onRequestCertificate}>{t('actions.applyCertificate')}</Button>} />
            <div className="site-form-inline-row">
            <FormRow label={t('fields.sni')} tip={t('help.sni')}>
              <Input aria-label={t('fields.sni')} disabled={readOnly} value={tls.sni ?? ''}
                onChange={(event) => update({ tls: { ...tls, sni: event.target.value } })} />
            </FormRow>
            <FormRow label={t('fields.trust')} tip={t('help.trust')}>
              <Select aria-label={t('fields.trust')} disabled={readOnly} value={tls.trust}
                options={(['system', 'custom', 'none'] as const).map((value) => ({ value, label: t(`options.trust.${value}`) }))}
                onChange={(trust) => update({ tls: trust === 'custom' ? { ...tls, trust } : { sni: tls.sni, trust } })} />
            </FormRow>
            </div>
            {tls.trust === 'none' ? (
              <Alert type="warning" showIcon className="site-origin-no-verify" message={t('noVerifyWarning')} />
            ) : null}
            {tls.trust === 'custom' ? (
              <FormRow label={t('fields.caPem')}>
                <Input.TextArea aria-label={t('fields.caPem')} disabled={readOnly} autoSize={{ minRows: 4, maxRows: 10 }} value={tls.ca_pem ?? ''}
                  placeholder="-----BEGIN CERTIFICATE-----" onChange={(event) => update({ tls: { ...tls, ca_pem: event.target.value } })} />
              </FormRow>
            ) : null}
          </>
        ) : null}
      </section>

      <section className="site-basic-section is-wide" aria-labelledby="site-origin-host">
        <h2 id="site-origin-host">{t('sections.host')}</h2>
        <div role="radiogroup" aria-labelledby="site-origin-host">
          <Radio.Group className="site-origin-choice-grid is-three" name="site-origin-request-host" disabled={readOnly}
            value={forwarding.request_host.mode} onChange={(event) => changeHost(event.target.value as OriginRequestHostMode)}>
            {/* 三项：访问域名 / 访问域名+端口 / 固定 Host；源站主机名是我方保留项，放最后 */}
            {(['visitor', 'visitor_port', 'custom', 'origin'] as OriginRequestHostMode[]).map((value) => (
              <Radio key={value} value={value} className="site-origin-choice">
                <strong>{t(`options.requestHost.${value}`)}</strong>
                <span>{t(`choices.requestHost.${value}`)}</span>
              </Radio>
            ))}
          </Radio.Group>
        </div>
        {forwarding.request_host.mode === 'custom' ? (
          <FormRow label={t('fields.requestHostValue')}>
            <Input aria-label={t('fields.requestHostValue')} disabled={readOnly} value={forwarding.request_host.value ?? ''}
              onChange={(event) => update({ request_host: { mode: 'custom', value: event.target.value } })} />
          </FormRow>
        ) : null}
      </section>

      <section className="site-basic-section" id="site-origin-timeout">
        <h2>{t('sections.timeout')}</h2>
        {/* The pool stores milliseconds; the form edits seconds. */}
        {/* site-parity3a：回源超时 / 连接超时两列并排 */}
        <div className="site-form-row-pair">
        <FormRow label={t('fields.readTimeout')}>
          <InputNumber aria-label={t('fields.readTimeout')} addonAfter={t('units.seconds')} disabled={readOnly} min={0.1} max={300} step={1}
            value={pool.read_timeout_ms / 1000} onChange={(seconds) => seconds !== null && update({ read_timeout_ms: Math.round(seconds * 1000) })} />
        </FormRow>
        <FormRow label={t('fields.connectTimeout')}>
          <InputNumber aria-label={t('fields.connectTimeout')} addonAfter={t('units.seconds')} disabled={readOnly} min={0.05} max={30} step={1}
            value={pool.connect_timeout_ms / 1000} onChange={(seconds) => seconds !== null && update({ connect_timeout_ms: Math.round(seconds * 1000) })} />
        </FormRow>
        </div>
      </section>

      <section className="site-basic-section" id="site-origin-reuse">
        <h2>{t('sections.reuse')}</h2>
        <div className="site-form-inline-row">
        <FormRow label={t('fields.keepalive')} tip={t('help.keepalive')}>
          <div className="site-form-inline">
            <Switch aria-label={t('fields.keepalive')} checked={keepalive.enabled} disabled={readOnly}
              onChange={(checked) => update({ keepalive_enabled: checked, keepalive_idle_timeout_ms: keepalive.idleTimeoutMs })} />
            <span className="site-form-row-help">{keepalive.enabled ? t('help.keepaliveOn') : t('help.keepaliveOff')}</span>
          </div>
        </FormRow>
        {keepalive.enabled ? (
          <FormRow label={t('fields.keepaliveIdleTimeout')} tip={t('help.keepaliveIdleTimeout')}>
            <InputNumber aria-label={t('fields.keepaliveIdleTimeout')} addonAfter={t('units.seconds')} min={1} max={300} precision={0} disabled={readOnly}
              value={Math.round(keepalive.idleTimeoutMs / 1000)}
              onChange={(seconds) => seconds !== null && update({ keepalive_enabled: true, keepalive_idle_timeout_ms: seconds * 1000 })} />
          </FormRow>
        ) : null}
        </div>
      </section>

      <section className="site-basic-section" id="site-origin-auth">
        <h2>{t('sections.auth')}</h2>
        <FormRow label={t('fields.originAuthSwitch')}>
          <div className="site-form-inline">
            <Switch aria-label={t('aria.originAuthSwitch')} disabled={readOnly} checked={forwarding.origin_auth_enabled}
              onChange={(enabled) => update({ origin_auth_enabled: enabled })} />
            <span className="site-form-row-help">{forwarding.origin_auth_enabled ? t('help.originAuthOn') : t('help.originAuthOff')}</span>
          </div>
        </FormRow>
        {canReadOriginAuth && forwarding.origin_auth_enabled ? (
          <FormRow label={t('fields.originAuth')} help={t('help.originAuth')}>
            <Link to="/site/origin-auth/rules">{t('actions.originAuthRules')}</Link>
          </FormRow>
        ) : null}
      </section>

      <section className="site-basic-section">
        <div className="site-basic-title-line"><h2>{t('sections.more')}</h2><span>{t('description')}</span></div>
        <FormRow label={t('fields.followRedirect')} tip={t('help.followRedirect')}>
          <div className="site-form-inline">
            <Switch aria-label={t('fields.followRedirect')} disabled={readOnly} checked={redirect.enabled}
              onChange={(enabled) => update({ follow_redirect: { ...redirect, enabled, cross_origin: enabled && redirect.cross_origin } })} />
            <InputNumber aria-label={t('fields.followRedirectHops')} disabled={readOnly || !redirect.enabled} min={1} max={maxFollowRedirectHops} precision={0}
              value={redirect.max_hops} onChange={(hops) => hops !== null && update({ follow_redirect: { ...redirect, max_hops: hops } })} />
          </div>
        </FormRow>
        {redirect.enabled ? (
          <FormRow label={t('fields.followRedirectCrossOrigin')} tip={t('help.followRedirectCrossOrigin')}>
            <Switch aria-label={t('fields.followRedirectCrossOrigin')} disabled={readOnly} checked={redirect.cross_origin}
              onChange={(crossOrigin) => update({ follow_redirect: { ...redirect, cross_origin: crossOrigin } })} />
          </FormRow>
        ) : null}
        {/* WebSocket 只在高级设置 → 性能与协议（SiteEdgeOptionsSection）。 */}
        <FormRow label={t('fields.trustedProxies')} tip={t('help.trustedProxies')}>
          <Input.TextArea aria-label={t('fields.trustedProxies')} disabled={readOnly} autoSize={{ minRows: 2, maxRows: 6 }}
            value={forwarding.trusted_proxy_cidrs.join('\n')}
            onChange={(event) => update({ trusted_proxy_cidrs: lines(event.target.value) })} />
        </FormRow>
      </section>
      </div>

      {conditional ? (
        <Collapse className="site-origin-conditional" defaultActiveKey={conditionalOpen ? ['conditional'] : []}
          items={[{ key: 'conditional', label: t('sections.conditional'), extra: <span className="site-form-row-help">{t('help.conditional')}</span>, children: conditional }]} />
      ) : null}
    </div>
  )
}
