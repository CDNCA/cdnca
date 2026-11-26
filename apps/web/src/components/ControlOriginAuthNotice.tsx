import { useQuery } from '@tanstack/react-query'
import { Alert, Form, Select, Typography } from 'antd'
import type { FormItemProps } from 'antd'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'

import { controlOriginAuthApi, sourceIPHeaderReadable, sourceIPHeaders } from '../api/controlOriginAuth'
import { useSessionStore } from '../auth/session'
import '../i18n/controlOriginAuth'

/** 源IP请求头 sits in System settings → Other → Access and network; ?section= scrolls to it and focuses it (SystemGlobalSettingsPage). */
export const controlOriginAuthSection = 'originauth'
export const controlOriginAuthSettingsPath = `/sys/setting?tab=other&section=${controlOriginAuthSection}`
const anchorID = `system-settings-${controlOriginAuthSection}-title`

/** GET /v1/admin/control-origin-auth for platform identities with system_configuration.read. */
function useControlOriginAuthStatus(refetchInterval?: number) {
  const principal = useSessionStore((state) => state.principal)
  const accessToken = useSessionStore((state) => state.accessToken)
  const canRead = principal?.scope_kind === 'platform' &&
    (principal.permissions.includes('system_configuration.read') || principal.permissions.includes('platform.admin'))
  const query = useQuery({
    queryKey: ['control-origin-auth'],
    queryFn: ({ signal }) => controlOriginAuthApi.get(accessToken ?? '', signal),
    enabled: canRead && Boolean(accessToken),
    retry: false,
    // react-query skips the interval while the document is hidden (refetchIntervalInBackground is off).
    refetchInterval,
  })
  return { canRead, status: query.data }
}

// CDN-ORIGIN-AUTH-HINT: the warning of the platform home, only while a CDN
// request without the visitor IP is seen, linking to 源IP请求头.
export default function ControlOriginAuthNotice() {
  const { t } = useTranslation('controlOriginAuth')
  const { canRead, status } = useControlOriginAuthStatus(60_000)
  if (!canRead || !status?.cdn_without_origin_auth) return null
  const keyOnly = status.origin_auth_enabled && status.key_only && status.real_ip_header !== ''
  return <Alert type="warning" showIcon role="alert" data-testid="control-origin-auth-home" style={{ marginBottom: 16 }}
    message={keyOnly ? t('keyOnlyTitle') : t('title')}
    description={keyOnly ? t('keyOnly', { header: status.real_ip_header })
      : <>{t('homeSummary')} <Link to={controlOriginAuthSettingsPath}>{t('homeLink')}</Link></>} />
}

/**
 * 源IP请求头: the choice, saved with the tab, and
 * one line saying where the visitor IP comes from by the saved value. A host
 * with origin authentication applied (install-control.sh origin-auth) shows
 * that line only. X-Forwarded-For / X-Real-IP are offered where control-api
 * can read the client's own values (sourceIPHeaderReadable).
 */
export function VisitorIPSetting({ value, saved, disabled, onChange, field }: {
  value: string
  saved: string
  disabled: boolean
  onChange: (value: string) => void
  field?: Pick<FormItemProps, 'validateStatus' | 'help'>
}) {
  const { t } = useTranslation('controlOriginAuth')
  const { status } = useControlOriginAuthStatus()
  const effective = saved !== '' && sourceIPHeaderReadable(saved, status) ? saved : ''
  const unresolved = status?.cdn_without_origin_auth === true
  // With the origin key on, a request nginx confirmed carries the visitor IP the deployment's header gave; a CDN
  // request that did not match the key still takes 源IP请求头 (control-api withVisitorIP), so the selector stays.
  // The key alone does not confirm the visitor IP; a CDN request that matched it without one (key_only), or gave none, is said too.
  const originAuth = status?.origin_auth_enabled === true
  return <div data-testid="visitor-ip-settings">
    {originAuth ? <Typography.Paragraph data-testid="visitor-ip-origin-auth" data-state="origin_auth" type={unresolved ? 'warning' : undefined}
      style={{ marginBottom: 12 }}>
      {status.visitor_ip_confirmed && status.real_ip_header !== '' ? t('status.originAuthHeader', { header: status.real_ip_header }) : t('status.originAuth')}
      {unresolved ? ` · ${status.key_only && status.real_ip_header !== ''
        ? t('status.keyOnly', { header: status.real_ip_header }) : t('status.unresolved')}` : null}
    </Typography.Paragraph> : null}
    <Form.Item label={<span id={anchorID} tabIndex={-1} style={{ scrollMarginTop: 'var(--section-scroll-offset, 8px)' }}>{t('fieldLabel')}</span>}
      {...field} style={{ marginBottom: 8 }}>
      <Select<string> value={value} onChange={onChange} disabled={disabled} virtual={false} aria-label={t('fieldLabel')}
        style={{ width: '100%', maxWidth: 320 }}
        options={[{ value: '', label: t('options.direct') }, ...sourceIPHeaders.map((header) => ({
          value: header, label: header === 'X-Forwarded-For' ? t('options.X-Forwarded-For') : header,
          disabled: !sourceIPHeaderReadable(header, status) && header !== value,
        }))]} />
    </Form.Item>
    <Typography.Text type={unresolved && !originAuth ? 'warning' : 'secondary'} data-testid="visitor-ip-status" data-state={effective === '' ? 'direct' : 'header'}>
      {/* With the origin key on, the selection governs only the requests nginx did not confirm (withVisitorIP). */}
      {originAuth
        ? (effective === '' ? t('status.unverifiedDirect') : t('status.unverifiedHeader', { header: effective }))
        : (effective === '' ? t('status.direct') : t('status.header', { header: effective }))}
      {unresolved && !originAuth ? ` · ${t('status.unresolved')}` : null}
    </Typography.Text>
  </div>
}
