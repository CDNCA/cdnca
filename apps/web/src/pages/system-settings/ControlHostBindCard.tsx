import { useState } from 'react'
import { Alert, Descriptions, Form, Input, Tag, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

import '../../i18n/controlHostBind'

// ctl-bind-domain: shows how this console is reached and the root command
// that binds a domain (control-api control-host bind). Nothing is executed
// from the page: the bind rewrites certificates and services as root.
// The state comes from the page itself: the browser address and the
// runtime-config.js pins install-control.sh / the bind publish (an empty
// __CDNCA_CONTROL_CA_SHA256__ means a publicly trusted certificate).
type HostRuntime = { __CDNCA_CONTROL_CA_SHA256__?: string; __CDNCA_GATEWAY_SERVER_NAME__?: string }

const controlBinary = '/data/cdnca-native-root/cdnca/current/bin/control-api'
const domainPattern = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/

export function isBindableDomain(value: string): boolean {
  return value.length <= 253 && domainPattern.test(value)
}

export function bindCommand(domain: string, withCertificate = false): string {
  const base = `sudo ${controlBinary} control-host bind --domain ${domain}`
  return withCertificate ? `${base} --cert-file /path/fullchain.pem --key-file /path/privkey.pem` : base
}

function isIPAddress(host: string): boolean {
  return /^[0-9.]+$/.test(host) || host.startsWith('[')
}

export default function ControlHostBindCard({ location = window.location, runtime = window as HostRuntime }: {
  location?: Pick<Location, 'hostname' | 'origin'>
  runtime?: HostRuntime
}) {
  const { t } = useTranslation('controlHostBind')
  const byIP = isIPAddress(location.hostname)
  const [domain, setDomain] = useState(byIP ? '' : location.hostname)
  const normalized = domain.trim().toLowerCase().replace(/\.$/, '')
  const valid = isBindableDomain(normalized)
  const publicCertificate = (runtime.__CDNCA_CONTROL_CA_SHA256__ ?? '') === ''
  const shown = valid ? normalized : t('domainPlaceholder')
  const requirements = t('requirements', { returnObjects: true }) as string[]
  const command = (text: string, testID: string) => <Typography.Paragraph className="control-host-bind-command" data-testid={testID}>
    <Typography.Text code copyable={valid ? { text, tooltips: [t('copy'), t('copied')] } : false}>{text}</Typography.Text>
  </Typography.Paragraph>
  return <section id="system-host" className="system-settings-config-card sys-setting-section-anchor" aria-labelledby="system-host-title" data-testid="control-host-bind-card">
    <h2 id="system-host-title" className="system-settings-config-card-title">{t('title')}</h2>
    <Typography.Paragraph type="secondary">{t('intro')}</Typography.Paragraph>
    <Descriptions size="small" column={1} bordered title={t('current')} style={{ marginBottom: 16 }}>
      <Descriptions.Item label={t('address')}><Typography.Text data-testid="control-host-address">{location.origin}</Typography.Text></Descriptions.Item>
      <Descriptions.Item label={t('certificate')}>
        {publicCertificate ? <Tag color="success">{t('certificatePublic')}</Tag> : <Tag color="warning">{t('certificatePrivate')}</Tag>}
      </Descriptions.Item>
      {runtime.__CDNCA_GATEWAY_SERVER_NAME__ ? <Descriptions.Item label={t('gateway')}>{runtime.__CDNCA_GATEWAY_SERVER_NAME__}</Descriptions.Item> : null}
    </Descriptions>
    {byIP ? <Alert type="info" showIcon message={t('ipNotice')} style={{ marginBottom: 16 }} /> : null}
    {/* 与本页其他配置行同为水平布局：页面 CSS 给卡片内 label/control 的是横向 flex-basis(170/760px)，竖排时会变成高度，留出大片空白。 */}
    <Form component="div">
      <Form.Item label={t('domainLabel')} validateStatus={domain !== '' && !valid ? 'error' : undefined}
        help={domain !== '' && !valid ? t('domainInvalid') : undefined}>
        <Input value={domain} onChange={(event) => setDomain(event.target.value)} placeholder={t('domainPlaceholder')}
          aria-label={t('domainLabel')} style={{ maxWidth: 420 }} autoComplete="off" spellCheck={false} />
      </Form.Item>
    </Form>
    <Typography.Text strong>{t('commandLabel')}</Typography.Text>
    {command(bindCommand(shown), 'control-host-bind-command')}
    <Typography.Text type="secondary">{t('commandCertLabel')}</Typography.Text>
    {command(bindCommand(shown, true), 'control-host-bind-command-cert')}
    <Typography.Text type="secondary">{t('statusLabel')}</Typography.Text>
    <Typography.Paragraph className="control-host-bind-command">
      <Typography.Text code copyable={{ text: `sudo ${controlBinary} control-host status`, tooltips: [t('copy'), t('copied')] }}>{`sudo ${controlBinary} control-host status`}</Typography.Text>
    </Typography.Paragraph>
    <Typography.Text strong>{t('requirementsTitle')}</Typography.Text>
    <ul className="control-host-bind-requirements">{requirements.map((item) => <li key={item}>{item}</li>)}</ul>
    <Typography.Paragraph type="secondary" style={{ marginBottom: 0 }}>{t('baota')}</Typography.Paragraph>
  </section>
}
