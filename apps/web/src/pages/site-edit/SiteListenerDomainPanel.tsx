import { Alert, Input, Space, Switch, Tag } from 'antd'
import { useTranslation } from 'react-i18next'

import {
  canonicalSiteDomains,
  type SiteBasicConfig,
  type SiteIPv6RuntimeState,
} from '../../api/sites'
import '../../i18n/siteListenerDomains'
import { SettingRow, SettingSection } from './SiteEditFields'
import type { BasicValidationErrors } from './siteEditValidation'

export interface SiteListenerDomainPanelProps {
  value: SiteBasicConfig
  ipv6RuntimeState: SiteIPv6RuntimeState
  errors: BasicValidationErrors
  readOnly?: boolean
  onChange: (value: SiteBasicConfig) => void
}

function splitPorts(value: string): string[] {
  return value.split(/[\s,]+/u).map((item) => item.trim()).filter(Boolean)
}

function splitDomains(value: string): string[] {
  return value.split(/[\s,]+/u).map((item) => item.trim()).filter(Boolean)
}

export default function SiteListenerDomainPanel({
  value,
  ipv6RuntimeState,
  errors,
  readOnly = false,
  onChange,
}: SiteListenerDomainPanelProps) {
  const { t } = useTranslation('siteListenerDomains')

  return (
    <SettingSection title={t('title')}>
      <Alert type="info" showIcon message={t('description')} />
      <SettingRow label={t('fields.domain')} help={t('help.domain')}>
        <Input.TextArea
          aria-label={t('fields.domain')}
          status={errors.domains ? 'error' : undefined}
          disabled={readOnly}
          autoSize={{ minRows: 2, maxRows: 8 }}
          value={value.domains.join('\n')}
          onChange={(event) => {
            if (readOnly) return
            const draft = splitDomains(event.target.value)
            const inputType = (event.nativeEvent as InputEvent).inputType
            const isPartialTypedDomain = inputType === 'insertText' && draft.some((domain) => domain === '*' || domain.endsWith('.'))
            onChange({
              ...value,
              domains: isPartialTypedDomain ? draft : canonicalSiteDomains(draft) ?? draft,
            })
          }}
        />
        {errors.domains ? <span className="site-field-error">{errors.domains}</span> : null}
      </SettingRow>
      <SettingRow label={t('fields.httpEnabled')} help={t('help.http')}>
        <Switch aria-label={t('fields.httpEnabled')} checked={value.http_enabled} disabled />
      </SettingRow>
      <SettingRow label={t('fields.httpPorts')} help={t('help.ports')}>
        <Input
          aria-label={t('fields.httpPorts')}
          status={errors.http_listen_ports ? 'error' : undefined}
          disabled={readOnly}
          value={value.http_listen_ports.join(' ')}
          onChange={(event) => {
            if (!readOnly) onChange({ ...value, http_listen_ports: splitPorts(event.target.value) })
          }}
        />
        {errors.http_listen_ports ? <span className="site-field-error">{errors.http_listen_ports}</span> : null}
      </SettingRow>
      <SettingRow label={t('fields.ipv6Enabled')} help={t('help.ipv6')}>
        <Space size="small">
          <Switch
            aria-label={t('fields.ipv6Enabled')}
            checked={value.ipv6_enabled}
            disabled={readOnly}
            onChange={(checked) => {
              if (!readOnly) onChange({ ...value, ipv6_enabled: checked })
            }}
          />
          <Tag color={ipv6RuntimeState === 'active' ? 'success' : ipv6RuntimeState === 'failed' ? 'error' : 'default'}>
            {t(`runtime.${ipv6RuntimeState}`)}
          </Tag>
        </Space>
      </SettingRow>
      <SettingRow label={t('fields.httpsEnabled')}>
        <Switch
          aria-label={t('fields.httpsEnabled')}
          checked={value.https_enabled}
          disabled={readOnly}
          onChange={(checked) => {
            if (!readOnly) onChange({ ...value, https_enabled: checked })
          }}
        />
      </SettingRow>
      <SettingRow label={t('fields.httpsPorts')} help={t('help.ports')}>
        <Input
          aria-label={t('fields.httpsPorts')}
          status={errors.https_listen_ports ? 'error' : undefined}
          disabled={readOnly || !value.https_enabled}
          value={value.https_listen_ports.join(' ')}
          onChange={(event) => {
            if (!readOnly && value.https_enabled) {
              onChange({ ...value, https_listen_ports: splitPorts(event.target.value) })
            }
          }}
        />
        {errors.https_listen_ports ? (
          <span className="site-field-error">{errors.https_listen_ports}</span>
        ) : null}
      </SettingRow>
    </SettingSection>
  )
}
