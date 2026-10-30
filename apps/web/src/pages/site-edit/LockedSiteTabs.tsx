import { Button, Input, Radio, Select, Switch, Table, type TableColumnsType } from 'antd'
import { useTranslation } from 'react-i18next'

import type { AppRole } from '../../auth/session'
import {
  LockedControl,
  LockedSectionNotice,
  SettingRow,
  SettingSection,
} from './SiteEditFields'

function LockedTable({ columns }: { columns?: TableColumnsType<Record<string, string>> }) {
  const { t } = useTranslation('sites')
  const resolvedColumns = columns ?? [
    { title: t('edit.locked.columns.condition'), dataIndex: 'condition' },
    { title: t('edit.locked.columns.action'), dataIndex: 'action' },
    { title: t('edit.locked.columns.mode'), dataIndex: 'mode' },
    { title: t('edit.locked.columns.remark'), dataIndex: 'remark' },
    { title: t('edit.locked.columns.status'), dataIndex: 'status' },
    { title: t('edit.locked.columns.operation'), dataIndex: 'operation' },
  ]
  return (
    <div className="site-locked-table">
      <Table
        rowKey="id"
        size="small"
        columns={resolvedColumns}
        dataSource={[]}
        pagination={false}
        locale={{ emptyText: t('values.placeholder') }}
        scroll={{ x: 720 }}
      />
    </div>
  )
}

export function OriginSiteTab() {
  const { t } = useTranslation('sites')
  return (
    <div className="site-edit-tab-panel">
      <LockedSectionNotice />
      <SettingSection title={t('edit.locked.origin.protocolSection')}>
        <SettingRow label={t('edit.locked.origin.protocol')}>
          <LockedControl>
            <Radio.Group
              disabled
              options={['HTTP', 'HTTPS', t('edit.locked.origin.followProtocol'), t('edit.locked.origin.followPortProtocol')]}
            />
          </LockedControl>
        </SettingRow>
      </SettingSection>
      <SettingSection title={t('edit.locked.origin.domainSection')}>
        <SettingRow label={t('edit.locked.origin.domain')}>
          <LockedControl>
            <Radio.Group
              disabled
              options={[t('edit.locked.origin.visitDomain'), t('edit.locked.origin.visitDomainPort'), t('edit.locked.origin.custom')]}
            />
          </LockedControl>
        </SettingRow>
      </SettingSection>
      <SettingSection title={t('edit.locked.origin.timeoutSection')}>
        <SettingRow label={t('edit.locked.origin.timeout')}>
          <Input disabled suffix={t('edit.locked.seconds')} />
        </SettingRow>
        <SettingRow label={t('edit.locked.origin.connectTimeout')}>
          <Input disabled suffix={t('edit.locked.seconds')} />
        </SettingRow>
      </SettingSection>
      <SettingSection title={t('edit.locked.origin.auth')}>
        <SettingRow label={t('edit.locked.switch')}><Switch disabled /></SettingRow>
      </SettingSection>
    </div>
  )
}

export function SecuritySiteTab() {
  const { t } = useTranslation('sites')
  const security = 'edit.locked.security'
  return (
    <div className="site-edit-tab-panel">
      <LockedSectionNotice />
      <SettingSection title={t(`${security}.cc`)}>
        <SettingRow label={t(`${security}.defaultProtection`)}>
          <LockedControl>
            <Radio.Group
              disabled
              options={[
                t(`${security}.off`), t(`${security}.loose`), t(`${security}.js`), t(`${security}.fiveSecond`),
                t(`${security}.click`), t(`${security}.slider`), t(`${security}.captcha`), t(`${security}.rotate`),
                t(`${security}.simpleClick`), t(`${security}.simpleSlider`), t(`${security}.custom`),
              ]}
            />
          </LockedControl>
        </SettingRow>
        <SettingRow label={t(`${security}.autoSwitch`)}><Switch disabled /></SettingRow>
        <SettingRow label={t(`${security}.customRules`)}>
          <div className="site-locked-actions">
            <Button type="primary" disabled>{t(`${security}.addRule`)}</Button>
            <Button disabled>{t(`${security}.enableAll`)}</Button>
            <Button disabled>{t(`${security}.disableAll`)}</Button>
          </div>
          <LockedTable />
        </SettingRow>
        <SettingRow label={t(`${security}.crawler`)}>
          <Radio.Group disabled options={[t(`${security}.notSet`), t(`${security}.allow`), t(`${security}.block`)]} />
        </SettingRow>
      </SettingSection>
      <SettingSection title={t(`${security}.more`)}>
        <SettingRow label={t(`${security}.blacklistTime`)}><Input disabled suffix={t('edit.locked.seconds')} /></SettingRow>
        <SettingRow label={t(`${security}.whitelistTime`)}><Input disabled suffix={t('edit.locked.seconds')} /></SettingRow>
        <SettingRow label={t(`${security}.cookieDomain`)}><Input disabled /></SettingRow>
        <SettingRow label={t(`${security}.blacklist`)}><Input.TextArea disabled rows={3} /></SettingRow>
        <SettingRow label={t(`${security}.whitelist`)}><Input.TextArea disabled rows={3} /></SettingRow>
        <SettingRow label={t(`${security}.blockProxy`)}><Switch disabled /></SettingRow>
        <SettingRow label={t(`${security}.regionBlock`)}>
          <Radio.Group
            disabled
            options={[
              t(`${security}.notSet`), t(`${security}.abroadWith`), t(`${security}.abroadWithout`),
              t(`${security}.chinaWith`), t(`${security}.chinaWithout`), t(`${security}.custom`),
            ]}
          />
        </SettingRow>
      </SettingSection>
    </div>
  )
}

export function AccessSiteTab() {
  const { t } = useTranslation('sites')
  return (
    <div className="site-edit-tab-panel">
      <LockedSectionNotice />
      <SettingSection title={t('edit.locked.access.aclSettings')}>
        <SettingRow label={t('edit.locked.access.aclSelect')} help={t('edit.locked.access.aclHelp')}>
          <Select disabled placeholder={t('edit.basic.selectPlaceholder')} options={[]} />
        </SettingRow>
      </SettingSection>
      <SettingSection title={t('edit.locked.access.hotlink')}>
        <SettingRow label={t('edit.locked.switch')}><Switch disabled /></SettingRow>
      </SettingSection>
      <SettingSection title={t('edit.locked.access.cors')}>
        <SettingRow label={t('edit.locked.switch')}><Switch disabled /></SettingRow>
        <SettingRow label="allow_origin"><Input disabled /></SettingRow>
        <SettingRow label="allow_methods"><Input disabled /></SettingRow>
        <SettingRow label="allow_headers"><Input disabled /></SettingRow>
        <SettingRow label="expose_headers"><Input disabled /></SettingRow>
        <SettingRow label="allow_credentials">
          <Radio.Group disabled options={[t('edit.locked.access.allow'), t('edit.locked.access.deny')]} />
        </SettingRow>
        <SettingRow label="max_age"><Input disabled /></SettingRow>
      </SettingSection>
    </div>
  )
}

function RuleSection({ title, button }: { title: string; button: string }) {
  const { t } = useTranslation('sites')
  return (
    <SettingSection title={title}>
      <SettingRow label={t('edit.locked.switch')}><Switch disabled /></SettingRow>
      <SettingRow label={button}><Button type="primary" disabled>{button}</Button></SettingRow>
    </SettingSection>
  )
}

export function AdvancedSiteTab({ role }: { role: AppRole }) {
  const { t } = useTranslation('sites')
  const advanced = 'edit.locked.advanced'
  return (
    <div className="site-edit-tab-panel">
      <LockedSectionNotice />
      <SettingSection title={t(`${advanced}.upload`)}>
        <SettingRow label={t(`${advanced}.sizeLimit`)}>
          <Radio.Group disabled options={[t(`${advanced}.unlimited`), t(`${advanced}.custom`)]} />
        </SettingRow>
      </SettingSection>
      <SettingSection title={t(`${advanced}.compression`)}>
        <SettingRow label={t(`${advanced}.gzip`)}><Switch disabled /></SettingRow>
      </SettingSection>
      <SettingSection title={t(`${advanced}.websocket`)}>
        <SettingRow label="Websocket"><Switch disabled /></SettingRow>
      </SettingSection>
      <SettingSection title={t(`${advanced}.searchOrigin`)}>
        <SettingRow label={t('edit.locked.switch')}><Switch disabled /></SettingRow>
      </SettingSection>
      <RuleSection title={t(`${advanced}.errorPages`)} button={t(`${advanced}.addPage`)} />
      <RuleSection title={t(`${advanced}.redirects`)} button={t(`${advanced}.addRedirect`)} />
      <RuleSection title={t(`${advanced}.originHeaders`)} button={t(`${advanced}.addRequestHeader`)} />
      <RuleSection title={t(`${advanced}.responseHeaders`)} button={t(`${advanced}.addResponseHeader`)} />
      <SettingSection title={t(`${advanced}.other`)}>
        <SettingRow label={t(`${advanced}.originCertificate`)}><Switch disabled /></SettingRow>
        <SettingRow label={t(`${advanced}.realtimeReturn`)}><Switch disabled /></SettingRow>
        <SettingRow label={t(`${advanced}.realtimeSend`)}><Switch disabled /></SettingRow>
      </SettingSection>
      {role === 'admin' ? (
        <SettingSection title={t(`${advanced}.admin`)}>
          <SettingRow label={t(`${advanced}.requestHeaders`)}><Switch disabled /></SettingRow>
          <SettingRow label={t(`${advanced}.responseHeadersLog`)}><Switch disabled /></SettingRow>
          <SettingRow label={t(`${advanced}.requestBody`)}><Switch disabled /></SettingRow>
          <SettingRow label={t(`${advanced}.requestBodyLimit`)}><Input suffix="KB" disabled /></SettingRow>
          <SettingRow label={t(`${advanced}.defaultSite`)}><Switch disabled /></SettingRow>
          <SettingRow label={t(`${advanced}.l2`)}>
            <Radio.Group disabled options={[t(`${advanced}.package`), t(`${advanced}.off`), t(`${advanced}.custom`)]} />
          </SettingRow>
        </SettingSection>
      ) : null}
    </div>
  )
}
