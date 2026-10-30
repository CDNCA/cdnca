import { useEffect, useMemo, useState } from 'react'
import { Alert, Button, Form, Input, Modal, Select, Switch, Tabs } from 'antd'
import { useFormSubmitError } from '@cdnca/ui'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../api/auth'
import {
  creatableDNSProviderTypes,
  isValidCustomHTTPCredential,
  isValidDNSLACredential,
  isValidNameComCredential,
  dnsProviderSplitsCarrierLines,
  type CreatableDNSProviderType,
  type DNSProvider,
  type DNSProviderCredentials,
} from '../api/dns'
import { useSessionStore } from '../auth/session'
import { localizedUnknownApiError } from '../i18n/apiError'
import '../i18n/dnsProviders'
import '../i18n/dnsConfig'
import CnameDomainPanel from './dns/CnameDomainPanel'
import DnsConfigForm from './dns/DnsConfigForm'
import './NodeDnsPage.css'

interface CredentialField {
  name: string
  secret?: boolean
  select?: string[]
  // i18n prefix of the select option labels (raw values otherwise).
  selectLabels?: string
  pattern?: RegExp
  max?: number
  validate?: (value: unknown) => boolean
}

export interface ProviderForm {
  target_scope_id?: string
  name: string
  remark?: string
  provider_type: string
  status: 'unverified' | 'disabled'
  replace_credentials: boolean
  credentials: DNSProviderCredentials
}

export type DNSProviderEditorState = { mode: 'create' } | { mode: 'edit'; item: DNSProvider }

// Shared with the certificate page; this page owns the provider credential contract.
// eslint-disable-next-line react-refresh/only-export-components
export const credentialFields: Record<CreatableDNSProviderType, CredentialField[]> = {
  cloudflare: [{ name: 'api_token', secret: true, max: 4096 }],
  aliyun: [
    { name: 'access_key_id', secret: true, max: 4096 },
    { name: 'access_key_secret', secret: true, max: 4096 },
  ],
  huawei: [
    { name: 'access_key', secret: true, max: 128 },
    { name: 'secret_key', secret: true, max: 256 },
    { name: 'region', select: ['cn-north-4', 'ap-southeast-3'] },
    { name: 'project_id', secret: true, pattern: /^[a-f0-9]{32}$/, max: 32 },
  ],
  dnspod_cn: [
    { name: 'dp_id', secret: true, pattern: /^[1-9][0-9]{0,19}$/, max: 20 },
    { name: 'dp_key', secret: true, max: 256 },
  ],
  dns_com: [
    { name: 'api_key', secret: true, max: 128 },
    { name: 'api_secret', secret: true, max: 256 },
    // Plan tier: opens DNS lines (free/enterprise: 三网, flagship: +境外).
    { name: 'plan', select: ['free', 'enterprise', 'flagship'], selectLabels: 'dnsComPlans' },
  ],
  dns_la: [
    { name: 'api_id', secret: true, validate: (value) => isValidDNSLACredential('api_id', value) },
    { name: 'api_secret', secret: true, validate: (value) => isValidDNSLACredential('api_secret', value) },
  ],
  namecom: [
    { name: 'username', validate: (value) => isValidNameComCredential('username', value) },
    { name: 'api_token', secret: true, validate: (value) => isValidNameComCredential('api_token', value) },
  ],
  custom_http: [
    { name: 'endpoint', validate: (value) => isValidCustomHTTPCredential('endpoint', value) },
    { name: 'secret', secret: true, validate: (value) => isValidCustomHTTPCredential('secret', value) },
  ],
}

// eslint-disable-next-line react-refresh/only-export-components
export function isCreatableProviderType(value: string): value is CreatableDNSProviderType {
  return creatableDNSProviderTypes.some((providerType) => providerType === value)
}

export function providerLabel(value: string, t: TFunction<'dnsProviders'>): string {
  if (isCreatableProviderType(value) || value === 'dnsdun') return t(`providers.${value}`)
  return t('providers.unknown', { type: value })
}




export function errorMessage(error: ApiError, t: TFunction<'dnsProviders'>): string {
  const knownCodes = new Set([
    'validation_error', 'permission_denied', 'dns_resource_not_found', 'dns_resource_conflict',
    'version_conflict', 'idempotency_conflict', 'credential_encryption_unavailable',
    'provider_verification_unsupported', 'provider_disabled', 'provider_credentials_invalid',
    'provider_token_inactive', 'provider_credentials_rejected', 'provider_verification_rate_limited',
    'provider_verification_unavailable', 'provider_verification_invalid_response', 'provider_verification_timeout',
    'dns_provider_platform_managed', 'dns_provider_reauthorization_required',
  ])
  const statusCode = knownCodes.has(error.code) ? error.code : error.status === 403
    ? 'permission_denied'
    : error.status === 404
      ? 'dns_resource_not_found'
      : error.status === 409
        ? 'dns_resource_conflict'
        : error.status === 412
          ? 'version_conflict'
          : error.status === 422
            ? 'validation_error'
            : error.code
  return knownCodes.has(statusCode)
    ? t(`errors.${statusCode}`)
    : localizedUnknownApiError(error, t('errors.request_failed'))
}

export function ProviderEditor({
  editor,
  isAdmin,
  pending,
  uncertain,
  error,
  onCancel,
  onSubmit,
  onRetry,
  onCloseAndRefresh,
  sectioned = false,
}: {
  // sectioned：用户端「新增DNS API」的 基础信息 / 验证信息 分区横排布局，含备注
  sectioned?: boolean
  editor: DNSProviderEditorState | null
  isAdmin: boolean
  pending: boolean
  uncertain: boolean
  error: ApiError | null
  onCancel: () => void
  onSubmit: (values: ProviderForm) => void
  onRetry: () => void
  onCloseAndRefresh: () => void
}) {
  const { t } = useTranslation('dnsProviders')
  const [form] = Form.useForm<ProviderForm>()
  const providerType = Form.useWatch('provider_type', form) ?? 'cloudflare'
  const replaceCredentials = Form.useWatch('replace_credentials', form) ?? false
  const status = Form.useWatch('status', form)
  const readOnlyProvider = editor?.mode === 'edit' && !isCreatableProviderType(editor.item.provider_type)
  // DNS-UX-20261027-02：禁用会撤销旧凭据，重新启用就是重新授权，必须录入新凭据。
  const reauthorizing = editor?.mode === 'edit' && editor.item.status === 'disabled' && status === 'unverified'
  const needsCredentials = isCreatableProviderType(providerType) &&
    (editor?.mode === 'create' || replaceCredentials || reauthorizing)
  const providerOptions = editor?.mode === 'edit'
    ? [{ value: editor.item.provider_type, label: providerLabel(editor.item.provider_type, t) }]
    : creatableDNSProviderTypes.map((value) => ({ value, label: t(`providers.${value}`) }))

  useEffect(() => {
    if (!editor) return
    form.resetFields()
    form.setFieldsValue(editor.mode === 'create'
      ? {
          name: '', remark: '', provider_type: 'cloudflare', status: 'unverified',
          replace_credentials: true, credentials: {},
        }
      : {
          name: editor.item.name,
          remark: editor.item.remark ?? '',
          provider_type: editor.item.provider_type,
          status: editor.item.status === 'disabled' ? 'disabled' : 'unverified',
          replace_credentials: false,
          credentials: {},
        })
  }, [editor, form])

  // A refusal naming a field (fix-fielderr-be2) is marked on the form instead of
  // the alert; "credentials" marks the first credential input.
  const firstCredential = credentialFields[providerType as CreatableDNSProviderType]?.[0]?.name ?? ''
  const errorMap = useMemo(() => ({ credentials: ['credentials', firstCredential] }), [firstCredential])
  const markSubmitError = useFormSubmitError(form, errorMap)
  const [fieldMarked, setFieldMarked] = useState(false)
  useEffect(() => {
    if (error && !uncertain) form.setFieldValue('credentials', {})
    setFieldMarked(Boolean(error && !uncertain && markSubmitError(error)))
  }, [error, form, markSubmitError, uncertain])

  return (
    <Modal
      className="identity-modal"
      title={editor?.mode === 'edit' ? t('editor.editTitle') : sectioned ? t('editor.createTitleDnsApi') : t('editor.createTitle')}
      open={editor !== null}
      width={620}
      confirmLoading={pending}
      okText={uncertain ? t('actions.retrySameRequest') : t('actions.save')}
      cancelText={t('actions.cancel')}
      cancelButtonProps={{ disabled: pending || uncertain }}
      closable={!pending && !uncertain}
      maskClosable={!pending && !uncertain}
      keyboard={!pending && !uncertain}
      onCancel={onCancel}
      onOk={() => uncertain ? onRetry() : void form.validateFields()
        .then((values) => onSubmit(reauthorizing ? { ...values, replace_credentials: true } : values))
        .catch(() => undefined)}
      destroyOnHidden
    >
      {error && !fieldMarked ? (
        <Alert
          className="identity-alert"
          type={uncertain ? 'warning' : 'error'}
          showIcon
          message={uncertain ? t('uncertainty.title') : errorMessage(error, t)}
          description={uncertain ? t('uncertainty.description') : undefined}
          action={uncertain ? <Button size="small" onClick={onCloseAndRefresh}>{t('actions.closeAndRefresh')}</Button> : undefined}
        />
      ) : null}
      <Form form={form} layout={sectioned ? 'horizontal' : 'vertical'} labelCol={sectioned ? { flex: '96px' } : undefined}
        labelAlign="right" colon={sectioned} className={sectioned ? 'dns-provider-editor--sectioned' : undefined}
        requiredMark={false} disabled={pending || uncertain}>
        {sectioned ? <h3 className="dns-provider-editor-section">{t('editor.sectionBasic')}</h3> : null}
        {isAdmin && editor?.mode === 'create' ? (
          <Form.Item name="target_scope_id" label={t('editor.targetScope')} rules={[{ required: true, whitespace: true, message: t('validation.targetScope') }]}>
            <Input autoComplete="off" />
          </Form.Item>
        ) : null}
        <Form.Item name="name" label={t('editor.name')} rules={[{ required: true, whitespace: true, max: 128, message: t('validation.name') }]}>
          <Input autoComplete="off" placeholder={sectioned ? t('editor.namePlaceholder') : undefined} />
        </Form.Item>
        {sectioned ? (
          <Form.Item name="remark" label={t('editor.remark')} rules={[{ max: 256, message: t('validation.remark') }]}>
            <Input autoComplete="off" placeholder={t('editor.remarkPlaceholder')} />
          </Form.Item>
        ) : null}
        <Form.Item name="provider_type" label={t('editor.providerType')} rules={[{ required: true }]}>
          <Select
            disabled={editor?.mode === 'edit'}
            options={providerOptions}
            onChange={() => form.setFieldValue('credentials', {})}
          />
        </Form.Item>
        {!dnsProviderSplitsCarrierLines(providerType) ? (
          <Alert type="warning" showIcon message={t('editor.linesUnsupported')} />
        ) : null}
        {editor?.mode === 'edit' && !readOnlyProvider ? (
          <>
            {/* DNS-01：启用与验证分开。只改名称/备注保留"已验证"，替换凭据才需重新验证 */}
            <Form.Item name="status" label={t('editor.status')} rules={[{ required: true }]}
              extra={editor.item.status === 'verified' ? t('editor.statusKeepsVerification')
                : editor.item.status === 'disabled' && !reauthorizing ? t('editor.statusReauthorize') : undefined}>
              <Select options={[
                { value: 'unverified', label: editor.item.status === 'disabled' ? t('editor.statusReauthorizeOption') : t('editor.statusEnabled') },
                { value: 'disabled', label: t('states.disabled') },
              ]} />
            </Form.Item>
            {reauthorizing ? (
              <Alert className="dns-provider-editor-reauthorize" type="info" showIcon message={t('editor.reauthorizeRequired')} />
            ) : (
              <Form.Item name="replace_credentials" label={t('editor.replaceCredentials')} valuePropName="checked" extra={t('editor.credentialsNeverShown')}>
                <Switch />
              </Form.Item>
            )}
          </>
        ) : null}
        {sectioned ? (
          <>
            <h3 className="dns-provider-editor-section">{t('editor.sectionCredentials')}</h3>
            <p className="dns-provider-editor-hint">{t('editor.sectionCredentialsHint')}</p>
          </>
        ) : null}
        {sectioned && !needsCredentials && editor?.mode === 'create' ? (
          <p className="dns-provider-editor-placeholder">{t('editor.credentialsPending')}</p>
        ) : null}
        {needsCredentials ? credentialFields[providerType].map((field) => (
          <Form.Item
            key={field.name}
            name={['credentials', field.name]}
            label={t(`credentials.${field.name}`)}
            extra={field.name === 'plan' ? t('credentials.planHint') : undefined}
            initialValue={field.select && field.selectLabels ? field.select[0] : undefined}
            rules={[
              ...(field.validate ? [{
                validator: (_rule: unknown, value: unknown) => field.validate?.(value)
                  ? Promise.resolve()
                  : Promise.reject(new Error(t('validation.credential'))),
              }] : [
                { required: true, whitespace: !field.select, message: t('validation.credential') },
                ...(field.max ? [{ max: field.max, message: t('validation.credential') }] : []),
                ...(field.pattern ? [{ pattern: field.pattern, message: t('validation.credential') }] : []),
              ]),
            ]}
          >
            {field.select ? (
              <Select options={field.select.map((value) => ({
                value, label: field.selectLabels ? t(`${field.selectLabels}.${value}`) : value }))} />
            ) : field.secret ? (
              <Input.Password autoComplete="new-password" visibilityToggle />
            ) : (
              <Input autoComplete="off" />
            )}
          </Form.Item>
        )) : null}
        {readOnlyProvider ? <Alert type="info" showIcon message={t('editor.readOnlyProvider')} /> : null}
      </Form>
    </Modal>
  )
}

// 节点管理 > DNS配置: a DNS配置 tab (provider, ID,
// Token, TTL, IP weight, last DNS error, 保存配置 / 记录修复 / 清除CDN无关解析)
// and a CNAME域名 tab. The configuration is installation wide (platform
// administrator) and synchronised into every tenant.
export default function NodeDnsPage() {
  const { t } = useTranslation('dnsConfig')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const [tab, setTab] = useState('config')
  if (!accessToken || !principal) return null
  const owner = [String(sessionEpoch), principal.user_id, principal.scope_kind, principal.scope_id]
  const canManage = principal.permissions.includes('dns.manage')
  return (
    <section className="identity-page dns-page" aria-labelledby="dns-config-title">
      <div className="identity-toolbar"><h1 id="dns-config-title">{t('title')}</h1></div>
      <div className="dns-card">
        <Tabs className="dns-tabs" activeKey={tab} onChange={setTab} animated={false} destroyOnHidden items={[
          { key: 'config', label: t('tabs.config'),
            children: <DnsConfigForm key={owner.join('/')} accessToken={accessToken} owner={owner} canManage={canManage} /> },
          { key: 'cname', label: t('tabs.cname'),
            children: <CnameDomainPanel key={owner.join('/')} accessToken={accessToken} owner={owner} canManage={canManage} /> },
        ]} />
      </div>
    </section>
  )
}
