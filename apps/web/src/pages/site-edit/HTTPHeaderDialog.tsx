// 新增源站请求头 / 客户端响应头 dialog: name with
// presets, value with variable presets, 执行动作 cards 添加/覆盖/删除, 允许重复.
import { useEffect, useId, useState } from 'react'
import { Alert, Button, Input, Modal, Space, Switch } from 'antd'
import { MODAL_WIDTH, ModalFooter } from '@cdnca/ui'
import { useTranslation } from 'react-i18next'

import { headerVariables, validHeaderVariables, type HeaderAction } from '../../api/httpPolicies'
import '../../i18n/httpPolicies'

const requestNamePresets = ['X-Request-ID', 'X-Trace-ID', 'X-Origin-Host', 'X-Client-IP', 'X-CDN-Node', 'X-Site-ID']
const responseNamePresets = ['Cache-Control', 'X-Frame-Options', 'X-Content-Type-Options', 'Content-Security-Policy', 'Referrer-Policy']
// the seven common ones, in this order; the rest of headerVariables are accepted too
const variablePresets = ['remote_addr', 'tls_fp', 'isp', 'areacode', 'country', 'province', 'city'] as const
const tokenPattern = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$/
// CU-ADV-01 B：与服务端 httppolicycontrol/validate.go 同一份受管头名单，弹窗里就地拒绝并保留草稿，
// 不发一次必被 422 拒绝、回滚整份配置的请求。
const commonManagedHeaders = new Set(['connection', 'content-length', 'host', 'keep-alive', 'proxy-authenticate',
  'proxy-authorization', 'proxy-connection', 'te', 'trailer', 'transfer-encoding', 'upgrade'])
const requestManagedHeaders = new Set(['cookie', 'forwarded', 'origin', 'x-forwarded-for', 'x-forwarded-host',
  'x-forwarded-proto', 'x-real-ip', 'access-control-request-headers', 'access-control-request-method'])
const responseManagedHeaders = new Set(['location', 'refresh', 'vary', 'alt-svc', 'strict-transport-security', 'x-cdn-cache'])

function managedHeaderName(name: string, request: boolean): boolean {
  const lower = name.toLowerCase()
  return commonManagedHeaders.has(lower) || lower.startsWith('x-cdnca-') || lower.startsWith('access-control-') ||
    (request ? requestManagedHeaders : responseManagedHeaders).has(lower)
}
const printablePattern = /^[\x20-\x7e]{1,1024}$/

export interface HTTPHeaderDialogProps {
  open: boolean
  side: 'request' | 'response'
  action: HeaderAction | null
  // names already used by the other entries (lower case)
  takenNames: string[]
  disabled: boolean
  onCancel: () => void
  onSubmit: (action: HeaderAction) => void
}

export default function HTTPHeaderDialog(props: HTTPHeaderDialogProps) {
  const { t } = useTranslation('httpPolicies')
  const id = useId()
  const [name, setName] = useState('')
  const [value, setValue] = useState('')
  const [kind, setKind] = useState<HeaderAction['kind']>('add')
  const [duplicate, setDuplicate] = useState(false)
  const [error, setError] = useState<string>()
  const request = props.side === 'request'

  useEffect(() => {
    if (!props.open) return
    setName(props.action?.name ?? '')
    setValue(props.action?.values.join('|') ?? '')
    setKind(props.action?.kind ?? 'add')
    setDuplicate(props.action?.allow_duplicate ?? false)
    setError(undefined)
  }, [props.action, props.open])

  function submit() {
    const trimmed = name.trim()
    if (!tokenPattern.test(trimmed) || props.takenNames.includes(trimmed.toLowerCase())) {
      setError(t('headerNameInvalid'))
      return
    }
    if (managedHeaderName(trimmed, request)) {
      setError(t('headerNameManaged', { name: trimmed }))
      return
    }
    const values = kind === 'delete' ? [] : value.split('|').map((item) => item.trim()).filter(Boolean)
    if (kind !== 'delete' && (values.length === 0 || values.length > 16 ||
      values.some((item) => !printablePattern.test(item) || !validHeaderVariables(item)))) {
      setError(t('headerValueInvalid'))
      return
    }
    props.onSubmit({ kind, name: trimmed, values, ...(kind === 'add' && duplicate ? { allow_duplicate: true } : {}) })
  }

  const kinds: Array<[HeaderAction['kind'], string, string]> = [
    ['add', t('actionAdd'), t('actionAddDesc')],
    ['set', t('actionSet'), t('actionSetDesc')],
    ['delete', t('actionDelete'), t(request ? 'actionDeleteDesc' : 'actionDeleteResponseDesc')],
  ]
  const title = props.action
    ? t(request ? 'editHeaderDialog' : 'editResponseHeaderDialog')
    : t(request ? 'requestHeaderDialog' : 'responseHeaderDialog')
  const nameLabel = t(request ? 'headerName' : 'responseHeaderName')
  const valueLabel = t(request ? 'headerValue' : 'responseHeaderValue')

  return (
    <Modal open={props.open} title={title} onCancel={props.onCancel} width={MODAL_WIDTH.M} destroyOnHidden className="http-header-dialog"
      footer={<ModalFooter okText={t('ok')} cancelText={t('cancel')} okDisabled={props.disabled} onOk={submit} onCancel={props.onCancel} />}>
      <div className="http-dialog-field">
        <label htmlFor={`${id}-name`}>{nameLabel}</label>
        <Input id={`${id}-name`} value={name} disabled={props.disabled}
          placeholder={t(request ? 'headerNamePlaceholder' : 'responseHeaderNamePlaceholder')}
          onChange={(event) => setName(event.target.value)} />
        <Space size={8} wrap className="http-dialog-presets">
          {(request ? requestNamePresets : responseNamePresets).map((preset) => (
            <Button key={preset} size="small" disabled={props.disabled} onClick={() => setName(preset)}>{preset}</Button>
          ))}
        </Space>
      </div>
      {kind !== 'delete' ? (
        <div className="http-dialog-field">
          <label htmlFor={`${id}-value`}>{valueLabel}</label>
          <Input id={`${id}-value`} value={value} disabled={props.disabled} placeholder={t('headerValuePlaceholder')}
            onChange={(event) => setValue(event.target.value)} />
          <Space size={8} wrap className="http-dialog-presets">
            {variablePresets.map((variable) => (
              <Button key={variable} size="small" disabled={props.disabled}
                onClick={() => setValue((current) => `${current}$${variable}`)}>${variable}</Button>
            ))}
          </Space>
          <small className="http-dialog-help">{headerVariables.map((variable) => `$${variable}`).join(' ')}</small>
        </div>
      ) : null}
      <div className="http-dialog-field">
        <span id={`${id}-kind`}>{t('headerAction')}</span>
        <div className="http-dialog-cards" role="radiogroup" aria-labelledby={`${id}-kind`}>
          {kinds.map(([value, label, desc]) => (
            <button key={value} type="button" role="radio" aria-checked={kind === value} disabled={props.disabled}
              className={`http-dialog-card${kind === value ? ' http-dialog-card--active' : ''}`}
              onClick={() => setKind(value)}>
              <strong>{label}</strong><span>{desc}</span>
            </button>
          ))}
        </div>
      </div>
      {kind === 'add' ? (
        <div className="http-dialog-switch-row">
          <div><strong>{t('allowDuplicate')}</strong><span>{t('allowDuplicateDesc')}</span></div>
          <Switch aria-label={t('allowDuplicate')} checked={duplicate} disabled={props.disabled} onChange={setDuplicate} />
        </div>
      ) : null}
      {error ? <Alert type="warning" showIcon message={error} /> : null}
    </Modal>
  )
}
