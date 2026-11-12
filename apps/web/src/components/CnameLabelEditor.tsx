import { useEffect, useState } from 'react'
import { App, Button, Input, Modal } from 'antd'
import { useTranslation } from 'react-i18next'

import { cnameLabelsApi, type CnameLabelKind } from '../api/cnameLabels'
import { useSessionStore } from '../auth/session'
import { localizedApiError } from '../i18n/apiError'
import '../i18n/cnameLabel'
import './CnameLabelEditor.css'

export interface CnameLabelEditorProps {
  kind: CnameLabelKind
  subjectID: string
  /** 'full'：完整主机名（网站），预览「主机名.CNAME 域名」；'prefix'：前缀模板（线路组），预览「前缀-xxxxxxxx.CNAME 域名」。 */
  mode: 'full' | 'prefix'
  /** 预览用的 CNAME 域名，未知时留空。 */
  domain?: string
  disabled?: boolean
  /** 保存成功（网站名称一改就会重新生成 CNAME）后，让页面重新读取。 */
  onSaved?: () => void
}

// 与服务端 cnameallocation.validateLabel 一致：小写字母、数字、连字符，不以连字符开头结尾。
const labelPattern = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/
const randomSample = 'xxxxxxxx'

function newKey(): string {
  return `cname-label-${crypto.randomUUID()}`
}

/** 预览文本；名称为空时返回空串。 */
export function cnameLabelPreview(mode: 'full' | 'prefix', label: string, domain: string): string {
  const name = label.trim().toLowerCase()
  if (!name) return ''
  const host = mode === 'prefix' ? `${name}-${randomSample}` : name
  return domain ? `${host}.${domain}` : host
}

export default function CnameLabelEditor({ kind, subjectID, mode, domain = '', disabled = false, onSaved }: CnameLabelEditorProps) {
  const { t } = useTranslation('cnameLabel')
  const { t: tErrors } = useTranslation('errors')
  const { message } = App.useApp()
  const accessToken = useSessionStore((state) => state.accessToken)
  const [saved, setSaved] = useState('')
  const [draft, setDraft] = useState('')
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [regenerating, setRegenerating] = useState(false)
  const [confirm, setConfirm] = useState<number | null>(null)

  useEffect(() => {
    if (!accessToken) return
    let current = true
    setLoading(true)
    cnameLabelsApi.get(accessToken, kind, subjectID).then((label) => {
      if (!current) return
      setSaved(label)
      setDraft(label)
      setError(null)
    }, () => { if (current) setError(t('loadFailed')) }).finally(() => { if (current) setLoading(false) })
    return () => { current = false }
  }, [accessToken, kind, subjectID, t])

  const normalized = draft.trim().toLowerCase()
  const invalid = normalized !== '' && !labelPattern.test(normalized)
  const dirty = normalized !== saved
  const preview = invalid ? '' : cnameLabelPreview(mode, normalized, domain)

  async function save() {
    if (!accessToken || invalid || !dirty) return
    setSaving(true)
    setError(null)
    try {
      const label = await cnameLabelsApi.put(accessToken, kind, subjectID, normalized, newKey())
      setSaved(label)
      setDraft(label)
      void message.success(t('saved'))
      onSaved?.()
    } catch (reason) {
      setError(localizedApiError(reason))
    } finally {
      setSaving(false)
    }
  }

  async function askRegenerate() {
    if (!accessToken) return
    setError(null)
    try {
      setConfirm(await cnameLabelsApi.affected(accessToken, kind, subjectID))
    } catch (reason) {
      setError(localizedApiError(reason))
    }
  }

  async function regenerate() {
    if (!accessToken) return
    setRegenerating(true)
    try {
      const count = await cnameLabelsApi.regenerate(accessToken, kind, subjectID, newKey())
      setConfirm(null)
      void message.success(t('regenerateDone', { count }))
      onSaved?.()
    } catch (reason) {
      setConfirm(null)
      setError(localizedApiError(reason))
    } finally {
      setRegenerating(false)
    }
  }

  const fieldLabel = mode === 'full' ? t('hostname') : t('prefix')
  return (
    <div className="cname-label-editor">
      <div className="cname-label-editor-row">
        <Input
          aria-label={fieldLabel}
          value={draft}
          maxLength={mode === 'full' ? 63 : 54}
          disabled={disabled || loading}
          status={invalid || error ? 'error' : undefined}
          placeholder={mode === 'full' ? t('hostnamePlaceholder') : t('prefixPlaceholder')}
          onChange={(event) => setDraft(event.target.value)}
          onPressEnter={() => void save()}
        />
        <Button type="primary" loading={saving} disabled={disabled || loading || invalid || !dirty} onClick={() => void save()}>{mode === 'full' ? t('saveHostname') : t('savePrefix')}</Button>
        {mode === 'prefix' ? (
          <Button disabled={disabled || loading || dirty} onClick={() => void askRegenerate()}>{t('regenerate')}</Button>
        ) : null}
      </div>
      {preview ? (
        <p className="cname-label-editor-preview" data-testid="cname-label-preview">
          <span>{t('previewLabel')}</span> <code>{preview}</code>
        </p>
      ) : null}
      <p className="cname-label-editor-help">{mode === 'full' ? t('hostnameHelp') : t('prefixHelp')}</p>
      {invalid ? <p className="cname-label-editor-error" role="alert">{tErrors('cname_label_invalid')}</p> : null}
      {error ? <p className="cname-label-editor-error" role="alert">{error}</p> : null}
      <Modal
        title={t('regenerateTitle')}
        open={confirm !== null}
        okText={t('confirm')}
        cancelText={t('cancel')}
        okButtonProps={{ disabled: confirm === 0, loading: regenerating }}
        onOk={() => void regenerate()}
        onCancel={() => { if (!regenerating) setConfirm(null) }}
        destroyOnHidden
      >
        <p>{confirm === 0 ? t('regenerateNone') : t('regenerateConfirm', { count: confirm ?? 0 })}</p>
      </Modal>
    </div>
  )
}
