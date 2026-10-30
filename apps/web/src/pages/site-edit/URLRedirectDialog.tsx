// 新增转向 dialog: 匹配路径 (regex, $1 groups),
// 目标地址, 预览, 转向类型 301/302/307/308/内部重写, 高级条件 (folded). 内部重写
// is our rewrites list; the others are redirects. The redirect target's host
// joins redirect_allowed_hosts on save (the caller).
import { useEffect, useId, useState } from 'react'
import { Alert, Button, Empty, Input, Modal, Select, Space, Switch } from 'antd'
import { MODAL_WIDTH, ModalFooter } from '@cdnca/ui'
import { ChevronDown, ChevronUp, Plus, Trash2 } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import {
  maxRuleConditions,
  ruleConditionSources,
  type RuleCondition,
  type RuleConditionSource,
} from '../../api/httpPolicies'
import '../../i18n/httpPolicies'
import { matchKindOf, regexPath, type RedirectType, type URLRedirectDraft } from './urlRedirectDraft'

export interface URLRedirectDialogProps {
  open: boolean
  draft: URLRedirectDraft | null
  disabled: boolean
  onCancel: () => void
  onSubmit: (draft: URLRedirectDraft) => void
}

const typeOptions: RedirectType[] = [301, 302, 307, 308, 'rewrite']
const emptyDraft: URLRedirectDraft = { type: 301, match_kind: 'regex', match_path: '/(.*)', target: '', preserve_query: true, conditions: [] }

export default function URLRedirectDialog(props: URLRedirectDialogProps) {
  const { t } = useTranslation('httpPolicies')
  const id = useId()
  const [draft, setDraft] = useState<URLRedirectDraft>(emptyDraft)
  const [conditionsOpen, setConditionsOpen] = useState(false)
  const [condition, setCondition] = useState<{ source?: RuleConditionSource; name: string; pattern: string }>({ name: '', pattern: '' })
  const [error, setError] = useState<string>()

  useEffect(() => {
    if (!props.open) return
    setDraft(props.draft ?? emptyDraft)
    setConditionsOpen(Boolean(props.draft?.conditions.length))
    setCondition({ name: '', pattern: '' })
    setError(undefined)
  }, [props.draft, props.open])

  const typeLabel = (type: RedirectType) => type === 'rewrite' ? t('redirectRewrite') : t(`redirect${type}`)
  const typeDesc = (type: RedirectType) => type === 'rewrite' ? t('redirectRewriteDesc') : t(`redirect${type}Desc`)

  function addCondition() {
    const pattern = condition.pattern.trim()
    const name = condition.name.trim().toLowerCase()
    let valid = Boolean(condition.source) && pattern.length > 0 && pattern.length <= 256 && /^[\x20-\x7e]+$/.test(pattern) &&
      (condition.source !== 'header' || /^[a-z0-9][a-z0-9-]{0,63}$/.test(name))
    try { new RegExp(pattern) } catch { valid = false }
    if (!valid || draft.conditions.length >= maxRuleConditions) {
      setError(t('conditionInvalid'))
      return
    }
    const next: RuleCondition = condition.source === 'header' ? { source: 'header', name, pattern } : { source: condition.source!, pattern }
    setDraft((value) => ({ ...value, conditions: [...value.conditions, next] }))
    setCondition({ name: '', pattern: '' })
    setError(undefined)
  }

  function submit() {
    const matchPath = draft.match_path.trim()
    const target = draft.target.trim()
    const kind = matchKindOf(matchPath, draft.match_kind)
    const rewrite = draft.type === 'rewrite'
    // a redirect needs scheme://host/path (the server refuses a bare host)
    if (!matchPath || !target || (rewrite ? !target.startsWith('/') : !/^https?:\/\/[^/\s]+\/\S*$/.test(target))) {
      setError(t('redirectTargetInvalid'))
      return
    }
    props.onSubmit({ ...draft, match_kind: kind, match_path: regexPath(matchPath, kind), target })
  }

  const preview = draft.match_path && draft.target ? `${draft.match_path} → ${draft.target}` : ''

  return (
    <Modal open={props.open} title={t(props.draft ? 'editRedirectDialog' : 'redirectDialog')} onCancel={props.onCancel} width={MODAL_WIDTH.M} destroyOnHidden className="url-redirect-dialog"
      footer={<ModalFooter okText={t('ok')} cancelText={t('cancel')} okDisabled={props.disabled} onOk={submit} onCancel={props.onCancel} />}>
      <div className="http-dialog-field">
        <label htmlFor={`${id}-match`}>{t('matchPath')}</label>
        <Input id={`${id}-match`} value={draft.match_path} disabled={props.disabled} placeholder={t('matchPathPlaceholder')}
          onChange={(event) => setDraft((value) => ({ ...value, match_path: event.target.value }))} />
      </div>
      <div className="http-dialog-field">
        <label htmlFor={`${id}-target`}>{t('targetUrl')}</label>
        <Input id={`${id}-target`} value={draft.target} disabled={props.disabled}
          placeholder={t(draft.type === 'rewrite' ? 'rewriteTargetPlaceholder' : 'targetPlaceholder')}
          onChange={(event) => setDraft((value) => ({ ...value, target: event.target.value }))} />
        <small className="http-dialog-help">{t('targetHelp')}</small>
        {preview ? <div className="http-dialog-preview"><span>{t('preview')}</span> {preview}</div> : null}
      </div>
      <div className="http-dialog-field">
        <span id={`${id}-type`}>{t('redirectType')}</span>
        <div className="http-dialog-types" role="radiogroup" aria-labelledby={`${id}-type`}>
          {typeOptions.map((type) => (
            <button key={String(type)} type="button" role="radio" aria-checked={draft.type === type} disabled={props.disabled}
              className={`http-dialog-type${draft.type === type ? ' http-dialog-type--active' : ''}`}
              onClick={() => setDraft((value) => ({ ...value, type }))}>{typeLabel(type)}</button>
          ))}
        </div>
        <small className="http-dialog-help">{typeDesc(draft.type)}</small>
      </div>
      <div className="http-dialog-switch-row">
        <div><strong>{t('preserveQuery')}</strong></div>
        <Switch aria-label={t('preserveQuery')} checked={draft.preserve_query} disabled={props.disabled}
          onChange={(value) => setDraft((current) => ({ ...current, preserve_query: value }))} />
      </div>
      <div className="http-dialog-conditions">
        <Button type="link" className="http-dialog-conditions__toggle" aria-expanded={conditionsOpen} aria-controls={`${id}-conditions`}
          icon={conditionsOpen ? <ChevronUp size={14} aria-hidden="true" /> : <ChevronDown size={14} aria-hidden="true" />}
          onClick={() => setConditionsOpen((value) => !value)}>{t('conditions')}</Button>
        <span className="http-dialog-conditions__state">
          {draft.conditions.length ? t('conditionsSet', { count: draft.conditions.length }) : t('conditionsUnset')}
        </span>
      </div>
      <div id={`${id}-conditions`} hidden={!conditionsOpen} className="http-dialog-conditions__panel">
        {draft.conditions.length === 0 ? <Empty image={null} description={t('conditionsEmpty')} /> : (
          <ul className="http-dialog-conditions__list">
            {draft.conditions.map((item, index) => (
              <li key={`${index}-${item.source}`}>
                <span>{item.source === 'header' ? `${t('sources_header')} ${item.name}` : t(`sources_${item.source}`)}</span>
                <code>{item.pattern}</code>
                <Button type="text" danger size="small" aria-label={t('removeCondition')} disabled={props.disabled}
                  icon={<Trash2 size={14} aria-hidden="true" />}
                  onClick={() => setDraft((value) => ({ ...value, conditions: value.conditions.filter((_, position) => position !== index) }))} />
              </li>
            ))}
          </ul>
        )}
        <Space.Compact className="http-dialog-conditions__add" block>
          <Select<RuleConditionSource> aria-label={t('conditionSource')} placeholder={t('conditionSource')} value={condition.source}
            disabled={props.disabled} style={{ minWidth: 150 }}
            options={ruleConditionSources.map((value) => ({ value, label: t(`sources_${value}`) }))}
            onChange={(source) => setCondition((value) => ({ ...value, source }))} />
          {condition.source === 'header' ? (
            <Input aria-label={t('conditionHeader')} placeholder={t('conditionHeader')} value={condition.name} disabled={props.disabled}
              onChange={(event) => setCondition((value) => ({ ...value, name: event.target.value }))} />
          ) : null}
          <Input aria-label={t('conditionPattern')} placeholder={t('conditionPattern')} value={condition.pattern} maxLength={256}
            disabled={props.disabled} onChange={(event) => setCondition((value) => ({ ...value, pattern: event.target.value }))} />
          <Button icon={<Plus size={14} aria-hidden="true" />} disabled={props.disabled} onClick={addCondition}>{t('addCondition')}</Button>
        </Space.Compact>
      </div>
      {error ? <Alert type="warning" showIcon message={error} /> : null}
    </Modal>
  )
}
