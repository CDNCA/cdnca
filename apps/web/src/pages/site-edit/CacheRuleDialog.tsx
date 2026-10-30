// 新增/编辑缓存规则 dialog, laid out as: 基础规则
// (缓存范围 首页/全站/目录/后缀/单个路径, 有效期 + unit + presets), 缓存策略
// (忽略 URL 参数, 强制 CDN 缓存), 高级设置 folded (分片回源, 忽略 Vary,
// 不缓存条件). Our own match conditions (path regex, content types, status
// codes, action, browser lifetime) stay under 更多匹配条件.
import { useEffect, useId, useState } from 'react'
import { Alert, Button, Empty, Input, InputNumber, Modal, Radio, Select, Space, Switch, Tooltip } from 'antd'
import { MODAL_WIDTH, ModalFooter } from '@cdnca/ui'
import { ChevronDown, ChevronUp, CircleHelp, Plus, Trash2 } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import {
  cacheConditionSources,
  cacheNoCacheConditionsMax,
  cachePathRegexMaxLength,
  validExactPath,
  type CacheConditionSource,
  type CacheNoCacheCondition,
  type CachePolicyRule,
  type CacheRuleAction,
} from '../../api/cachePolicies'
import '../../i18n/cachePolicy'
import { ruleScope, ruleSliceBytes, type CacheRuleScope } from './cacheRuleScope'

type Unit = 'd' | 'h' | 's'

const unitSeconds: Record<Unit, number> = { d: 86400, h: 3600, s: 1 }
const presets: Array<[string, number]> = [['m10', 600], ['h1', 3600], ['d1', 86400], ['d7', 7 * 86400], ['d30', 30 * 86400]]

function splitTTL(seconds: number): { value: number; unit: Unit } {
  if (seconds > 0 && seconds % 86400 === 0) return { value: seconds / 86400, unit: 'd' }
  if (seconds > 0 && seconds % 3600 === 0) return { value: seconds / 3600, unit: 'h' }
  return { value: seconds, unit: 's' }
}

function scopeText(rule: CachePolicyRule, scope: CacheRuleScope): string {
  if (scope === 'dir') return rule.path_prefix ?? ''
  if (scope === 'path') return rule.path_exact ?? ''
  if (scope === 'suffix') return (rule.extensions ?? []).map((value) => value.replace(/^\./, '')).join('|')
  return ''
}

interface Draft {
  scope: CacheRuleScope
  scopeValue: string
  ttl: number | null
  unit: Unit
  rule: CachePolicyRule
}

function draftOf(rule: CachePolicyRule): Draft {
  const scope = ruleScope(rule)
  const { value, unit } = splitTTL(rule.ttl_seconds)
  return { scope, scopeValue: scopeText(rule, scope), ttl: rule.action === 'no_cache' ? null : value, unit, rule }
}

// applyScope writes the 缓存范围 into the rule's match fields.
function applyScope(rule: CachePolicyRule, scope: CacheRuleScope, value: string): CachePolicyRule {
  const next: CachePolicyRule = { ...rule, path_exact: undefined, path_prefix: '' }
  const extensions = scope === 'suffix'
    ? value.split(/[|,\s]+/).map((item) => item.trim().toLowerCase().replace(/^\.?/, '.')).filter((item) => item !== '.')
    : rule.extensions ?? []
  if (scope === 'home') return { ...next, path_exact: '/', extensions: [] }
  if (scope === 'site') return { ...next, path_prefix: '/', extensions }
  if (scope === 'dir') return { ...next, path_prefix: value.trim(), extensions }
  if (scope === 'path') return { ...next, path_exact: value.trim(), extensions: [] }
  return { ...next, extensions }
}

export interface CacheRuleDialogProps {
  open: boolean
  // the rule to edit, or the new rule's defaults
  rule: CachePolicyRule
  editing: boolean
  // the policy's own values the rule inherits when a setting is unset
  inheritedIgnoreQuery: boolean
  inheritedSliceBytes: number
  disabled: boolean
  // CU-SITE-03: why the save carrying this rule was refused (the dialog reopened with it)
  serverError?: string
  onCancel: () => void
  onSubmit: (rule: CachePolicyRule) => void
}

export default function CacheRuleDialog(props: CacheRuleDialogProps) {
  const { t } = useTranslation('cachePolicy')
  const id = useId()
  const [draft, setDraft] = useState<Draft>(() => draftOf(props.rule))
  const [advancedOpen, setAdvancedOpen] = useState(false)
  const [moreOpen, setMoreOpen] = useState(false)
  const [error, setError] = useState<string>()
  const [condition, setCondition] = useState<{ source?: CacheConditionSource; name: string; pattern: string }>({ name: '', pattern: '' })

  useEffect(() => {
    if (!props.open) return
    const next = draftOf(props.rule)
    setDraft(next)
    setError(undefined)
    setCondition({ name: '', pattern: '' })
    setAdvancedOpen(Boolean(next.rule.slice_bytes !== undefined || next.rule.ignore_vary || next.rule.no_cache?.length))
    setMoreOpen(Boolean(next.rule.path_regex || next.rule.content_types?.length || next.rule.status_codes?.length ||
      next.rule.action === 'no_cache' || next.rule.browser_ttl_seconds))
  }, [props.open, props.rule])

  const rule = draft.rule
  const noCache = rule.action === 'no_cache'
  const set = (patch: Partial<CachePolicyRule>) => setDraft((value) => ({ ...value, rule: { ...value.rule, ...patch } }))
  const conditions = rule.no_cache ?? []

  const sliced = (rule.slice_bytes ?? props.inheritedSliceBytes) > 0
  const ignoreQuery = rule.ignore_query ?? props.inheritedIgnoreQuery
  // an unset force_cache follows the site's mode: rules exist only in 自定义规则 (override)
  const forceCache = rule.force_cache ?? true

  function addCondition() {
    const pattern = condition.pattern.trim()
    const name = condition.name.trim().toLowerCase()
    if (!condition.source || !pattern || pattern.length > cachePathRegexMaxLength ||
      condition.source === 'header' && !/^[a-z0-9][a-z0-9-]{0,63}$/.test(name)) {
      setError(t('validation.invalidCondition'))
      return
    }
    try { new RegExp(pattern) } catch { setError(t('validation.invalidCondition')); return }
    if (conditions.length >= cacheNoCacheConditionsMax) {
      setError(t('validation.tooManyConditions', { max: cacheNoCacheConditionsMax }))
      return
    }
    const next: CacheNoCacheCondition = condition.source === 'header'
      ? { source: 'header', name, pattern } : { source: condition.source, pattern }
    set({ no_cache: [...conditions, next] })
    setCondition({ name: '', pattern: '' })
    setError(undefined)
  }

  function submit() {
    let next = applyScope(rule, draft.scope, draft.scopeValue)
    if (draft.scope === 'path' && !validExactPath(next.path_exact ?? '')) {
      setError(t('validation.invalidExactPath'))
      return
    }
    if (draft.scope === 'dir' && !(next.path_prefix ?? '').startsWith('/')) {
      setError(t('validation.invalidPath'))
      return
    }
    if (draft.scope === 'suffix' && (next.extensions?.length ?? 0) === 0) {
      setError(t('validation.invalidExtension'))
      return
    }
    if (!noCache) {
      const seconds = (draft.ttl ?? 0) * unitSeconds[draft.unit]
      if (!Number.isInteger(seconds) || seconds < 1 || seconds > 31_536_000) {
        setError(t('validation.ttlRange'))
        return
      }
      next = { ...next, ttl_seconds: seconds }
    } else {
      next = { ...next, ttl_seconds: 0, browser_ttl_seconds: 0, ignore_query: undefined, slice_bytes: undefined,
        force_cache: undefined, ignore_vary: undefined, no_cache: undefined }
    }
    if (!next.path_exact) delete next.path_exact
    props.onSubmit(next)
  }

  // inherited: the site's setting already does it (the rule cannot undo it)
  const switchRow = (key: string, checked: boolean, onChange: (value: boolean) => void, help?: string, inherited = false) => (
    <div className="cache-rule-dialog-row">
      <div className="cache-rule-dialog-row__main">
        <span className="cache-rule-dialog-row__title" id={`${id}-${key}`}>
          {t(`dialog.${key}`)}
          {help ? <Tooltip title={help}><CircleHelp size={13} aria-label={help} className="cache-rule-dialog-help" /></Tooltip> : null}
        </span>
        <span className="cache-rule-dialog-row__desc">{t(`dialog.${key}Desc`)}</span>
      </div>
      <Switch aria-label={t(`dialog.${key}`)} checked={checked} disabled={props.disabled || noCache || inherited} onChange={onChange} />
    </div>
  )

  return (
    <Modal
      open={props.open}
      title={t(props.editing ? 'dialog.editTitle' : 'dialog.addTitle')}
      footer={<ModalFooter okText={t('dialog.ok')} cancelText={t('dialog.cancel')} okDisabled={props.disabled} onOk={submit} onCancel={props.onCancel} />}
      onCancel={props.onCancel}
      width={MODAL_WIDTH.M}
      destroyOnHidden
      className="cache-rule-dialog"
    >
      <h4 className="cache-rule-dialog-section">{t('dialog.basic')}</h4>
      <div className="cache-rule-dialog-field">
        <span id={`${id}-scope`}>{t('dialog.scope')}：</span>
        <div>
          <Radio.Group
            aria-labelledby={`${id}-scope`}
            optionType="button"
            value={draft.scope}
            disabled={props.disabled}
            onChange={(event) => setDraft((value) => ({ ...value, scope: event.target.value as CacheRuleScope, scopeValue: '' }))}
            options={(['home', 'site', 'dir', 'suffix', 'path'] as const).map((value) => ({ value, label: t(`dialog.scopes.${value}`) }))}
          />
          {draft.scope === 'dir' || draft.scope === 'suffix' || draft.scope === 'path' ? (
            <Input
              className="cache-rule-dialog-scope-input"
              aria-label={t(`dialog.scopeInput.${draft.scope}`)}
              placeholder={t(`dialog.scopeInput.${draft.scope}`)}
              value={draft.scopeValue}
              disabled={props.disabled}
              onChange={(event) => setDraft((value) => ({ ...value, scopeValue: event.target.value }))}
            />
          ) : null}
        </div>
      </div>
      <div className="cache-rule-dialog-field">
        <span id={`${id}-expire`}>{t('dialog.expire')}：</span>
        <div>
          <Space.Compact>
            <InputNumber
              aria-label={t('dialog.expire')}
              min={1}
              precision={0}
              value={draft.ttl}
              disabled={props.disabled || noCache}
              onChange={(value) => setDraft((current) => ({ ...current, ttl: value }))}
            />
            <Select<Unit>
              aria-label={t('dialog.expireUnit')}
              value={draft.unit}
              disabled={props.disabled || noCache}
              options={(['d', 'h', 's'] as const).map((value) => ({ value, label: t(`dialog.units.${value}`) }))}
              onChange={(unit) => setDraft((value) => ({ ...value, unit }))}
            />
          </Space.Compact>
          <Space size={6} wrap className="cache-rule-dialog-presets">
            {presets.map(([key, seconds]) => (
              <Button key={key} size="small" disabled={props.disabled || noCache}
                onClick={() => setDraft((value) => ({ ...value, ...splitTTL(seconds), ttl: splitTTL(seconds).value }))}>
                {t(`dialog.presets.${key}`)}
              </Button>
            ))}
          </Space>
        </div>
      </div>

      <h4 className="cache-rule-dialog-section">{t('dialog.strategy')}</h4>
      <div className="cache-rule-dialog-card">
        {switchRow('ignoreQuery', ignoreQuery, (value) => set({ ignore_query: value || undefined }), t('dialog.ignoreQueryHelp'),
          props.inheritedIgnoreQuery)}
        {switchRow('forceCache', forceCache, (value) => set({ force_cache: value ? undefined : false }), t('dialog.forceCacheHelp'))}
      </div>

      <div className="cache-rule-dialog-toggle">
        <Button
          icon={advancedOpen ? <ChevronUp size={14} aria-hidden="true" /> : <ChevronDown size={14} aria-hidden="true" />}
          iconPosition="end"
          aria-expanded={advancedOpen}
          aria-controls={`${id}-advanced`}
          onClick={() => setAdvancedOpen((value) => !value)}
        >
          {t(advancedOpen ? 'actions.hideAdvanced' : 'actions.showAdvanced')}
        </Button>
      </div>
      <div id={`${id}-advanced`} hidden={!advancedOpen}>
        <h4 className="cache-rule-dialog-section">{t('dialog.advanced')}</h4>
        <div className="cache-rule-dialog-card">
          {switchRow('slice', sliced, (value) => set({
            slice_bytes: value === props.inheritedSliceBytes > 0 ? undefined : value ? ruleSliceBytes : 0,
          }))}
          {switchRow('ignoreVary', rule.ignore_vary ?? false, (value) => set({ ignore_vary: value || undefined }))}
        </div>
        <div className="cache-rule-dialog-conditions">
          <div className="cache-rule-dialog-conditions__head">
            <strong>{t('dialog.noCache')}</strong>
            <span>{t('dialog.noCacheCount', { count: conditions.length })}</span>
          </div>
          <p>{t('dialog.noCacheDesc')}</p>
          {conditions.length === 0 ? (
            <Empty image={null} description={t('dialog.noCacheEmpty')} className="cache-rule-dialog-conditions__empty" />
          ) : (
            <ul className="cache-rule-dialog-conditions__list">
              {conditions.map((item, index) => (
                <li key={`${index}-${item.source}-${item.pattern}`}>
                  <span>{item.source === 'header' ? `${t('dialog.sources.header')} ${item.name}` : t(`dialog.sources.${item.source}`)}</span>
                  <code>{item.pattern}</code>
                  <Button type="text" danger size="small" aria-label={t('dialog.removeCondition')} disabled={props.disabled || noCache}
                    icon={<Trash2 size={14} aria-hidden="true" />}
                    onClick={() => set({ no_cache: conditions.filter((_, position) => position !== index) })} />
                </li>
              ))}
            </ul>
          )}
          <div className="cache-rule-dialog-conditions__add">
            <Select<CacheConditionSource>
              aria-label={t('dialog.noCacheSource')}
              placeholder={t('dialog.noCacheSource')}
              value={condition.source}
              disabled={props.disabled || noCache}
              options={cacheConditionSources.map((value) => ({ value, label: t(`dialog.sources.${value}`) }))}
              onChange={(source) => setCondition((value) => ({ ...value, source }))}
            />
            {condition.source === 'header' ? (
              <Input aria-label={t('dialog.noCacheHeader')} placeholder={t('dialog.noCacheHeader')} value={condition.name}
                disabled={props.disabled || noCache} onChange={(event) => setCondition((value) => ({ ...value, name: event.target.value }))} />
            ) : null}
            <Input aria-label={t('dialog.noCachePattern')} placeholder={t('dialog.noCachePattern')} value={condition.pattern}
              maxLength={cachePathRegexMaxLength} disabled={props.disabled || noCache}
              onChange={(event) => setCondition((value) => ({ ...value, pattern: event.target.value }))} />
            <Button icon={<Plus size={14} aria-hidden="true" />} disabled={props.disabled || noCache} onClick={addCondition}>
              {t('dialog.addCondition')}
            </Button>
          </div>
        </div>

        <div className="cache-rule-dialog-toggle">
          <Button type="link" aria-expanded={moreOpen} aria-controls={`${id}-more`} onClick={() => setMoreOpen((value) => !value)}>
            {t('dialog.more')}
          </Button>
        </div>
        <div id={`${id}-more`} hidden={!moreOpen} className="cache-rule-dialog-more">
          {draft.scope !== 'suffix' && draft.scope !== 'home' && draft.scope !== 'path' ? (
            <label>
              <span>{t('fields.extensions')}</span>
              <Input aria-label={t('fields.extensions')} value={(rule.extensions ?? []).join(', ')} disabled={props.disabled}
                onChange={(event) => set({ extensions: event.target.value.split(',').map((item) => item.trim()).filter(Boolean) })} />
            </label>
          ) : null}
          <label>
            <span>{t('fields.pathRegex')}</span>
            <Input aria-label={t('fields.pathRegex')} placeholder={t('placeholders.pathRegex')} value={rule.path_regex ?? ''}
              maxLength={cachePathRegexMaxLength} disabled={props.disabled} onChange={(event) => set({ path_regex: event.target.value })} />
          </label>
          <label>
            <span>{t('fields.contentTypes')}</span>
            <Input aria-label={t('fields.contentTypes')} placeholder={t('placeholders.contentTypes')}
              value={(rule.content_types ?? []).join(', ')} disabled={props.disabled}
              onChange={(event) => set({ content_types: event.target.value.split(',').map((item) => item.trim()).filter(Boolean) })} />
          </label>
          <label>
            <span>{t('fields.statusCodes')}</span>
            <Input aria-label={t('fields.statusCodes')} value={(rule.status_codes ?? []).join(', ')} disabled={props.disabled}
              onChange={(event) => set({ status_codes: event.target.value.split(',').map((item) => item.trim()).filter(Boolean).map(Number) })} />
          </label>
          <label>
            <span>{t('fields.action')}</span>
            <Select<CacheRuleAction>
              aria-label={t('fields.action')}
              value={rule.action ?? 'cache'}
              disabled={props.disabled}
              options={(['cache', 'no_cache'] as const).map((value) => ({ value, label: t(`ruleActions.${value}`) }))}
              onChange={(action) => {
                set(action === 'no_cache' ? { action, browser_ttl_seconds: 0 } : { action, browser_ttl_seconds: 0 })
                if (action === 'cache' && draft.ttl === null) setDraft((value) => ({ ...value, ttl: 1, unit: 'h' }))
              }}
            />
          </label>
          <label>
            <span>{t('fields.browserTtlSeconds')}</span>
            <InputNumber aria-label={t('fields.browserTtlSeconds')} min={0} precision={0} placeholder={t('help.browserTtlOff')}
              value={noCache ? null : rule.browser_ttl_seconds ?? 0} disabled={props.disabled || noCache}
              onChange={(value) => set({ browser_ttl_seconds: Number(value ?? 0) })} />
            <small>{noCache ? t('help.noCache') : t('help.browserTtl')}</small>
          </label>
        </div>
      </div>
      {error ?? props.serverError ? (
        <Alert type="warning" showIcon role="alert" message={error ?? props.serverError} className="cache-rule-dialog-error" />
      ) : null}
    </Modal>
  )
}
