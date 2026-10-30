import { Alert, Button, Input, InputNumber, Select, Space } from 'antd'
import { ArrowDown, ArrowUp, Plus, Trash2 } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import type {
  ResponseHeaderActionKind,
  ResponseHeaderOp,
  ResponseRuleAction,
  SiteResponseRule,
} from '../../api/siteAccess'
import { newResponseRule } from './siteResponseRules'
import '../../i18n/siteAccess'
import { FormRow, SettingGroup } from './SiteEditFields'

const maxRules = 32
const actions: ResponseRuleAction[] = ['headers', 'log', 'error_page', 'block']
const ops: ResponseHeaderOp[] = ['exists', 'absent', 'equals', 'regex']
const kinds: ResponseHeaderActionKind[] = ['set', 'add', 'delete']

/**
 * 站点响应规则（响应阶段状态码/响应头）：按顺序在节点
 * 收到响应头时执行，不读响应体。
 */
export default function SiteResponseRulesEditor({ rules, statusTexts, disabled, onChange, onStatusText }: {
  rules: SiteResponseRule[]
  /** The status fields as typed (parsed on every change, kept for editing). */
  statusTexts: string[]
  disabled: boolean
  onChange: (rules: SiteResponseRule[], statusTexts: string[]) => void
  onStatusText: (index: number, text: string) => void
}) {
  const { t } = useTranslation('siteAccess')
  const update = (index: number, patch: Partial<SiteResponseRule>) =>
    onChange(rules.map((rule, position) => position === index ? { ...rule, ...patch } : rule), statusTexts)
  const move = (index: number, offset: number) => {
    const next = [...rules]
    const texts = [...statusTexts]
    ;[next[index], next[index + offset]] = [next[index + offset], next[index]]
    ;[texts[index], texts[index + offset]] = [texts[index + offset], texts[index]]
    onChange(next, texts)
  }
  return <SettingGroup title={t('responseRules.title')} tip={t('responseRules.hint')}>
    <Alert type="info" showIcon message={t('responseRules.cacheHint')} />
    {rules.map((rule, index) => {
      const label = (name: string) => `${t(name)} ${index + 1}`
      const headers = rule.headers ?? []
      const headerActions = rule.header_actions ?? []
      return <div key={index} role="group" aria-label={label('responseRules.rule')} className="site-response-rule">
        <Space wrap>
          <Input aria-label={label('responseRules.id')} style={{ width: 160 }} value={rule.id} disabled={disabled}
            onChange={(event) => update(index, { id: event.target.value })} />
          <Button aria-label={label('responseRules.up')} icon={<ArrowUp size={15} />} disabled={disabled || index === 0}
            onClick={() => move(index, -1)} />
          <Button aria-label={label('responseRules.down')} icon={<ArrowDown size={15} />} disabled={disabled || index === rules.length - 1}
            onClick={() => move(index, 1)} />
          <Button danger icon={<Trash2 size={15} />} disabled={disabled}
            onClick={() => onChange(rules.filter((_, position) => position !== index), statusTexts.filter((_, position) => position !== index))}>
            {t('responseRules.remove')}</Button>
        </Space>
        <FormRow label={t('responseRules.statuses')} help={t('responseRules.statusesHint')}>
          <Input aria-label={label('responseRules.statuses')} style={{ maxWidth: 320 }} value={statusTexts[index] ?? ''} disabled={disabled}
            placeholder="404, 500-504" onChange={(event) => onStatusText(index, event.target.value)} />
        </FormRow>
        <FormRow label={t('responseRules.headers')} help={t('responseRules.headersHint')}>
          <Space direction="vertical">
            {headers.map((condition, position) => <Space key={position} wrap>
              <Input aria-label={`${label('responseRules.headerName')}.${position + 1}`} style={{ width: 180 }} value={condition.name}
                disabled={disabled} placeholder="X-Powered-By"
                onChange={(event) => update(index, { headers: headers.map((item, at) => at === position ? { ...item, name: event.target.value } : item) })} />
              <Select aria-label={`${label('responseRules.op')}.${position + 1}`} style={{ width: 140 }} value={condition.op} disabled={disabled}
                options={ops.map((value) => ({ value, label: t(`responseRules.ops.${value}`) }))}
                onChange={(value) => update(index, { headers: headers.map((item, at) => at === position ? { ...item, op: value } : item) })} />
              {condition.op === 'equals' || condition.op === 'regex'
                ? <Input aria-label={`${label('responseRules.headerValue')}.${position + 1}`} style={{ width: 220 }} value={condition.value ?? ''}
                  disabled={disabled}
                  onChange={(event) => update(index, { headers: headers.map((item, at) => at === position ? { ...item, value: event.target.value } : item) })} />
                : null}
              <Button aria-label={`${label('responseRules.removeCondition')}.${position + 1}`} icon={<Trash2 size={15} />} disabled={disabled}
                onClick={() => update(index, { headers: headers.filter((_, at) => at !== position) })} />
            </Space>)}
            <Button icon={<Plus size={15} />} disabled={disabled || headers.length >= 8}
              onClick={() => update(index, { headers: [...headers, { name: '', op: 'exists' }] })}>{label('responseRules.addCondition')}</Button>
          </Space>
        </FormRow>
        <FormRow label={t('responseRules.action')} help={t(`responseRules.actionHints.${rule.action}`)}>
          <Select aria-label={label('responseRules.action')} style={{ width: 200 }} value={rule.action} disabled={disabled}
            options={actions.map((value) => ({ value, label: t(`responseRules.actions.${value}`) }))}
            onChange={(value) => update(index, {
              action: value,
              header_actions: value === 'headers' && !headerActions.length ? [{ kind: 'set', name: '', value: '' }] : headerActions,
              status: value === 'error_page' || value === 'block' ? rule.status ?? (value === 'block' ? 403 : 503) : undefined,
            })} />
        </FormRow>
        {rule.action === 'headers' ? <FormRow label={t('responseRules.headerActions')} help={t('responseRules.reservedHint')}>
          <Space direction="vertical">
            {headerActions.map((action, position) => <Space key={position} wrap>
              <Select aria-label={`${label('responseRules.kind')}.${position + 1}`} style={{ width: 120 }} value={action.kind} disabled={disabled}
                options={kinds.map((value) => ({ value, label: t(`responseRules.kinds.${value}`) }))}
                onChange={(value) => update(index, { header_actions: headerActions.map((item, at) => at === position ? { ...item, kind: value } : item) })} />
              <Input aria-label={`${label('responseRules.actionName')}.${position + 1}`} style={{ width: 180 }} value={action.name} disabled={disabled}
                onChange={(event) => update(index, { header_actions: headerActions.map((item, at) => at === position ? { ...item, name: event.target.value } : item) })} />
              {action.kind !== 'delete'
                ? <Input aria-label={`${label('responseRules.actionValue')}.${position + 1}`} style={{ width: 220 }} value={action.value ?? ''}
                  disabled={disabled}
                  onChange={(event) => update(index, { header_actions: headerActions.map((item, at) => at === position ? { ...item, value: event.target.value } : item) })} />
                : null}
              <Button aria-label={`${label('responseRules.removeAction')}.${position + 1}`} icon={<Trash2 size={15} />}
                disabled={disabled || headerActions.length <= 1}
                onClick={() => update(index, { header_actions: headerActions.filter((_, at) => at !== position) })} />
            </Space>)}
            <Button icon={<Plus size={15} />} disabled={disabled || headerActions.length >= 16}
              onClick={() => update(index, { header_actions: [...headerActions, { kind: 'set', name: '', value: '' }] })}>
              {label('responseRules.addAction')}</Button>
          </Space>
        </FormRow> : null}
        {rule.action === 'error_page' || rule.action === 'block' ? <FormRow label={t('responseRules.status')}>
          <InputNumber aria-label={label('responseRules.status')} min={400} max={599} value={rule.status} disabled={disabled}
            onChange={(value) => update(index, { status: value ?? undefined })} />
        </FormRow> : null}
      </div>
    })}
    <Button icon={<Plus size={15} />} disabled={disabled || rules.length >= maxRules}
      onClick={() => onChange([...rules, newResponseRule(rules)], [...statusTexts, ''])}>{t('responseRules.add')}</Button>
    {rules.length ? <Alert type="info" showIcon message={t('responseRules.nodeHint')} /> : null}
  </SettingGroup>
}
