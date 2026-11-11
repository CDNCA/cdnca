import { useEffect, useRef, useState } from 'react'
import { Alert, Button, Checkbox, Drawer, Input, Radio, Segmented, Select, Space, Switch } from 'antd'
import { useTranslation } from 'react-i18next'

import {
  rewriteContentTypes, rewriteKinds, type RewriteContentType, type RewriteKind, type RewriteRule, type RewriteScheme,
} from '../../api/contentRewrite'

// 内容改写 rule editor: the fields of
// the chosen kind; the server's field error (rules[i].<field>) lands under
// its field and in a summary that takes focus.

export interface FieldProblem { field: string; reason: string }

interface Props {
  open: boolean
  rule: RewriteRule
  isNew: boolean
  saving: boolean
  problem?: FieldProblem
  onCancel: () => void
  onSave: (rule: RewriteRule) => void
}

const fieldOf = (problem?: FieldProblem) => problem?.field.replace(/^rules\[\d+\]\./u, '')

export function RuleDrawer({ open, rule, isNew, saving, problem, onCancel, onSave }: Props) {
  const { t } = useTranslation('contentRewrite')
  const [draft, setDraft] = useState<RewriteRule>(rule)
  const [touched, setTouched] = useState<Record<string, boolean>>({})
  const summaryRef = useRef<HTMLDivElement>(null)
  useEffect(() => { setDraft(rule); setTouched({}) }, [rule])
  useEffect(() => { if (problem) summaryRef.current?.focus() }, [problem])
  const set = (patch: Partial<RewriteRule>) => setDraft((current) => ({ ...current, ...patch }))
  const blur = (name: string) => () => setTouched((current) => ({ ...current, [name]: true }))
  const serverField = fieldOf(problem)
  // inline checks on blur (lengths and required fields); the server decides the rest
  const local: Record<string, string | undefined> = {
    name: [...draft.name].length > 64 ? t('form.tooLong') : undefined,
    from_hosts: draft.kind === 'link' && (draft.from_hosts ?? []).length === 0 ? t('form.required') : undefined,
    to_host: draft.kind === 'link' && !(draft.to_host ?? '').trim() ? t('form.required') : undefined,
    find: draft.kind === 'replace' && !(draft.find ?? '') ? t('form.required')
      : new TextEncoder().encode(draft.find ?? '').length > 256 ? t('form.tooLong') : undefined,
  }
  const errorOf = (name: string) => serverField === name ? problem?.reason : touched[name] ? local[name] : undefined
  const field = (name: string, label: string, control: React.ReactNode, hint?: string) => {
    const error = errorOf(name)
    return (
      <div className="cr-field">
        <label className="cr-label" htmlFor={`cr-${name}`}>{label}</label>
        {control}
        {hint ? <div className="cr-hint" id={`cr-${name}-hint`}>{hint}</div> : null}
        {error ? <div className="cr-error" role="alert" id={`cr-${name}-error`}>{error}</div> : null}
      </div>
    )
  }
  const described = (name: string, hint?: boolean) => [hint ? `cr-${name}-hint` : '', errorOf(name) ? `cr-${name}-error` : '']
    .filter(Boolean).join(' ') || undefined
  const tags = (name: 'paths' | 'from_hosts' | 'hosts', label: string, hint: string) => field(name, label,
    <Select id={`cr-${name}`} mode="tags" open={false} tokenSeparators={[',', ' ', '，']} value={draft[name] ?? []}
      aria-describedby={described(name, true)} aria-invalid={Boolean(errorOf(name))} onBlur={blur(name)}
      onChange={(value: string[]) => set({ [name]: value })} />, hint)
  const valid = Object.values(local).every((value) => value === undefined)
  return (
    <Drawer open={open} width={520} title={isNew ? t('drawerNew') : t('drawerEdit')} onClose={onCancel} destroyOnHidden
      footer={<Space className="cr-drawer-footer">
        <Button onClick={onCancel}>{t('cancel')}</Button>
        <Button type="primary" loading={saving} onClick={() => {
          setTouched({ name: true, from_hosts: true, to_host: true, find: true })
          if (valid) onSave(draft)
        }}>{t('save')}</Button>
      </Space>}>
      {problem ? <div ref={summaryRef} tabIndex={-1} className="cr-summary">
        <Alert type="error" showIcon message={t('errorSummary')}
          description={<a href={`#cr-${serverField}`}>{problem.reason}</a>} />
      </div> : null}
      {field('name', t('form.name'), <Input id="cr-name" value={draft.name} maxLength={64} onBlur={blur('name')}
        aria-describedby={described('name')} aria-invalid={Boolean(errorOf('name'))}
        onChange={(event) => set({ name: event.target.value })} />)}
      {field('kind', t('form.kind'), <Segmented id="cr-kind" block value={draft.kind}
        onChange={(value) => set({ kind: value as RewriteKind })}
        options={rewriteKinds.map((kind) => ({ value: kind, label: t(`kind.${kind}`) }))} />)}
      {draft.kind === 'link' ? <>
        {tags('from_hosts', t('form.fromHosts'), t('form.fromHostsHint'))}
        {field('to_host', t('form.toHost'), <Input id="cr-to_host" className="cr-mono" value={draft.to_host ?? ''}
          onBlur={blur('to_host')} aria-describedby={described('to_host', true)} aria-invalid={Boolean(errorOf('to_host'))}
          onChange={(event) => set({ to_host: event.target.value })} />, t('form.toHostHint'))}
        {field('scheme', t('form.scheme'), <Radio.Group id="cr-scheme" value={draft.scheme ?? 'keep'}
          onChange={(event) => set({ scheme: event.target.value as RewriteScheme })}
          options={(['keep', 'https', 'http'] as const).map((value) => ({ value, label: t(`form.schemes.${value}`) }))} />)}
      </> : null}
      {draft.kind === 'replace' ? <>
        {field('find', t('form.find'), <Input.TextArea id="cr-find" className="cr-mono" rows={2} value={draft.find ?? ''}
          onBlur={blur('find')} aria-describedby={described('find', draft.regex)} aria-invalid={Boolean(errorOf('find'))}
          onChange={(event) => set({ find: event.target.value })} />, draft.regex ? t('form.regexHint') : undefined)}
        {field('replace', t('form.replace'), <Input.TextArea id="cr-replace" className="cr-mono" rows={2} maxLength={1024}
          value={draft.replace ?? ''} aria-describedby={described('replace')} aria-invalid={Boolean(errorOf('replace'))}
          onChange={(event) => set({ replace: event.target.value })} />)}
        <Space size="large" wrap className="cr-field">
          <Checkbox checked={draft.regex ?? false} onChange={(event) => set({ regex: event.target.checked })}>{t('form.regex')}</Checkbox>
          <Checkbox checked={draft.ignore_case ?? false} onChange={(event) => set({ ignore_case: event.target.checked })}>{t('form.ignoreCase')}</Checkbox>
        </Space>
      </> : null}
      {draft.kind === 'https' ? <>
        <div className="cr-field">
          <Checkbox checked={draft.include_site_domains ?? true} onChange={(event) => set({ include_site_domains: event.target.checked })}>
            {t('form.includeSiteDomains')}
          </Checkbox>
        </div>
        {tags('hosts', t('form.hosts'), t('form.hostsHint'))}
      </> : null}
      {tags('paths', t('form.paths'), t('form.pathsHint'))}
      <div className="cr-field" role="group" aria-labelledby="cr-content_types-label"
        aria-describedby={draft.kind !== 'replace' ? 'cr-content_types-hint' : undefined}>
        <span className="cr-label" id="cr-content_types-label">{t('form.contentTypes')}</span>
        <Checkbox.Group value={draft.content_types} onChange={(value) => set({ content_types: value as RewriteContentType[] })}
          options={rewriteContentTypes.map((value) => ({ value, label: t(`types.${value}`) }))} />
        {draft.kind !== 'replace' ? <div className="cr-hint" id="cr-content_types-hint">{t('form.htmlScope')}</div> : null}
        {errorOf('content_types') ? <div className="cr-error" role="alert">{errorOf('content_types')}</div> : null}
      </div>
      <div className="cr-field cr-inline">
        <Switch id="cr-enabled" checked={draft.enabled} onChange={(enabled) => set({ enabled })} />
        <label htmlFor="cr-enabled">{t('form.enabled')}</label>
      </div>
    </Drawer>
  )
}
