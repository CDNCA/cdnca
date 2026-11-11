import { useEffect, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Drawer, Form, Input, Radio, Spin, Switch, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import {
  createSecurityStringSet,
  getSecurityStringSet,
  parseStringSetEntries,
  stringSetLimits,
  stringSetMatchModes,
  updateSecurityStringSet,
  type SecurityStringSet,
  type SecurityStringSetAudience,
  type SecurityStringSetSummary,
  type StringSetMatchMode,
} from '../../api/securityStringSets'
import '../../i18n/securityLists'
import { DRAWER_WIDTH, InlineNotice, ModalFooter, useFeedback } from '@cdnca/ui'
import { formatBytes, lineOfEntry, memberLimit, summarizeMembers } from './stringSetMembers'

interface SetForm {
  name: string
  description: string
  match_mode: StringSetMatchMode
  case_sensitive: boolean
  entries: string
}

const maxListedProblems = 5

/**
 * 添加 / 编辑 / 查看字符串集合: name, description, match
 * mode and case (fixed after creation), members one per line with a live
 * counter and line-numbered problems under the box.
 */
export function StringSetDrawer({ target, audience, accessToken, readOnly, onClose, onSaved }: {
  target: SecurityStringSetSummary | 'new' | null
  audience: SecurityStringSetAudience
  accessToken: string
  readOnly: boolean
  onClose: () => void
  onSaved: (set: SecurityStringSet) => void
}) {
  const { t } = useTranslation('securityLists')
  const feedback = useFeedback()
  const [form] = Form.useForm<SetForm>()
  const [busy, setBusy] = useState(false)
  const [serverProblem, setServerProblem] = useState<string | null>(null)
  const existing = target !== null && target !== 'new' ? target : null
  const detail = useQuery({
    queryKey: ['security-string-sets', audience, 'detail', existing?.id, existing?.revision],
    queryFn: () => getSecurityStringSet(accessToken, audience, existing?.id ?? ''),
    enabled: Boolean(existing && accessToken),
    retry: false,
  })

  useEffect(() => {
    if (target === null) return
    setServerProblem(null)
    if (target === 'new') {
      form.setFieldsValue({ name: '', description: '', match_mode: 'exact', case_sensitive: true, entries: '' })
    } else if (detail.data) {
      form.setFieldsValue({ name: detail.data.name, description: detail.data.description, match_mode: detail.data.match_mode,
        case_sensitive: detail.data.case_sensitive, entries: detail.data.entries.join('\n') })
    }
  }, [target, detail.data, form])

  const mode = (Form.useWatch('match_mode', form) ?? 'exact') as StringSetMatchMode
  const caseSensitive = Form.useWatch('case_sensitive', form) ?? true
  const entriesText = (Form.useWatch('entries', form) ?? '') as string
  const summary = useMemo(() => summarizeMembers(entriesText, mode, caseSensitive), [entriesText, mode, caseSensitive])
  const limit = memberLimit(mode)
  const over = summary.overCount || summary.overBytes

  const problemText = summary.problems.length === 0 ? null : (
    <>
      {summary.problems.slice(0, maxListedProblems).map((problem) => t('errors.line', { line: problem.line, reason: t(`lineReason.${problem.reason}`) })).join('；')}
      {summary.problems.length > maxListedProblems ? `（${t('form.moreProblems', { count: summary.problems.length - maxListedProblems })}）` : null}
    </>
  )

  const showServerError = (error: unknown, text: string) => {
    if (!(error instanceof ApiError)) return feedback.error(t('errors.failed'))
    if (error.code === 'validation_error' && error.field) {
      const entry = /^entries\[(\d+)\]$/.exec(error.field)
      if (entry) {
        const line = lineOfEntry(text, Number(entry[1]))
        setServerProblem(t('errors.line', { line: line ?? Number(entry[1]) + 1, reason: t(`lineReason.${error.reason ?? 'empty'}`, { defaultValue: error.reason ?? '' }) }))
        return
      }
      if (error.field === 'entries') {
        setServerProblem(t(`setReason.${error.reason ?? 'none'}`, { defaultValue: t('setReason.none') }))
        return
      }
      if (error.field === 'name' || error.field === 'description') {
        form.setFields([{ name: error.field, errors: [t('errors.failed')] }])
        return
      }
    }
    switch (error.code) {
      case 'string_set_name_conflict':
        form.setFields([{ name: 'name', errors: [t('errors.nameConflict')] }])
        form.scrollToField('name')
        return
      case 'version_conflict':
        feedback.error(t('errors.version'), { detail: t('errors.versionDetail'), actions: [{ label: t('actions.reload'), primary: true, onClick: () => { void detail.refetch() } }] })
        return
      case 'string_set_limit':
        feedback.error(t('errors.limit'))
        return
      case 'string_set_not_found':
        feedback.error(t('errors.notFound'))
        return
    }
    feedback.error(error.status === 403 ? t('errors.permission') : t('errors.failed'))
  }

  const save = async () => {
    const values = await form.validateFields().catch(() => null)
    if (!values) return
    setServerProblem(null)
    const entries = parseStringSetEntries(values.entries ?? '')
    if (entries.length === 0) {
      setServerProblem(t('setReason.none'))
      return
    }
    if (summary.problems.length > 0 || over) {
      // Saving stays possible; the reason is shown at the member box.
      form.scrollToField('entries')
      document.getElementById('string-set-members')?.focus()
      return
    }
    setBusy(true)
    try {
      const saved = existing
        ? await updateSecurityStringSet(accessToken, audience, detail.data ?? existing,
          { name: values.name.trim(), description: (values.description ?? '').trim(), entries })
        : await createSecurityStringSet(accessToken, audience, { name: values.name.trim(),
          description: (values.description ?? '').trim(), match_mode: values.match_mode, case_sensitive: values.case_sensitive, entries })
      onSaved(saved)
    } catch (error) {
      showServerError(error, values.entries ?? '')
    } finally {
      setBusy(false)
    }
  }

  const title = target === 'new' ? t('form.createTitle')
    : readOnly ? t('form.viewTitle', { name: existing?.name ?? '' }) : t('form.editTitle', { name: existing?.name ?? '' })
  const counterId = 'string-set-members-counter'
  const problemsId = 'string-set-members-problems'

  return (
    <Drawer open={target !== null} title={title} width={DRAWER_WIDTH.L} onClose={onClose} destroyOnHidden
      footer={readOnly ? null : <ModalFooter onCancel={onClose} onOk={() => void save()} okText={t('actions.save')} cancelText={t('actions.cancel')} loading={busy} />}>
      {existing && detail.isLoading ? <Spin /> : (
        <Form form={form} layout="vertical" disabled={readOnly} className="string-set-form">
          <Form.Item name="name" label={t('form.name')} rules={[{ required: true, whitespace: true, max: stringSetLimits.maxNameLength }]}>
            <Input maxLength={stringSetLimits.maxNameLength} />
          </Form.Item>
          <Form.Item name="description" label={t('form.description')} rules={[{ max: stringSetLimits.maxDescriptionLength }]}>
            <Input maxLength={stringSetLimits.maxDescriptionLength} />
          </Form.Item>
          {existing ? (
            <Form.Item label={t('form.mode')} extra={t('form.modeLocked')}>
              <Typography.Text>{t(`mode.${mode}`)} · {t(caseSensitive ? 'case.sensitive' : 'case.insensitive')}</Typography.Text>
            </Form.Item>
          ) : (
            <>
              <Form.Item name="match_mode" label={t('form.mode')} extra={t('form.modeLocked')} rules={[{ required: true }]}>
                <Radio.Group className="string-set-modes">
                  {stringSetMatchModes.map((value) => (
                    <Radio key={value} value={value}>
                      <span className="string-set-mode-name">{t(`mode.${value}`)}</span>
                      <span className="string-set-mode-example">{t(`modeExample.${value}`)}</span>
                    </Radio>
                  ))}
                </Radio.Group>
              </Form.Item>
              <Form.Item name="case_sensitive" label={t('form.caseSensitive')} valuePropName="checked"
                extra={caseSensitive ? t('form.caseHint') : t('form.caseInsensitiveHint')}>
                <Switch />
              </Form.Item>
            </>
          )}
          {mode === 'prefix' ? <InlineNotice type="warning">{t('form.prefixHint')}</InlineNotice> : null}
          {mode === 'wildcard' ? <InlineNotice type="warning">{t('form.wildcardHint')}</InlineNotice> : null}
          <Form.Item name="entries" label={
            <span className="string-set-members-label">
              <span>{t('form.members')}</span>
              <span id={counterId} className={over ? 'string-set-counter string-set-counter-over' : 'string-set-counter'} aria-live="polite">
                {over ? '⚠ ' : null}{t('form.counter', { n: summary.count.toLocaleString(), max: limit.toLocaleString(), size: formatBytes(summary.bytes) })}
              </span>
            </span>
          } extra={t('form.normalizeHint')}>
            <Input.TextArea id="string-set-members" className="string-set-members" autoSize={{ minRows: 8, maxRows: 20 }}
              spellCheck={false} aria-describedby={`${counterId} ${problemsId}`} aria-invalid={summary.problems.length > 0 || over || Boolean(serverProblem)} />
          </Form.Item>
          <div id={problemsId}>
            <InlineNotice>{problemText}</InlineNotice>
            <InlineNotice>{summary.overCount ? t('setReason.too_many_entries') : summary.overBytes ? t('setReason.too_large') : null}</InlineNotice>
            <InlineNotice onClose={() => setServerProblem(null)}>{serverProblem}</InlineNotice>
          </div>
        </Form>
      )}
    </Drawer>
  )
}
