import { useRef, useState } from 'react'
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Form, Input, Modal, Pagination, Switch, Table, Typography } from 'antd'
import { useFeedbackMessage, useFeedback, FeedbackWhen, InlineNotice } from '@cdnca/ui'
import type { InputRef, TableColumnsType } from 'antd'
import { Plus, Search, Trash2 } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import { dnsPlatformApi, type PlatformDNSZone } from '../../api/dnsPlatform'
import '../../i18n/dnsConfig'

const domainPattern = /^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$/i
const newKey = (action: string) => `dns-zone-${action}-${crypto.randomUUID()}`

type Editor = { mode: 'create' } | { mode: 'edit'; zone: PlatformDNSZone }
type ZoneField = 'name' | 'remark'

// C11: refusals that are about the domain field are shown on it, not as a toast.
const nameFieldCodes = new Set(['dns_zone_not_hosted', 'dns_resource_conflict', 'platform_zone_conflict', 'dns_zone_in_use'])

// CNAME域名: the domains site CNAMEs are allocated under (dns_zones copies in
// every tenant; the first one is the default allocation zone). 参与随机分配
// (fix-cnamerand): new sites without a CNAME domain draw one of the checked
// domains; with none checked they use the default zone.
export default function CnameDomainPanel({ accessToken, owner, canManage }: { accessToken: string; owner: string[]; canManage: boolean }) {
  const { t } = useTranslation('dnsConfig')
  const queryClient = useQueryClient()
  const [messageApi, messageContext] = useFeedbackMessage()
  const feedback = useFeedback()
  const [modal, modalContext] = Modal.useModal()
  const [page, setPage] = useState(1)
  const [limit, setLimit] = useState(10)
  const [search, setSearch] = useState('')
  const [selectNotice, setSelectNotice] = useState(false)
  const [draftSearch, setDraftSearch] = useState('')
  const [selected, setSelected] = useState<PlatformDNSZone[]>([])
  const [editor, setEditor] = useState<Editor | null>(null)
  const [form, setForm] = useState({ name: '', remark: '', random: false })
  // C04：输入错误显示在字段下并聚焦，不再叠第二层弹窗。
  const [fieldErrors, setFieldErrors] = useState<Partial<Record<ZoneField, string>>>({})
  const nameInput = useRef<InputRef>(null)
  const saveKey = useRef<string | null>(null)
  const prefix = ['dns-platform-zones', ...owner]
  const zonesQuery = useQuery({
    queryKey: [...prefix, page, limit, search], placeholderData: keepPreviousData, retry: false,
    queryFn: () => dnsPlatformApi.zones(accessToken, { page, limit, search }),
  })
  const failure = (fallback: string, cause: unknown) => {
    const code = cause instanceof ApiError ? cause.code : ''
    if (code === 'dns_zone_in_use') return t('errors.zoneInUse')
    if (code === 'dns_resource_conflict') return t('errors.zoneConflict')
    return t(`errors.codes.${code}`, { defaultValue: '' }) || `${fallback}${code ? ` (${code})` : ''}`
  }
  const refresh = () => queryClient.invalidateQueries({ queryKey: prefix })
  // NET-UX-3 (#69): the editor a save was sent from; a late reply of an older
  // save must not close or mark errors on an editor opened afterwards.
  const editorRef = useRef<Editor | null>(null)
  editorRef.current = editor
  const saveMutation = useMutation({
    mutationFn: (sentFrom: Editor | null) => {
      saveKey.current ??= newKey(sentFrom?.mode ?? 'create')
      const input = { name: form.name.trim().toLowerCase().replace(/\.$/, ''), remark: form.remark.trim(), random_allocation: form.random }
      return sentFrom?.mode === 'edit'
        ? dnsPlatformApi.updateZone(accessToken, sentFrom.zone, input, saveKey.current)
        : dnsPlatformApi.createZone(accessToken, input, saveKey.current)
    },
    onSuccess: async (_, sentFrom) => {
      if (editorRef.current === sentFrom) {
        saveKey.current = null
        setEditor(null)
      }
      messageApi.success(t('messages.zoneSaved'))
      await refresh()
    },
    onError: (cause, sentFrom) => {
      // An older editor is gone: report it, never on the fields of the new one.
      if (editorRef.current !== sentFrom) {
        feedback.error(failure(t('errors.saveFailed'), cause))
        return
      }
      const code = cause instanceof ApiError ? cause.code : ''
      const field: ZoneField | undefined = nameFieldCodes.has(code) ? 'name'
        : code === 'validation_error' && cause instanceof ApiError && (cause.field === 'name' || cause.field === 'remark') ? cause.field
          : undefined
      if (field) {
        // The same input would be refused again: the next save is a new request.
        saveKey.current = null
        setFieldErrors({ [field]: code === 'validation_error' ? t(field === 'name' ? 'errors.zoneName' : 'errors.remarkInvalid') : failure(t('errors.saveFailed'), cause) })
        return
      }
      feedback.error(failure(t('errors.saveFailed'), cause))
    },
  })
  // The list switch saves the mark alone (name and remark as listed).
  const randomMutation = useMutation({
    mutationFn: ({ zone, random }: { zone: PlatformDNSZone; random: boolean }) =>
      dnsPlatformApi.updateZone(accessToken, zone, { name: zone.name, remark: zone.remark, random_allocation: random }, newKey('random')),
    onSuccess: async () => {
      messageApi.success(t('zone.randomSaved'))
      await refresh()
    },
    onError: async (cause) => {
      feedback.error(failure(t('errors.saveFailed'), cause))
      await refresh()
    },
  })
  const deleteZones = async (zones: PlatformDNSZone[]) => {
    const failures: string[] = []
    for (const zone of zones) {
      try {
        await dnsPlatformApi.deleteZone(accessToken, zone, newKey('delete'))
      } catch (cause) {
        failures.push(`${zone.name}：${failure(t('errors.deleteFailed'), cause)}`)
      }
    }
    setSelected([])
    await refresh()
    // C11: deleting the last rows of the last page goes back to the page before.
    const after = queryClient.getQueryData<{ items: PlatformDNSZone[]; total: number }>([...prefix, page, limit, search])
    if (page > 1 && after && after.items.length === 0) setPage(Math.max(1, Math.ceil(after.total / limit)))
    if (failures.length > 0) feedback.error(failures.join('；'))
    else messageApi.success(t('messages.zoneDeleted'))
  }
  const confirmDelete = (zones: PlatformDNSZone[]) => {
    if (zones.length === 0) {
      // fix-feedbackui2: said under the toolbar, not in a dialog.
      setSelectNotice(true)
      return
    }
    setSelectNotice(false)
    void modal.confirm({
      title: t('actions.delete'), okText: t('actions.ok'), cancelText: t('actions.cancel'), okButtonProps: { danger: true },
      content: zones.length === 1 ? t('messages.deleteOneConfirm', { name: zones[0].name })
        : <>{t('messages.deleteConfirm', { count: zones.length })}<ul className="dns-zone-delete-list">
          {zones.map((zone) => <li key={zone.id}>{zone.name}</li>)}</ul></>,
      onOk: () => deleteZones(zones),
    })
  }
  const open = (next: Editor) => {
    saveKey.current = null
    setFieldErrors({})
    setForm(next.mode === 'edit' ? { name: next.zone.name, remark: next.zone.remark, random: next.zone.random_allocation }
      : { name: '', remark: '', random: false })
    setEditor(next)
  }
  const submit = () => {
    if (!domainPattern.test(form.name.trim().replace(/\.$/, ''))) {
      setFieldErrors({ name: t('errors.zoneName') })
      nameInput.current?.focus()
    } else saveMutation.mutate(editor)
  }
  const columns: TableColumnsType<PlatformDNSZone> = [
    { title: t('zone.id'), dataIndex: 'display_id', width: 220 },
    { title: t('zone.name'), dataIndex: 'name', width: 300 },
    { title: t('zone.remark'), dataIndex: 'remark' },
    {
      title: t('zone.random'), key: 'random', align: 'center', width: 140, render: (_, zone) => <Switch size="small"
        aria-label={t('zone.randomRow', { name: zone.name })} checked={zone.random_allocation}
        loading={randomMutation.isPending && randomMutation.variables?.zone.id === zone.id}
        disabled={!canManage || randomMutation.isPending} onChange={(random) => randomMutation.mutate({ zone, random })} />,
    },
    {
      title: t('zone.actions'), key: 'actions', align: 'center', width: 251, render: (_, zone) => <span className="dns-zone-actions">
        <Typography.Link disabled={!canManage} onClick={() => open({ mode: 'edit', zone })}>{t('actions.edit')}</Typography.Link>
        <Typography.Link disabled={!canManage} onClick={() => confirmDelete([zone])}>{t('actions.delete')}</Typography.Link>
      </span>,
    },
  ]
  const data = zonesQuery.data
  // Selection covers only the rows on screen: a new search, page or page size
  // clears it, and a refresh keeps only the rows still listed.
  const query = (next: { page: number; limit?: number; search?: string }) => {
    setSelected([])
    setPage(next.page)
    if (next.limit !== undefined) setLimit(next.limit)
    if (next.search !== undefined) setSearch(next.search)
  }
  const visible = new Set((data?.items ?? []).map((zone) => zone.id))
  const shown = zonesQuery.isError ? [] : selected.filter((zone) => visible.has(zone.id))
  // A failed read never shows stale rows as current: no list, no actions on it.
  const listed = zonesQuery.isError ? [] : data?.items ?? []

  return <div className="dns-cname-panel">
    {messageContext}{modalContext}
    <Alert className="dns-cname-help" type="info" showIcon message={t('zone.nameHelp')} description={t('zone.randomHelp')} />
    <div className="dns-cname-toolbar">
      <Button type="primary" icon={<Plus size={14} />} disabled={!canManage} onClick={() => open({ mode: 'create' })}>{t('actions.addZone')}</Button>
      <Button danger icon={<Trash2 size={14} />} disabled={!canManage || zonesQuery.isError} onClick={() => confirmDelete(shown)}>{t('actions.delete')}</Button>
      <Input className="dns-cname-search" aria-label={t('zone.search')} placeholder={t('zone.search')} value={draftSearch}
        suffix={<Search size={14} aria-hidden="true" onClick={() => query({ page: 1, search: draftSearch })} />}
        onChange={(event) => setDraftSearch(event.target.value)} onPressEnter={() => query({ page: 1, search: draftSearch })} />
    </div>
    <InlineNotice type="warning" onClose={() => setSelectNotice(false)}>{selectNotice && shown.length === 0 ? t('messages.selectFirst') : null}</InlineNotice>
    {zonesQuery.isError ? <FeedbackWhen title={t('errors.zonesLoadFailed')}
      action={<Button size="small" onClick={() => void zonesQuery.refetch()}>{t('actions.retry')}</Button>} /> : null}
    <Table<PlatformDNSZone> className="dns-cname-table" rowKey="id" size="middle" columns={columns} dataSource={listed}
      loading={zonesQuery.isFetching} pagination={false} locale={{ emptyText: zonesQuery.isError ? t('errors.zonesLoadFailed') : t('zone.empty') }}
      rowSelection={{ columnWidth: 70, selectedRowKeys: shown.map((zone) => zone.id), getCheckboxProps: () => ({ disabled: !canManage }),
        onChange: (_, rows) => setSelected(rows) }} />
    <Pagination className="dns-cname-pagination" current={page} pageSize={limit} total={zonesQuery.isError ? 0 : data?.total ?? 0} showSizeChanger
      pageSizeOptions={[10, 20, 50, 100]} showTotal={(total) => t('zone.total', { total })}
      locale={{ items_per_page: '条/页' }} onChange={(next, size) => query({ page: size === limit ? next : 1, limit: size })} />
    <Modal open={editor !== null} title={editor?.mode === 'edit' ? t('zone.editTitle') : t('zone.addTitle')} width={520}
      className="dns-zone-modal" rootClassName="dns-zone-modal-root" onCancel={() => setEditor(null)} destroyOnHidden
      footer={[
        <Button key="cancel" onClick={() => setEditor(null)}>{t('actions.cancel')}</Button>,
        <Button key="ok" type="primary" loading={saveMutation.isPending} onClick={submit}>{t('actions.ok')}</Button>,
      ]}>
      <Form className="dns-zone-form" labelCol={{ flex: '100px' }} labelAlign="right" colon={false}>
        <Form.Item label={t('zone.nameLabel')} extra={t('zone.nameHelp')}
          validateStatus={fieldErrors.name ? 'error' : undefined} help={fieldErrors.name}>
          <Input ref={nameInput} aria-label={t('zone.name')} value={form.name} placeholder={t('zone.namePlaceholder')} autoComplete="off"
            aria-invalid={fieldErrors.name ? true : undefined}
            onChange={(event) => { saveKey.current = null; setFieldErrors({}); setForm((value) => ({ ...value, name: event.target.value })) }} />
        </Form.Item>
        <Form.Item label={t('zone.remarkLabel')} validateStatus={fieldErrors.remark ? 'error' : undefined} help={fieldErrors.remark}>
          <Input aria-label={t('zone.remark')} value={form.remark} placeholder={t('zone.remarkPlaceholder')} autoComplete="off" maxLength={255}
            aria-invalid={fieldErrors.remark ? true : undefined}
            onChange={(event) => { saveKey.current = null; setFieldErrors({}); setForm((value) => ({ ...value, remark: event.target.value })) }} />
        </Form.Item>
        <Form.Item label={t('zone.randomLabel')} extra={t('zone.randomEditHelp')}>
          <Switch aria-label={t('zone.random')} checked={form.random}
            onChange={(random) => { saveKey.current = null; setForm((value) => ({ ...value, random })) }} />
        </Form.Item>
      </Form>
    </Modal>
  </div>
}
