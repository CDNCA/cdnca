import { useState } from 'react'
import { Checkbox, Form, Input, InputNumber, Modal, Select } from 'antd'
import { useTranslation } from 'react-i18next'

import { dnsHubRecordTypes, validRecordName, validRecordValue, type DNSHubRecord, type DNSHubRecordType, type DNSHubRecordValue } from '../../api/dnsHub'
import { managedUsage, ttlBounds } from './dnsHubShared'

export function ManagedConfirm({ usage, onChange }: { usage: string; onChange: (value: boolean) => void }) {
  const { t } = useTranslation('dnsHub')
  return (
    <div className="dns-hub-managed-confirm" role="group" aria-label={t('managed.confirmTitle')}>
      <p>{t('managed.confirmBody', { usage })}</p>
      <Checkbox onChange={(event) => onChange(event.target.checked)}>{t('managed.confirmCheck')}</Checkbox>
    </div>
  )
}

interface FormValues {
  name: string
  type: DNSHubRecordType
  value: string
  ttl: number
  line: string
}

export function DnsHubRecordModal({ open, record, providerType, lines, supportsWeight, onCancel, onSubmit, onError }: {
  open: boolean
  record?: DNSHubRecord
  providerType: string
  // 账号 supported_lines（契约 v1：line 必须在其中）
  lines: string[]
  supportsWeight: boolean
  onCancel: () => void
  onSubmit: (input: DNSHubRecordValue, confirmManaged: boolean) => Promise<void>
  onError: (error: unknown) => void
}) {
  const { t } = useTranslation('dnsHub')
  const [form] = Form.useForm<FormValues>()
  const [saving, setSaving] = useState(false)
  const [acknowledged, setAcknowledged] = useState(false)
  const type = Form.useWatch('type', form) ?? record?.type ?? 'A'
  const { min, max } = ttlBounds(providerType)
  const lineOptions = lines.length ? lines : ['默认']
  const managed = record?.managed

  async function submit() {
    const values = await form.validateFields().catch(() => null)
    if (!values) return
    setSaving(true)
    try {
      // 改名、改类型不允许（改名 = 删 + 建），编辑时这两项锁定；权重原样保留
      await onSubmit({ name: values.name.trim(), type: values.type, value: values.value.trim(), ttl: values.ttl, line: values.line,
        weight: supportsWeight ? record?.weight ?? 0 : 0 }, Boolean(managed))
    } catch (error) {
      onError(error)
    } finally {
      setSaving(false)
    }
  }

  return (
    <Modal open={open} title={t(record ? 'form.editTitle' : 'form.addTitle')} onCancel={onCancel} onOk={() => void submit()}
      okText={t('form.save')} cancelText={t('form.cancel')} confirmLoading={saving} destroyOnHidden
      okButtonProps={{ disabled: Boolean(managed) && !acknowledged, danger: Boolean(managed) }}>
      <Form<FormValues> form={form} layout="vertical" requiredMark={false} initialValues={{
        name: record?.name ?? '', type: record?.type ?? 'A', value: record?.value ?? '',
        ttl: record?.ttl ?? Math.max(min, 600), line: record?.line && lineOptions.includes(record.line) ? record.line : lineOptions[0],
      }}>
        <Form.Item name="name" label={t('form.name')} extra={t('form.nameHelp')}
          rules={[{ validator: (_rule, value: string) => validRecordName((value ?? '').trim()) ? Promise.resolve() : Promise.reject(new Error(t('form.nameInvalid'))) }]}>
          <Input autoComplete="off" spellCheck={false} disabled={Boolean(record)} />
        </Form.Item>
        <Form.Item name="type" label={t('form.type')}>
          <Select disabled={Boolean(record)} options={dnsHubRecordTypes.map((value) => ({ value, label: value }))}
            onChange={() => void form.validateFields(['value']).catch(() => undefined)} />
        </Form.Item>
        <Form.Item name="value" label={t('form.value')} dependencies={['type']}
          rules={[{ validator: (_rule, value: string) => validRecordValue(form.getFieldValue('type'), (value ?? '').trim())
            ? Promise.resolve() : Promise.reject(new Error(t(`form.valueInvalid.${form.getFieldValue('type') as DNSHubRecordType}`))) }]}>
          {type === 'TXT'
            ? <Input.TextArea autoSize={{ minRows: 2, maxRows: 6 }} placeholder={t(`form.valuePlaceholder.${type}`)} spellCheck={false} />
            : <Input placeholder={t(`form.valuePlaceholder.${type}`)} autoComplete="off" spellCheck={false} />}
        </Form.Item>
        <div className="dns-hub-form-row">
          <Form.Item name="line" label={t('form.line')}
            extra={lineOptions.length === 1 ? t('form.lineHelpSingle') : providerType === 'huawei' && record ? t('form.lineHelpHuawei') : undefined}>
            <Select disabled={lineOptions.length === 1} options={lineOptions.map((value) => ({ value, label: value }))} />
          </Form.Item>
          <Form.Item name="ttl" label={t('form.ttl')}
            rules={[{ validator: (_rule, value: number) => Number.isInteger(value) && value >= min && value <= max
              ? Promise.resolve() : Promise.reject(new Error(t('form.ttlInvalid', { min, max }))) }]}>
            <InputNumber min={min} max={max} precision={0} style={{ width: '100%' }} />
          </Form.Item>
        </div>
        {managed ? <ManagedConfirm usage={managedUsage(t, managed)} onChange={setAcknowledged} /> : null}
      </Form>
    </Modal>
  )
}
