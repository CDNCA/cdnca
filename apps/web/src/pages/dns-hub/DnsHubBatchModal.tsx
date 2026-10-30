import { useState } from 'react'
import { Alert, Form, Input, InputNumber, Modal, Radio, Select, Table, Tag } from 'antd'
import { useTranslation } from 'react-i18next'

import { dnsHubApi, dnsHubRecordTypes, maxBatchItems, recordValue, validRecordName, validRecordValue, type DNSHubBatchItem, type DNSHubBatchItemResult, type DNSHubDomain, type DNSHubRecordType } from '../../api/dnsHub'
import { useSessionStore } from '../../auth/session'
import { batchErrorKey, dnsHubErrorKey, domainKey, newIdempotencyKey } from './dnsHubShared'

type BatchAction = 'create' | 'set_ttl'
type DomainState = 'applied' | 'failed' | 'uncertain' | 'skipped'

// 后端批量接口每次 1–50 条；批量加记录每个域名一条，所以一次最多 50 个域名
const maxTargets = maxBatchItems
const stateColors = { applied: 'success', failed: 'error', uncertain: 'warning', skipped: 'default' } as const

interface FormValues {
  action: BatchAction
  name: string
  type: DNSHubRecordType
  value: string
  ttl: number
  filterName?: string
  filterType?: DNSHubRecordType
}

interface DomainResult {
  provider_id: string
  apex: string
  state: DomainState
  changed?: number
  errorKey?: string
}

function summarize(domain: DNSHubDomain, items: DNSHubBatchItemResult[]): DomainResult {
  const base = { provider_id: domain.provider_id, apex: domain.apex }
  if (!items.length) return { ...base, state: 'skipped', changed: 0 }
  const failed = items.find((item) => item.error)
  const applied = items.filter((item) => !item.error && item.state === 'applied').length
  if (failed) return { ...base, state: 'failed', changed: applied, errorKey: batchErrorKey(failed.error) }
  if (items.some((item) => item.state === 'uncertain')) return { ...base, state: 'uncertain', changed: applied }
  return { ...base, state: 'applied', changed: applied }
}

export function DnsHubBatchModal({ open, targets, onClose }: { open: boolean; targets: DNSHubDomain[]; onClose: (changed: boolean) => void }) {
  const { t } = useTranslation('dnsHub')
  const [form] = Form.useForm<FormValues>()
  const action = Form.useWatch('action', form) ?? 'create'
  const type = Form.useWatch('type', form) ?? 'TXT'
  const [running, setRunning] = useState(false)
  const [result, setResult] = useState<DomainResult[]>()
  const [error, setError] = useState<string>()
  const overLimit = targets.length > maxTargets

  async function run() {
    const values = await form.validateFields().catch(() => null)
    if (!values) return
    setRunning(true)
    setError(undefined)
    try {
      const token = useSessionStore.getState().accessToken ?? ''
      // owner[i] = 第 i 条属于哪个域名；读记录失败的域名直接记失败、不提交
      const items: DNSHubBatchItem[] = []
      const owner: number[] = []
      const readFailed = new Map<number, string>()
      if (values.action === 'create') {
        const record = { name: values.name.trim(), type: values.type, value: values.value.trim(), ttl: values.ttl, line: '默认', weight: 0 }
        targets.forEach(({ provider_id, apex }, index) => { items.push({ provider_id, apex, action: 'create', ...record }); owner.push(index) })
      } else {
        // 统一改 TTL：实时读每个域名的记录，按主机记录/类型筛选；本平台在用的记录不在批量里改（须逐条确认影响）
        const name = values.filterName?.trim()
        const lists = await Promise.all(targets.map((domain) => dnsHubApi.records(token, domain.provider_id, domain.apex, values.filterType ? { type: values.filterType } : {})
          .then((list) => list.items, (failure: unknown) => failure)))
        lists.forEach((list, index) => {
          if (!Array.isArray(list)) { readFailed.set(index, dnsHubErrorKey(list)); return }
          const { provider_id, apex } = targets[index]
          for (const record of list) {
            if (record.managed || record.ttl === values.ttl || (name && record.name !== name) || (values.filterType && record.type !== values.filterType)) continue
            items.push({ provider_id, apex, action: 'update', record_ref: record.record_ref, ...recordValue(record), ttl: values.ttl, expected: recordValue(record) })
            owner.push(index)
          }
        })
      }
      const outcomes: DNSHubBatchItemResult[] = []
      const key = newIdempotencyKey('dns-hub-batch')
      for (let start = 0, chunk = 0; start < items.length; start += maxBatchItems, chunk += 1) {
        const response = await dnsHubApi.batch(token, items.slice(start, start + maxBatchItems), `${key}.c${chunk}`)
        outcomes.push(...response.results)
      }
      setResult(targets.map((domain, index) => readFailed.has(index)
        ? { provider_id: domain.provider_id, apex: domain.apex, state: 'failed', errorKey: readFailed.get(index) }
        : summarize(domain, outcomes.filter((_item, position) => owner[position] === index))))
    } catch (failure) {
      setError(t(dnsHubErrorKey(failure)))
    } finally {
      setRunning(false)
    }
  }

  const counts = { applied: 0, failed: 0, uncertain: 0, skipped: 0 }
  for (const item of result ?? []) counts[item.state] += 1

  return (
    <Modal open={open} width={640} title={t('batch.title', { count: targets.length })} destroyOnHidden
      onCancel={() => onClose(Boolean(result))} cancelText={t('form.cancel')}
      okText={t('batch.run')} onOk={() => void run()} confirmLoading={running}
      okButtonProps={{ disabled: overLimit || Boolean(result), hidden: Boolean(result) }}>
      {overLimit ? <Alert type="warning" showIcon message={t('batch.limit', { max: maxTargets })} className="dns-hub-alert" /> : null}
      {error ? <Alert type="error" showIcon message={error} className="dns-hub-alert" /> : null}
      {result ? (
        <>
          <p role="status">{t('batch.summary', counts)}</p>
          <Table<DomainResult> size="small" rowKey={(item) => domainKey(item)} pagination={false} scroll={{ y: 320 }} dataSource={result}
            columns={[
              { title: t('domains.title'), key: 'apex', render: (_v, item) => item.apex },
              { title: t('batch.resultTitle'), key: 'state', render: (_v, item) => (
                <>
                  <Tag color={stateColors[item.state]}>{t(`batch.states.${item.state}`)}</Tag>
                  {item.changed !== undefined ? t('batch.changed', { count: item.changed }) : null}
                  {item.errorKey ? <span className="dns-hub-muted"> {t(item.errorKey)}</span> : null}
                </>
              ) },
            ]} />
        </>
      ) : (
        <Form<FormValues> form={form} layout="vertical" requiredMark={false} initialValues={{ action: 'create', type: 'TXT', name: '', value: '', ttl: 600 }}>
          <Form.Item name="action" label={t('batch.action')}>
            <Radio.Group optionType="button" options={(['create', 'set_ttl'] as const).map((value) => ({ value, label: t(`batch.actions.${value}`) }))} />
          </Form.Item>
          {action === 'create' ? (
            <>
              <div className="dns-hub-form-row">
                <Form.Item name="name" label={t('form.name')} rules={[{ validator: (_r, value: string) => validRecordName((value ?? '').trim()) ? Promise.resolve() : Promise.reject(new Error(t('form.nameInvalid'))) }]}>
                  <Input autoComplete="off" spellCheck={false} />
                </Form.Item>
                <Form.Item name="type" label={t('form.type')}>
                  <Select options={dnsHubRecordTypes.map((value) => ({ value, label: value }))} />
                </Form.Item>
              </div>
              <Form.Item name="value" label={t('form.value')} dependencies={['type']}
                rules={[{ validator: (_r, value: string) => validRecordValue(form.getFieldValue('type'), (value ?? '').trim()) ? Promise.resolve() : Promise.reject(new Error(t(`form.valueInvalid.${form.getFieldValue('type') as DNSHubRecordType}`))) }]}>
                <Input placeholder={t(`form.valuePlaceholder.${type}`)} autoComplete="off" spellCheck={false} />
              </Form.Item>
            </>
          ) : (
            <div className="dns-hub-form-row">
              <Form.Item name="filterName" label={t('batch.filterName')} rules={[{ validator: (_r, value?: string) => !value?.trim() || validRecordName(value.trim()) ? Promise.resolve() : Promise.reject(new Error(t('form.nameInvalid'))) }]}>
                <Input autoComplete="off" spellCheck={false} />
              </Form.Item>
              <Form.Item name="filterType" label={t('batch.filterType')}>
                <Select allowClear options={dnsHubRecordTypes.map((value) => ({ value, label: value }))} />
              </Form.Item>
            </div>
          )}
          {action === 'set_ttl' ? <p className="dns-hub-muted">{t('batch.managedSkipped')}</p> : null}
          <Form.Item name="ttl" label={t('form.ttl')} rules={[{ validator: (_r, value: number) => Number.isInteger(value) && value >= 1 && value <= 86400 ? Promise.resolve() : Promise.reject(new Error(t('form.ttlInvalid', { min: 1, max: 86400 }))) }]}>
            <InputNumber min={1} max={86400} precision={0} style={{ width: '100%' }} />
          </Form.Item>
        </Form>
      )}
    </Modal>
  )
}
