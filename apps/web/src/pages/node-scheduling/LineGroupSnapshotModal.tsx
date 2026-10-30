import { useEffect, useState } from 'react'
import { Button, Form, Input, InputNumber, Modal, Radio, Select, Switch, Tooltip } from 'antd'
import { ArrowDown, ArrowUp, Check, Plus, Trash2 } from 'lucide-react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'

import { useFormSubmitError } from '@cdnca/ui'

import type { NodeLineGroup, NodeLineGroupSnapshotInput } from '../../api/nodeScheduling'
import { snapshotFromGroup, uuidPattern, validCodePointLength, validIPAddress } from './shared'

type SnapshotFormValues = NodeLineGroupSnapshotInput

const resolvedValuePattern = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/
const maximumSortOrder = 2_147_483_647

function newEndpoint() {
  return {
    id: globalThis.crypto?.randomUUID?.() ?? '00000000-0000-4000-8000-000000000000',
    node_id: '',
    address: '',
    port: 443,
    region: '',
    carrier: '',
    priority: 0,
    weight: 100,
    enabled: true,
  }
}

const defaultPolicy = {
  probe_interval_ms: 10_000,
  probe_timeout_ms: 3_000,
  failure_threshold: 3,
  recovery_threshold: 3,
  failure_debounce_ms: 0,
  recovery_debounce_ms: 0,
}

function hasAdvancedConfiguration(item: NodeLineGroup | null): boolean {
  if (!item) return false
  return Object.entries(defaultPolicy).some(([key, value]) => (
    item.health_policy[key as keyof typeof defaultPolicy] !== value
  )) || item.endpoints.some((endpoint) => endpoint.weight !== 100)
}

export default function LineGroupSnapshotModal({
  item,
  open,
  pending,
  titleKey,
  regionOptions = [],
  l2ConfigOptions = [],
  submitError = null,
  onCancel,
  onSubmit,
}: {
  item: NodeLineGroup | null
  open: boolean
  pending: boolean
  titleKey?: 'titles.createGroup' | 'titles.createTopology'
  regionOptions?: string[]
  l2ConfigOptions?: Array<{ value: string; label: string }>
  /** A server refusal naming a field (endpoints[n].port, name …): marked on that field. */
  submitError?: unknown
  onCancel: () => void
  onSubmit: (input: NodeLineGroupSnapshotInput) => void
}) {
  const { t } = useTranslation('nodeScheduling')
  const [form] = Form.useForm<SnapshotFormValues>()
  const [advanced, setAdvanced] = useState(false)
  const referenceLineGroupFields = titleKey === undefined
  const referenceRegionOptions = [...new Set([
    item?.region,
    ...regionOptions,
  ].filter((value): value is string => Boolean(value)))]

  useEffect(() => {
    if (!open) return
    setAdvanced(hasAdvancedConfiguration(item))
    form.setFieldsValue(item ? snapshotFromGroup(item) : {
      name: '',
      region: '',
      resolved_value: '',
      ipv4_resolved_value: '',
      l2_config_id: null,
      failover_mode: 'primary_offline',
      note: '',
      sort_order: 100,
      health_policy: { ...defaultPolicy },
      endpoints: referenceLineGroupFields ? [] : [newEndpoint()],
    })
  }, [form, item, open, referenceLineGroupFields])

  const markSubmitError = useFormSubmitError(form)
  useEffect(() => {
    if (!open || !submitError) return
    // weight / health_policy live in the advanced part: show it before marking.
    const advancedField = (submitError as { field?: unknown }).field
    if (typeof advancedField === 'string' && /^(health_policy|endpoints\[\d+\]\.weight)/.test(advancedField)) setAdvanced(true)
    const timer = setTimeout(() => markSubmitError(submitError))
    return () => clearTimeout(timer)
  }, [markSubmitError, open, submitError])

  const setAdvancedMode = (enabled: boolean) => {
    if (!enabled) {
      const endpoints = form.getFieldValue('endpoints') as SnapshotFormValues['endpoints'] | undefined
      form.setFieldsValue({
        health_policy: { ...defaultPolicy },
        endpoints: endpoints?.map((endpoint) => ({ ...endpoint, weight: 100 })),
      })
    }
    setAdvanced(enabled)
  }

  const submit = () => void form.validateFields().then(() => {
    onSubmit(form.getFieldsValue(true) as SnapshotFormValues)
  }).catch(() => undefined)

  return (
    <Modal
      className={referenceLineGroupFields
        ? `node-scheduling-modal node-line-groups-modal node-line-groups-modal-${item ? 'edit' : 'create'}`
        : 'node-scheduling-modal'}
      width={referenceLineGroupFields ? 520 : 1040}
      open={open}
      title={item ? t('titles.editGroup') : t(titleKey ?? 'titles.createGroup')}
      onCancel={onCancel}
      footer={referenceLineGroupFields ? [
        <Button key="cancel" className="node-line-group-cancel" onClick={onCancel} disabled={pending}>{t('actions.cancel')}</Button>,
        <Button
          key="confirm"
          type="primary"
          className="node-line-group-confirm"
          icon={<Check size={14} strokeWidth={2} aria-hidden="true" />}
          loading={pending}
          onClick={submit}
        >
          {t('actions.confirm')}
        </Button>,
      ] : [
        <Button key="cancel" onClick={onCancel} disabled={pending}>{t('actions.cancel')}</Button>,
        <Button key="save" type="primary" loading={pending} onClick={submit}>
          {t(item ? 'actions.save' : 'actions.create')}
        </Button>,
      ]}
      destroyOnHidden
    >
      <Form
        form={form}
        layout={referenceLineGroupFields ? 'horizontal' : 'vertical'}
        labelCol={referenceLineGroupFields ? { flex: '100px' } : undefined}
        wrapperCol={referenceLineGroupFields ? { flex: 1 } : undefined}
        colon={!referenceLineGroupFields}
        requiredMark={false}
      >
        {referenceLineGroupFields && !item ? (
          <Form.Item
            name="region"
            label={t('form.referenceRegion')}
            rules={[{
              validator: (_, value: string) => validCodePointLength(value ?? '', 0, 64)
                ? Promise.resolve()
                : Promise.reject(new Error(t('validation.labelLength'))),
            }]}
          >
            <Select
              options={[
                { value: '', label: t('values.defaultRegion') },
                ...referenceRegionOptions.map((value) => ({ value, label: value })),
              ]}
            />
          </Form.Item>
        ) : null}

        <Form.Item
          name="name"
          label={t(referenceLineGroupFields ? 'form.referenceName' : 'form.name')}
          rules={[
            { validator: (_, value: string) => validCodePointLength(value ?? '', 1, 128)
              ? Promise.resolve()
              : Promise.reject(new Error(t('validation.nameLength'))) },
          ]}
        >
          <Input placeholder={t(referenceLineGroupFields ? 'form.referenceNamePlaceholder' : 'form.namePlaceholder')} />
        </Form.Item>

        {referenceLineGroupFields ? (
          <>
            <Form.Item name="resolved_value" label={t('form.referenceResolvedValue')} rules={[{
              validator: (_, value: string) => !value || resolvedValuePattern.test(value)
                ? Promise.resolve()
                : Promise.reject(new Error(t('validation.resolvedValue'))),
            }]}>
              <Input placeholder={t('form.referenceResolvedValuePlaceholder')} />
            </Form.Item>
            {item ? (
              <Form.Item name="ipv4_resolved_value" label={t('form.ipv4ResolvedValue')} rules={[{
                validator: (_, value: string) => !value || resolvedValuePattern.test(value)
                  ? Promise.resolve()
                  : Promise.reject(new Error(t('validation.resolvedValue'))),
              }]}>
                <Input placeholder={t('form.ipv4ResolvedValuePlaceholder')} />
              </Form.Item>
            ) : null}
            <Form.Item name="note" label={t('form.referenceNote')} rules={[{
              validator: (_, value: string) => validCodePointLength(value ?? '', 0, 512)
                ? Promise.resolve()
                : Promise.reject(new Error(t('validation.note'))),
            }]}>
              <Input placeholder={t('form.referenceNotePlaceholder')} />
            </Form.Item>
            <Form.Item name="sort_order" label={t('form.referenceSort')} rules={[
              { type: 'number', min: 1, max: maximumSortOrder, message: t('validation.sortOrder') },
            ]}>
              <InputNumber controls={false} placeholder={t('form.referenceSortPlaceholder')} style={{ width: '100%' }} />
            </Form.Item>
            {item ? (
              <>
                <Form.Item
                  label={t('form.l2Configuration')}
                  extra={(
                    <>
                      {t('form.l2ConfigurationHelp')}{' '}
                      <Link to="/node/l2-config">{t('form.l2ConfigurationManage')}</Link>
                    </>
                  )}
                >
                  <Form.Item name="l2_config_id" noStyle>
                    <Select
                      allowClear
                      aria-label={t('form.l2Configuration')}
                      placeholder={t('form.l2ConfigurationPlaceholder')}
                      options={l2ConfigOptions}
                    />
                  </Form.Item>
                </Form.Item>
                <Form.Item name="failover_mode" label={t('form.failoverMode')} extra={t('form.failoverModeHelp')}>
                  <Radio.Group className="node-line-failover-radio" optionType="button" buttonStyle="outline">
                    <Radio.Button value="primary_offline">{t('values.failoverPrimaryOffline')}</Radio.Button>
                    <Radio.Button value="online_less_than_backup_count">{t('values.failoverOnlineLessThanBackup')}</Radio.Button>
                  </Radio.Group>
                </Form.Item>
              </>
            ) : null}
          </>
        ) : <>

          <Form.Item label={t('form.advancedSettings')}>
            <Switch
              aria-label={t('form.advancedSettings')}
              checked={advanced}
              checkedChildren={t('values.advanced')}
              unCheckedChildren={t('values.simpleDefaults')}
              onChange={setAdvancedMode}
            />
          </Form.Item>

          {advanced ? <div className="node-scheduling-policy-grid">
            <Form.Item name={['health_policy', 'probe_interval_ms']} label={t('form.probeInterval')} rules={[
              { type: 'number', min: 1000, max: 300000, message: t('validation.probeInterval') },
            ]}>
              <InputNumber min={1000} max={300000} step={1000} />
            </Form.Item>
            <Form.Item name={['health_policy', 'probe_timeout_ms']} label={t('form.probeTimeout')} dependencies={[
              ['health_policy', 'probe_interval_ms'],
            ]} rules={[
              { type: 'number', min: 100, max: 60000, message: t('validation.probeTimeout') },
              ({ getFieldValue }) => ({
                validator: (_, value: number) =>
                  value <= getFieldValue(['health_policy', 'probe_interval_ms'])
                    ? Promise.resolve()
                    : Promise.reject(new Error(t('validation.probeTimeout'))),
              }),
            ]}>
              <InputNumber min={100} max={60000} step={100} />
            </Form.Item>
            {(['failure_threshold', 'recovery_threshold'] as const).map((field) => (
              <Form.Item key={field} name={['health_policy', field]} label={t(
                field === 'failure_threshold' ? 'form.failureThreshold' : 'form.recoveryThreshold',
              )} rules={[{ type: 'number', min: 1, max: 20, message: t('validation.threshold') }]}>
                <InputNumber min={1} max={20} />
              </Form.Item>
            ))}
            {(['failure_debounce_ms', 'recovery_debounce_ms'] as const).map((field) => (
              <Form.Item key={field} name={['health_policy', field]} label={t(
                field === 'failure_debounce_ms' ? 'form.failureDebounce' : 'form.recoveryDebounce',
              )} rules={[{ type: 'number', min: 0, max: 3600000, message: t('validation.debounce') }]}>
                <InputNumber min={0} max={3600000} step={1000} />
              </Form.Item>
            ))}
          </div> : null}

        <Form.List name="endpoints" rules={[{
          validator: (_, endpoints: SnapshotFormValues['endpoints']) => {
            if (!endpoints?.length) return Promise.reject(new Error(t('validation.endpoints')))
            const ids = endpoints.map((endpoint) => endpoint.id.toLowerCase())
            const addresses = endpoints.map((endpoint) => `${endpoint.address.toLowerCase()}:${endpoint.port}`)
            return new Set(ids).size === ids.length && new Set(addresses).size === addresses.length
              ? Promise.resolve()
              : Promise.reject(new Error(t('validation.duplicateEndpoint')))
          },
        }]}>
          {(fields, { add, remove, move }, { errors }) => (
            <section className="node-scheduling-endpoints" aria-label={t('form.endpoints')}>
              <div className="node-scheduling-section-heading">
                <h2>{t('form.endpoints')}</h2>
                <Button icon={<Plus size={15} />} onClick={() => add(newEndpoint())}>
                  {t('actions.addEndpoint')}
                </Button>
              </div>
              {fields.map((field, index) => (
                <div className="node-scheduling-endpoint-row" key={field.key}>
                  <Form.Item name={[field.name, 'id']} label={t('form.endpointID')} rules={[
                    { required: true, message: t('validation.required') },
                    { pattern: uuidPattern, message: t('validation.uuid') },
                  ]}><Input /></Form.Item>
                  <Form.Item name={[field.name, 'node_id']} label={t('form.nodeID')} rules={[
                    { required: true, message: t('validation.required') },
                    { pattern: uuidPattern, message: t('validation.uuid') },
                  ]}><Input /></Form.Item>
                  <Form.Item name={[field.name, 'address']} label={t('form.address')} rules={[
                    { required: true, message: t('validation.required') },
                    { validator: (_, value: string) => validIPAddress(value ?? '')
                      ? Promise.resolve()
                      : Promise.reject(new Error(t('validation.ip'))) },
                  ]}><Input /></Form.Item>
                  <Form.Item name={[field.name, 'port']} label={t('form.port')} rules={[
                    { type: 'number', min: 1, max: 65535, message: t('validation.port') },
                  ]}><InputNumber min={1} max={65535} /></Form.Item>
                  <Form.Item name={[field.name, 'region']} label={t('form.region')} rules={[
                    { validator: (_, value: string) => validCodePointLength(value ?? '', 0, 64)
                      ? Promise.resolve()
                      : Promise.reject(new Error(t('validation.labelLength'))) },
                  ]}>
                    <Input />
                  </Form.Item>
                  <Form.Item name={[field.name, 'carrier']} label={t('form.carrier')} extra={t('form.carrierHelp')} rules={[
                    { validator: (_, value: string) => validCodePointLength(value ?? '', 0, 64)
                      ? Promise.resolve()
                      : Promise.reject(new Error(t('validation.labelLength'))) },
                  ]}>
                    <Input />
                  </Form.Item>
                  <Form.Item name={[field.name, 'priority']} label={t('form.priority')} rules={[
                    { type: 'number', min: 0, max: 65535, message: t('validation.priority') },
                  ]}><InputNumber min={0} max={65535} /></Form.Item>
                  {advanced ? <Form.Item name={[field.name, 'weight']} label={t('form.weight')} rules={[
                    { type: 'number', min: 1, max: 100, message: t('validation.weight') },
                  ]}><InputNumber min={1} max={100} /></Form.Item> : null}
                  <Form.Item name={[field.name, 'enabled']} label={t('form.enabled')} valuePropName="checked">
                    <Switch />
                  </Form.Item>
                  <div className="node-scheduling-endpoint-actions">
                    <Tooltip title={t('actions.moveUp')}>
                      <Button aria-label={t('actions.moveUp')} icon={<ArrowUp size={15} />} disabled={index === 0} onClick={() => move(index, index - 1)} />
                    </Tooltip>
                    <Tooltip title={t('actions.moveDown')}>
                      <Button aria-label={t('actions.moveDown')} icon={<ArrowDown size={15} />} disabled={index === fields.length - 1} onClick={() => move(index, index + 1)} />
                    </Tooltip>
                    <Tooltip title={t('actions.deleteEndpoint')}>
                      <Button danger aria-label={t('actions.deleteEndpoint')} icon={<Trash2 size={15} />} disabled={fields.length === 1} onClick={() => remove(index)} />
                    </Tooltip>
                  </div>
                </div>
              ))}
              <Form.ErrorList errors={errors} />
            </section>
          )}
          </Form.List>
        </>}
      </Form>
    </Modal>
  )
}
