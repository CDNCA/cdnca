import { useEffect, useState, type ReactNode } from 'react'
import { Alert, Button, Checkbox, Collapse, Form, Input, InputNumber, Modal, Radio, Select, Switch } from 'antd'
import { Plus, Trash2 } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import type { ScopeKind } from '../api/auth'
import type { Stream, StreamACL, StreamACLAction, StreamOrigin, UpdateStreamRequest } from '../api/streams'
import StreamGroupSelect from './StreamGroupSelect'
import { isIPAddress, validCIDR } from './streamForm'
import { streamOriginShares } from './originWeightShare'
import '../i18n/originWeight'

type BatchField = 'group_ids' | 'enabled' | 'balance_way' | 'upstream_port' | 'proxy_protocol_v1' | 'origins' |
  'acl_default' | 'acl_rules' | 'listen_ipv6'
interface BatchValues {
  group_ids: string[]
  enabled: boolean
  balance_way: 'rr' | 'ip_hash'
  upstream_port?: number
  proxy_protocol_v1: boolean
  origins: StreamOrigin[]
  acl_default: StreamACLAction
  acl_rules: Array<{ cidr: string; action: StreamACLAction }>
  listen_ipv6: boolean
}

export type StreamBatchACLPatch = Partial<StreamACL>

// 「批量修改转发」：目标转发卡片 + 折叠组（默认全收起），每组内逐项勾选，勾选的项才覆盖，组底有「批量修改」。
// admin 两组（源站设置 / 访问控制），用户端多一组基本设置在最前；我方批量走逐条 PATCH（保留原有幂等与修订）。
// 源站设置：负载方式、回源端口、Proxy Protocol、源站列表；访问控制：ACL默认行为、ACL规则、IPv6开启。
// 「区域屏蔽」不放进批量：四层地域要自带 CIDR 映射，不是内置地域库预设。
export default function StreamBatchModifyModal({ open, items, busy, locked, scopeKind, scopeID, sessionEpoch, onCancel, onApply }: {
  open: boolean
  items: Stream[]
  busy: boolean
  locked: boolean
  scopeKind: ScopeKind
  scopeID: string
  sessionEpoch: number
  onCancel: () => void
  onApply: (patch: Partial<UpdateStreamRequest>, acl?: StreamBatchACLPatch) => void
}) {
  const { t } = useTranslation('streams')
  const [form] = Form.useForm<BatchValues>()
  const { t: tW } = useTranslation('originWeight')
  // fix-weighthint: live share of each origin row (down rows get none); the
  // balance method text only when 负载方式 is checked (unchecked keeps each stream's own)
  const originValues = Form.useWatch('origins', { form, preserve: true }) as Array<StreamOrigin | undefined> | undefined
  const balanceWay = (Form.useWatch('balance_way', { form, preserve: true }) as BatchValues['balance_way'] | undefined) ?? 'rr'
  const originShares = streamOriginShares(originValues ?? [])
  const [checked, setChecked] = useState<BatchField[]>([])
  const [panels, setPanels] = useState<string[]>([])
  const [problem, setProblem] = useState('')
  // 分组只能在同一租户内选：选中的转发跨租户时不提供分组项。
  const scopes = [...new Set(items.map((item) => item.scope_id))]
  const singleScope = scopes.length === 1 ? scopes[0]! : ''

  useEffect(() => {
    if (!open) return
    setChecked([])
    setPanels([])
    setProblem('')
    form.setFieldsValue({ group_ids: [], enabled: true, balance_way: 'rr', upstream_port: undefined, proxy_protocol_v1: false,
      origins: [{ address: '', weight: 1, down: false }], acl_default: 'allow', acl_rules: [], listen_ipv6: false })
  }, [form, open])

  const toggle = (field: BatchField, on: boolean) => setChecked((current) => on ? [...current, field] : current.filter((entry) => entry !== field))
  const row = (field: BatchField, label: string, control: ReactNode) => (
    <div className="stream-batch-row" key={field}>
      <Checkbox checked={checked.includes(field)} onChange={(event) => toggle(field, event.target.checked)}>{label}</Checkbox>
      {checked.includes(field) ? <div className="stream-batch-row-control">{control}</div> : null}
    </div>
  )
  const apply = (fields: BatchField[]) => {
    const picked = checked.filter((field) => fields.includes(field))
    if (picked.length === 0) { setProblem('batchModify.noneChecked'); return }
    const validate = picked.flatMap((field) => field === 'upstream_port' ? ['upstream_port']
      : field === 'origins' ? ['origins'] : field === 'acl_rules' ? ['acl_rules'] : [])
    void form.validateFields(validate, { recursive: true }).then(() => {
      setProblem('')
      const values = form.getFieldsValue(true) as BatchValues
      const patch: Partial<UpdateStreamRequest> = {}
      if (picked.includes('group_ids')) patch.group_ids = values.group_ids ?? []
      if (picked.includes('enabled')) patch.enabled = Boolean(values.enabled)
      if (picked.includes('balance_way')) patch.balance_way = values.balance_way
      if (picked.includes('upstream_port')) patch.upstream_port = values.upstream_port
      if (picked.includes('proxy_protocol_v1')) {
        patch.proxy_protocol_v1 = Boolean(values.proxy_protocol_v1)
        if (patch.proxy_protocol_v1) patch.toa = false
      }
      if (picked.includes('origins')) {
        // 单个源站可为域名（沿用该转发的 DNS 策略由服务端校验）；多个只能是 IP。
        patch.origins = values.origins.map((origin) => ({ address: origin.address.trim(), weight: origin.weight, down: Boolean(origin.down) }))
      }
      // ACL 两项可只勾一项：未勾的那一项由各转发保留原值（列表页逐条合并）。
      const acl: StreamBatchACLPatch | undefined = picked.includes('acl_default') || picked.includes('acl_rules') ? {
        ...(picked.includes('acl_default') ? { default_action: values.acl_default } : {}),
        ...(picked.includes('acl_rules') ? { rules: values.acl_rules.map((rule) => ({ cidr: rule.cidr.trim(), action: rule.action })) } : {}),
      } : undefined
      if (picked.includes('listen_ipv6')) patch.listen_ipv6 = Boolean(values.listen_ipv6)
      onApply(patch, acl)
    }, () => undefined)
  }
  const applyButton = (fields: BatchField[]) => (
    <Button type="primary" className="stream-batch-apply" disabled={locked || items.length === 0} loading={busy} onClick={() => apply(fields)}>{t('batchModify.apply')}</Button>
  )
  const basicFields: BatchField[] = ['group_ids', 'enabled']
  const originFields: BatchField[] = ['balance_way', 'upstream_port', 'proxy_protocol_v1', 'origins']
  const accessFields: BatchField[] = ['acl_default', 'acl_rules', 'listen_ipv6']
  const actionOptions = [{ value: 'allow', label: t('acl.allow') }, { value: 'deny', label: t('acl.deny') }]

  return (
    <Modal
      className="identity-modal stream-batch-modify-modal"
      title={t('batchModify.title')}
      open={open}
      width={800}
      maskClosable={false}
      footer={null}
      onCancel={() => { if (!locked) onCancel() }}
      destroyOnHidden
    >
      <div className="stream-batch-target">
        <strong>{t('batchModify.target')}</strong>
        <span>{t('batchModify.count', { count: items.length })}</span>
      </div>
      {problem ? <Alert className="stream-batch-alert" type="error" showIcon message={t(problem)} /> : null}
      <Form form={form} component={false}>
        <Collapse className="stream-form-collapse" activeKey={panels} onChange={(keys) => setPanels(keys as string[])} items={[
          {
            key: 'basic', label: t('batchModify.basic'), forceRender: true, children: <>
              {singleScope ? row('group_ids', t('form.group'), <Form.Item name="group_ids" noStyle>
                <StreamGroupSelect open={open} scopeKind={scopeKind} scopeID={scopeID} sessionEpoch={sessionEpoch} targetScopeID={singleScope} groups={[]} />
              </Form.Item>) : null}
              {row('enabled', t('batchModify.enabled'), <Form.Item name="enabled" valuePropName="checked" noStyle><Switch aria-label={t('batchModify.enabled')} /></Form.Item>)}
              {applyButton(basicFields)}
            </>,
          },
          {
            key: 'origin', label: t('batchModify.origin'), forceRender: true, children: <>
              {row('balance_way', t('form.balanceWay'), <Form.Item name="balance_way" noStyle>
                <Radio.Group optionType="button" buttonStyle="solid" options={[
                  { value: 'rr', label: t('detail.roundRobin') }, { value: 'ip_hash', label: t('detail.ipHash') },
                ]} />
              </Form.Item>)}
              {row('upstream_port', t('detail.originPort'), <Form.Item name="upstream_port" rules={[
                { required: true, message: t('form.upstreamPortRequired') },
                { type: 'number', min: 1, max: 65535, message: t('form.upstreamPortRange') },
              ]}>
                <InputNumber aria-label={t('detail.originPort')} min={1} max={65535} precision={0} style={{ width: 180 }} />
              </Form.Item>)}
              {row('proxy_protocol_v1', 'Proxy Protocol', <Form.Item name="proxy_protocol_v1" valuePropName="checked" noStyle><Switch aria-label="Proxy Protocol" /></Form.Item>)}
              {row('origins', t('origins.title'), <Form.List name="origins" rules={[{
                validator: (_, value: StreamOrigin[] | undefined) => {
                  const list = value ?? []
                  if (list.length === 0) return Promise.reject(new Error(t('origins.required')))
                  if (list.length > 64) return Promise.reject(new Error(t('origins.tooMany')))
                  if (list.every((origin) => origin?.down)) return Promise.reject(new Error(t('origins.allDown')))
                  if (list.length > 1 && list.some((origin) => !isIPAddress(origin?.address?.trim() ?? ''))) return Promise.reject(new Error(t('origins.multipleNeedIP')))
                  return Promise.resolve()
                },
              }]}>
                {(fields, { add, remove }, { errors }) => <div className="stream-origin-list">
                  {fields.map((field) => <div className="stream-origin-row" key={field.key}>
                    <Form.Item name={[field.name, 'address']} rules={[{ required: true, whitespace: true, message: t('origins.addressRequired') }]}>
                      <Input aria-label={t('origins.address')} placeholder={t('origins.addressPlaceholder')} />
                    </Form.Item>
                    <Form.Item name={[field.name, 'weight']} rules={[{ type: 'number', min: 1, max: 100, required: true, message: t('origins.weightRange') }]}>
                      <InputNumber aria-label={t('origins.weight')} min={1} max={100} precision={0} addonBefore={t('origins.weight')} />
                    </Form.Item>
                    <Form.Item name={[field.name, 'down']} getValueProps={(down: boolean) => ({ value: down ? 'down' : 'up' })}
                      getValueFromEvent={(value: string) => value === 'down'}>
                      <Select aria-label={t('origins.state')} options={[{ value: 'up', label: t('origins.up') }, { value: 'down', label: t('origins.down') }]} />
                    </Form.Item>
                    <span className="stream-origin-share" aria-live="polite">{originShares[field.name] == null ? tW('down') : tW('share', { share: originShares[field.name] })}</span>
                    <Button type="text" aria-label={t('origins.remove')} icon={<Trash2 size={14} />} disabled={fields.length === 1} onClick={() => remove(field.name)} />
                  </div>)}
                  <p className="stream-origin-weight-help">{tW('help')}{checked.includes('balance_way') ? ` ${tW(`stream.${balanceWay}`)}` : ''}</p>
                  <Button icon={<Plus size={14} />} disabled={fields.length >= 64} onClick={() => add({ address: '', weight: 1, down: false })}>{t('origins.add')}</Button>
                  <Form.ErrorList errors={errors} />
                </div>}
              </Form.List>)}
              {applyButton(originFields)}
            </>,
          },
          {
            key: 'access', label: t('batchModify.access'), forceRender: true, children: <>
              {row('acl_default', t('acl.defaultAction'), <Form.Item name="acl_default" noStyle>
                <Radio.Group optionType="button" buttonStyle="solid" options={actionOptions} />
              </Form.Item>)}
              {row('acl_rules', t('acl.rules'), <Form.List name="acl_rules">
                {(fields, { add, remove }) => <div className="stream-acl-list">
                  {fields.length === 0 ? <span className="stream-acl-empty">{t('acl.empty')}</span> : null}
                  {fields.map((field) => <div className="stream-acl-row" key={field.key}>
                    <Form.Item name={[field.name, 'cidr']} rules={[{
                      validator: (_, value: string) => validCIDR(value?.trim() ?? '') || isIPAddress(value?.trim() ?? '')
                        ? Promise.resolve() : Promise.reject(new Error(t('acl.cidrInvalid'))),
                    }]}>
                      <Input aria-label={t('acl.ip')} placeholder={t('acl.ipPlaceholder')} />
                    </Form.Item>
                    <Form.Item name={[field.name, 'action']}>
                      <Select aria-label={t('acl.action')} options={actionOptions} />
                    </Form.Item>
                    <Button type="text" aria-label={t('acl.remove')} icon={<Trash2 size={14} />} onClick={() => remove(field.name)} />
                  </div>)}
                  <Button icon={<Plus size={14} />} disabled={fields.length >= 1024} onClick={() => add({ cidr: '', action: 'deny' })}>{t('acl.add')}</Button>
                </div>}
              </Form.List>)}
              {row('listen_ipv6', t('acl.ipv6'), <Form.Item name="listen_ipv6" noStyle>
                <Radio.Group optionType="button" buttonStyle="solid" options={[{ value: true, label: t('acl.ipv6On') }, { value: false, label: t('acl.ipv6Off') }]} />
              </Form.Item>)}
              {applyButton(accessFields)}
            </>,
          },
        ]} />
      </Form>
    </Modal>
  )
}
