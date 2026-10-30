import { Alert, Button, Checkbox, Form, Input, InputNumber, Popconfirm, Radio, Select, Switch, type FormInstance } from 'antd'
import { ArrowDown, ArrowUp, Plus, Trash2 } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { streamGuardRulesMax, validStreamServerName, type StreamAdditionalListener, type StreamGuardMatch } from '../api/streams'
import '../i18n/streamGuard'
import {
  guardRuleProblem, newGuardRuleID, normalizeServerNames, parseRegionCIDRs, portRangeProblem, splitInput, streamGuardTags,
  validRegionCIDRs, type GuardRuleRow, type StreamFormValues,
} from './streamForm'

// 单 IP 新建连接速率：放在“单客户端连接上限”旁边。0 为不限，此时突发与拉黑不可填。
export function StreamNewConnectionRateFields({ itemClassName }: { itemClassName?: string }) {
  const { t } = useTranslation('streams')
  const rate = Form.useWatch('max_new_connections_per_client_per_second') as number | null | undefined
  const limited = typeof rate === 'number' && rate > 0
  return <>
    <Form.Item className={itemClassName} name="max_new_connections_per_client_per_second" label={t('form.newConnectionRate')}
      extra={t('form.newConnectionRateHelp')} rules={[
        { required: true, message: t('form.newConnectionRateRequired') },
        { type: 'integer', min: 0, max: 100000, message: t('form.newConnectionRateRange') },
      ]}>
      <InputNumber min={0} max={100000} precision={0} style={{ width: '100%' }} />
    </Form.Item>
    <Form.Item className={itemClassName} name="new_connection_burst" label={t('form.newConnectionBurst')} rules={[
      { type: 'integer', min: 0, max: 100000, message: t('form.newConnectionBurstRange') },
    ]}>
      <InputNumber min={0} max={100000} precision={0} disabled={!limited} style={{ width: '100%' }} />
    </Form.Item>
    <Form.Item className={itemClassName} name="new_connection_ban_seconds" label={t('form.newConnectionBan')}
      extra={t('form.newConnectionBanHelp')} rules={[
        { type: 'integer', min: 0, max: 86400, message: t('form.newConnectionBanRange') },
      ]}>
      <InputNumber min={0} max={86400} precision={0} disabled={!limited} style={{ width: '100%' }} />
    </Form.Item>
  </>
}

// 端口范围结束端口 (listen_port_end, tcp/udp v9)：留空为单端口；放在监听端口旁边。
export function StreamListenPortEndField({ form, itemClassName }: { form: FormInstance<StreamFormValues>; itemClassName?: string }) {
  const { t } = useTranslation('streams')
  return <Form.Item className={itemClassName} name="listen_port_end" label={t('form.listenPortEnd')} extra={t('form.listenPortEndHelp')}
    dependencies={['listen_port', 'tls_passthrough']} rules={[{
      validator: (_, value: number | null | undefined) => {
        const problem = portRangeProblem(form.getFieldValue('listen_port') as number | undefined, value, Boolean(form.getFieldValue('tls_passthrough')))
        return problem ? Promise.reject(new Error(t(`form.${problem}`))) : Promise.resolve()
      },
    }]}>
    <InputNumber<number> min={2} max={65535} precision={0} placeholder={t('form.listenPortEndPlaceholder')} style={{ width: '100%' }} />
  </Form.Item>
}

// 跟随端口回源 (upstream_follow_port, tcp/udp v9)：开启后按客户端访问的端口回源，回源端口不可填。
export function StreamFollowPortField({ itemClassName }: { itemClassName?: string }) {
  const { t } = useTranslation('streams')
  return <Form.Item className={itemClassName} name="upstream_follow_port" label={t('form.followPort')} valuePropName="checked"
    extra={t('form.followPortHelp')}>
    <Switch />
  </Form.Item>
}

// 会话日志 (session_log, tcp/udp v7)。
export function StreamSessionLogField({ itemClassName }: { itemClassName?: string }) {
  const { t } = useTranslation('streams')
  return <Form.Item className={itemClassName} name="session_log_enabled" label={t('form.sessionLog')} valuePropName="checked"
    extra={t('form.sessionLogHelp')}>
    <Switch />
  </Form.Item>
}

export function StreamDNSFields({ form }: { form: FormInstance<StreamFormValues> }) {
  const { t } = useTranslation('streams')
  return <div className="stream-form-grid">
    <Form.Item name={['dns_policy', 'positive_min_ttl_seconds']} label={t('form.dnsPositiveMin')} rules={[
      { required: true, message: t('form.dnsPositiveMinRequired') },
      { type: 'number', min: 1, max: 300, message: t('form.dnsPositiveMinRange') },
    ]}>
      <InputNumber min={1} max={300} precision={0} style={{ width: '100%' }} />
    </Form.Item>
    <Form.Item name={['dns_policy', 'positive_max_ttl_seconds']} label={t('form.dnsPositiveMax')} dependencies={[["dns_policy", "positive_min_ttl_seconds"]]} rules={[
      { required: true, message: t('form.dnsPositiveMaxRequired') },
      { validator: (_, value: number) => value >= form.getFieldValue(['dns_policy', 'positive_min_ttl_seconds']) && value <= 86400 ? Promise.resolve() : Promise.reject(new Error(t('form.dnsPositiveMaxRange'))) },
    ]}>
      <InputNumber min={1} max={86400} precision={0} style={{ width: '100%' }} />
    </Form.Item>
    <Form.Item name={['dns_policy', 'negative_ttl_seconds']} label={t('form.dnsNegative')} rules={[
      { required: true, message: t('form.dnsNegativeRequired') },
      { type: 'number', min: 1, max: 3600, message: t('form.dnsNegativeRange') },
    ]}>
      <InputNumber min={1} max={3600} precision={0} style={{ width: '100%' }} />
    </Form.Item>
    <Form.Item name={['dns_policy', 'stale_if_error_seconds']} label={t('form.dnsStaleIfError')} dependencies={[["dns_policy", "positive_max_ttl_seconds"]]} rules={[
      { required: true, message: t('form.dnsStaleRequired') },
      { validator: (_, value: number) => value >= form.getFieldValue(['dns_policy', 'positive_max_ttl_seconds']) && value <= 86400 ? Promise.resolve() : Promise.reject(new Error(t('form.dnsStaleRange'))) },
    ]}>
      <InputNumber min={1} max={86400} precision={0} style={{ width: '100%' }} />
    </Form.Item>
  </div>
}

export function StreamGeoFields({ form }: { form: FormInstance<StreamFormValues> }) {
  const { t } = useTranslation('streams')
  return <div className="stream-form-grid">
    <Form.Item name={['geo_policy', 'unknown_region_action']} label={t('form.geoUnknownAction')} rules={[
      { required: true, message: t('form.geoUnknownRequired') },
    ]}>
      <Select options={[
        { value: 'allow', label: t('form.geoAllow') },
        { value: 'block', label: t('form.geoBlock') },
      ]} />
    </Form.Item>
    <Form.Item name="geo_trusted_proxy_cidrs" label={t('form.geoTrustedProxyCIDRs')} dependencies={['proxy_protocol_inbound']} rules={[
      { validator: (_, value: string) => {
        const hasCIDRs = splitInput(value).length > 0
        return hasCIDRs === Boolean(form.getFieldValue('proxy_protocol_inbound'))
          ? Promise.resolve()
          : Promise.reject(new Error(t('form.geoTrustedProxyContract')))
      } },
    ]}>
      <Input.TextArea rows={2} placeholder={t('form.geoTrustedProxyPlaceholder')} />
    </Form.Item>
    <Form.Item name="geo_blocked_regions" label={t('form.geoBlockedRegions')}>
      <Input placeholder={t('form.geoBlockedRegionsPlaceholder')} />
    </Form.Item>
    <Form.Item name="geo_region_cidrs" label={t('form.geoRegionCIDRs')} dependencies={['geo_blocked_regions']} rules={[
      { validator: (_, value: string) => {
        if (!validRegionCIDRs(value ?? '')) return Promise.reject(new Error(t('form.geoRegionCIDRsInvalid')))
        const mapped = new Set(parseRegionCIDRs(value ?? '').map((entry) => entry.region))
        return splitInput(form.getFieldValue('geo_blocked_regions')).every((region) => mapped.has(region.toUpperCase()))
          ? Promise.resolve()
          : Promise.reject(new Error(t('form.geoBlockedRegionMissing')))
      } },
    ]}>
      <Input.TextArea rows={3} placeholder={t('form.geoRegionCIDRsPlaceholder')} />
    </Form.Item>
  </div>
}

export function StreamTLSPassthroughFields({ form }: { form: FormInstance<StreamFormValues> }) {
  const { t } = useTranslation('streams')
  const enabled = Form.useWatch('tls_passthrough', form)
  const protocol = Form.useWatch('protocol', form)
  // PROXY 开关可能未挂载（新建抽屉的高级区），从完整 store 读取。
  const proxyInbound = Form.useWatch('proxy_protocol_inbound', { form, preserve: true })
  const proxyV1 = Form.useWatch('proxy_protocol_v1', { form, preserve: true })
  return <>
    <Form.Item name="tls_passthrough" label={t('form.tlsPassthrough')} valuePropName="checked" dependencies={['protocol']}
      extra={protocol === 'tcp' && !enabled ? t('form.sharedPortTCPNotice') : undefined} rules={[
      { validator: (_, value: boolean) => {
        const listeners = (form.getFieldValue('additional_listeners') ?? []) as StreamAdditionalListener[]
        return !value || (form.getFieldValue('protocol') === 'tcp' && listeners.every((listener) => listener.protocol === 'tcp'))
          ? Promise.resolve()
          : Promise.reject(new Error(t('form.tlsPassthroughTCPOnly')))
      } },
    ]}>
      <Switch />
    </Form.Item>
    {/* 字段保留原始输入（tag 的 key 需唯一），校验与提交时再规范化，规范化后重复报错。 */}
    {enabled ? <Form.Item name="server_names" label={t('form.serverNames')} extra={t('form.serverNamesHelp')} rules={[
      { validator: (_, value: string[] | undefined) => {
        const names = normalizeServerNames(value)
        if (names.length === 0) return Promise.reject(new Error(t('form.serverNamesRequired')))
        if (names.length > 32) return Promise.reject(new Error(t('form.serverNamesTooMany')))
        const invalid = names.find((name) => !validStreamServerName(name))
        if (invalid) return Promise.reject(new Error(t('form.serverNamesInvalid', { name: invalid })))
        const duplicate = names.find((name, index) => names.indexOf(name) !== index)
        return duplicate ? Promise.reject(new Error(t('form.serverNamesDuplicate', { name: duplicate }))) : Promise.resolve()
      } },
    ]}>
      <Select mode="tags" open={false} suffixIcon={null} tokenSeparators={[',', '，', ' ', '\n']} placeholder={t('form.serverNamesPlaceholder')} />
    </Form.Item> : null}
    {enabled && (proxyInbound || proxyV1) ? <Alert type="warning" showIcon message={t('form.sharedPortProxyWarning')} /> : null}
  </>
}

// 回源携带客户端 IP：关闭 / PROXY protocol v1 / TOA（三选一）。表单仍存 proxy_protocol_v1 与 toa 两个布尔值。
// TOA 只用于 TCP、且与入站 PROXY 互斥；目标节点不具备 L4_TOA 时发布会被拒绝并列出节点。
export function StreamClientAddressField({ form, disabled }: { form: FormInstance<StreamFormValues>; disabled?: boolean }) {
  const { t } = useTranslation('streams')
  const proxyV1 = Form.useWatch('proxy_protocol_v1', { form, preserve: true })
  const toa = Form.useWatch('toa', { form, preserve: true })
  const protocol = Form.useWatch('protocol', { form, preserve: true })
  const listeners = Form.useWatch('additional_listeners', { form, preserve: true }) as StreamAdditionalListener[] | undefined
  const proxyInbound = Form.useWatch('proxy_protocol_inbound', { form, preserve: true })
  const hasUDP = protocol === 'udp' || Boolean(listeners?.some((listener) => listener.protocol === 'udp'))
  const value = toa ? 'toa' : proxyV1 ? 'proxy_v1' : 'off'
  return <>
  {/* 提交值仍来自这两个隐藏字段。 */}
  <Form.Item name="proxy_protocol_v1" hidden valuePropName="checked"><Switch /></Form.Item>
  <Form.Item name="toa" hidden valuePropName="checked"><Switch /></Form.Item>
  <Form.Item label={t('form.clientAddress')} extra={value === 'toa' ? t('form.clientAddressTOAHelp') : t('form.clientAddressHelp')}>
    <Radio.Group optionType="button" buttonStyle="solid" disabled={disabled || hasUDP} value={value}
      onChange={(event) => form.setFieldsValue({ proxy_protocol_v1: event.target.value === 'proxy_v1', toa: event.target.value === 'toa' })}
      options={[
        { value: 'off', label: t('form.clientAddressOff') },
        { value: 'proxy_v1', label: t('form.proxyV1') },
        { value: 'toa', label: t('form.clientAddressTOA'), disabled: Boolean(proxyInbound) },
      ]} />
  </Form.Item>
  </>
}

// 防护规则 (guard_rules, tcp/udp v10)：按顺序判定，可增删、排序；条件/动作/阈值逐条编辑。
export function StreamGuardRulesFields({ form, disabled }: { form: FormInstance<StreamFormValues>; disabled?: boolean }) {
  const { t } = useTranslation('streamGuard')
  const passthrough = Boolean(Form.useWatch('tls_passthrough', { form, preserve: true }))
  const rows = (Form.useWatch('guard_rule_rows', { form, preserve: true }) ?? []) as GuardRuleRow[]
  const tagOptions = streamGuardTags.map((tag) => ({ value: tag, label: t(`tagNames.${tag.replace(/[:-]/gu, '_')}`) }))
  return <Form.List name="guard_rule_rows">
    {(fields, { add, remove, move }) => <div className="stream-guard-rules">
      {fields.length === 0 ? <p className="stream-guard-empty">{t('empty')}</p> : null}
      {fields.map((field, index) => {
        const row = rows[index] ?? ({} as GuardRuleRow)
        const number = index + 1
        const match = row.first_packet_match as StreamGuardMatch | undefined
        return <fieldset key={field.key} className="stream-guard-rule" aria-label={t('rule', { index: number })}>
          <legend>{t('rule', { index: number })}</legend>
          <div className="stream-guard-rule-tools">
            <Button size="small" type="text" icon={<ArrowUp size={14} />} aria-label={t('moveUp', { index: number })} disabled={disabled || index === 0} onClick={() => move(index, index - 1)} />
            <Button size="small" type="text" icon={<ArrowDown size={14} />} aria-label={t('moveDown', { index: number })} disabled={disabled || index === fields.length - 1} onClick={() => move(index, index + 1)} />
            <Popconfirm title={t('removeConfirm', { index: number })} okText={t('confirm')} cancelText={t('cancel')} disabled={disabled} onConfirm={() => remove(index)}>
              <Button size="small" type="text" danger icon={<Trash2 size={14} />} aria-label={t('remove', { index: number })} disabled={disabled} />
            </Popconfirm>
          </div>
          <Form.Item name={[field.name, 'id']} hidden><Input /></Form.Item>
          <Form.Item name={[field.name, 'action']} label={t('action')} dependencies={[['guard_rule_rows', field.name], 'tls_passthrough']} rules={[{
            validator: () => {
              const current = form.getFieldValue(['guard_rule_rows', field.name]) as GuardRuleRow | undefined
              const problem = current ? guardRuleProblem(current, Boolean(form.getFieldValue('tls_passthrough'))) : null
              return problem ? Promise.reject(new Error(t(`problems.${problem}`))) : Promise.resolve()
            },
          }]}>
            <Radio.Group optionType="button" buttonStyle="solid" options={(['drop', 'ban', 'allow'] as const).map((value) => ({ value, label: t(`actions.${value}`) }))} />
          </Form.Item>
          <p className="stream-guard-caption">{t('conditions')}</p>
          <div className="stream-form-grid">
            <Form.Item name={[field.name, 'first_packet_match']} label={t('firstPacket')} extra={t('firstPacketHelp')}>
              <Select allowClear placeholder={t('firstPacketNone')} options={(['prefix_hex', 'contains', 'regex'] as const).map((value) => ({ value, label: t(`matches.${value}`) }))} />
            </Form.Item>
            {match ? <Form.Item name={[field.name, 'first_packet_value']} label={t('firstPacketValue')}>
              <Input placeholder={t(`firstPacketPlaceholder.${match}`)} maxLength={512} />
            </Form.Item> : <div />}
            <Form.Item name={[field.name, 'client_cidrs']} label={t('clientIP')}>
              <Input.TextArea rows={2} placeholder={t('clientIPPlaceholder')} />
            </Form.Item>
            <Form.Item name={[field.name, 'client_negate']} label=" " valuePropName="checked"><Checkbox>{t('negate')}</Checkbox></Form.Item>
            <Form.Item name={[field.name, 'tags']} label={t('tags')} extra={t('geoHelp')}>
              <Select mode="multiple" allowClear placeholder={t('tagsPlaceholder')} options={tagOptions} />
            </Form.Item>
            <Form.Item name={[field.name, 'tags_negate']} label=" " valuePropName="checked"><Checkbox>{t('negate')}</Checkbox></Form.Item>
            <Form.Item name={[field.name, 'countries']} label={t('countries')}>
              <Input placeholder={t('countriesPlaceholder')} />
            </Form.Item>
            <Form.Item name={[field.name, 'countries_negate']} label=" " valuePropName="checked"><Checkbox>{t('negate')}</Checkbox></Form.Item>
            {passthrough || row.server_names?.length ? <Form.Item name={[field.name, 'server_names']} label={t('serverNames')} extra={t('serverNamesHelp')}>
              <Select mode="tags" open={false} suffixIcon={null} tokenSeparators={[',', '，', ' ', '\n']} />
            </Form.Item> : null}
          </div>
          <Form.Item name={[field.name, 'geo_other']} hidden><Input /></Form.Item>
          {row.geo_other?.length ? <p className="stream-guard-caption">{t('otherGeo', { count: row.geo_other.length })}</p> : null}
          {row.action === 'ban' ? <div className="stream-form-grid">
            <Form.Item name={[field.name, 'ban_seconds']} label={t('banSeconds')} extra={t('banHelp')}>
              <InputNumber min={1} max={86400} precision={0} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item name={[field.name, 'threshold']} label={t('threshold')} extra={t('thresholdHelp')}>
              <InputNumber min={1} max={10000} precision={0} style={{ width: '100%' }} />
            </Form.Item>
            {(row.threshold ?? 1) > 1 ? <Form.Item name={[field.name, 'window_seconds']} label={t('window')}>
              <InputNumber min={1} max={3600} precision={0} style={{ width: '100%' }} />
            </Form.Item> : null}
          </div> : null}
        </fieldset>
      })}
      {fields.length >= streamGuardRulesMax ? <Alert type="info" showIcon message={t('tooMany', { count: streamGuardRulesMax })} /> : null}
      <Button icon={<Plus size={14} />} disabled={disabled || fields.length >= streamGuardRulesMax}
        onClick={() => add({ id: newGuardRuleID(), action: 'drop', ban_seconds: 600, threshold: 1 } satisfies GuardRuleRow)}>{t('add')}</Button>
    </div>}
  </Form.List>
}
