// 条件源站规则的新增/编辑弹窗：站点「条件源站」页与网站默认设置（#30）共用。
import { useEffect, useState } from 'react'
import { Form, Input, InputNumber, Modal, Select } from 'antd'
import { FormGrid, MODAL_WIDTH, ModalFooter } from '@cdnca/ui'
import { useTranslation } from 'react-i18next'

import type { OriginRoute } from '../../api/siteOriginRouting'
import '../../i18n/siteOriginRouting'

interface RouteFormValues {
  id: string
  priority: number
  path_prefix?: string
  node_regions?: string
  client_cidrs?: string
  pool_id: string
}

function commaSeparatedValues(value: string | undefined): string[] | undefined {
  const values = value?.split(',').map((item) => item.trim()).filter(Boolean) ?? []
  return values.length > 0 ? values : undefined
}

export interface ConditionalOriginRouteDialogProps {
  // 正在编辑的规则（undefined：新增）
  route: OriginRoute | undefined
  // 可选的源站池 ID；新增规则默认选 defaultPoolId
  poolIds: string[]
  defaultPoolId: string
  // 其他规则已用的 ID（重复时拒绝）
  takenIds: string[]
  // 是否提供备用源站池（默认设置只有一个占位池，不提供）
  allowFallback: boolean
  disabled: boolean
  // 整份文档校验（站点页）；返回 false 时在路径字段提示文档不合法
  validate?: (route: OriginRoute) => boolean
  onCancel: () => void
  onApply: (route: OriginRoute) => void
}

export default function ConditionalOriginRouteDialog(props: ConditionalOriginRouteDialogProps) {
  const { t } = useTranslation('siteOriginRouting')
  const [form] = Form.useForm<RouteFormValues>()
  const [fallbackPoolId, setFallbackPoolId] = useState<string | undefined>(props.route?.fallback_pool_id)
  const { route, defaultPoolId } = props

  useEffect(() => {
    form.setFieldsValue({
      id: route?.id ?? '',
      priority: route?.priority ?? 0,
      path_prefix: route?.path_prefix ?? '',
      node_regions: route?.node_regions?.join(', ') ?? '',
      client_cidrs: route?.client_cidrs?.join(', ') ?? '',
      pool_id: route?.pool_id ?? defaultPoolId,
    })
  }, [defaultPoolId, form, route])

  const apply = async () => {
    if (props.disabled) return
    let values: RouteFormValues
    try {
      values = await form.validateFields()
    } catch {
      return
    }
    const next: OriginRoute = {
      id: values.id,
      priority: values.priority,
      ...(values.path_prefix ? { path_prefix: values.path_prefix } : {}),
      ...(commaSeparatedValues(values.node_regions) ? { node_regions: commaSeparatedValues(values.node_regions) } : {}),
      ...(commaSeparatedValues(values.client_cidrs) ? { client_cidrs: commaSeparatedValues(values.client_cidrs) } : {}),
      pool_id: values.pool_id,
      ...(props.allowFallback && fallbackPoolId ? { fallback_pool_id: fallbackPoolId } : {}),
    }
    if (!next.path_prefix && !next.node_regions?.length && !next.client_cidrs?.length) {
      form.setFields([{ name: 'path_prefix', errors: [t('validation.routePredicate')] }])
      return
    }
    if (props.takenIds.includes(next.id)) {
      form.setFields([{ name: 'id', errors: [t('validation.duplicateRoute')] }])
      return
    }
    if (props.validate && !props.validate(next)) {
      form.setFields([{ name: 'path_prefix', errors: [t('validation.routeDocument')] }])
      return
    }
    props.onApply(next)
  }

  const poolOptions = props.poolIds.map((id) => ({ label: id, value: id }))
  return (
    <Modal
      open
      destroyOnHidden
      title={t(route ? 'dialogs.editRoute' : 'dialogs.addRoute')}
      width={MODAL_WIDTH.M}
      footer={<ModalFooter okText={t('actions.applyRoute')} cancelText={t('actions.cancel')} okDisabled={props.disabled} onOk={() => void apply()} onCancel={props.onCancel} />}
      onCancel={props.onCancel}
    >
      <Form<RouteFormValues> form={form} layout="vertical" disabled={props.disabled} clearOnDestroy>
        <FormGrid columns={2}>
          <Form.Item
            name="id"
            label={t('fields.routeId')}
            rules={[
              { required: true, message: t('validation.required') },
              { pattern: /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u, message: t('validation.routeId') },
            ]}
          >
            <Input autoComplete="off" maxLength={64} />
          </Form.Item>
          <Form.Item name="priority" label={t('fields.priority')} rules={[{ required: true }]}>
            <InputNumber min={-1000} max={1000} precision={0} />
          </Form.Item>
          <FormGrid.Full>
            <Form.Item
              name="path_prefix"
              label={t('fields.path')}
              rules={[{
                validator: (_, value: unknown) => typeof value !== 'string' || value.length === 0 ||
                  value.length <= 2048 && value.startsWith('/') && !value.includes('//') &&
                  !/[\\?#%]/u.test(value) && value.trim() === value
                  ? Promise.resolve()
                  : Promise.reject(new Error(t('validation.path'))),
              }]}
            >
              <Input autoComplete="off" maxLength={2048} />
            </Form.Item>
          </FormGrid.Full>
          <Form.Item name="node_regions" label={t('fields.regions')} extra={t('help.regions')}>
            <Input autoComplete="off" placeholder={t('placeholders.commaSeparated')} />
          </Form.Item>
          <Form.Item name="client_cidrs" label={t('fields.cidrs')}>
            <Input autoComplete="off" placeholder={t('placeholders.commaSeparated')} />
          </Form.Item>
          <Form.Item name="pool_id" label={t('fields.routePool')} rules={[{ required: true }]}>
            <Select options={poolOptions} />
          </Form.Item>
          {props.allowFallback ? (
            <Form.Item label={t('fields.routeFallbackPool')}>
              <Select aria-label={t('fields.routeFallbackPool')} allowClear value={fallbackPoolId} options={poolOptions} onChange={setFallbackPoolId} />
            </Form.Item>
          ) : null}
        </FormGrid>
      </Form>
    </Modal>
  )
}
