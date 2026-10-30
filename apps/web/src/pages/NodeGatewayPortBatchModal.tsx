import { useState } from 'react'
import { Alert, Form, Input, InputNumber, Modal, Space, Table, Tag, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../api/auth'
import { nodesApi, type CreateNodeGatewayPortTransitionRequest } from '../api/nodes'
import '../i18n/nodeInventoryDetail'

interface BatchNode {
  id: string
  name: string
  revision: number
}

interface FormValues {
  oldAddress: string
  oldListenAddress: string
  oldServerName: string
  newAddress: string
  newListenAddress: string
  newServerName: string
  compatibilityMinutes: number
  rollbackMinutes: number
}

interface ItemResult {
  node: BatchNode
  errorKey?: string
}

function errorKey(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.code === 'node_port_transition_conflict') return 'errors.transitionConflict'
    if (error.code === 'node_port_transition_invalid') return 'errors.transitionInvalid'
    if (error.code === 'node_port_transition_not_found') return 'errors.transitionNotFound'
  }
  return 'errors.transitionUnavailable'
}

// NodeGatewayPortBatchModal creates one 更换通讯端口 transition per selected
// node with the same endpoint pair (FX39). Each transition keeps its own
// switch / finalize / rollback lifecycle on the node detail page.
export function NodeGatewayPortBatchModal({ open, accessToken, nodes, onClose }: {
  open: boolean
  accessToken: string
  nodes: BatchNode[]
  onClose: () => void
}) {
  const { t } = useTranslation('nodeInventoryDetail')
  const [form] = Form.useForm<FormValues>()
  const [submitting, setSubmitting] = useState(false)
  const [results, setResults] = useState<ItemResult[] | null>(null)
  const [formError, setFormError] = useState('')

  const submit = async (values: FormValues) => {
    if (values.rollbackMinutes <= values.compatibilityMinutes) {
      setFormError(t('errors.rollbackWindow'))
      return
    }
    setFormError('')
    setSubmitting(true)
    const now = Date.now()
    const base = {
      old_endpoint: { address: values.oldAddress, listen_address: values.oldListenAddress, server_name: values.oldServerName },
      new_endpoint: { address: values.newAddress, listen_address: values.newListenAddress, server_name: values.newServerName },
      compatibility_deadline: new Date(now + values.compatibilityMinutes * 60_000).toISOString(),
      rollback_deadline: new Date(now + values.rollbackMinutes * 60_000).toISOString(),
    }
    const outcome: ItemResult[] = []
    for (const node of nodes) {
      const input: CreateNodeGatewayPortTransitionRequest = { ...base, expected_node_revision: node.revision }
      try {
        await nodesApi.createGatewayPortTransition(accessToken, node.id, input, crypto.randomUUID())
        outcome.push({ node })
      } catch (error) {
        outcome.push({ node, errorKey: errorKey(error) })
      }
    }
    setResults(outcome)
    setSubmitting(false)
  }

  const close = () => {
    setResults(null)
    setFormError('')
    form.resetFields()
    onClose()
  }

  const failed = results?.filter((item) => item.errorKey).length ?? 0
  return (
    <Modal
      open={open}
      title={results ? t('transition.batch.resultsTitle') : t('transition.batch.title', { count: nodes.length })}
      okText={results ? t('transition.actions.cancel') : t('transition.batch.submit', { count: nodes.length })}
      cancelText={t('transition.actions.cancel')}
      confirmLoading={submitting}
      onCancel={close}
      onOk={() => (results ? close() : void form.submit())}
      cancelButtonProps={results ? { style: { display: 'none' } } : undefined}
      destroyOnClose
    >
      {results ? (
        <>
          <Typography.Paragraph>
            {t('transition.batch.summary', { succeeded: results.length - failed, failed })}
          </Typography.Paragraph>
          <Table
            size="small"
            rowKey={(item) => item.node.id}
            pagination={false}
            dataSource={results}
            columns={[
              { dataIndex: ['node', 'name'], title: t('transition.batch.node') },
              {
                key: 'result',
                render: (_: unknown, item: ItemResult) => item.errorKey
                  ? <Tag color="error">{t(item.errorKey)}</Tag>
                  : <Tag color="success">{t('transition.batch.created')}</Tag>,
              },
            ]}
          />
        </>
      ) : (
        <>
          <Typography.Paragraph type="secondary">{t('transition.batch.description')}</Typography.Paragraph>
          {formError && <Alert type="error" showIcon message={formError} />}
          <Form form={form} layout="vertical" onFinish={(values) => void submit(values)}
            initialValues={{ compatibilityMinutes: 30, rollbackMinutes: 60 }}>
            {(['old', 'new'] as const).map((prefix) => (
              <div key={prefix}>
                <Form.Item label={t(`transition.fields.${prefix}Address`)} name={`${prefix}Address`} rules={[{ required: true }]}>
                  <Input placeholder={t('transition.placeholders.endpoint')} />
                </Form.Item>
                <Form.Item label={t(`transition.fields.${prefix}ListenAddress`)} name={`${prefix}ListenAddress`} rules={[{ required: true }]}>
                  <Input placeholder={t('transition.placeholders.listenAddress')} />
                </Form.Item>
                <Form.Item label={t(`transition.fields.${prefix}ServerName`)} name={`${prefix}ServerName`} rules={[{ required: true }]}>
                  <Input />
                </Form.Item>
              </div>
            ))}
            <Space wrap>
              <Form.Item label={t('transition.fields.compatibilityMinutes')} name="compatibilityMinutes" rules={[{ required: true }]}>
                <InputNumber min={1} max={1440} />
              </Form.Item>
              <Form.Item label={t('transition.fields.rollbackMinutes')} name="rollbackMinutes" rules={[{ required: true }]}>
                <InputNumber min={2} max={2880} />
              </Form.Item>
            </Space>
          </Form>
        </>
      )}
    </Modal>
  )
}
