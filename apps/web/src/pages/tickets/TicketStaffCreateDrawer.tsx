import { useRef, useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { Alert, App, Button, Drawer, Form, Input, Select, Space, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import {
  ticketCategories, ticketPriorities, ticketsApi, type StaffCreateTicketInput, type TicketCategory, type TicketDetail,
  type TicketPriority,
} from '../../api/tickets'
import { usersApi } from '../../api/users'
import { useSessionStore } from '../../auth/session'
import '../../i18n/tickets'
import { outcomeUnknown, useIdempotencyKey } from '../market/idempotency'

type FormValues = Omit<StaffCreateTicketInput, 'assignee_user_id'> & { assignee_user_id?: string }

// fix-ticket2 ①：管理端代用户新建工单。目标用户按用户名/邮箱/手机号搜索（纯数字按用户 ID），
// 与 StreamOwnerSelect 同一套 GET /v1/admin/users 规则；处理人不选则后端默认为当前客服。
// 一次提交一把幂等键：结果未知时同内容重试会重放，不会重复建单。
export function TicketStaffCreateDrawer({ onClose, onCreated, errorText }: {
  onClose: () => void
  onCreated: (detail: TicketDetail) => void
  errorText: (error: unknown) => string
}) {
  const { t } = useTranslation('tickets')
  const { message } = App.useApp()
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const [form] = Form.useForm<FormValues>()
  const [search, setSearch] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [unknown, setUnknown] = useState(false)
  const key = useIdempotencyKey('ticket-staff-create')
  const inFlight = useRef(false)
  const users = useQuery({
    queryKey: ['ticket-staff-create-users', search],
    queryFn: async () => {
      const term = search.trim()
      const page = await usersApi.list(token, {
        page: 1, limit: 20, ...(/^\d+$/u.test(term) ? { display_id: term } : term ? { search: term } : {}),
      })
      return page.items
    },
    staleTime: 30_000,
    retry: false,
  })
  const assignees = useQuery({ queryKey: ['tickets', 'admin', 'assignees'], queryFn: () => ticketsApi.assignees(token) })
  const create = useMutation({
    mutationFn: ({ input, idempotencyKey }: { input: StaffCreateTicketInput; idempotencyKey: string }) =>
      ticketsApi.staffCreate(token, input, idempotencyKey),
    onSettled: () => { inFlight.current = false },
    onSuccess: (detail, { idempotencyKey }) => {
      key.complete(idempotencyKey)
      void message.success(t('staffCreate.created', { no: detail.ticket.ticket_no }))
      onCreated(detail)
    },
    onError: (err, { idempotencyKey }) => {
      if (outcomeUnknown(err)) {
        setUnknown(true)
        setError(t('create.unknown'))
        return
      }
      key.complete(idempotencyKey)
      setUnknown(false)
      if (err instanceof ApiError && err.code === 'invalid_ticket') {
        form.setFields([{ name: 'user_id', errors: [t('staffCreate.userNotFound')] }])
      }
      setError(errorText(err))
    },
  })
  const userOptions = (users.data ?? []).map((user) => ({
    value: user.id, label: `${user.username}（${user.display_id}）${user.email ? ` · ${user.email}` : ''}`,
  }))
  return (
    <Drawer open onClose={onClose} width="min(640px, 100vw)" title={t('staffCreate.title')} destroyOnHidden
      className="ticket-staff-create">
      {error ? <Alert type="error" showIcon className="ticket-drawer-alert" message={error} /> : null}
      <Form<FormValues> form={form} layout="vertical" initialValues={{ category: 'technical', priority: 'normal' }}
        onValuesChange={() => setUnknown(false)}
        onFinish={(values) => {
          if (inFlight.current) return
          inFlight.current = true
          setError(null)
          const input: StaffCreateTicketInput = {
            user_id: values.user_id, category: values.category, priority: values.priority,
            subject: values.subject.trim(), body: values.body,
            ...(values.assignee_user_id ? { assignee_user_id: values.assignee_user_id } : {}),
          }
          create.mutate({ input, idempotencyKey: key.keyFor(input) })
        }}>
        <Form.Item name="user_id" label={t('staffCreate.user')} rules={[{ required: true, message: t('staffCreate.userRequired') }]}>
          <Select showSearch allowClear filterOption={false} onSearch={setSearch} loading={users.isFetching}
            aria-label={t('staffCreate.user')} placeholder={t('staffCreate.userPlaceholder')} options={userOptions}
            notFoundContent={users.isFetching ? null : users.isError ? t('staffCreate.userFailed') : t('staffCreate.userNotFound')} />
        </Form.Item>
        <Space wrap size={16}>
          <Form.Item name="category" label={t('create.category')}>
            <Select<TicketCategory> style={{ width: 160 }} aria-label={t('create.category')}
              options={ticketCategories.map((value) => ({ value, label: t(`categories.${value}`) }))} />
          </Form.Item>
          <Form.Item name="priority" label={t('create.priority')}>
            <Select<TicketPriority> style={{ width: 120 }} aria-label={t('create.priority')}
              options={ticketPriorities.map((value) => ({ value, label: t(`priorities.${value}`) }))} />
          </Form.Item>
          <Form.Item name="assignee_user_id" label={t('staffCreate.assignee')}>
            <Select allowClear style={{ width: 200 }} aria-label={t('staffCreate.assignee')} placeholder={t('staffCreate.assigneeSelf')}
              loading={assignees.isFetching}
              options={(assignees.data ?? []).map((item) => ({ value: item.user_id, label: item.display_name || item.username }))} />
          </Form.Item>
        </Space>
        <Form.Item name="subject" label={t('create.subject')} rules={[{ required: true, whitespace: true, max: 200 }]}>
          <Input maxLength={200} />
        </Form.Item>
        <Form.Item name="body" label={t('staffCreate.body')} rules={[{ required: true, whitespace: true, max: 20000 }]}
          extra={<Typography.Text type="secondary">{t('staffCreate.bodyHint')}</Typography.Text>}>
          <Input.TextArea rows={8} maxLength={20000} />
        </Form.Item>
        <Space>
          <Button type="primary" htmlType="submit" loading={create.isPending}>
            {unknown ? t('create.checkResult') : t('create.submit')}</Button>
          <Button onClick={onClose}>{t('create.cancel')}</Button>
        </Space>
      </Form>
    </Drawer>
  )
}
