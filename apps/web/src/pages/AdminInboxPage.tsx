import { useCallback, useEffect, useState } from 'react'
import { App, Button, Checkbox, List, Space, Tag, Typography } from 'antd'
import { useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'

import { inboxApiFor, type AdminInboxMessage, type InboxScope } from '../api/adminInbox'
import { useSessionStore } from '../auth/session'
import { inboxUnreadKey } from '../components/AdminInboxBell'
import { localizedApiError } from '../i18n/apiError'
import { adminInboxText } from '../i18n/adminInbox'
import { FeedbackWhen } from '@cdnca/ui'

// Message center: for platform administrators node offline/recovered, HTTP-01
// drift and staff ticket events; for tenant members (scope account) the
// in-app notices such as attack escalation (N23).
export default function AdminInboxPage({ scope = 'admin' }: { scope?: InboxScope }) {
  const api = inboxApiFor(scope)
  const { t, i18n } = useTranslation('adminInbox')
  const { message } = App.useApp()
  const queryClient = useQueryClient()
  const accessToken = useSessionStore(state => state.accessToken)
  const [items, setItems] = useState<AdminInboxMessage[]>([])
  const [cursor, setCursor] = useState<string | null>(null)
  const [unread, setUnread] = useState(0)
  const [unreadOnly, setUnreadOnly] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const [loading, setLoading] = useState(false)

  const load = useCallback(async (next: string | null) => {
    if (!accessToken) return
    setLoading(true)
    try {
      const page = await api.list(accessToken, { unreadOnly, cursor: next })
      setItems(current => next ? [...current, ...page.items] : page.items)
      setCursor(page.next_cursor)
      setUnread(page.unread)
      setError(null)
    } catch (caught) {
      setError(caught)
    } finally {
      setLoading(false)
    }
  }, [accessToken, unreadOnly, api])
  useEffect(() => { void load(null) }, [load])

  const refreshBadge = () => void queryClient.invalidateQueries({ queryKey: inboxUnreadKey(scope) })
  const markRead = async (item: AdminInboxMessage) => {
    if (!accessToken || item.read_at) return
    try {
      await api.read(accessToken, item.id)
      setItems(current => current.map(entry => entry.id === item.id ? { ...entry, read_at: new Date().toISOString() } : entry)
        .filter(entry => !unreadOnly || !entry.read_at))
      setUnread(value => Math.max(0, value - 1))
      refreshBadge()
    } catch (caught) {
      setError(caught)
    }
  }
  const readAll = async () => {
    if (!accessToken) return
    try {
      await api.readAll(accessToken)
      message.success(t('readAllDone'))
      refreshBadge()
      await load(null)
    } catch (caught) {
      setError(caught)
    }
  }
  const formatter = new Intl.DateTimeFormat(i18n.resolvedLanguage ?? 'zh-CN', { dateStyle: 'medium', timeStyle: 'short' })

  return (
    <div className="page-stack admin-inbox-page">
      <Typography.Title level={3}>{t('title')}</Typography.Title>
      <Space>
        <Checkbox checked={unreadOnly} onChange={event => setUnreadOnly(event.target.checked)}>{t('unreadOnly')}</Checkbox>
        <Button disabled={unread === 0} onClick={() => void readAll()}>{t('readAll')}</Button>
      </Space>
      {error ? <FeedbackWhen title={localizedApiError(error)} /> : null}
      <List
        className="admin-inbox-list"
        size="small"
        loading={loading && items.length === 0}
        locale={{ emptyText: t('empty') }}
        dataSource={items}
        renderItem={item => (
          <List.Item actions={item.read_at ? [] : [<Button key="read" type="link" onClick={() => void markRead(item)}>{t('markRead')}</Button>]}>
            <List.Item.Meta
              title={<Space>{item.read_at ? null : <Tag color="blue">{t('unread')}</Tag>}<span>{adminInboxText(t, item.event_type, item.params)}</span>
                {/* Only console-relative links (aggregated edge alerts carry the schedule page). */}
                {item.params.link?.startsWith('/') && !item.params.link.startsWith('//') ? <Link to={item.params.link}>{t('open')}</Link> : null}</Space>}
              description={formatter.format(new Date(item.created_at))}
            />
          </List.Item>
        )}
      />
      {cursor ? <Button loading={loading} onClick={() => void load(cursor)}>{t('loadMore')}</Button> : null}
    </div>
  )
}
