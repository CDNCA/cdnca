import { useEffect, useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { Alert, Button, Form, Input, Space } from 'antd'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../api/auth'
import { frozenSession } from '../api/controlBackup'
import { controlBackupError, controlBackupMessage, type ControlBackupKey } from '../i18n/controlBackup'
import ControlBackupPanel from './ControlBackupPanel'
import './ControlUpgradesPage.css'

// fix-migrollback：迁移冻结期间 control-api 已停，只有冻结控制台在答。
// 这里用它自己的登录（内存会话，不写库），只显示迁移进度、日志、停止与回退。

interface FrozenSession { token: string; expiresAt: number; canManage: boolean }

const liveProbeMilliseconds = 10_000

export default function FrozenConsolePage({ now = Date.now }: { now?: () => number }) {
  const { i18n } = useTranslation()
  const language = i18n.resolvedLanguage ?? 'zh-CN'
  const bt = (key: ControlBackupKey) => controlBackupMessage(language, key)
  const [session, setSession] = useState<FrozenSession | null>(null)
  const [form] = Form.useForm<{ username: string; password: string }>()
  const signIn = useMutation({
    mutationFn: (values: { username: string; password: string }) => frozenSession(values.username, values.password),
    onSuccess: (result) => { form.resetFields(); setSession({ token: result.access_token, expiresAt: Date.parse(result.expires_at), canManage: result.can_manage }) },
    onError: () => form.setFieldValue('password', ''),
  })
  // After a rollback the real control-api answers again: leave the frozen page.
  const resumed = useQuery({
    queryKey: ['control-backup', 'frozen-resumed'],
    queryFn: async () => {
      const response = await fetch('/health/ready', { cache: 'no-store' }).catch(() => null)
      return response?.ok === true
    },
    refetchInterval: liveProbeMilliseconds,
  })
  useEffect(() => {
    if (resumed.data) window.location.assign('/dashboard/login')
  }, [resumed.data])
  // The frozen session lasts 30 minutes (server clock); sign in again after.
  useEffect(() => {
    if (!session) return
    // setTimeout keeps a 32-bit delay; a longer one would fire at once.
    const timer = window.setTimeout(() => setSession(null), Math.min(Math.max(session.expiresAt - now(), 0), 2_147_483_647))
    return () => window.clearTimeout(timer)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session])
  const active = session !== null

  return <main className="frozen-console" aria-labelledby="frozen-console-title">
    <header className="frozen-console-header">
      <h1 id="frozen-console-title">{bt('frozenTitle')}</h1>
      {active ? <Button onClick={() => setSession(null)}>{bt('frozenSignOut')}</Button> : null}
    </header>
    <Alert type="warning" showIcon message={bt('frozenIntro')} />
    {resumed.data ? <Alert type="success" showIcon message={bt('serviceResumed')} /> : null}
    {active
      ? <>
        {!session.canManage ? <Alert type="info" showIcon message={bt('frozenReadOnly')} /> : null}
        <ControlBackupPanel accessToken={session.token} canManage={session.canManage} frozen />
      </>
      : <Form form={form} layout="vertical" className="frozen-console-sign-in" requiredMark={false}
        onFinish={(values) => signIn.mutate(values)}>
        {signIn.isError ? <Alert type="error" showIcon message={bt('frozenSignInFailed')}
          description={controlBackupError(language, signIn.error instanceof ApiError ? signIn.error.code : undefined)} /> : null}
        <Form.Item name="username" label={bt('frozenUsername')} rules={[{ required: true, message: bt('required') }]}>
          <Input autoComplete="username" />
        </Form.Item>
        <Form.Item name="password" label={bt('frozenPassword')} rules={[{ required: true, message: bt('required') }]}>
          <Input.Password autoComplete="current-password" />
        </Form.Item>
        <Space><Button type="primary" htmlType="submit" loading={signIn.isPending}>{bt('frozenSignIn')}</Button></Space>
      </Form>}
  </main>
}
