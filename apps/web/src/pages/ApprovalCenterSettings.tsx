import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Checkbox, Switch, Tag, Typography } from 'antd'
import { Save } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../api/auth'
import { approvalCenterApi, type ApprovalRule } from '../api/approvalCenter'
import { useSessionStore } from '../auth/session'
import { runtimeFeaturesQueryKey } from '../components/useRuntimeFeatures'
import '../i18n/approvalCenter'

// 系统设置「其他」页的审批中心开关与受管操作（Q7）。开关默认关闭；首次打开时预选首批 4 类。
export function ApprovalCenterSettings() {
  const { t } = useTranslation('approvalCenter')
  const { message } = App.useApp()
  const queryClient = useQueryClient()
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const permissions = useSessionStore((state) => state.principal?.permissions ?? [])
  const canManage = permissions.includes('approvals.manage')
  const visible = canManage || permissions.includes('approvals.read')
  const settings = useQuery({ queryKey: ['approval-center', 'settings'], queryFn: () => approvalCenterApi.settings(token), enabled: visible && Boolean(token) })
  // null = untouched: show the saved values (never saved: the first batch preselected, Q7).
  const [draft, setDraft] = useState<{ enabled: boolean; rules: ApprovalRule[] } | null>(null)
  const saved = settings.data
  const enabled = draft?.enabled ?? saved?.enabled ?? false
  const rules = draft?.rules ?? (saved ? (saved.revision === 0 ? saved.catalog.filter((rule) => rule.default).map((rule) => rule.name) : saved.rules) : [])
  const setEnabled = (value: boolean) => setDraft({ enabled: value, rules })
  const setRules = (value: ApprovalRule[]) => setDraft({ enabled, rules: value })
  const save = useMutation({
    mutationFn: () => approvalCenterApi.saveSettings(token, { enabled, rules, revision: settings.data?.revision ?? 0 }),
    onSuccess: (next) => {
      queryClient.setQueryData(['approval-center', 'settings'], next)
      setDraft(null)
      void queryClient.invalidateQueries({ queryKey: runtimeFeaturesQueryKey })
      void message.success(t('saved'))
    },
  })
  if (!visible || !settings.data) return null
  const error = save.error instanceof ApiError ? save.error.code : save.error ? 'unknown' : null
  return (
    // fix-sysother：白卡 + 卡头注明单独保存；规则多选按网格排开（系统配置「其它配置」统一风格）。
    <section data-testid="approval-center-settings" className="system-settings-config-card sys-other-card sys-approval-card" aria-labelledby="approval-center-settings-title">
      <div className="sys-other-card-head">
        <h2 id="approval-center-settings-title" className="system-settings-config-card-title">{t('settingsTitle')}</h2>
        <span className="sys-other-card-sub">{t('separateSave')}</span>
      </div>
      <Typography.Paragraph type="secondary">{t('intro')}</Typography.Paragraph>
      <Typography.Paragraph type="secondary">{t('approvers')}</Typography.Paragraph>
      <div className={`sys-setting-v2-toggle sys-approval-toggle${enabled ? ' is-on' : ''}`}>
        <span className="sys-setting-v2-toggle-text"><span className="sys-setting-v2-toggle-title">{t('enabled')}</span></span>
        <Switch checked={enabled} disabled={!canManage} onChange={setEnabled} aria-label={t('enabled')} />
      </div>
      <Typography.Text strong className="sys-approval-rules-label">{t('rulesLabel')}</Typography.Text>
      <Checkbox.Group className="sys-approval-rules" value={rules} disabled={!canManage} onChange={(values) => setRules(values as ApprovalRule[])}>
        {settings.data.catalog.map((rule) => <Checkbox key={rule.name} value={rule.name}>
          {t(`rules.${rule.name}`, { defaultValue: rule.name })}{rule.default ? <Tag style={{ marginLeft: 8 }}>{t('firstBatch')}</Tag> : null}
        </Checkbox>)}
      </Checkbox.Group>
      {error ? <Alert type="error" showIcon message={t(`errors.${error}`, { defaultValue: t('errors.unknown') })} style={{ marginBottom: 12 }} /> : null}
      <Button type="primary" icon={<Save size={14} />} disabled={!canManage} loading={save.isPending} onClick={() => save.mutate()}>{t('save')}</Button>
    </section>
  )
}
