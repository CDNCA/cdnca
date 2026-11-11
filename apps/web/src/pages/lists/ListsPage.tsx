import { Tabs } from 'antd'
import { useTranslation } from 'react-i18next'
import { useSearchParams } from 'react-router-dom'

import type { SecurityStringSetAudience } from '../../api/securityStringSets'
import { useSessionStore } from '../../auth/session'
import '../../i18n/securityLists'
import { PageHeader, PageSection } from '@cdnca/ui'
import { IPListsTab } from './IPListsTab'
import { StringSetsTab } from './StringSetsTab'
import './lists.css'

const tabs = ['ip', 'strings'] as const
type ListsTab = (typeof tabs)[number]

// 列表与对象: the named sets WAF rules
// reference, IP lists and string sets on two tabs (?tab=ip / ?tab=strings).
// The old /site/ip-lists route redirects to ?tab=ip.
export default function ListsPage() {
  const { t } = useTranslation('securityLists')
  const [searchParams, setSearchParams] = useSearchParams()
  const accessToken = useSessionStore((state) => state.accessToken) ?? ''
  const principal = useSessionStore((state) => state.principal)
  const audience: SecurityStringSetAudience = principal?.scope_kind === 'platform' ? 'admin' : 'tenant'
  const canManage = principal?.permissions.includes('security_policies.manage') ||
    principal?.permissions.includes('platform.admin') || false
  const requested = searchParams.get('tab')
  const active: ListsTab = tabs.includes(requested as ListsTab) ? requested as ListsTab : 'ip'
  const headingID = 'lists-page-title'

  return (
    <PageSection className="lists-page" aria-labelledby={headingID}>
      <PageHeader title={<span id={headingID}>{t('title')}</span>}
        description={<>{t('description')}{audience === 'tenant' ? <> {t('platformHint')}</> : null}</>} />
        <Tabs activeKey={active} destroyOnHidden
          onChange={(key) => setSearchParams((current) => { const next = new URLSearchParams(current); next.set('tab', key); return next }, { replace: true })}
          items={[
            { key: 'ip', label: t('tabs.ip'), children: principal ? <IPListsTab audience={audience} accessToken={accessToken} canManage={canManage} scopeID={principal.scope_id} /> : null },
            { key: 'strings', label: t('tabs.strings'), children: principal ? <StringSetsTab audience={audience} accessToken={accessToken} canManage={canManage} /> : null },
          ]} />
    </PageSection>
  )
}
