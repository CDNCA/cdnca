import type { ReactNode } from 'react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Result } from 'antd'
import type { TFunction } from 'i18next'
import { Activity, BarChart3, Grid3X3, Megaphone, Pencil } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'

import { ApiError, type Principal } from '../api/auth'
import {
  dashboardApi,
  formatDashboardBytes,
  formatDashboardInteger,
  formatDashboardLoginSource,
  type DashboardFilters,
  type DashboardSection,
  type DashboardUnavailableReason,
  type TenantDashboard,
  type TenantDashboardRange,
} from '../api/dashboard'
import { useSessionStore } from '../auth/session'
import { AnalyticsSettlingHint, DashboardAnalyticsView } from '../components/DashboardOverview'
import { DataState } from '../components/DataState'
import { localizedUnknownApiError } from '../i18n/apiError'
import { businessTimeZone, formatBandwidth, formatDateTime, formatNumber } from '../i18n/formatters'
import { peakHourlyBandwidth } from './adminHomeMetrics'
import type { UserHomeBlock } from '../api/theme'
import { useThemeRuntime } from '../theme/runtime'
import '../styles/userHomeReference.css'

// Mirrors control-api dashboard tenantReadPermissions (the server still checks
// the billing/package codes; the community edition no longer shows those facts).
const requiredDashboardPermissions = [
  'sites.read',
  'certificates.read',
  'billing.account.read',
  'package_subscriptions.read',
  'traffic_packages.read',
  'announcements.read',
  'jobs.read',
] as const

type TenantDashboardOwner = readonly ['tenant', string, string, string, number]
const staleTenantDashboardRead = new Error('stale tenant dashboard read')

function tenantDashboardOwner(principal: Principal, sessionEpoch: number): TenantDashboardOwner | null {
  if (
    principal.scope_kind !== 'tenant' ||
    !principal.scope_id ||
    !principal.tenant_id ||
    !principal.user_id ||
    !sessionEpoch
  ) return null
  return ['tenant', principal.scope_id, principal.tenant_id, principal.user_id, sessionEpoch]
}

function currentTenantDashboardAccess(ownerKey: string): string | null {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (!accessToken || !principal ||
    !requiredDashboardPermissions.every((permission) => principal.permissions.includes(permission))) return null
  const owner = tenantDashboardOwner(principal, sessionEpoch)
  return owner && JSON.stringify(owner) === ownerKey ? accessToken : null
}

function errorMessage(error: unknown, t: TFunction<'userHome'>): string {
  if (!(error instanceof ApiError)) return t('errors.request_failed')
  switch (error.code) {
    case 'network_error':
    case 'request_failed':
    case 'invalid_response':
    case 'dashboard_storage_unavailable':
    case 'dashboard_query_timeout':
    case 'dashboard_request_cancelled':
      return t(`errors.${error.code}`)
    default:
      return localizedUnknownApiError(error, t('errors.request_failed'))
  }
}

function greetingKey(date: Date): string {
  const hour = date.getHours()
  if (hour < 6) return 'greeting.lateNight'
  if (hour < 12) return 'greeting.morning'
  if (hour < 18) return 'greeting.afternoon'
  return 'greeting.evening'
}

function SectionUnavailable({ reason }: { reason: DashboardUnavailableReason }) {
  const { t } = useTranslation('userHome')
  return <div className="user-dashboard-unavailable" role="status">{t(`unavailable.${reason}`)}</div>
}

function SectionValue<T>({ section, children }: {
  section: DashboardSection<T>
  children: (value: T) => ReactNode
}) {
  return section.available ? children(section.value) : <SectionUnavailable reason={section.reason} />
}

function DashboardRangeControl({ value, onChange, ariaLabel }: {
  value: TenantDashboardRange
  onChange: (value: TenantDashboardRange) => void
  ariaLabel: string
}) {
  const { t } = useTranslation('userHome')
  const options: Array<{ value: TenantDashboardRange; label: string }> = [
    { value: 'today', label: t('ranges.today') },
    { value: 'yesterday', label: t('ranges.yesterday') },
    { value: 'seven_days', label: t('ranges.sevenDays') },
    { value: 'thirty_days', label: t('ranges.thirtyDays') },
  ]
  return (
    <div className="user-dashboard-range" role="radiogroup" aria-label={ariaLabel}>
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          role="radio"
          aria-checked={value === option.value}
          className={value === option.value ? 'is-selected' : ''}
          onClick={() => onChange(option.value)}
        >
          {option.label}
        </button>
      ))}
    </div>
  )
}

function DashboardCard({ title, icon, toolbar, className = '', children }: {
  title: string
  icon: ReactNode
  toolbar?: ReactNode
  className?: string
  children: ReactNode
}) {
  return (
    <section className={`user-dashboard-card ${className}`.trim()}>
      <header className="user-dashboard-card-heading">
        <h2>{icon}<span>{title}</span></h2>
        {toolbar ? <div className="user-dashboard-card-extra">{toolbar}</div> : null}
      </header>
      {children}
    </section>
  )
}

function accountDisplayID(principal: Principal): string | null {
  const value = principal.display_id?.trim()
  return value && /^[1-9][0-9]{0,18}$/.test(value) ? value : null
}

function UserProfileCard({ principal, data }: { principal: Principal; data?: TenantDashboard }) {
  const { t, i18n } = useTranslation('userHome')
  const navigate = useNavigate()
  const locale = i18n.resolvedLanguage ?? 'zh-CN'
  const title = principal.username || principal.display_name
  const displayID = accountDisplayID(principal)
  const verification = data?.identity_verification.available
    ? t(data.identity_verification.value.verified ? 'profile.verified' : 'profile.unverified')
    : t('values.placeholder')
  const profile = data?.profile.available ? data.profile.value : undefined
  const lastLogin = profile?.last_login_at
    ? (locale === 'en-US' ? formatDateTime(profile.last_login_at, locale) : formatDateTime(profile.last_login_at, locale).replaceAll('/', '-'))
    : t('values.placeholder')
  const loginSource = (profile && formatDashboardLoginSource(profile, locale)) ?? t('values.placeholder')
  return (
    <section className="user-dashboard-card user-profile-card" aria-label={t('profile.ariaLabel')}>
      <div className="user-profile-avatar" aria-hidden="true">{title.slice(0, 1).toUpperCase()}</div>
      <div className="user-profile-content">
        <div className="user-profile-title-row">
          <h1>{title}</h1>
          <button type="button" aria-label={t('profile.edit')} onClick={() => navigate('/account/user')}>
            <Pencil size={12} aria-hidden="true" />
          </button>
          <p>{t(greetingKey(new Date()))}</p>
        </div>
        <dl className="user-profile-facts">
          <div><dt>{t('profile.accountId')}:</dt><dd title={principal.user_id}>{displayID ?? t('values.placeholder')}</dd></div>
          <div><dt>{t('profile.identity')}:</dt><dd>{verification}</dd></div>
          <div><dt>{t('profile.lastLogin')}:</dt><dd>{lastLogin}</dd></div>
          <div><dt>{t('profile.loginIp')}:</dt><dd>{loginSource}</dd></div>
        </dl>
      </div>
    </section>
  )
}

function NoticeList({ notices, locale }: {
  notices: DashboardSection<{ unread: number; items: Array<{ id: string; title: string; published_at: string; read_at?: string }> }>
  locale: string
}) {
  const { t } = useTranslation('userHome')
  if (!notices.available) return <SectionUnavailable reason={notices.reason} />
  if (notices.value.items.length === 0) return <div className="user-dashboard-empty">{t('notices.empty')}</div>
  return (
    <ul className="user-notice-list">
      {notices.value.items.slice(0, 3).map((notice) => (
        <li key={notice.id}>
          <span>{notice.title}</span>
          <time dateTime={notice.published_at}>{formatDateTime(notice.published_at, locale)}</time>
        </li>
      ))}
    </ul>
  )
}

function NetworkMetrics({ data, locale }: { data: TenantDashboard; locale: string }) {
  const { t } = useTranslation('userHome')
  if (!data.analytics.available) return <SectionUnavailable reason={data.analytics.reason} />
  const analytics = data.analytics.value
  const peak = peakHourlyBandwidth(analytics) ?? (analytics.summary.average_bandwidth_bps === 0 ? 0 : null)
  const bandwidth = peak === null ? t('values.placeholder') : peak === 0 ? '0Kbps' : formatBandwidth(peak, locale).replaceAll(' ', '')
  const traffic = formatDashboardBytes(analytics.summary.total_bytes, locale).replaceAll(' ', '').replace(/^0B$/, '0KB')
  const requests = `${formatDashboardInteger(analytics.summary.request_count, locale)}${locale === 'en-US' ? ' requests' : '次'}`
  const blockedIPs = analytics.blocked_ip_count === undefined
    ? t('values.placeholder')
    : `${formatDashboardInteger(analytics.blocked_ip_count, locale)}${locale === 'en-US' ? ' IPs' : '个'}`
  return (
    <>
    <AnalyticsSettlingHint minutes={analytics.settling_minutes} />
    <dl className="user-network-metrics">
      <div><dt>{t('metrics.peakBandwidth')}</dt><dd>{bandwidth}</dd></div>
      <div><dt>{t('metrics.requests')}</dt><dd>{requests}</dd></div>
      <div><dt>{t('metrics.totalTraffic')}</dt><dd>{traffic}</dd></div>
      <div><dt>{t('metrics.blockedIps')}</dt><dd>{blockedIPs}</dd></div>
    </dl>
    </>
  )
}

function orderedBlocks(order: readonly UserHomeBlock[], blocks: { key: UserHomeBlock; node: () => ReactNode }[]): ReactNode[] {
  return order.flatMap((key) => blocks.filter((block) => block.key === key).map((block) => block.node()))
}

export function UserHomePage() {
  const { t } = useTranslation('userHome')
  const sessionStatus = useSessionStore((state) => state.status)
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)

  if (sessionStatus === 'bootstrapping' || !principal || !accessToken) {
    return (
      <section className="tenant-overview dashboard-page" aria-label={t('states.pageLoading')}>
        <DataState status="loading" className="dashboard-page-state" message={t('states.pageLoading')} />
      </section>
    )
  }

  const owner = tenantDashboardOwner(principal, sessionEpoch)
  if (!owner || !requiredDashboardPermissions.every((permission) => principal.permissions.includes(permission))) {
    return <Result className="identity-page identity-forbidden" status="403" title={t('errors.forbiddenTitle')} subTitle={t('errors.permission_denied')} />
  }

  const ownerKey = JSON.stringify(owner)
  return <UserHomePageContent key={ownerKey} owner={owner} ownerKey={ownerKey} principal={principal} />
}

function UserHomePageContent({ owner, ownerKey, principal }: {
  owner: TenantDashboardOwner
  ownerKey: string
  principal: Principal
}) {
  const { t, i18n } = useTranslation('userHome')
  const locale = i18n.resolvedLanguage ?? 'zh-CN'
  const [range, setRange] = useState<TenantDashboardRange>('today')
  const [filters] = useState<DashboardFilters>({})
  const queryClient = useQueryClient()
  const queryOwner = useRef(owner).current
  const queryPrefix = useMemo(() => ['dashboard', ...queryOwner] as const, [queryOwner])
  const lineageActiveRef = useRef(true)
  const currentSessionCanRead = useCallback(() => (
    lineageActiveRef.current && Boolean(currentTenantDashboardAccess(ownerKey))
  ), [ownerKey])

  useEffect(() => {
    lineageActiveRef.current = true
    return () => {
      lineageActiveRef.current = false
      if (!currentTenantDashboardAccess(ownerKey)) queryClient.removeQueries({ queryKey: queryPrefix })
    }
  }, [ownerKey, queryClient, queryPrefix])

  const dashboardQuery = useQuery({
    queryKey: [...queryPrefix, range, businessTimeZone, filters],
    queryFn: async ({ signal }) => {
      const token = currentTenantDashboardAccess(ownerKey)
      if (!token) throw staleTenantDashboardRead
      try {
        const result = await dashboardApi.tenant(token, range, businessTimeZone, signal, filters)
        if (!currentSessionCanRead()) throw staleTenantDashboardRead
        return result
      } catch (error) {
        if (!currentSessionCanRead()) throw staleTenantDashboardRead
        throw error
      }
    },
    placeholderData: (previousData) => previousData,
    staleTime: 30_000,
  })

  // PA-17 layout slot user_home_blocks: which preset blocks show, in order.
  const blocks = useThemeRuntime().layout.user_home_blocks
  const error = dashboardQuery.error
  if (error instanceof ApiError && error.status === 403) {
    return <Result className="identity-page identity-forbidden" status="403" title={t('errors.forbiddenTitle')} subTitle={t('errors.permission_denied')} />
  }

  const data = dashboardQuery.data
  const rangeControl = (ariaLabel: string) => (
    <DashboardRangeControl value={range} onChange={setRange} ariaLabel={ariaLabel} />
  )

  const dataBlocks = blocks.filter((block) => block === 'network' || block === 'monitoring' || block === 'top')
  const stateCard = (key: string) => dashboardQuery.isPending ? (
    <section key={key} className="user-dashboard-card user-network-card user-dashboard-state-card">
      <div className="user-dashboard-state-toolbar">{rangeControl(t('ranges.networkLabel'))}</div>
      <DataState status="loading" className="dashboard-page-state" message={t('states.loading')} />
    </section>
  ) : error ? (
    <section key={key} className="user-dashboard-card user-network-card user-dashboard-state-card">
      <div className="user-dashboard-state-toolbar">{rangeControl(t('ranges.networkLabel'))}</div>
      <DataState status="error" className="dashboard-page-state" message={errorMessage(error, t)} onRetry={() => void dashboardQuery.refetch()} />
    </section>
  ) : null
  // While loading or failed, the first data block shows the state card.
  const dataBlock = (key: UserHomeBlock, render: (value: TenantDashboard) => ReactNode) => {
    if (!data) return key === dataBlocks[0] ? stateCard(key) : null
    return render(data)
  }
  const mainBlocks: { key: UserHomeBlock; node: () => ReactNode }[] = [
    { key: 'profile', node: () => <UserProfileCard key="profile" principal={principal} data={data} /> },
    { key: 'network', node: () => dataBlock('network', (value) => (
      <DashboardCard
        key="network"
        title={t('sections.network')}
        icon={<BarChart3 size={14} aria-hidden="true" />}
        toolbar={rangeControl(t('ranges.networkLabel'))}
        className="user-network-card"
      >
        <NetworkMetrics data={value} locale={locale} />
      </DashboardCard>
    )) },
    { key: 'monitoring', node: () => dataBlock('monitoring', (value) => (
      <div key="monitoring" className="user-monitor-grid">
        <DashboardCard
          title={t('sections.monitoring')}
          icon={<Activity size={14} aria-hidden="true" />}
          toolbar={rangeControl(t('ranges.monitorLabel'))}
          className="user-monitor-card"
        >
          <SectionValue section={value.analytics}>{(analytics) => (
            <DashboardAnalyticsView analytics={analytics} locale={locale} variant="admin" mode="trend" />
          )}</SectionValue>
        </DashboardCard>
        {blocks.includes('top') ? (
          <DashboardCard
            title={t('sections.top')}
            icon={<Activity size={14} aria-hidden="true" />}
            className="user-top-card"
          >
            <SectionValue section={value.analytics}>{(analytics) => (
              <DashboardAnalyticsView analytics={analytics} locale={locale} variant="admin" mode="rankings" />
            )}</SectionValue>
          </DashboardCard>
        ) : null}
      </div>
    )) },
    // "top" sits in the monitoring grid; alone it takes the grid itself.
    { key: 'top', node: () => blocks.includes('monitoring') ? null : dataBlock('top', (value) => (
      <div key="top" className="user-monitor-grid">
        <DashboardCard
          title={t('sections.top')}
          icon={<Activity size={14} aria-hidden="true" />}
          className="user-top-card"
        >
          <SectionValue section={value.analytics}>{(analytics) => (
            <DashboardAnalyticsView analytics={analytics} locale={locale} variant="admin" mode="rankings" />
          )}</SectionValue>
        </DashboardCard>
      </div>
    )) },
  ]
  const sideBlocks: { key: UserHomeBlock; node: () => ReactNode }[] = data ? [
    { key: 'notices', node: () => (
      <DashboardCard key="notices" title={t('sections.systemNotices')} icon={<Megaphone size={14} aria-hidden="true" />} className="user-notices-card">
        <NoticeList notices={data.notices} locale={locale} />
      </DashboardCard>
    ) },
    { key: 'usage', node: () => (
      <DashboardCard key="usage" title={t('sections.usage')} icon={<Grid3X3 size={14} aria-hidden="true" />} className="user-usage-card">
        <dl className="user-usage-list">
          <div><dt>{t('usage.domains')}</dt><dd>{data.resources.available ? formatNumber(data.resources.value.domains_total, locale) : t('values.placeholder')}</dd></div>
          <div><dt>{t('usage.forwards')}</dt><dd>{data.resources.available ? formatNumber(data.resources.value.forwards_total, locale) : t('values.placeholder')}</dd></div>
          <div><dt>{t('usage.certificates')}</dt><dd>{data.certificates.available ? formatNumber(data.certificates.value.total, locale) : t('values.placeholder')}</dd></div>
        </dl>
      </DashboardCard>
    ) },
  ] : []

  return (
    <section
      className="tenant-overview dashboard-page"
      aria-label={t('title')}
      aria-busy={dashboardQuery.isFetching}
      data-dashboard-state={dashboardQuery.isPending ? 'loading' : error ? 'error' : 'ready'}
    >
      <div className="user-dashboard-layout">
        <main className="user-dashboard-main">
          {orderedBlocks(blocks, mainBlocks)}
        </main>

        {data && sideBlocks.some((block) => blocks.includes(block.key)) ? (
          <aside className="user-dashboard-side">
            {orderedBlocks(blocks, sideBlocks)}
          </aside>
        ) : null}
      </div>
    </section>
  )
}
