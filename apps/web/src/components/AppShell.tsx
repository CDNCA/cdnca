import { useEffect, useMemo, useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { Badge, Dropdown, Menu, Tooltip, type MenuProps } from 'antd'
import { useFeedback } from '@cdnca/ui'
import { IndentDecrease, IndentIncrease, LogOut, Moon, RotateCw, Sun, UserRound } from 'lucide-react'
import { Outlet, useLocation, useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'

import {
  homeForPrincipal,
  logoutSession,
  refreshSession,
  roleForPrincipal,
  useSessionStore,
} from '../auth/session'
import {
  getBreadcrumbLabels,
  getNavigation,
  getNavigationSelectionKey,
  getParentNavigationKey,
  isImplementedPath,
  pluginPageRoute,
  withPluginPages,
  type NavIcon,
  type NavigationItem,
} from '../routes/navigation'
import { canLeaveCurrentPage } from '../routes/navigationGuard'
import { PublicBrandAssetImage, PublicBrandFavicon } from './PublicBrandAssetImage'
import { AnnouncementPopup } from './AnnouncementPopup'
import { ticketMenuKey, useTicketMenuBadge } from './useTicketMenuBadge'
import { AdminInboxBell } from './AdminInboxBell'
import { useGrantedModules } from './useGrantedModules'
import { useRuntimeFeatures } from './useRuntimeFeatures'
import { pluginPagePath, pluginPageTitle, usePluginUIPages } from '../pluginui/usePluginUIPages'
import { GlobalScript } from './GlobalScript'
import { localizedText } from '../api/theme'
import { useBrandName, useThemeBrandName, useThemeRuntime } from '../theme/runtime'
import { useSystemBranding } from './useSystemBranding'
import '../i18n/appShellReference'
import '../i18n/themes'
import '../i18n/adminAccess'
import '../i18n/adminInbox'
import './AppShell.css'

const iconMap = {
  overview: 'overview',
  analytics: 'analytics',
  nodes: 'nodes',
  sites: 'sites',
  stream: 'stream',
  config: 'config',
  system: 'system',
  account: 'account',
  edge: 'edge',
  market: 'market',
} satisfies Record<NavIcon, string>

function menuIcon(icon?: NavIcon) {
  if (!icon) return undefined
  return <i className={`shell-nav-icon shell-nav-icon--${iconMap[icon]}`} aria-hidden="true" />
}

function toMenuItems(items: NavigationItem[], badges: Record<string, number> = {}): MenuProps['items'] {
  return items.map((item) => ({
    key: item.key,
    label: badges[item.key] ? (
      <span className="shell-nav-badge-label">
        {item.label}
        <Badge count={badges[item.key]} size="small" overflowCount={99} style={{ marginInlineStart: 6 }} />
      </span>
    ) : item.label,
    icon: menuIcon(item.icon),
    disabled: item.implemented === false,
    children: item.children ? toMenuItems(item.children, badges) : undefined,
  }))
}

function isMobileViewport() {
  return typeof window !== 'undefined' && window.matchMedia('(max-width: 767px)').matches
}

export function AppShell() {
  const principal = useSessionStore((state) => state.principal)
  const accessToken = useSessionStore((state) => state.accessToken)
  const navigate = useNavigate()
  const location = useLocation()
  const [collapsed, setCollapsed] = useState(false)
  const [mobile, setMobile] = useState(isMobileViewport)
  const [mobileOpen, setMobileOpen] = useState(false)
  const [themeMode, setThemeMode] = useState<'light' | 'dark'>(() => (
    window.localStorage.getItem('cdnca.ui.theme') === 'dark' ? 'dark' : 'light'
  ))
  const [openKeys, setOpenKeys] = useState<string[]>([])
  // PA-17 layout slots: sidebar variant, header links, footer text.
  const { layout } = useThemeRuntime()
  const darkSidebar = layout.sidebar === 'dark' && themeMode !== 'dark'
  // Dark mode paints the sidebar and header dark too: both want the dark-background logo.
  const brandSlot = darkSidebar || themeMode === 'dark' ? 'logo_dark' : 'logo'
  const feedback = useFeedback()
  const { t, i18n } = useTranslation(['common', 'navigation', 'appShellReference'])
  const locale = i18n.resolvedLanguage ?? 'zh-CN'
  // The active theme's name wins; the system settings name and
  // console title apply only when the theme sets none.
  const systemBranding = useSystemBranding(principal, accessToken)
  const themeBrandName = useThemeBrandName(locale)
  const brandName = useBrandName(locale, systemBranding?.systemName)
  const footerText = localizedText(layout.footer_text, locale)

  if (!principal) {
    throw new Error('Protected application shell requires an authenticated principal')
  }

  const role = roleForPrincipal(principal)
  const consoleTitle = themeBrandName || (role === 'admin' ? systemBranding?.adminTitle : systemBranding?.userTitle)?.trim() || ''
  useEffect(() => {
    if (consoleTitle) document.title = consoleTitle
  }, [consoleTitle])
  const pendingTickets = useTicketMenuBadge(principal, accessToken)
  const grantedModules = useGrantedModules(accessToken)
  const runtimeFeatures = useRuntimeFeatures(accessToken)
  const pluginPages = usePluginUIPages(accessToken)
  const pluginMenu = useMemo(() => pluginPages
    .filter((page) => page.mount === 'menu' && page.role === role && page.menu_parent)
    .map((page) => ({ parentKey: page.menu_parent as string, key: pluginPagePath(page), label: pluginPageTitle(page, locale) })),
  [locale, pluginPages, role])
  const menuItems = useMemo(
    () => toMenuItems(withPluginPages(getNavigation(role, t, principal.permissions, grantedModules, runtimeFeatures), pluginMenu),
      { [ticketMenuKey]: pendingTickets }),
    [grantedModules, pendingTickets, pluginMenu, principal.permissions, role, runtimeFeatures, t],
  )
  const breadcrumbLabels = useMemo(
    () => getBreadcrumbLabels(role, location.pathname, t),
    [location.pathname, role, t],
  )
  const currentBreadcrumb = breadcrumbLabels.at(-1) ?? ''
  const fullBreadcrumb = breadcrumbLabels.join('/')
  useEffect(() => {
    const parentKey = getParentNavigationKey(role, location.pathname)
    if (parentKey) {
      setOpenKeys((keys) => (keys.includes(parentKey) ? keys : [...keys, parentKey]))
    }
  }, [location.pathname, role])

  useEffect(() => {
    const media = window.matchMedia('(max-width: 767px)')
    const update = (event: MediaQueryListEvent) => {
      setMobile(event.matches)
      if (!event.matches) setMobileOpen(false)
    }
    media.addEventListener('change', update)
    return () => media.removeEventListener('change', update)
  }, [])

  useEffect(() => {
    if (!mobileOpen) return
    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      document.body.style.overflow = previousOverflow
    }
  }, [mobileOpen])

  useEffect(() => {
    const dark = themeMode === 'dark'
    document.body.classList.toggle('i-theme-dark', dark)
    document.documentElement.dataset.theme = themeMode
    document.documentElement.style.colorScheme = themeMode
    return () => {
      document.body.classList.remove('i-theme-dark')
      delete document.documentElement.dataset.theme
      document.documentElement.style.removeProperty('color-scheme')
    }
  }, [themeMode])

  const refreshMutation = useMutation({
    mutationFn: refreshSession,
    onError: () => feedback.error(t('common:sessionRefreshFailed')),
  })
  const refreshLabel = role === 'admin' ? t('appShellReference:refreshPage') : t('common:refreshSession')

  const onMenuClick: MenuProps['onClick'] = ({ key }) => {
    const pluginMenuPage = pluginPageRoute.test(key) && pluginMenu.some((page) => page.key === key)
    if (!pluginMenuPage && !isImplementedPath(role, key, principal.permissions, grantedModules, runtimeFeatures)) return
    if (!canLeaveCurrentPage()) return
    navigate(key)
    setMobileOpen(false)
  }

  // C02: who is signed in, on which side, with which roles (both sides; the
  // platform and tenant sessions can be open side by side in one browser).
  const roleNames = principal.roles.map((name) => t(`common:roleName.${name}`, { defaultValue: name })).join('、')
  const identityItem = {
    key: 'identity',
    disabled: true,
    label: (
      <span className="shell-account-identity">
        <strong>{principal.display_name || principal.username}</strong>
        <small>@{principal.username}</small>
        <small>{t(principal.scope_kind === 'platform' ? 'common:scopePlatform' : 'common:scopeTenant')}{roleNames ? ` · ${roleNames}` : ''}</small>
      </span>
    ),
  }
  const accountMenu: MenuProps = {
    items: [
      identityItem,
      { type: 'divider' as const },
      // fp-role ID-03：管理员没有账户中心侧栏，个人资料从账号菜单进入（用户端在侧栏）。
      ...(role === 'admin' && isImplementedPath(role, '/account/user', principal.permissions)
        ? [{ key: 'profile', label: t('navigation:profile'), icon: <UserRound size={14} aria-hidden="true" /> }] : []),
      ...(role === 'admin' && isImplementedPath(role, '/sys/setting', principal.permissions)
        ? [
          { key: 'settings', label: t('appShellReference:systemSettings'), icon: <i className="shell-account-icon shell-account-icon--settings" aria-hidden="true" /> },
          { type: 'divider' as const },
        ] : []),
      { key: 'logout', label: t('common:logout'), icon: role === 'admin'
        ? <i className="shell-account-icon shell-account-icon--logout" aria-hidden="true" />
        : <LogOut size={14} aria-hidden="true" /> },
    ],
    onClick: ({ key }) => {
      if (key === 'profile' && isImplementedPath(role, '/account/user', principal.permissions) && canLeaveCurrentPage()) {
        navigate('/account/user')
        setMobileOpen(false)
      }
      if (key === 'settings' && isImplementedPath(role, '/sys/setting', principal.permissions) && canLeaveCurrentPage()) {
        navigate('/sys/setting')
        setMobileOpen(false)
      }
      // Signing out is immediate: leave first, so the session
      // guard does not record this page as the return path, then clear.
      if (key === 'logout' && canLeaveCurrentPage()) {
        navigate('/login', { replace: true })
        void logoutSession()
      }
    },
  }

  const toggleNavigation = () => {
    if (mobile) setMobileOpen((open) => !open)
    else setCollapsed((value) => !value)
  }

  const goToOverview = () => {
    if (canLeaveCurrentPage()) navigate(homeForPrincipal(principal))
  }

  return (
    <div className={`app-shell${role === 'admin' ? ' is-admin' : ''}${collapsed ? ' is-collapsed' : ''}${themeMode === 'dark' ? ' is-dark' : ''}${darkSidebar ? ' is-sidebar-dark' : ''}`}>
      <PublicBrandFavicon />
      <aside className={`app-sidebar${mobileOpen ? ' is-mobile-open' : ''}`}>
        <button
          className="shell-brand"
          type="button"
          aria-label={t('common:returnOverview')}
          onClick={goToOverview}
        >
          <span className="shell-brand-crop">
            <PublicBrandAssetImage alt={brandName} slot={brandSlot} />
          </span>
        </button>
        <Menu
          className="shell-menu"
          theme={darkSidebar ? 'dark' : 'light'}
          mode="inline"
          inlineCollapsed={collapsed && !mobile}
          items={menuItems}
          selectedKeys={[getNavigationSelectionKey(role, location.pathname)]}
          openKeys={openKeys}
          onOpenChange={(keys) => setOpenKeys(keys)}
          onClick={onMenuClick}
        />
      </aside>
      {mobileOpen ? (
        <button
          className="mobile-scrim"
          type="button"
          aria-label={t('common:closeNavigation')}
          onClick={() => setMobileOpen(false)}
        />
      ) : null}
      <header className="app-header">
        <button
          className="mobile-header-brand"
          type="button"
          aria-label={t('common:returnOverview')}
          onClick={goToOverview}
        >
          <PublicBrandAssetImage alt={brandName} slot={themeMode === 'dark' ? 'logo_dark' : 'logo'} />
        </button>
        <Tooltip
          title={mobile
            ? t('common:openNavigation')
            : collapsed
              ? t('common:expandNavigation')
              : t('common:collapseNavigation')}
        >
          <button
            className="header-icon-button"
            type="button"
            aria-label={mobile
              ? t('common:openNavigation')
              : collapsed
                ? t('common:expandNavigation')
                : t('common:collapseNavigation')}
            onClick={toggleNavigation}
          >
            {collapsed && !mobile
              ? <IndentIncrease size={18} aria-hidden="true" />
              : <IndentDecrease size={18} aria-hidden="true" />}
          </button>
        </Tooltip>
        <Tooltip title={refreshLabel}>
          <button
            className="header-icon-button"
            type="button"
            aria-label={refreshLabel}
            disabled={role === 'user' && refreshMutation.isPending}
            onClick={() => {
              if (role === 'admin') {
                if (canLeaveCurrentPage()) navigate(0)
              } else refreshMutation.mutate()
            }}
          >
            <RotateCw
              className={role === 'user' && refreshMutation.isPending ? 'is-spinning' : undefined}
              size={17}
              aria-hidden="true"
            />
          </button>
        </Tooltip>
        {/* 顶部条只显示「页面标题」一级，没有面包屑。
            完整层级保留在无障碍文本里供屏幕阅读器使用。 */}
        <nav className="shell-breadcrumb" aria-label={t('common:breadcrumb')}>
          <span className="shell-breadcrumb-a11y visually-hidden">{fullBreadcrumb}</span>
          <span className="shell-breadcrumb-current" aria-hidden="true">{currentBreadcrumb}</span>
        </nav>
        {layout.header_links.length > 0 ? (
          <nav className="shell-header-links" aria-label={t('themes:shell.headerLinks')}>
            {layout.header_links.map((link) => (
              <a key={link.url} href={link.url} target="_blank" rel="noopener noreferrer">{localizedText(link.label, locale)}</a>
            ))}
          </nav>
        ) : null}
        {role === 'admin' && principal.scope_kind === 'platform' ? <AdminInboxBell accessToken={accessToken} /> : null}
        {role === 'user' ? <AdminInboxBell accessToken={accessToken} scope="account" /> : null}
        <button
          className="shell-theme-toggle"
          type="button"
          aria-label={t(themeMode === 'dark' ? 'common:switchToLightTheme' : 'common:switchToDarkTheme')}
          aria-pressed={themeMode === 'dark'}
          onClick={() => setThemeMode((value) => {
            const next = value === 'light' ? 'dark' : 'light'
            window.localStorage.setItem('cdnca.ui.theme', next)
            return next
          })}
        >
          <span className={`shell-theme-option${themeMode === 'light' ? ' is-active' : ''}`} aria-hidden="true">
            <Sun size={14} />
          </span>
          <span className={`shell-theme-option${themeMode === 'dark' ? ' is-active' : ''}`} aria-hidden="true">
            <Moon size={14} />
          </span>
        </button>
        <Dropdown
          menu={accountMenu}
          placement="bottomRight"
          trigger={['click']}
          overlayClassName={role === 'admin' ? 'shell-account-menu' : undefined}
          align={role === 'admin' ? { offset: [9, 18] } : undefined}
        >
          <Tooltip title={role === 'admin' ? undefined : t('common:account')}>
            <button className="account-trigger" type="button" aria-label={t('common:accountMenu')}>
              <span className="account-avatar" aria-hidden="true">
                <UserRound size={18} strokeWidth={1.6} />
              </span>
            </button>
          </Tooltip>
        </Dropdown>
      </header>
      <main className="app-main">
        <Outlet />
        {footerText ? <footer className="app-footer">{footerText}</footer> : null}
      </main>
      <AnnouncementPopup />
      <GlobalScript />
    </div>
  )
}
