import { forwardRef, useEffect, useId, useMemo, useRef, useState, type ButtonHTMLAttributes, type ReactNode } from 'react'
import { useMutation } from '@tanstack/react-query'
import { Badge, Dropdown, Menu, Tooltip, type MenuProps } from 'antd'
import { useFeedback } from '@cdnca/ui'
import { IndentDecrease, IndentIncrease, LogOut, Moon, RotateCw, Sun, UserRound } from 'lucide-react'
import { Link, Outlet, useLocation, useNavigate } from 'react-router-dom'
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
  getNavigationTrail,
  getNavigationSelectionKey,
  getOpenNavigationKeys,
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
import '../i18n/tenantMembers'
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

// 分组展开箭头画的是图标字体字符 U+F116（styles.css .ant-menu-submenu-arrow::before），
// 默认箭头元素没有 aria-hidden，Chrome 把它并进分组名。沿用同一 class 保持外观与旋转动画，只对辅助技术隐藏。
function SubmenuArrow() {
  return <i className="ant-menu-submenu-arrow" aria-hidden="true" />
}

// 抽屉内第一个可 Tab 到的元素（品牌按钮或菜单容器）；最后一个固定是抽屉外的关闭按钮（遮罩）。
const drawerTabbable = 'a[href]:not([tabindex="-1"]), button:not([disabled]), input:not([disabled]), [tabindex]:not([tabindex="-1"])'

// 页面菜单项放真实链接（href 含 basename），可在新标签打开。带 Ctrl/⌘/Shift/Alt 的点击与回车交给浏览器，
// 不冒泡到 Menu、不做离开检查；普通点击不让 Link 自己跳，冒泡给 Menu 的 onClick 走离开检查与 navigate。
// 回车只走链接的原生 click 这一条路，避免 rc-menu 的 Enter 处理再导航一次。tabIndex -1 保持菜单的方向键焦点模型。
function MenuLink({ to, label, children }: { to: string; label?: string; children: ReactNode }) {
  return (
    <Link
      to={to}
      aria-label={label}
      tabIndex={-1}
      onClick={(event) => {
        if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || event.button !== 0) event.stopPropagation()
        else event.preventDefault()
      }}
      onKeyDown={(event) => {
        if (event.key === 'Enter') event.stopPropagation()
      }}
    >
      {children}
    </Link>
  )
}

function toMenuItems(items: NavigationItem[], badges: Record<string, number> = {}): MenuProps['items'] {
  return items.map((item) => {
    const label = badges[item.key] ? (
      <span className="shell-nav-badge-label">
        {item.label}
        <Badge count={badges[item.key]} size="small" overflowCount={99} style={{ marginInlineStart: 6 }} />
      </span>
    ) : item.label
    const page = !item.children && item.implemented !== false && item.key.startsWith('/')
    return {
      key: item.key,
      label: page ? <MenuLink to={item.key} label={item.accessibleLabel}>{label}</MenuLink> : label,
      'aria-label': item.accessibleLabel,
      icon: menuIcon(item.icon),
      disabled: item.implemented === false,
      children: item.children ? toMenuItems(item.children, badges) : undefined,
    }
  })
}

/**
 * an icon button whose Tooltip repeats its accessible name. The
 * Tooltip always points aria-describedby at its text; dropped here so a screen
 * reader does not read the name twice (the Tooltip stays visible).
 */
const NamedIconButton = forwardRef<HTMLButtonElement, ButtonHTMLAttributes<HTMLButtonElement>>(
  function NamedIconButton(props, ref) {
    return <button ref={ref} type="button" {...props} aria-describedby={undefined} />
  },
)

const noKeys: string[] = []
const myPluginsPath = '/sys/plugin-store?tab=mine'

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
  const sidebarId = useId()
  // rc-menu 用 id 拼 data-menu-id 与子列表 id，固定下来才能找到刚展开的分组。
  const menuId = `${sidebarId}menu`
  const navigationToggleRef = useRef<HTMLButtonElement>(null)
  const sidebarRef = useRef<HTMLElement>(null)
  const scrimRef = useRef<HTMLButtonElement>(null)
  const wasMobileOpen = useRef(false)
  const [themeMode, setThemeMode] = useState<'light' | 'dark'>(() => (
    window.localStorage.getItem('cdnca.ui.theme') === 'dark' ? 'dark' : 'light'
  ))
  const [manualOpenKeys, setManualOpenKeys] = useState<{ key: string; keys: string[] }>({ key: '', keys: [] })
  const [routeClosedKeys, setRouteClosedKeys] = useState<{ path: string; keys: string[] }>({ path: '', keys: [] })
  // 折叠（图标）模式的弹出层开合单独管理。antd 进折叠模式时会回调 onOpenChange([])，
  // 弹出层开合也走同一回调；两者都不得改写宽侧栏展开的分组和按角色保存的偏好。
  const [popupOpenKeys, setPopupOpenKeys] = useState<string[]>([])
  // PA-17 layout slots: sidebar variant, header links, footer text.
  const { layout } = useThemeRuntime()
  const darkSidebar = layout.sidebar === 'dark' && themeMode !== 'dark'
  // layout_slots.header = dark: the top bar takes the dark sidebar's color (one frame).
  const darkHeader = darkSidebar && layout.header === 'dark'
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
  const navigation = useMemo(
    () => withPluginPages(getNavigation(role, t, principal.permissions, grantedModules, runtimeFeatures), pluginMenu),
    [grantedModules, pluginMenu, principal.permissions, role, runtimeFeatures, t],
  )
  const menuItems = useMemo(
    () => toMenuItems(navigation, { [ticketMenuKey]: pendingTickets }),
    [navigation, pendingTickets],
  )
  // 插件设置页（plugin_settings）不进侧栏；可用时当前项取清单里的本地化页名，上一级是插件商店的
  // 「我的插件」（管理员看不到插件商店时只留页名），侧栏高亮插件商店。
  const settingsPage = useMemo(() => (pluginPageRoute.test(location.pathname)
    ? pluginPages.find((page) => page.mount === 'plugin_settings' && page.role === role && pluginPagePath(page) === location.pathname)
    : undefined), [location.pathname, pluginPages, role])
  const storeTrail = useMemo(() => (settingsPage ? getNavigationTrail(navigation, '/sys/plugin-store') : undefined),
    [navigation, settingsPage])
  // 插件菜单页不在静态路由表里，标题与展开祖先从组装好的菜单树（已按角色过滤、含真实挂载点）里查。
  const pluginTrail = useMemo(() => {
    if (!pluginPageRoute.test(location.pathname)) return undefined
    const menuTrail = getNavigationTrail(navigation, location.pathname)
    if (menuTrail || !settingsPage) return menuTrail
    const current = { key: location.pathname, label: pluginPageTitle(settingsPage, locale) }
    return storeTrail ? [...storeTrail, { key: myPluginsPath, label: t('pluginUI:myPlugins') }, current] : [current]
  }, [locale, location.pathname, navigation, settingsPage, storeTrail, t])
  const breadcrumbLabels = useMemo(
    () => (pluginTrail
      ? [t('navigation:home'), ...pluginTrail.map((item) => item.label)]
      : getBreadcrumbLabels(role, location.pathname, t)),
    [location.pathname, pluginTrail, role, t],
  )
  const routeAncestors = useMemo(
    // Only groups open (a settings page's trail also holds the 插件商店 and 我的插件 pages).
    () => (pluginTrail ? pluginTrail.slice(0, -1).map((item) => item.key).filter((key) => !key.startsWith('/'))
      : getOpenNavigationKeys(role, location.pathname)),
    [location.pathname, pluginTrail, role],
  )
  const currentBreadcrumb = breadcrumbLabels.at(-1) ?? ''
  const fullBreadcrumb = breadcrumbLabels.join('/')
  // 按角色只记用户手动开合的分组；当前页的父组临时展开，离开该页即释放，不写进偏好。
  // 旧键 cdnca.ui.menu-open.<role> 混进过自动展开的分组，不再读取也不删除：v2 没值或显式为 [] 时都保持全收拢，
  // 不回退旧键，否则刷新后看到的仍是被污染的那几组。
  // 偏好按账号存（角色 + 作用域 + 用户 ID），同一浏览器换账号不继承上一个账号的展开；
  // 只按角色存的 v2 键没有归属，不读不删。换键时在同一次渲染里换成新账号的值，不会先画出上一个账号的分组。
  const openKeysStorageKey = `cdnca.ui.menu-open.${role}.${principal.scope_id}.${principal.user_id}.v3`
  if (manualOpenKeys.key !== openKeysStorageKey) {
    let saved: string[] = []
    try {
      const parsed: unknown = JSON.parse(window.localStorage.getItem(openKeysStorageKey) ?? '[]')
      if (Array.isArray(parsed)) saved = parsed.filter((key): key is string => typeof key === 'string')
    } catch {
      saved = []
    }
    setManualOpenKeys({ key: openKeysStorageKey, keys: saved })
  }
  const manualKeys = manualOpenKeys.key === openKeysStorageKey ? manualOpenKeys.keys : noKeys
  // 当前页里被用户手动关上的父组：在这一页保持关闭；地址一变（含浏览器后退）就释放，再进相关深链时父链完整打开。
  if (routeClosedKeys.path !== location.pathname) setRouteClosedKeys({ path: location.pathname, keys: noKeys })
  const closedHere = routeClosedKeys.path === location.pathname ? routeClosedKeys.keys : noKeys
  const openKeys = useMemo(
    () => [...new Set([...manualKeys, ...routeAncestors.filter((key) => !closedHere.includes(key))])],
    [closedHere, manualKeys, routeAncestors],
  )
  const onInlineOpenChange = (keys: string[]) => {
    const opened = keys.filter((key) => !openKeys.includes(key))
    const closed = openKeys.filter((key) => !keys.includes(key))
    if (opened.length === 0 && closed.length === 0) return
    const nextManual = [...manualKeys.filter((key) => !closed.includes(key)), ...opened.filter((key) => !manualKeys.includes(key))]
    setManualOpenKeys({ key: openKeysStorageKey, keys: nextManual })
    try {
      window.localStorage.setItem(openKeysStorageKey, JSON.stringify(nextManual))
    } catch {
      // storage unavailable: the menu still works, it just forgets
    }
    setRouteClosedKeys({
      path: location.pathname,
      keys: [...closedHere.filter((key) => !opened.includes(key)), ...closed.filter((key) => routeAncestors.includes(key))],
    })
    const revealed = opened.at(-1)
    if (revealed) revealOpenedGroup(revealed)
  }

  // 用户点开的分组在展开动画结束后，只滚菜单容器、按最小位移露出组标题和尽量多的直接子项。
  const cancelReveal = useRef<() => void>(undefined)
  useEffect(() => () => cancelReveal.current?.(), [])
  const revealOpenedGroup = (key: string) => {
    cancelReveal.current?.()
    const menu = sidebarRef.current?.querySelector<HTMLElement>('.shell-menu')
    if (!menu) return
    const titleId = `${menuId}-${key}`
    const listId = `${titleId}-popup`
    const finish = () => {
      stop()
      const title = [...menu.querySelectorAll<HTMLElement>('[data-menu-id]')].find((node) => node.getAttribute('data-menu-id') === titleId)
      const list = document.getElementById(listId)
      if (!title || !list || title.getAttribute('aria-expanded') !== 'true') return
      const view = menu.getBoundingClientRect()
      const viewTop = view.top + menu.clientTop
      const viewBottom = viewTop + menu.clientHeight
      const top = title.getBoundingClientRect().top
      let bottom = title.getBoundingClientRect().bottom
      for (const item of list.children) {
        const itemBottom = item.getBoundingClientRect().bottom
        if (itemBottom - top > menu.clientHeight) break
        bottom = itemBottom
      }
      const delta = top < viewTop ? top - viewTop : Math.max(0, bottom - viewBottom)
      if (delta !== 0) menu.scrollTop += delta
    }
    // antd 折叠动画以子列表 height 的 transitionend 结束（motionDeadline 500ms 兜底）；没有过渡时同样由兜底计时器收尾。
    // 减少动态效果时不播展开动画，子列表下一帧就已就位，直接在下一帧滚动，不等兜底。
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    const onTransitionEnd = (event: TransitionEvent) => {
      if (event.propertyName === 'height' && (event.target as HTMLElement | null)?.id === listId) finish()
    }
    const frame = reduced ? window.requestAnimationFrame(finish) : undefined
    const timer = reduced ? undefined : window.setTimeout(finish, 520)
    const stop = () => {
      if (frame !== undefined) window.cancelAnimationFrame(frame)
      window.clearTimeout(timer)
      menu.removeEventListener('transitionend', onTransitionEnd)
      cancelReveal.current = undefined
    }
    if (!reduced) menu.addEventListener('transitionend', onTransitionEnd)
    cancelReveal.current = stop
  }

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

  // 移动抽屉关闭后把焦点还给导航开关；切到桌面宽度时不抢焦点。
  useEffect(() => {
    if (wasMobileOpen.current && !mobileOpen && mobile) navigationToggleRef.current?.focus()
    wasMobileOpen.current = mobileOpen
  }, [mobile, mobileOpen])

  // 移动抽屉打开后焦点送进抽屉（当前菜单项，没有就送到关闭按钮），Tab/Shift+Tab 只在抽屉与关闭按钮之间轮转，
  // Escape 关闭（焦点由上面的效果还给开关）；顶栏与正文同时 inert。变宽到桌面时 mobileOpen 复位，限制随之解除。
  const drawerOpen = mobile && mobileOpen
  const menuCollapsed = collapsed && !mobile
  useEffect(() => {
    const sidebar = sidebarRef.current
    const scrim = scrimRef.current
    if (!drawerOpen || !sidebar || !scrim) return
    ;(sidebar.querySelector<HTMLElement>('.ant-menu-item-selected') ?? scrim).focus()
    const onKeyDown = (event: KeyboardEvent) => {
      const active = document.activeElement
      // 焦点在抽屉外（例如盖在上面的弹窗）时不接管按键。
      if (active !== document.body && !sidebar.contains(active) && active !== scrim) return
      if (event.key === 'Escape') {
        event.preventDefault()
        setMobileOpen(false)
        return
      }
      if (event.key !== 'Tab') return
      const first = sidebar.querySelector<HTMLElement>(drawerTabbable) ?? scrim
      if (active === document.body || active === (event.shiftKey ? first : scrim)) {
        event.preventDefault()
        ;(event.shiftKey ? scrim : first).focus()
      }
    }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [drawerOpen])

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
    <div className={`app-shell${role === 'admin' ? ' is-admin' : ''}${collapsed ? ' is-collapsed' : ''}${themeMode === 'dark' ? ' is-dark' : ''}${darkSidebar ? ' is-sidebar-dark' : ''}${darkHeader ? ' is-header-dark' : ''}`}>
      <PublicBrandFavicon />
      <aside
        id={sidebarId}
        ref={sidebarRef}
        className={`app-sidebar${mobileOpen ? ' is-mobile-open' : ''}`}
        inert={mobile && !mobileOpen}
      >
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
          id={menuId}
          className="shell-menu"
          theme={darkSidebar ? 'dark' : 'light'}
          mode="inline"
          inlineCollapsed={menuCollapsed}
          expandIcon={SubmenuArrow}
          items={menuItems}
          selectedKeys={[storeTrail ? '/sys/plugin-store' : getNavigationSelectionKey(role, location.pathname)]}
          openKeys={menuCollapsed ? popupOpenKeys : openKeys}
          onOpenChange={(keys) => (menuCollapsed ? setPopupOpenKeys(keys) : onInlineOpenChange(keys))}
          onClick={onMenuClick}
        />
      </aside>
      {mobileOpen ? (
        <button
          ref={scrimRef}
          className="mobile-scrim"
          type="button"
          aria-label={t('common:closeNavigation')}
          onClick={() => setMobileOpen(false)}
        />
      ) : null}
      <header className="app-header" inert={drawerOpen}>
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
          <NamedIconButton
            className="header-icon-button"
            aria-label={mobile
              ? t('common:openNavigation')
              : collapsed
                ? t('common:expandNavigation')
                : t('common:collapseNavigation')}
            aria-expanded={mobile ? mobileOpen : !collapsed}
            aria-controls={sidebarId}
            ref={navigationToggleRef}
            onClick={toggleNavigation}
          >
            {collapsed && !mobile
              ? <IndentIncrease size={18} aria-hidden="true" />
              : <IndentDecrease size={18} aria-hidden="true" />}
          </NamedIconButton>
        </Tooltip>
        <Tooltip title={refreshLabel}>
          <NamedIconButton
            className="header-icon-button"
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
          </NamedIconButton>
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
      <main className="app-main" inert={drawerOpen}>
        <Outlet />
        {footerText ? <footer className="app-footer">{footerText}</footer> : null}
      </main>
      <AnnouncementPopup />
      <GlobalScript />
    </div>
  )
}
