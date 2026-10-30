// 外壳级后台请求与被拦截的页面无关：租户外壳的公告弹窗只读自己的未读公告（2026-09-25）、
// 全站JS 读公开系统设置（NF26，components/GlobalScript.tsx）；管理端外壳的工单菜单角标读待处理数
// （components/useTicketMenuBadge.ts）；两端外壳菜单读本地租约授予的模块（PA-15，
// components/useGrantedModules.ts）；两端外壳菜单读可见的 ui_page 插件页（PA-19，
// pluginui/usePluginUIPages.ts）；两端外壳菜单读已挂载的可选运行时（components/useRuntimeFeatures.ts）；平台管理端与租户外壳的消息中心铃铛读未读数（components/AdminInboxBell.tsx）；
// 两端外壳的授权锁定横幅读锁定状态（ADR 0014 LIC-BAN-06，components/InstallationLockBanner.tsx）。
// 平台管理端外壳读系统配置的系统名称与后台标题，租户外壳读公开品牌接口（fix-ui1026 #4 / L6，components/useSystemBranding.ts）。
// 路由守卫测试只排除这些，被拦截页面自身的请求一律不允许。
export const shellBackgroundRequests: ReadonlySet<string> = new Set([
  // 公告弹窗按服务端「未读且需弹窗」读取（filter=popup，d1dded72c）。
  '/v1/account/messages?filter=popup&limit=100',
  '/v1/system-settings/public',
  '/v1/admin/tickets/summary',
  '/v1/admin/inbox/unread-count',
  '/v1/account/inbox/unread-count',
  '/v1/modules',
  '/v1/runtime-features',
  '/v1/plugin-ui/pages',
  '/v1/installation-lock',
  '/v1/admin/system-settings',
])

export function pageRequests(fetchSpy: { mock: { calls: unknown[][] } }): string[] {
  return fetchSpy.mock.calls.map(([url]) => String(url)).filter((url) => !shellBackgroundRequests.has(url))
}
