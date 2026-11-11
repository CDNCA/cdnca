import type { MarketLibraryItem, MarketLicense, MarketPlugin, MarketPricePlan } from '../../api/market'
import type { PluginInstallation } from '../../api/pluginInstallations'
import type { PluginUIPage } from '../../api/pluginUI'
import { pluginPagePath } from '../../pluginui/usePluginUIPages'
import { moduleRoutePath } from '../../routes/navigation'
import type { TFunction } from 'i18next'

import { activePlans, formatMinor } from '../plugin-market/pluginStoreModel'

export type PublisherKind = 'official' | 'certified' | 'third_party'

// A plugin the market does not label is a third party (market 027 derives it from the seller).
export function publisherOf(plugin: Pick<MarketPlugin, 'publisher_kind'>): PublisherKind {
  return plugin.publisher_kind === 'official' || plugin.publisher_kind === 'certified' ? plugin.publisher_kind : 'third_party'
}

const liveLicenseStates = new Set(['trialing', 'active', 'past_due'])

export function liveLicense(licenses: MarketLicense[], pluginID: string): MarketLicense | undefined {
  return licenses.find((l) => l.plugin_id === pluginID && liveLicenseStates.has(l.status))
}

// Cheapest plan on sale; a free plan wins. Null when nothing is on sale.
export function headlinePlan(plans: MarketPricePlan[] | undefined): MarketPricePlan | null {
  const onSale = activePlans(plans ?? [])
  if (!onSale.length) return null
  return onSale.find((p) => p.kind === 'free') ?? [...onSale].sort((a, b) => a.price_minor - b.price_minor)[0]
}

// The store button follows 获取/购买 → 同步 → 启用 (ADR 0007 §8.5), only from server facts:
//   purchase     no live licence of this controller (a free plan shows 获取);
//   distributing licensed, this controller has no installation of it yet: the licence still
//                travels market → license service (verification, authorization) → artifact sync.
//                Taking the licence is not a download (F1, PLUG-USE 10-27): nothing to use before it is here;
//   installed    an enabled installation: installed and usable. For a theme or rule pack this is not proof that a
//                slot or site applies it (that lives on its own page), so it never reads as 使用中;
//   enabled      the lease grants the official feature code (the function itself is on);
//   activating   official entry licensed, the lease has not picked the feature code up yet;
//   revoked      held here before but the licence ended or moved to another controller (授权失效).
//   disabled     stopped on this controller (停用, can be enabled again): an official feature plugin through the local stop
//                list (library locally_disabled), an installable one paused here or by the platform. The
//                library says that much to every session: installed && !enabled is a controller whose installations are
//                all paused, since an installation head is enabled, disabled or uninstalled; the
//                platform record (plugin_installations.platform.read) only adds who paused it.
export type StoreState = 'purchase' | 'distributing' | 'installed' | 'enabled' | 'activating' | 'revoked' | 'disabled'

// Kinds that only work once the controller's platform administrator confirmed an installation (user
// 11-05): themes and rule packs for the controller, page plugins and external services for the tenants chosen.
const installableKinds = new Set(['theme', 'rule_pack', 'ui_page', 'provider', 'external_service'])
// Of those, a feature code never stands in for the installation: a page plugin such as CF 优选 carries one that the
// default package already grants, yet nothing is usable before it is installed.
const installFirstKinds = new Set(['ui_page', 'provider', 'external_service'])

/** The platform administrator confirms its installation under 我的插件 (tenants never do). */
export function needsInstallConfirm(plugin: Pick<MarketPlugin, 'kind'>): boolean {
  return installableKinds.has(plugin.kind)
}

export function storeState(plugin: MarketPlugin, licenses: MarketLicense[], library: MarketLibraryItem[],
  modules: string[], installation?: Pick<PluginInstallation, 'status'>): StoreState {
  const licensed = !!liveLicense(licenses, plugin.plugin_id)
  const local = library.find((item) => item.plugin_id === plugin.plugin_id)
  if (!licensed) return local && (local.installed || local.withdrawn) ? 'revoked' : 'purchase'
  if (local?.locally_disabled) return 'disabled'
  if (installation?.status === 'disabled') return 'disabled'
  if (plugin.feature_code && !installFirstKinds.has(plugin.kind)) return modules.includes(plugin.feature_code) ? 'enabled' : 'activating'
  if (local?.enabled) return 'installed'
  if (local?.installed) return 'disabled'
  return 'distributing'
}

/**
 * After an acquisition, does the plugin still wait for the controller administrator's installation? Feature plugins
 * (official module.* / pack.* codes) are active once the lease follows; everything that is installed is pending.
 */
export function acquiredPendingInstall(plugin: Pick<MarketPlugin, 'kind' | 'feature_code'>): boolean {
  return installFirstKinds.has(plugin.kind) || (installableKinds.has(plugin.kind) && !plugin.feature_code)
}

/** Settled: nothing changes without a person (or a purchase) any more, so polling after an acquisition can stop. */
export function settledState(state: StoreState): boolean {
  return state !== 'activating' && state !== 'purchase'
}

// Where an administrator enables an installed plugin, by kind; null: installed by the platform administrator in My plugins.
// The community edition has no theme management page (default theme only), so a theme has none.
export function enablePath(plugin: Pick<MarketPlugin, 'kind' | 'applies_to'>): string | null {
  switch (plugin.kind) {
    case 'rule_pack': return '/site/rule-packs'
    case 'theme': return null
    case 'provider': return '/sys/plugin-providers'
    default: return null
  }
}

// Official feature codes whose function has no menu entry of its own: the page where it is switched on.
const featurePages: Record<string, string> = {
  // CRS 档位在 WAF 规则的托管 WAF 动作里选；高级 CC 规则组由站点 CC 规则引用。
  'pack.crs': '/site/waf-rule',
  'pack.cc.advanced': '/site/cc-rule',
}

// Where an administrator configures a plugin this controller owns (我的插件 去配置): its own admin menu page
// (ui_page), else its plugin_settings page (same /plugin-ui route, no menu item), the menu entry gated by its feature
// code, or the page of its kind. Null when it has none.
export function configPath(plugin: Pick<MarketPlugin, 'plugin_id' | 'kind' | 'applies_to' | 'feature_code'>,
  uiPages: readonly Pick<PluginUIPage, 'plugin_id' | 'page_id' | 'mount' | 'role'>[]): string | null {
  const page = uiPages.find((p) => p.plugin_id === plugin.plugin_id && p.mount === 'menu' && p.role === 'admin') ??
    uiPages.find((p) => p.plugin_id === plugin.plugin_id && p.mount === 'plugin_settings' && p.role === 'admin')
  if (page) return pluginPagePath(page)
  const code = plugin.feature_code
  return (code ? moduleRoutePath('admin', code) ?? featurePages[code] : undefined) ?? enablePath(plugin)
}

// The platform installation record a card or row acts on: the installed (enabled/disabled) one first, otherwise any
// record not uninstalled. Platform records only (/v1/platform/plugin-installations), which this controller's
// administrator disables and resumes.
export function installationOf(items: readonly PluginInstallation[], pluginID: string): PluginInstallation | undefined {
  const current = items.filter((item) => item.plugin_id === pluginID && item.status !== 'uninstalled')
  return current.find((item) => item.status === 'enabled' || item.status === 'disabled') ?? current[0]
}

// Paused by this controller (停用): the same record can be resumed here. A platform pause cannot (resume answers 409).
export function resumable(installation: Pick<PluginInstallation, 'status' | 'authorization_status' | 'paused_by'>): boolean {
  return installation.status === 'disabled' && installation.authorization_status === 'disabled' &&
    installation.paused_by === 'installation'
}

// A feature plugin the lease switches on is stopped on this controller through the local stop list (停用 / 重新启用):
// every plugin with an official feature code except the install-first kinds, which pause their installation
// record instead.
export function localSwitchable(plugin: Pick<MarketPlugin, 'kind' | 'feature_code'>): boolean {
  return Boolean(plugin.feature_code) && !installFirstKinds.has(plugin.kind)
}

// Codes that only work while another one does (control-api): automatic mitigation and attack auto-escalation act on
// 智能自动防御's verdicts (autodefense_runtime.go grants: no module.autodefense sends the empty snapshot;
// escalate/worker.go reads autodefense_site_node_states).
const featureNeeds: Record<string, string> = {
  'module.autodefense.auto': 'module.autodefense',
  'module.escalate': 'module.autodefense',
}

// The plugins still on here that stop working with featureCode (the stop confirmation lists them; their own state is
// left as it is).
export function dependentsOf<T extends Pick<MarketPlugin, 'feature_code'>>(featureCode: string, plugins: readonly T[],
  modules: readonly string[]): T[] {
  return plugins.filter((p) => p.feature_code && featureNeeds[p.feature_code] === featureCode && modules.includes(p.feature_code))
}

// Setup a feature still needs, only where this console already reads it: dnspup 拨测 is active once enabled with a
// key pair (control-api dnspupprobe: Active = licensed && enabled && secret_configured && not paused), so no secret
// is 未配置 and enabled=false is 已关闭. Every other feature: unknown here, null (the card links without a mark).
export function moduleSetup(featureCode: string, dnspup: { enabled: boolean; secret_configured: boolean } | undefined):
  'unconfigured' | 'off' | null {
  if (featureCode !== 'module.probe.dnspup' || !dnspup) return null
  if (!dnspup.secret_configured) return 'unconfigured'
  return dnspup.enabled ? null : 'off'
}

// What an installable plugin that is licensed here but has no local installation yet waits for. Only from data the
// console already reads:
//   noVersion      the market entry has no latest_version: the market lists only published versions there
//                  (market-service plugin.go, status = 'published'), so there is nothing to install yet;
//   pendingConfirm a platform installation record of it exists: the controller administrator confirms it below;
//   awaitingSync   anything else: a version exists but no record arrived yet (license catalog still syncing, or the
//                  license catalog lacks it; the console cannot tell these apart), or the records cannot be read here.
export type InstallWait = 'noVersion' | 'pendingConfirm' | 'awaitingSync'
export function installWait(pluginID: string, plugin: Pick<MarketPlugin, 'latest_version'> | undefined,
  installations: readonly PluginInstallation[] | undefined): InstallWait {
  if (plugin && !plugin.latest_version) return 'noVersion'
  return installations && installationOf(installations, pluginID) ? 'pendingConfirm' : 'awaitingSync'
}

export type OwnedState = Exclude<StoreState, 'purchase'> | InstallWait

export interface OwnedRow {
  pluginID: string; plugin?: MarketPlugin; state: OwnedState; path: string | null; installation?: PluginInstallation
}

// ownedRows: every plugin this controller holds (a live licence) or held (a local installation whose licence
// ended), in licence order. The state is the same server-derived one the Browse cards show; an installable plugin
// still on its way says what it waits for (installWait). installations: the platform records, undefined when this
// session cannot read them.
export function ownedRows(licenses: MarketLicense[], library: MarketLibraryItem[], modules: string[],
  catalog: Map<string, MarketPlugin>, path: (plugin: MarketPlugin) => string | null,
  installations?: readonly PluginInstallation[]): OwnedRow[] {
  const ids = [...new Set([
    ...licenses.filter((l) => liveLicense([l], l.plugin_id)).map((l) => l.plugin_id),
    ...library.filter((item) => item.installed || item.withdrawn).map((item) => item.plugin_id),
  ])]
  return ids.map((pluginID) => {
    const plugin = catalog.get(pluginID)
    const subject = plugin ?? { plugin_id: pluginID, kind: 'module', feature_code: null } as unknown as MarketPlugin
    const installation = installationOf(installations ?? [], pluginID)
    const state = storeState(subject, licenses, library, modules, installation)
    return {
      pluginID, plugin,
      state: state === 'distributing' && needsInstallConfirm(subject) ? installWait(pluginID, plugin, installations) : state as OwnedState,
      // 去配置只给已在本机可用的：授权生效中、同步中、待确认安装、已停用时对应页面还进不去。
      path: plugin && (state === 'enabled' || state === 'installed') ? path(plugin) : null,
      installation,
    }
  })
}

export function planPrice(t: TFunction, plan: MarketPricePlan): string {
  if (plan.kind === 'free' && plan.promo_until && plan.promo_then_kind && plan.promo_then_price_minor) {
    // 限免: "限免至 … ，到期后 ¥9.90/月" (the badge counts down; this names the date and the price).
    const then = planPrice(t, { ...plan, kind: plan.promo_then_kind, interval: plan.promo_then_interval ?? null,
      price_minor: plan.promo_then_price_minor, promo_until: null })
    return t('price.promo', { until: new Date(plan.promo_until).toLocaleString(), then })
  }
  if (plan.kind === 'free') return t('price.free')
  const price = formatMinor(plan.price_minor, plan.currency)
  if (plan.kind === 'subscription') return t(plan.interval === 'year' ? 'price.year' : 'price.month', { price })
  return t('price.one_time', { price })
}
