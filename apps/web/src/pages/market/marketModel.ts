import type { MarketLibraryItem, MarketLicense, MarketPlugin, MarketPricePlan } from '../../api/market'
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
//                Taking the licence is not a download (F1, PLUG-USE 10-27): no 去启用 before it is here;
//   enable       installed here, the administrator enables it where the plugin kind is managed;
//   installed    an enabled installation: installed and usable. For a theme or rule pack this is not proof that a
//                slot or site applies it (that lives on its own page), so it never reads as 使用中;
//   enabled      the lease grants the official feature code (the function itself is on);
//   activating   official entry licensed, the lease has not picked the feature code up yet;
//   revoked      held here before but the licence ended or moved to another controller (授权失效).
export type StoreState = 'purchase' | 'distributing' | 'enable' | 'installed' | 'enabled' | 'activating' | 'revoked'

export function storeState(plugin: MarketPlugin, licenses: MarketLicense[], library: MarketLibraryItem[],
  modules: string[]): StoreState {
  const licensed = !!liveLicense(licenses, plugin.plugin_id)
  const local = library.find((item) => item.plugin_id === plugin.plugin_id)
  if (!licensed) return local && (local.installed || local.withdrawn) ? 'revoked' : 'purchase'
  if (plugin.feature_code) return modules.includes(plugin.feature_code) ? 'enabled' : 'activating'
  if (local?.enabled) return 'installed'
  if (local?.installed) return 'enable'
  return 'distributing'
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
// (ui_page), the menu entry gated by its feature code, or the page of its kind. Null when it has none.
export function configPath(plugin: Pick<MarketPlugin, 'plugin_id' | 'kind' | 'applies_to' | 'feature_code'>,
  uiPages: readonly Pick<PluginUIPage, 'plugin_id' | 'page_id' | 'mount' | 'role'>[]): string | null {
  const page = uiPages.find((p) => p.plugin_id === plugin.plugin_id && p.mount === 'menu' && p.role === 'admin')
  if (page) return pluginPagePath(page)
  const code = plugin.feature_code
  return (code ? moduleRoutePath('admin', code) ?? featurePages[code] : undefined) ?? enablePath(plugin)
}

export type OwnedState = Exclude<StoreState, 'purchase'> | 'pendingConfirm'

export interface OwnedRow { pluginID: string; plugin?: MarketPlugin; state: OwnedState; path: string | null }

// ownedRows: every plugin this controller holds (a live licence) or held (a local installation whose licence
// ended), in licence order. The state is the same server-derived one the Browse cards show; a theme or rule
// pack still on its way waits for the controller administrator (the installation records below).
export function ownedRows(licenses: MarketLicense[], library: MarketLibraryItem[], modules: string[],
  catalog: Map<string, MarketPlugin>, path: (plugin: MarketPlugin) => string | null): OwnedRow[] {
  const ids = [...new Set([
    ...licenses.filter((l) => liveLicense([l], l.plugin_id)).map((l) => l.plugin_id),
    ...library.filter((item) => item.installed || item.withdrawn).map((item) => item.plugin_id),
  ])]
  return ids.map((pluginID) => {
    const plugin = catalog.get(pluginID)
    const subject = plugin ?? { plugin_id: pluginID, kind: 'module', feature_code: null } as unknown as MarketPlugin
    const state = storeState(subject, licenses, library, modules)
    const platform = subject.kind === 'theme' || subject.kind === 'rule_pack'
    return {
      pluginID, plugin, state: state === 'distributing' && platform ? 'pendingConfirm' : state as OwnedState,
      // 去配置只给已在本机可用的：授权生效中、同步中、待确认安装时对应页面还进不去。
      path: plugin && (state === 'enabled' || state === 'installed' || state === 'enable') ? path(plugin) : null,
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
