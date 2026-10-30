import type { MarketLibraryItem, MarketLicense, MarketPlugin, MarketPricePlan } from '../../api/market'
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
//   enabled      in use (an enabled installation, or the lease grants the official feature code);
//   activating   official entry licensed, the lease has not picked the feature code up yet;
//   revoked      held here before but the licence ended or moved to another controller (授权失效).
export type StoreState = 'purchase' | 'distributing' | 'enable' | 'enabled' | 'activating' | 'revoked'

export function storeState(plugin: MarketPlugin, licenses: MarketLicense[], library: MarketLibraryItem[],
  modules: string[]): StoreState {
  const licensed = !!liveLicense(licenses, plugin.plugin_id)
  const local = library.find((item) => item.plugin_id === plugin.plugin_id)
  if (!licensed) return local && (local.installed || local.withdrawn) ? 'revoked' : 'purchase'
  if (plugin.feature_code) return modules.includes(plugin.feature_code) ? 'enabled' : 'activating'
  if (local?.enabled) return 'enabled'
  if (local?.installed) return 'enable'
  return 'distributing'
}

// Where an administrator enables an installed plugin, by kind; null: in each tenant's plugin marketplace.
// The community edition has no theme management page (default theme only), so a theme has none.
export function enablePath(plugin: Pick<MarketPlugin, 'kind' | 'applies_to'>): string | null {
  switch (plugin.kind) {
    case 'rule_pack': return '/site/rule-packs'
    case 'theme': return null
    case 'provider': return '/sys/plugin-providers'
    default: return null
  }
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
