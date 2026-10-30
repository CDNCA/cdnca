import type { TFunction } from 'i18next'

import type { ClientIPIntel } from '../api/analyticsLogs'
import { quickBlockCarriers } from '../api/securityPolicies'
import { ipIntelTagKey } from '../i18n/ipIntel'

interface RowIPFields {
  country_code: string
  carrier: string
  ip_intel?: ClientIPIntel
}

function countryName(code: string, locale: string): string {
  try {
    return new Intl.DisplayNames([locale], { type: 'region' }).of(code) ?? code
  } catch {
    return code
  }
}

/**
 * The client address' region for log tables: country (locale name), then
 * province and city from the IP intelligence library (a municipality's city
 * repeats its province and is dropped). Falls back to the stored country code.
 */
export function logRegion(event: RowIPFields, locale: string): string {
  const intel = event.ip_intel
  if (!intel?.country) return event.country_code || '-'
  const parts = [countryName(intel.country, locale)]
  if (intel.province_name) parts.push(intel.province_name)
  if (intel.city_name && intel.city_name !== intel.province_name) parts.push(intel.city_name)
  return parts.join(' ')
}

/** The client address' carrier label (library tag), else the stored carrier text. */
export function logCarrier(event: RowIPFields, t: TFunction<'ipIntel'>): string {
  const carrier = event.ip_intel?.carrier
  // A tag newer than this page's table shows as its name.
  if (carrier) return (quickBlockCarriers as readonly string[]).includes(carrier) ? t(ipIntelTagKey(carrier)) : carrier
  // ui-errmsg-1024: the server's unknown sentinel reads as 未知.
  return event.carrier === '__unknown__' ? t('unknown') : event.carrier || '-'
}

/** 国内 IDC / 境外 IDC label, or ''. */
export function logIDC(event: RowIPFields, t: TFunction<'ipIntel'>): string {
  const idc = event.ip_intel?.idc
  return idc ? t(ipIntelTagKey(idc)) : ''
}

export function logASN(event: RowIPFields, t: TFunction<'ipIntel'>): string {
  const asn = event.ip_intel?.asn
  return asn ? t('asn', { asn }) : '-'
}
