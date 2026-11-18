import { geoAreas } from '../api/geoAreas'
import { provinceNames } from './analyticsRankLabels'

// ISO 3166-1 alpha-2 country codes (249, the officially assigned set) and the
// GB/T 2260 province-level codes; the control API accepts exactly these
// (regioncatalog.ValidGeo; TestValidGeoAcceptsTheWebCountryList holds the same list).
export const regionCountryCodes = [
  'AD', 'AE', 'AF', 'AG', 'AI', 'AL', 'AM', 'AO', 'AQ', 'AR', 'AS', 'AT', 'AU', 'AW', 'AX', 'AZ',
  'BA', 'BB', 'BD', 'BE', 'BF', 'BG', 'BH', 'BI', 'BJ', 'BL', 'BM', 'BN', 'BO', 'BQ', 'BR', 'BS',
  'BT', 'BV', 'BW', 'BY', 'BZ', 'CA', 'CC', 'CD', 'CF', 'CG', 'CH', 'CI', 'CK', 'CL', 'CM', 'CN',
  'CO', 'CR', 'CU', 'CV', 'CW', 'CX', 'CY', 'CZ', 'DE', 'DJ', 'DK', 'DM', 'DO', 'DZ', 'EC', 'EE',
  'EG', 'EH', 'ER', 'ES', 'ET', 'FI', 'FJ', 'FK', 'FM', 'FO', 'FR', 'GA', 'GB', 'GD', 'GE', 'GF',
  'GG', 'GH', 'GI', 'GL', 'GM', 'GN', 'GP', 'GQ', 'GR', 'GS', 'GT', 'GU', 'GW', 'GY', 'HK', 'HM',
  'HN', 'HR', 'HT', 'HU', 'ID', 'IE', 'IL', 'IM', 'IN', 'IO', 'IQ', 'IR', 'IS', 'IT', 'JE', 'JM',
  'JO', 'JP', 'KE', 'KG', 'KH', 'KI', 'KM', 'KN', 'KP', 'KR', 'KW', 'KY', 'KZ', 'LA', 'LB', 'LC',
  'LI', 'LK', 'LR', 'LS', 'LT', 'LU', 'LV', 'LY', 'MA', 'MC', 'MD', 'ME', 'MF', 'MG', 'MH', 'MK',
  'ML', 'MM', 'MN', 'MO', 'MP', 'MQ', 'MR', 'MS', 'MT', 'MU', 'MV', 'MW', 'MX', 'MY', 'MZ', 'NA',
  'NC', 'NE', 'NF', 'NG', 'NI', 'NL', 'NO', 'NP', 'NR', 'NU', 'NZ', 'OM', 'PA', 'PE', 'PF', 'PG',
  'PH', 'PK', 'PL', 'PM', 'PN', 'PR', 'PS', 'PT', 'PW', 'PY', 'QA', 'RE', 'RO', 'RS', 'RU', 'RW',
  'SA', 'SB', 'SC', 'SD', 'SE', 'SG', 'SH', 'SI', 'SJ', 'SK', 'SL', 'SM', 'SN', 'SO', 'SR', 'SS',
  'ST', 'SV', 'SX', 'SY', 'SZ', 'TC', 'TD', 'TF', 'TG', 'TH', 'TJ', 'TK', 'TL', 'TM', 'TN', 'TO',
  'TR', 'TT', 'TV', 'TW', 'TZ', 'UA', 'UG', 'UM', 'US', 'UY', 'UZ', 'VA', 'VC', 'VE', 'VG', 'VI',
  'VN', 'VU', 'WF', 'WS', 'YE', 'YT', 'ZA', 'ZM', 'ZW',
] as const

export interface GeoOption { value: string; label: string }

function countryLabel(code: string, locale: string): string {
  try {
    return new Intl.DisplayNames([locale], { type: 'region' }).of(code) ?? code
  } catch {
    return code
  }
}

/** Country options sorted by their localized name, each labelled "名称 (CN)". */
export function countryOptions(locale: string): GeoOption[] {
  const collator = new Intl.Collator(locale)
  return regionCountryCodes
    .map((code) => ({ value: code, label: `${countryLabel(code, locale)} (${code})` }))
    .sort((a, b) => collator.compare(a.label, b.label))
}

/** Province options (CN only), in code order, each labelled "名称 (440000)". */
export function provinceOptions(locale: string): GeoOption[] {
  return Object.entries(provinceNames).map(([code, name]) => ({
    value: code, label: `${locale.startsWith('zh') ? name.zh : name.en} (${code})`,
  }))
}

const zh = (locale: string) => locale.startsWith('zh')

/** Area (libs/geoarea: global, a continent or a region) display name, '' for an unknown code. */
export function areaName(code: string, locale: string): string {
  const area = geoAreas.find((item) => item.code === code)
  return area ? (zh(locale) ? area.name_zh : area.name_en) : ''
}

/** "亚洲 / 东南亚" for a region, the name alone for a continent or global, '' for an unknown code. */
export function areaPath(code: string, locale: string): string {
  const area = geoAreas.find((item) => item.code === code)
  if (!area) return ''
  return area.parent ? `${areaName(area.parent, locale)} / ${areaName(code, locale)}` : areaName(code, locale)
}

export interface GeoOptionGroup { label: string; options: GeoOption[] }

/**
 * Two-level area options for a Select: global, then one group per continent
 * holding the whole continent ("亚洲（全部）") and its regions, in libs/geoarea
 * order. prefix is put before every value (the node list filter's "area:").
 */
export function areaOptions(locale: string, prefix = ''): (GeoOption | GeoOptionGroup)[] {
  const out: (GeoOption | GeoOptionGroup)[] = []
  for (const area of geoAreas) {
    const name = areaName(area.code, locale)
    if (area.level === 'global') out.push({ value: prefix + area.code, label: name })
    if (area.level === 'continent') {
      out.push({ label: name, options: [{ value: prefix + area.code, label: zh(locale) ? `${name}（全部）` : `All of ${name}` }] })
    }
    const group = out[out.length - 1]
    if (area.level === 'region' && group && 'options' in group) group.options.push({ value: prefix + area.code, label: name })
  }
  return out
}

/**
 * Whether a region lies in the area: its own area is in it (the same area, a
 * region of that continent, anything for global), or its country is one of
 * the area's (a continent's countries are its regions' union; global: any).
 */
export function regionInArea(area: string, region: { area_code: string; country_code: string }): boolean {
  const found = geoAreas.find((item) => item.code === area)
  if (!found) return false
  if (region.area_code) {
    const own = geoAreas.find((item) => item.code === region.area_code)
    return Boolean(own && (own.code === area || area === 'global' || own.parent === area))
  }
  if (!region.country_code) return false
  return found.code === 'global' || found.countries.includes(region.country_code)
}

/** "亚洲 / 东南亚" or "中国 / 广东" style display of a region geography, '' when unset. */
export function geoLabel(area: string, country: string, province: string, locale: string): string {
  if (area) return areaPath(area, locale) || area
  if (!country) return ''
  const name = countryLabel(country, locale)
  const p = provinceNames[province]
  return p ? `${name} / ${zh(locale) ? p.zh : p.en}` : name
}
