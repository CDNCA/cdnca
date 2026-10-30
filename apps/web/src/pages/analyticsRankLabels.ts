import type { TFunction } from 'i18next'

import type { AnalyticsRankDimension, AnalyticsRankItem } from '../api/analytics'
import { quickBlockCarriers } from '../api/securityPolicies'
import { displayIP } from '../i18n/formatters'
import { ipIntelTagKey } from '../i18n/ipIntel'

// GB/T 2260 province-level codes (the IP library's province attribute).
export const provinceNames: Record<string, { zh: string; en: string }> = {
  '110000': { zh: '北京', en: 'Beijing' }, '120000': { zh: '天津', en: 'Tianjin' },
  '130000': { zh: '河北', en: 'Hebei' }, '140000': { zh: '山西', en: 'Shanxi' },
  '150000': { zh: '内蒙古', en: 'Inner Mongolia' }, '210000': { zh: '辽宁', en: 'Liaoning' },
  '220000': { zh: '吉林', en: 'Jilin' }, '230000': { zh: '黑龙江', en: 'Heilongjiang' },
  '310000': { zh: '上海', en: 'Shanghai' }, '320000': { zh: '江苏', en: 'Jiangsu' },
  '330000': { zh: '浙江', en: 'Zhejiang' }, '340000': { zh: '安徽', en: 'Anhui' },
  '350000': { zh: '福建', en: 'Fujian' }, '360000': { zh: '江西', en: 'Jiangxi' },
  '370000': { zh: '山东', en: 'Shandong' }, '410000': { zh: '河南', en: 'Henan' },
  '420000': { zh: '湖北', en: 'Hubei' }, '430000': { zh: '湖南', en: 'Hunan' },
  '440000': { zh: '广东', en: 'Guangdong' }, '450000': { zh: '广西', en: 'Guangxi' },
  '460000': { zh: '海南', en: 'Hainan' }, '500000': { zh: '重庆', en: 'Chongqing' },
  '510000': { zh: '四川', en: 'Sichuan' }, '520000': { zh: '贵州', en: 'Guizhou' },
  '530000': { zh: '云南', en: 'Yunnan' }, '540000': { zh: '西藏', en: 'Tibet' },
  '610000': { zh: '陕西', en: 'Shaanxi' }, '620000': { zh: '甘肃', en: 'Gansu' },
  '630000': { zh: '青海', en: 'Qinghai' }, '640000': { zh: '宁夏', en: 'Ningxia' },
  '650000': { zh: '新疆', en: 'Xinjiang' }, '710000': { zh: '台湾', en: 'Taiwan' },
  '810000': { zh: '香港', en: 'Hong Kong' }, '820000': { zh: '澳门', en: 'Macao' },
}

const browsers = new Set(['bot', 'wechat', 'qq', 'uc', 'samsung', 'edge', 'opera', 'firefox', 'chrome', 'safari', 'ie', 'other'])
const systems = new Set(['harmonyos', 'android', 'ios', 'windows', 'macos', 'chromeos', 'linux', 'other'])

function countryName(code: string, locale: string): string {
  try {
    return new Intl.DisplayNames([locale], { type: 'region' }).of(code) ?? code
  } catch {
    return code
  }
}

/** The display text of a ranking key: names for codes, the key itself otherwise. */
export function rankKeyLabel(
  dimension: AnalyticsRankDimension,
  key: string,
  t: TFunction<'analytics'>,
  tIPIntel: TFunction<'ipIntel'>,
  locale: string,
): string {
  if (key === '__unknown__') return t('table.unknown')
  switch (dimension) {
    case 'region':
      return /^[A-Z]{2}$/.test(key) ? countryName(key, locale) : key
    case 'province': {
      const name = provinceNames[key]
      return name ? (locale.startsWith('zh') ? name.zh : name.en) : key
    }
    case 'carrier':
      return (quickBlockCarriers as readonly string[]).includes(key) ? tIPIntel(ipIntelTagKey(key)) : key
    case 'browser':
      return browsers.has(key) ? t(`clientFamilies.browser.${key}`) : key
    case 'os':
      return systems.has(key) ? t(`clientFamilies.os.${key}`) : key
    case 'ip':
      return displayIP(key)
    default:
      return key
  }
}

/**
 * The display text of a ranking row: domains as host:port, hot URLs as
 * scheme://host:port/path (like the competitor). Unknown parts are left out:
 * no scheme → host:port/path, port 0 → host/path.
 */
export function rankItemLabel(
  dimension: AnalyticsRankDimension,
  item: AnalyticsRankItem,
  t: TFunction<'analytics'>,
  tIPIntel: TFunction<'ipIntel'>,
  locale: string,
): string {
  return rankAddressLabel(dimension, item) ?? rankKeyLabel(dimension, item.key, t, tIPIntel, locale)
}

/**
 * The address text of a domain / URL ranking row (also used by the home page
 * ranks), or undefined when the row has no address parts.
 */
export function rankAddressLabel(
  dimension: string,
  item: { host?: string; port?: number; path?: string; scheme?: string },
): string | undefined {
  if ((dimension !== 'domain' && dimension !== 'url') || !item.host) return undefined
  const address = item.port ? `${item.host}:${item.port}` : item.host
  if (dimension === 'domain') return address
  const path = item.path ?? ''
  return item.scheme ? `${item.scheme}://${address}${path}` : `${address}${path}`
}
