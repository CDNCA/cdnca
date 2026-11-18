// Generated from libs/geoarea/geoarea.go Areas; do not edit. After changing the areas run
//   GEOAREA_WRITE_WEB=1 GOWORK=off go -C libs/geoarea test -run TestWebMirror
// (TestWebMirror fails while this file and Areas differ).

export type GeoAreaLevel = 'global' | 'continent' | 'region'

export interface GeoArea {
  code: string
  name_zh: string
  name_en: string
  level: GeoAreaLevel
  /** The continent of a region; '' otherwise. */
  parent: string
  /** ISO 3166-1 alpha-2; empty for global, which covers every country; a continent's is its regions' union. */
  countries: readonly string[]
}

export const geoAreas: readonly GeoArea[] = [
  { code: 'global', name_zh: '全球', name_en: 'Global', level: 'global', parent: '', countries: [] },
  { code: 'asia', name_zh: '亚洲', name_en: 'Asia', level: 'continent', parent: '', countries: ['CN', 'HK', 'JP', 'KP', 'KR', 'MN', 'MO', 'TW', 'BN', 'ID', 'KH', 'LA', 'MM', 'MY', 'PH', 'SG', 'TH', 'TL', 'VN', 'AF', 'BD', 'BT', 'IN', 'LK', 'MV', 'NP', 'PK', 'AE', 'AM', 'AZ', 'BH', 'CY', 'GE', 'IL', 'IQ', 'IR', 'JO', 'KW', 'LB', 'OM', 'PS', 'QA', 'SA', 'SY', 'TR', 'YE', 'KG', 'KZ', 'TJ', 'TM', 'UZ'] },
  { code: 'east_asia', name_zh: '东亚', name_en: 'East Asia', level: 'region', parent: 'asia', countries: ['CN', 'HK', 'JP', 'KP', 'KR', 'MN', 'MO', 'TW'] },
  { code: 'southeast_asia', name_zh: '东南亚', name_en: 'Southeast Asia', level: 'region', parent: 'asia', countries: ['BN', 'ID', 'KH', 'LA', 'MM', 'MY', 'PH', 'SG', 'TH', 'TL', 'VN'] },
  { code: 'south_asia', name_zh: '南亚', name_en: 'South Asia', level: 'region', parent: 'asia', countries: ['AF', 'BD', 'BT', 'IN', 'LK', 'MV', 'NP', 'PK'] },
  { code: 'west_asia', name_zh: '西亚', name_en: 'West Asia', level: 'region', parent: 'asia', countries: ['AE', 'AM', 'AZ', 'BH', 'CY', 'GE', 'IL', 'IQ', 'IR', 'JO', 'KW', 'LB', 'OM', 'PS', 'QA', 'SA', 'SY', 'TR', 'YE'] },
  { code: 'central_asia', name_zh: '中亚', name_en: 'Central Asia', level: 'region', parent: 'asia', countries: ['KG', 'KZ', 'TJ', 'TM', 'UZ'] },
  { code: 'europe', name_zh: '欧洲', name_en: 'Europe', level: 'continent', parent: '', countries: ['AX', 'DK', 'EE', 'FI', 'FO', 'GB', 'GG', 'IE', 'IM', 'IS', 'JE', 'LT', 'LV', 'NO', 'SE', 'SJ', 'AT', 'BE', 'CH', 'DE', 'FR', 'LI', 'LU', 'MC', 'NL', 'AD', 'AL', 'BA', 'ES', 'GI', 'GR', 'HR', 'IT', 'ME', 'MK', 'MT', 'PT', 'RS', 'SI', 'SM', 'VA', 'BG', 'BY', 'CZ', 'HU', 'MD', 'PL', 'RO', 'RU', 'SK', 'UA'] },
  { code: 'northern_europe', name_zh: '北欧', name_en: 'Northern Europe', level: 'region', parent: 'europe', countries: ['AX', 'DK', 'EE', 'FI', 'FO', 'GB', 'GG', 'IE', 'IM', 'IS', 'JE', 'LT', 'LV', 'NO', 'SE', 'SJ'] },
  { code: 'western_europe', name_zh: '西欧', name_en: 'Western Europe', level: 'region', parent: 'europe', countries: ['AT', 'BE', 'CH', 'DE', 'FR', 'LI', 'LU', 'MC', 'NL'] },
  { code: 'southern_europe', name_zh: '南欧', name_en: 'Southern Europe', level: 'region', parent: 'europe', countries: ['AD', 'AL', 'BA', 'ES', 'GI', 'GR', 'HR', 'IT', 'ME', 'MK', 'MT', 'PT', 'RS', 'SI', 'SM', 'VA'] },
  { code: 'eastern_europe', name_zh: '东欧', name_en: 'Eastern Europe', level: 'region', parent: 'europe', countries: ['BG', 'BY', 'CZ', 'HU', 'MD', 'PL', 'RO', 'RU', 'SK', 'UA'] },
  { code: 'africa', name_zh: '非洲', name_en: 'Africa', level: 'continent', parent: '', countries: ['DZ', 'EG', 'EH', 'LY', 'MA', 'SD', 'TN', 'BF', 'BJ', 'CI', 'CV', 'GH', 'GM', 'GN', 'GW', 'LR', 'ML', 'MR', 'NE', 'NG', 'SH', 'SL', 'SN', 'TG', 'BI', 'DJ', 'ER', 'ET', 'IO', 'KE', 'KM', 'MG', 'MU', 'MW', 'MZ', 'RE', 'RW', 'SC', 'SO', 'SS', 'TZ', 'UG', 'YT', 'ZM', 'ZW', 'AO', 'CD', 'CF', 'CG', 'CM', 'GA', 'GQ', 'ST', 'TD', 'BW', 'LS', 'NA', 'SZ', 'ZA'] },
  { code: 'northern_africa', name_zh: '北非', name_en: 'Northern Africa', level: 'region', parent: 'africa', countries: ['DZ', 'EG', 'EH', 'LY', 'MA', 'SD', 'TN'] },
  { code: 'western_africa', name_zh: '西非', name_en: 'Western Africa', level: 'region', parent: 'africa', countries: ['BF', 'BJ', 'CI', 'CV', 'GH', 'GM', 'GN', 'GW', 'LR', 'ML', 'MR', 'NE', 'NG', 'SH', 'SL', 'SN', 'TG'] },
  { code: 'eastern_africa', name_zh: '东非', name_en: 'Eastern Africa', level: 'region', parent: 'africa', countries: ['BI', 'DJ', 'ER', 'ET', 'IO', 'KE', 'KM', 'MG', 'MU', 'MW', 'MZ', 'RE', 'RW', 'SC', 'SO', 'SS', 'TZ', 'UG', 'YT', 'ZM', 'ZW'] },
  { code: 'middle_africa', name_zh: '中非', name_en: 'Middle Africa', level: 'region', parent: 'africa', countries: ['AO', 'CD', 'CF', 'CG', 'CM', 'GA', 'GQ', 'ST', 'TD'] },
  { code: 'southern_africa', name_zh: '南部非洲', name_en: 'Southern Africa', level: 'region', parent: 'africa', countries: ['BW', 'LS', 'NA', 'SZ', 'ZA'] },
  { code: 'north_america', name_zh: '北美洲', name_en: 'North America', level: 'continent', parent: '', countries: ['BM', 'CA', 'GL', 'PM', 'US', 'BZ', 'CR', 'GT', 'HN', 'MX', 'NI', 'PA', 'SV', 'AG', 'AI', 'AW', 'BB', 'BL', 'BQ', 'BS', 'CU', 'CW', 'DM', 'DO', 'GD', 'GP', 'HT', 'JM', 'KN', 'KY', 'LC', 'MF', 'MQ', 'MS', 'PR', 'SX', 'TC', 'TT', 'VC', 'VG', 'VI'] },
  { code: 'northern_america', name_zh: '北美北部', name_en: 'Northern America', level: 'region', parent: 'north_america', countries: ['BM', 'CA', 'GL', 'PM', 'US'] },
  { code: 'central_america', name_zh: '中美洲', name_en: 'Central America', level: 'region', parent: 'north_america', countries: ['BZ', 'CR', 'GT', 'HN', 'MX', 'NI', 'PA', 'SV'] },
  { code: 'caribbean', name_zh: '加勒比', name_en: 'Caribbean', level: 'region', parent: 'north_america', countries: ['AG', 'AI', 'AW', 'BB', 'BL', 'BQ', 'BS', 'CU', 'CW', 'DM', 'DO', 'GD', 'GP', 'HT', 'JM', 'KN', 'KY', 'LC', 'MF', 'MQ', 'MS', 'PR', 'SX', 'TC', 'TT', 'VC', 'VG', 'VI'] },
  { code: 'south_america', name_zh: '南美洲', name_en: 'South America', level: 'continent', parent: '', countries: ['AR', 'BO', 'BR', 'CL', 'CO', 'EC', 'FK', 'GF', 'GY', 'PE', 'PY', 'SR', 'UY', 'VE'] },
  { code: 'oceania', name_zh: '大洋洲', name_en: 'Oceania', level: 'continent', parent: '', countries: ['AU', 'CC', 'CX', 'NF', 'NZ', 'FJ', 'NC', 'PG', 'SB', 'VU', 'FM', 'GU', 'KI', 'MH', 'MP', 'NR', 'PW', 'UM', 'AS', 'CK', 'NU', 'PF', 'PN', 'TK', 'TO', 'TV', 'WF', 'WS'] },
  { code: 'australia_new_zealand', name_zh: '澳新', name_en: 'Australia and New Zealand', level: 'region', parent: 'oceania', countries: ['AU', 'CC', 'CX', 'NF', 'NZ'] },
  { code: 'melanesia', name_zh: '美拉尼西亚', name_en: 'Melanesia', level: 'region', parent: 'oceania', countries: ['FJ', 'NC', 'PG', 'SB', 'VU'] },
  { code: 'micronesia', name_zh: '密克罗尼西亚', name_en: 'Micronesia', level: 'region', parent: 'oceania', countries: ['FM', 'GU', 'KI', 'MH', 'MP', 'NR', 'PW', 'UM'] },
  { code: 'polynesia', name_zh: '波利尼西亚', name_en: 'Polynesia', level: 'region', parent: 'oceania', countries: ['AS', 'CK', 'NU', 'PF', 'PN', 'TK', 'TO', 'TV', 'WF', 'WS'] },
]
