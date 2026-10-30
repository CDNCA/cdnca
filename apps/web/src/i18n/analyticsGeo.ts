import i18n from '.'

const zhCN = {
  title: 'IP 归属证据',
  actions: { verify: '核验 IP 归属', retry: '重试核验' },
  fields: {
    resolution: '归属结果', lookupReason: '查询原因', addressFamily: '地址族', countryRegion: '国家 / 地区', city: '城市', carrier: '运营商', asn: 'ASN',
    reconciliation: '日志对账', source: '日志原值', version: '数据库版本', provider: '数据提供方', publishedAt: '发布时间', effectiveAt: '生效时间', digest: '数据库摘要',
  },
  values: {
    matched: '已匹配', unknown: '未知', prefix_match: '网段匹配', no_prefix_match: '无匹配网段', ipv4: 'IPv4', ipv6: 'IPv6', match: '一致', mismatch: '不一致', unverified: '无法核验', empty: '未记录',
  },
  states: {
    unavailable: '归属证据暂不可用，请稍后重试。', timeout: '归属核验超时。', invalid: '归属证据未通过完整性校验。',
  },
}

const enUS = {
  title: 'IP attribution evidence',
  actions: { verify: 'Verify IP attribution', retry: 'Retry verification' },
  fields: {
    resolution: 'Resolution', lookupReason: 'Lookup reason', addressFamily: 'Address family', countryRegion: 'Country / region', city: 'City', carrier: 'Carrier', asn: 'ASN',
    reconciliation: 'Log reconciliation', source: 'Stored values', version: 'Database version', provider: 'Data provider', publishedAt: 'Published at', effectiveAt: 'Effective at', digest: 'Database digest',
  },
  values: {
    matched: 'Matched', unknown: 'Unknown', prefix_match: 'Prefix match', no_prefix_match: 'No matching prefix', ipv4: 'IPv4', ipv6: 'IPv6', match: 'Match', mismatch: 'Mismatch', unverified: 'Unverified', empty: 'Not recorded',
  },
  states: {
    unavailable: 'Attribution evidence is unavailable. Try again later.', timeout: 'Attribution lookup timed out.', invalid: 'Attribution evidence failed integrity validation.',
  },
}

function pseudo(value: unknown): unknown {
  if (typeof value === 'string') return `［${value.replace(/\s/g, '~')}］`
  if (!value || typeof value !== 'object') return value
  return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, pseudo(child)]))
}

i18n.addResourceBundle('zh-CN', 'analyticsGeo', zhCN, true, true)
i18n.addResourceBundle('en-US', 'analyticsGeo', enUS, true, true)
i18n.addResourceBundle('qps-ploc', 'analyticsGeo', pseudo(zhCN), true, true)
i18n.addResourceBundle('qps-Ploc', 'analyticsGeo', pseudo(zhCN), true, true)

export { enUS, zhCN }
export default i18n
