import i18n from './index'

// NF34: CC auto-ban history tab of the block log page.
const messages: Record<string, Record<string, unknown>> = {
  'zh-CN': {
    tabs: { ccBans: 'CC 自动封禁' },
    ccBans: {
      rule: 'CC 规则', count: '封禁次数', firstBannedAt: '首次封禁', lastBannedAt: '最近封禁', search: '搜索',
      window: '最近 {{days}} 天', empty: '暂无 CC 自动封禁记录', truncated: '仅显示最近 100 条，请按 IP 缩小范围。',
      tenant: '租户', tenantPlaceholder: '搜索租户主账号', tenantLookupFailed: '租户列表加载失败，请重试。',
    },
  },
  'en-US': {
    tabs: { ccBans: 'CC auto-bans' },
    ccBans: {
      rule: 'CC rule', count: 'Bans', firstBannedAt: 'First banned', lastBannedAt: 'Last banned', search: 'Search',
      window: 'Last {{days}} days', empty: 'No CC auto-bans', truncated: 'Showing the latest 100; filter by IP to narrow it.',
      tenant: 'Tenant', tenantPlaceholder: 'Search tenant owners', tenantLookupFailed: 'Could not load tenants. Try again.',
    },
  },
  'qps-ploc': {
    tabs: { ccBans: '[!! ÇÇ åüţö-ßåñs !!]' },
    ccBans: {
      rule: '[!! ÇÇ rülê !!]', count: '[!! ßåñs !!]', firstBannedAt: '[!! Fïrsţ ßåññêð !!]', lastBannedAt: '[!! Låsţ ßåññêð !!]',
      search: '[!! Sêårçh !!]', window: '[!! Låsţ {{days}} ðåÿs !!]', empty: '[!! Ñö ÇÇ åüţö-ßåñs !!]',
      truncated: '[!! Shöwïñg ţhê låţêsţ 100 !!]', tenant: '[!! Ţêñåñţ !!]', tenantPlaceholder: '[!! Sêårçh ţêñåñţ öwñêrs !!]',
      tenantLookupFailed: '[!! Çöülð ñöţ löåð ţêñåñţs !!]',
    },
  },
}

for (const [locale, blockState] of Object.entries({ ...messages, 'qps-Ploc': messages['qps-ploc'] })) {
  i18n.addResourceBundle(locale, 'analyticsLogs', { blockState }, true, true)
}
