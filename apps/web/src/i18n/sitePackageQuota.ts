import i18n from './index'

// 网站 / 四层转发写入被套餐额度拒绝（409 package_resource_quota_exceeded）时，在对应字段下就地说明。
const zhCN = {
  reached: {
    sites: '网站数量已达上限（{{used}}/{{limit}}）',
    domains: '域名数量已达上限（{{used}}/{{limit}}）',
    root_domains: '根域名数量已达上限（{{used}}/{{limit}}）',
    http_ports: '非标准端口数量已达上限（{{used}}/{{limit}}）',
    stream_ports: '四层转发端口数量已达上限（{{used}}/{{limit}}）',
  },
  actions: {
    upgrade: '升级套餐',
    manage: '管理套餐额度',
  },
}

const enUS: typeof zhCN = {
  reached: {
    sites: 'Website limit reached ({{used}}/{{limit}})',
    domains: 'Domain limit reached ({{used}}/{{limit}})',
    root_domains: 'Root domain limit reached ({{used}}/{{limit}})',
    http_ports: 'Non-standard port limit reached ({{used}}/{{limit}})',
    stream_ports: 'Forwarding port limit reached ({{used}}/{{limit}})',
  },
  actions: {
    upgrade: 'Upgrade package',
    manage: 'Manage package quota',
  },
}

for (const [locale, messages] of Object.entries({ 'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': zhCN, 'qps-Ploc': zhCN })) {
  i18n.addResourceBundle(locale, 'sitePackageQuota', messages, true, true)
}
