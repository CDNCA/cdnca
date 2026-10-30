import i18n from './index'

// 站点“防护”页“本站 CRS 档位”卡片（PA-12，securitypolicy.CRSOverride）。
const zhCN = {
  title: '本站 OWASP CRS 档位',
  hint: '档位与排除规则默认跟随本站应用的 WAF 规则库，可只为本站单独设置；其他站点不受影响。改动即自动下发到节点。',
  profile: 'CRS 档位', exclusions: '排除规则 ID',
  inherit: '跟随规则库（{{value}}）', custom: '本站单独设置',
  exclusionsHint: '这些规则对本站不生效（每个请求即时生效，不重载节点）；只能填所选档位允许排除的规则，留空表示不排除。',
  exclusionsInvalid: '填写 9 开头的 6 位规则 ID，用逗号分隔',
  notExported: '所选档位不允许排除：{{ids}}',
  none: '无', count: '{{count}} 条',
  noManagedWAF: '本站应用的 WAF 规则库没有启用 OWASP CRS 托管规则：先在上方“托管 WAF 防护档位”选择档位，再在这里单独调整。',
  openLibraries: '去设置规则库',
  loadFailed: '读取本站 CRS 设置失败', retry: '重试',
  save: '保存', saving: '正在保存', saved: '已保存，正在下发到节点。',
  packsSuspended: '以下规则包因超出新档位已挂起：{{packs}}；改回原档位或更换规则包后可恢复。',
  packsRestored: '以下规则包已随档位恢复生效：{{packs}}。',
  packsSuspendedNow: '当前已挂起的规则包（超出档位）：{{packs}}。',
  effective: '本站生效：{{profile}}，排除 {{exclusions}}',
  apps: '应用类型',
  appsPlaceholder: '不选（通用网站）',
  appsHint: '本站是下列应用时可选：加载 OWASP CRS 官方为该应用维护的排除规则，只放宽该应用后台等已知路径和参数上的误报；只对本站生效，与 CRS 档位一起发布。不确定就不选；只覆盖应用原版功能，第三方插件的误报不在其内。',
  appsUnavailable: '主控尚未下载应用排除包，暂无可选应用类型。',
  appsEffective: '应用类型：{{apps}}',
  errors: {
    crs_app_unavailable: '所选应用类型的排除包尚未下载到主控',
    crs_profile_unavailable: '所选档位尚未下载到主控',
    crs_exclusion_not_exported: '有规则不在所选档位允许排除的范围内',
    crs_no_managed_waf: '本站的 WAF 规则库没有启用 OWASP CRS',
    version_conflict: '站点已被修改，请刷新后重试', idempotency_conflict: '请求重复，请刷新后重试',
    site_locked: '站点已被平台管理员锁定', validation_error: '输入不正确',
    unknown: '保存失败（{{code}}）',
  },
}

const enUS: typeof zhCN = {
  title: 'OWASP CRS profile of this site',
  hint: 'The profile and the excluded rules follow the WAF rule library applied to this site unless set here for this site only; other sites are not affected. Goes to the nodes when saved.',
  profile: 'CRS profile', exclusions: 'Excluded rule IDs',
  inherit: 'Follow the library ({{value}})', custom: 'This site only',
  exclusionsHint: 'These rules do not run for this site (per request, no node reload); only rules the selected profile lets a site exclude. Empty excludes nothing.',
  exclusionsInvalid: 'Six-digit rule IDs starting with 9, comma separated',
  notExported: 'The selected profile does not let a site exclude: {{ids}}',
  none: 'none', count: '{{count}} rules',
  noManagedWAF: 'The WAF rule library applied to this site runs no OWASP CRS managed rules: choose a managed WAF tier above first.',
  openLibraries: 'Open rule libraries',
  loadFailed: 'Could not read this site\'s CRS settings', retry: 'Retry',
  save: 'Save', saving: 'Saving', saved: 'Saved. Deploying to the nodes.',
  packsSuspended: 'These rule packs are outside the new profile and were suspended: {{packs}}. Switch back to the previous profile or change the pack to restore them.',
  packsRestored: 'These rule packs are active again with this profile: {{packs}}.',
  packsSuspendedNow: 'Rule packs currently suspended (outside the profile): {{packs}}.',
  effective: 'This site runs {{profile}}, excluding {{exclusions}}',
  apps: 'Application types',
  appsPlaceholder: 'None (generic site)',
  appsHint: 'Select when this site runs one of these applications: loads the OWASP CRS official exclusion rules for it, which only relax known false positives on that application\'s admin paths and parameters. Applies to this site only and is published with the CRS profile. Leave empty if unsure; only the vanilla application is covered, not third-party plugins.',
  appsUnavailable: 'No application exclusion packs are downloaded on this control plane yet.',
  appsEffective: 'Application types: {{apps}}',
  errors: {
    crs_app_unavailable: 'An application type\'s exclusion pack is not downloaded on this control plane',
    crs_profile_unavailable: 'The selected profile is not downloaded on this control plane',
    crs_exclusion_not_exported: 'A rule is not one the selected profile lets a site exclude',
    crs_no_managed_waf: 'The site\'s WAF rule library runs no OWASP CRS',
    version_conflict: 'The site changed; refresh and try again', idempotency_conflict: 'Duplicate request; refresh and try again',
    site_locked: 'The site is locked by a platform administrator', validation_error: 'Invalid input',
    unknown: 'Save failed ({{code}})',
  },
}

function pseudo(value: unknown): unknown {
  return typeof value === 'string'
    ? `［${value}］`
    : Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudo(child)]))
}

export const siteCRSMessages = { 'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudo(zhCN), 'qps-Ploc': pseudo(zhCN) }

for (const [locale, messages] of Object.entries(siteCRSMessages)) i18n.addResourceBundle(locale, 'siteCRS', messages, true, true)
