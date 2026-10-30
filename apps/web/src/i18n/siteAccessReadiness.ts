import i18n from './index'

// fix-readiness：网站接入状态（服务端 access_readiness）。检查项名称、原因与分角色的建议操作。
const zhCN = {
  title: '接入状态',
  description: '访客能否通过 CNAME 访问本网站，逐项检查。',
  checkNow: '立即检查',
  checkedAt: '检查于 {{time}}',
  notChecked: '尚未检查',
  throttled: '刚检查过，请 {{seconds}} 秒后再试',
  checkFailed: '检查失败，请稍后重试',
  pass: '通过',
  fail: '未通过',
  state: {
    ready: '接入已就绪',
    pending: '接入未就绪：{{check}}',
    blocked: '接入受阻：{{check}}',
  },
  checks: {
    package: '套餐有效',
    line_group: '线路可用',
    cname_generated: 'CNAME 已生成',
    dns_resolved: '域名已解析到 CNAME',
    https_cert: 'HTTPS 证书有效',
    published: '已发布到节点',
  },
  short: {
    package: { default: '暂不可用', no_package: '未绑定套餐', package_disabled: '套餐已停用', package_deleted: '套餐已删除' },
    line_group: { default: '缺可用线路', no_line_group: '缺可用线路', no_online_nodes: '线路无在线节点' },
    cname_generated: { default: 'CNAME 未生成', cname_pending: 'CNAME 生成中' },
    dns_resolved: { default: '域名未解析到 CNAME', not_checked: '域名未解析到 CNAME', waiting_cname: '等待 CNAME' },
    https_cert: { default: 'HTTPS 证书无效', certificate_missing: 'HTTPS 缺证书' },
    published: { default: '未发布到节点', publishing: '发布中', publish_failed: '发布失败', site_disabled: '网站已停用' },
  },
  reasons: {
    package: {
      no_package: '网站没有绑定套餐，暂不可用：没有有效套餐的网站不会下发到节点。',
      package_disabled: '所绑套餐已停用，暂不可用：网站不会下发到节点。',
      package_deleted: '所绑套餐已删除，暂不可用：网站不会下发到节点。',
      default: '网站没有有效套餐，暂不可用。',
    },
    line_group: {
      no_line_group: '网站没有可用的线路组（网站、套餐的线路组或平台默认线路组都没有）。',
      no_online_nodes: '线路组里没有在线可调度的节点。',
      default: '网站没有可用的线路。',
    },
    cname_generated: {
      cname_pending: 'CNAME 正在生成，通常几分钟内完成。',
      default: 'CNAME 生成失败，原因见基本设置里的 CNAME。',
    },
    dns_resolved: {
      waiting_cname: 'CNAME 生成后才能检查解析。',
      not_checked: '还没有检查过当前域名的解析，后台每 10 分钟检查一次。',
      no_domains: '网站没有启用的域名。',
      dns_points_elsewhere: '域名解析指向了其他地址，没有指向本站的 CNAME。',
      dns_not_found: '没有查到域名的解析记录。',
      dns_lookup_failed: '解析查询失败，稍后会自动重试。',
      default: '域名还没有解析到本站的 CNAME。',
    },
    https_cert: {
      https_disabled: '未开启 HTTPS，无需证书。',
      certificate_missing: 'HTTPS 已开启但没有绑定证书。',
      certificate_expired: '证书已过期。',
      certificate_not_yet_valid: '证书还未到生效时间。',
      certificate_revoked: '证书已被吊销。',
      certificate_not_active: '绑定的证书版本还未激活。',
      default: '证书不可用。',
    },
    published: {
      site_disabled: '网站已停用，不会下发到节点。',
      not_published: '网站配置还没有发布到节点。',
      site_not_in_publication: '最近一次发布不包含本网站，网站配置没有在节点上生效。',
      publishing: '正在发布到节点，等待节点回执。',
      publish_failed: '最近一次发布没有在全部节点上成功。',
      default: '网站配置还没有在节点上生效。',
    },
  },
  advice: {
    dnsTarget: '在域名服务商处把域名的 CNAME 记录指向 {{cname}}。',
    waitDNS: '解析修改后通常几分钟到几小时生效，可点“立即检查”。',
    waitPublish: '稍等片刻，发布完成后会自动更新。',
    tenantPlatform: '这需要平台处理，请联系管理员。网站配置已保存。',
    adminLineGroup: '为网站、套餐或平台默认线路组配置可用线路。',
    adminNodes: '检查线路组里的节点是否在线、已启用且未被隔离。',
    adminPublish: '在发布记录里查看失败的节点。',
    tenantPublish: '可稍后重试保存；仍失败请联系管理员。',
    enableSite: '启用网站后会重新发布。',
    bindCertificate: '在 HTTPS 设置里绑定或更新证书。',
  },
  actions: {
    goLineGroups: '去线路组',
    goNodes: '去节点列表',
    goPublications: '去发布记录',
    contactAdmin: '联系管理员（提交工单）',
    goHttps: '去 HTTPS 设置',
  },
}

const enUS: typeof zhCN = {
  title: 'Access status',
  description: 'Whether visitors can reach this site through its CNAME, check by check.',
  checkNow: 'Check now',
  checkedAt: 'Checked {{time}}',
  notChecked: 'Not checked yet',
  throttled: 'Checked just now; try again in {{seconds}} s',
  checkFailed: 'The check failed; try again later',
  pass: 'Passed',
  fail: 'Not passed',
  state: {
    ready: 'Access ready',
    pending: 'Access not ready: {{check}}',
    blocked: 'Access blocked: {{check}}',
  },
  checks: {
    package: 'Valid package',
    line_group: 'Usable line',
    cname_generated: 'CNAME generated',
    dns_resolved: 'Domains point at the CNAME',
    https_cert: 'Valid HTTPS certificate',
    published: 'Published to nodes',
  },
  short: {
    package: { default: 'not served', no_package: 'no package bound', package_disabled: 'package disabled', package_deleted: 'package deleted' },
    line_group: { default: 'no usable line', no_line_group: 'no usable line', no_online_nodes: 'no online node on the line' },
    cname_generated: { default: 'CNAME not generated', cname_pending: 'CNAME generating' },
    dns_resolved: { default: 'DNS not pointed at the CNAME', not_checked: 'DNS not pointed at the CNAME', waiting_cname: 'waiting for the CNAME' },
    https_cert: { default: 'HTTPS certificate not valid', certificate_missing: 'HTTPS needs a certificate' },
    published: { default: 'not published to nodes', publishing: 'publishing', publish_failed: 'publishing failed', site_disabled: 'site disabled' },
  },
  reasons: {
    package: {
      no_package: 'No package is bound, so the site is not served: sites without a valid package are not sent to nodes.',
      package_disabled: 'The bound package is disabled, so the site is not sent to nodes.',
      package_deleted: 'The bound package was deleted, so the site is not sent to nodes.',
      default: 'The site has no valid package, so it is not served.',
    },
    line_group: {
      no_line_group: 'The site has no usable line group (none on the site, its package or as the platform default).',
      no_online_nodes: 'The line group has no online, schedulable node.',
      default: 'The site has no usable line.',
    },
    cname_generated: {
      cname_pending: 'The CNAME is being generated; this usually takes a few minutes.',
      default: 'Generating the CNAME failed; see the CNAME under Basic settings.',
    },
    dns_resolved: {
      waiting_cname: 'DNS can be checked once the CNAME exists.',
      not_checked: 'The current domains have not been checked yet; they are checked every 10 minutes.',
      no_domains: 'The site has no enabled domain.',
      dns_points_elsewhere: 'A domain resolves to another address, not to the site CNAME.',
      dns_not_found: 'No DNS record was found for a domain.',
      dns_lookup_failed: 'The DNS lookup failed; it is retried automatically.',
      default: 'The domains do not resolve to the site CNAME yet.',
    },
    https_cert: {
      https_disabled: 'HTTPS is off; no certificate is needed.',
      certificate_missing: 'HTTPS is on but no certificate is bound.',
      certificate_expired: 'The certificate has expired.',
      certificate_not_yet_valid: 'The certificate is not valid yet.',
      certificate_revoked: 'The certificate was revoked.',
      certificate_not_active: 'The bound certificate version is not active yet.',
      default: 'The certificate cannot be used.',
    },
    published: {
      site_disabled: 'The site is disabled and is not sent to nodes.',
      not_published: 'The site settings have not been published to nodes yet.',
      site_not_in_publication: 'The latest publication does not include this site, so its settings are not live on the nodes.',
      publishing: 'Publishing to nodes; waiting for their receipts.',
      publish_failed: 'The latest publication did not succeed on every node.',
      default: 'The site settings are not live on the nodes yet.',
    },
  },
  advice: {
    dnsTarget: 'At your DNS provider, point each domain’s CNAME record at {{cname}}.',
    waitDNS: 'DNS changes take minutes to hours; use “Check now” afterwards.',
    waitPublish: 'Wait a moment; this updates when publishing finishes.',
    tenantPlatform: 'The platform needs to fix this; contact the administrator. Your site settings are saved.',
    adminLineGroup: 'Configure a usable line for the site, its package or the platform default line group.',
    adminNodes: 'Check that the line group’s nodes are online, enabled and not isolated.',
    adminPublish: 'See the failed nodes in the publication records.',
    tenantPublish: 'Save again later; if it still fails, contact the administrator.',
    enableSite: 'Enable the site to publish it again.',
    bindCertificate: 'Bind or renew a certificate under HTTPS settings.',
  },
  actions: {
    goLineGroups: 'Go to line groups',
    goNodes: 'Go to nodes',
    goPublications: 'Go to publication records',
    contactAdmin: 'Contact the administrator (open a ticket)',
    goHttps: 'Go to HTTPS settings',
  },
}

type Messages = typeof zhCN

function pseudo(value: unknown): unknown {
  if (typeof value === 'string') {
    const tokens: string[] = []
    const protectedValue = value.replace(/\{\{[^{}]+\}\}/g, (token) => {
      tokens.push(token)
      return `__TOKEN_${tokens.length - 1}__`
    })
    return `［¡¡ ${protectedValue.replace(/[A-Za-z\u4e00-\u9fff]/g, '$&$&')} !!］`
      .replace(/__TOKEN_(\d+)__/g, (_match, index: string) => tokens[Number(index)] ?? '')
  }
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudo(child)]),
  )
}

const pseudoCN = pseudo(zhCN) as Messages

export const siteAccessReadinessMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', Messages> = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudoCN,
  'qps-Ploc': pseudoCN,
}

for (const [locale, messages] of Object.entries(siteAccessReadinessMessages)) {
  i18n.addResourceBundle(locale, 'siteAccessReadiness', messages, true, true)
}
