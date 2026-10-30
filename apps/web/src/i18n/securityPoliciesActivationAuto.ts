import i18n from './index'

// waf-tenant-fix（10-22 自动下发）：租户发布安全规则不再填节点/灰度/过期，
// 服务端按站点套餐主备线路组选节点；发布失败按错误码给可读原因与下一步。
const zhCN = {
  activation: {
    autoTargets: '发布目标：本站套餐主备线路组内的全部节点，先灰度 1 个节点，健康后自动全量。',
    autoPublishOnSave: '已保存，正在按套餐线路组下发到节点…',
    errors: {
      package_feature_denied: '当前套餐未开通该防护功能（WAF / CC），无法发布。请联系管理员为套餐开通，或在「套餐」页加购对应升级包后重试。',
      activation_expiry_too_late: '候选过期时间最多为当前时间后 15 分钟，请重新发布。',
      no_target_nodes: '本站套餐的线路组里没有可用节点，无法下发。请联系管理员检查套餐主备线路组的节点状态。',
      validation_error: '发布参数不合法，请刷新页面后重试；如反复出现请联系管理员。',
      publication_state_conflict: '本站点还有安全策略下发未完成（上一次发布仍在灰度或等待节点确认），暂时不能发布新版本。请稍后点「重新加载状态」确认完成后再发布；长时间不结束请联系管理员。',
    },
  },
}

const enUS: typeof zhCN = {
  activation: {
    autoTargets: "Targets: every node of this site's package primary/backup line groups. One node is canaried first, then the rest follow automatically once it is healthy.",
    autoPublishOnSave: "Saved. Publishing to the nodes of the package's line groups…",
    errors: {
      package_feature_denied: 'Your package does not include this protection (WAF / CC), so it cannot be published. Ask an administrator to enable it for the package, or buy the add-on on the Packages page and try again.',
      activation_expiry_too_late: 'A candidate can expire at most 15 minutes from now. Publish again.',
      no_target_nodes: "The site's package line groups have no available node. Ask an administrator to check the nodes of the package's primary/backup line groups.",
      validation_error: 'The publish request is invalid. Reload the page and try again; contact an administrator if it keeps happening.',
      publication_state_conflict: "A security policy release for this site has not finished yet (the previous release is still in canary or waiting for nodes to confirm), so a new version cannot be published now. Click Reload status later and publish again once it has finished; contact an administrator if it does not finish.",
    },
  },
}

/** Codes the activation panel explains itself (activation.errors.<code>). */
export const activationErrorCodes = Object.keys(zhCN.activation.errors)

function pseudo(value: unknown): unknown {
  if (typeof value === 'string') return `［${value}］`
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudo(child)]))
}

export const activationAutoMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', typeof zhCN> = {
  'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudo(zhCN) as typeof zhCN, 'qps-Ploc': pseudo(zhCN) as typeof zhCN,
}

for (const [locale, messages] of Object.entries(activationAutoMessages)) {
  i18n.addResourceBundle(locale, 'securityPolicies', messages, true, true)
}
