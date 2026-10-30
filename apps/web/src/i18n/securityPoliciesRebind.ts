import i18n from './index'

// waf-rebind（10-22 自动下发）：通用规则页修改已绑定站点的规则库后，主控按
// 套餐主备线路组自动重新下发；套餐未开通该功能的站点不下发，在此提示。
// 站点安全规则换绑（换用其他规则库）与撤下；回滚按钮按服务端
// status.rollback 判定可用，不可用时说明原因。
const zhCN = {
  rebind: {
    packageDenied: '{{count}} 个站点因套餐未开通未下发',
    packageDeniedDescription: '这些站点绑定的规则库已有新版本，但所属套餐未开通该防护功能（WAF / CC），节点上仍是旧版规则。为套餐开通或加购对应升级包后会自动下发。',
  },
  activation: {
    actions: {
      rebind: '换用其他规则库', detach: '撤下', detachConfirm: '确认撤下', cancel: '取消',
    },
    facts: { activePolicy: '生效规则库' },
    values: {
      noneActive: '未生效', deletedPolicy: '已删除的规则库（{{id}}）',
      rebindHint: '在上方选择另一个规则库后点「换用其他规则库」：走同样的灰度发布，生效后本站改用新规则库；失败则原规则库继续生效。',
    },
    detachDialog: {
      title: '撤下本站的{{kind}}规则？',
      content: '撤下也是一次灰度发布。生效后，本站节点不再执行「{{name}}」中的{{kind}}规则；发布失败则保持原状。撤下后该规则库不再被本站引用，可以删除。',
    },
    states: { detaching: '撤下中', detached: '已撤下' },
    notices: { rebind: '换绑已启动', detach: '撤下已启动' },
    rollbackReasons: {
      no_candidate: '本站还没有通过发布生效的版本，无法回滚。',
      in_flight: '有发布正在进行，完成或失败后才能回滚。',
      no_previous: '本次生效之前本站没有生效的规则，无可回滚的版本；如需停用请使用「撤下」。',
      previous_policy_deleted: '上一个生效的规则库已删除，无法回滚到它。',
    },
    rollbackTarget: '回滚到：{{name}} v{{version}}',
    errors: {
      security_policy_deleted: '该规则库已删除，不能再绑定到站点。请选择其他规则库。',
    },
  },
}

const enUS: typeof zhCN = {
  rebind: {
    packageDenied: '{{count}} site(s) not published: package does not include this feature',
    packageDeniedDescription: "These sites' bound library has a newer version, but their package does not include this protection (WAF / CC), so their nodes still run the old rules. They are published automatically once the package includes it or the add-on is bought.",
  },
  activation: {
    actions: {
      rebind: 'Switch to another library', detach: 'Withdraw', detachConfirm: 'Withdraw', cancel: 'Cancel',
    },
    facts: { activePolicy: 'Active library' },
    values: {
      noneActive: 'Not active', deletedPolicy: 'Deleted library ({{id}})',
      rebindHint: 'Choose another library above and click "Switch to another library": it goes through the same canary release; once active the site uses the new library, and if it fails the current one stays active.',
    },
    detachDialog: {
      title: 'Withdraw the {{kind}} rules from this site?',
      content: 'Withdrawing is a canary release too. Once active, the nodes stop enforcing the {{kind}} rules of "{{name}}" for this site; if it fails nothing changes. The library is then no longer used by this site and can be deleted.',
    },
    states: { detaching: 'Withdrawing', detached: 'Withdrawn' },
    notices: { rebind: 'Switch started', detach: 'Withdrawal started' },
    rollbackReasons: {
      no_candidate: 'Nothing has been activated for this site by a release yet, so there is nothing to roll back.',
      in_flight: 'A release is in progress; roll back once it completes or fails.',
      no_previous: 'No rules were active before this release, so there is no version to roll back to. Use "Withdraw" to stop enforcing them.',
      previous_policy_deleted: 'The previously active library was deleted, so the site cannot roll back to it.',
    },
    rollbackTarget: 'Rolls back to: {{name}} v{{version}}',
    errors: {
      security_policy_deleted: 'This library is deleted and cannot be bound to a site. Choose another library.',
    },
  },
}

/** Codes the activation panel explains itself (activation.errors.<code>). */
export const rebindErrorCodes = Object.keys(zhCN.activation.errors)

function pseudo(value: unknown): unknown {
  if (typeof value === 'string') return `［${value}］`
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudo(child)]))
}

export const rebindMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', typeof zhCN> = {
  'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudo(zhCN) as typeof zhCN, 'qps-Ploc': pseudo(zhCN) as typeof zhCN,
}

for (const [locale, messages] of Object.entries(rebindMessages)) {
  i18n.addResourceBundle(locale, 'securityPolicies', messages, true, true)
}
