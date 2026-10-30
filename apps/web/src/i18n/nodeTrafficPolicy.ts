import i18n from './index'

type TranslationTree = { [key: string]: string | TranslationTree }

const zhCN = {
  title: '节点流量与自动状态策略',
  description: '按节点自然月流量和定时时段自动停用或恢复，管理员状态始终优先。',
  loading: '正在加载节点流量策略',
  actions: {
    save: '保存策略', refresh: '刷新', retry: '重试', evaluate: '立即评估',
    advanced: '高级定时设置', addWindow: '添加停用时段', removeWindow: '删除时段',
  },
  fields: {
    monthlyLimit: '自然月流量上限（字节）', timezone: '结算时区', override: '手工覆盖',
    overrideExpiry: '覆盖到期时间', weekday: '星期', startMinute: '开始分钟', endMinute: '结束分钟',
  },
  values: {
    unlimited: '0 表示不限制', none: '不覆盖', forceEnabled: '强制启用', forceDisabled: '强制停用',
    active: '运行中', disabled: '管理员停用', retired: '已退役', pending: '待审批', draining: '排空中',
    unknown: '未知状态',
    weekdays: { sunday: '周日', monday: '周一', tuesday: '周二', wednesday: '周三', thursday: '周四', friday: '周五', saturday: '周六' },
  },
  state: {
    current: '当前节点状态：{{state}}', noEvaluation: '尚无自动评估记录', saveBeforeEvaluate: '请先保存初始策略，再执行自动评估。',
    evaluation: '周期 {{period}}，原因：{{reason}}', sync: '配置同步：{{status}}',
  },
  reasons: {
    within_policy: '未达到停用条件', monthly_limit_reached: '自然月流量已达到上限',
    scheduled_window: '当前处于定时停用时段', manual_force_enabled: '管理员临时强制启用',
    manual_force_disabled: '管理员临时强制停用', admin_state_protected: '管理员状态受保护',
    period_reset: '新自然月已恢复', policy_recovered: '策略条件解除后已恢复',
    unknown: '原因暂无法识别，请联系管理员核对。',
  },
  sync: { queued: '等待下发', running: '正在下发', succeeded: '同步成功', failed: '同步失败', unknown: '同步状态暂无法识别' },
  validation: {
    identity: '缺少有效的节点或作用域 ID', monthlyLimit: '流量上限必须是不小于 0 的安全整数',
    timezone: '请输入有效的 IANA 时区', minute: '分钟必须为 0 到 1439，开始与结束不能相同',
    overrideExpiry: '启用手工覆盖时必须设置未来的到期时间',
  },
  errors: {
    forbidden: '无权查看节点流量策略', load: '节点流量策略暂不可用，请稍后重试',
    write: '节点流量策略保存失败', permissionDenied: '无权修改节点流量策略',
    conflict: '策略已被其他操作修改，请刷新后重试', evaluate: '自动评估失败，现有节点状态保持不变',
  },
  notices: { saved: '节点流量策略已保存', evaluated: '节点流量策略评估完成' },
} satisfies TranslationTree

const enUS = {
  title: 'Node Traffic and Automatic State Policy',
  description: 'Automatically suppress or restore a node by natural-month traffic and scheduled windows. Administrative state always wins.',
  loading: 'Loading node traffic policy',
  actions: {
    save: 'Save Policy', refresh: 'Refresh', retry: 'Retry', evaluate: 'Evaluate Now',
    advanced: 'Advanced Schedule', addWindow: 'Add Suppression Window', removeWindow: 'Remove Window',
  },
  fields: {
    monthlyLimit: 'Natural-month Traffic Limit (bytes)', timezone: 'Settlement Timezone', override: 'Manual Override',
    overrideExpiry: 'Override Expiry', weekday: 'Weekday', startMinute: 'Start Minute', endMinute: 'End Minute',
  },
  values: {
    unlimited: '0 means unlimited', none: 'No Override', forceEnabled: 'Force Enabled', forceDisabled: 'Force Disabled',
    active: 'Active', disabled: 'Administratively Disabled', retired: 'Retired', pending: 'Pending', draining: 'Draining',
    unknown: 'Unknown state',
    weekdays: { sunday: 'Sunday', monday: 'Monday', tuesday: 'Tuesday', wednesday: 'Wednesday', thursday: 'Thursday', friday: 'Friday', saturday: 'Saturday' },
  },
  state: {
    current: 'Current node state: {{state}}', noEvaluation: 'No automatic evaluation yet', saveBeforeEvaluate: 'Save the initial policy before evaluating it.',
    evaluation: 'Period {{period}}, reason: {{reason}}', sync: 'Configuration sync: {{status}}',
  },
  reasons: {
    within_policy: 'No suppression condition matched', monthly_limit_reached: 'Natural-month traffic limit reached',
    scheduled_window: 'Scheduled suppression window is active', manual_force_enabled: 'Temporarily forced enabled',
    manual_force_disabled: 'Temporarily forced disabled', admin_state_protected: 'Administrative state is protected',
    period_reset: 'Restored for a new natural month', policy_recovered: 'Restored after policy conditions cleared',
    unknown: 'The reason is not recognized. Ask an administrator to verify it.',
  },
  sync: { queued: 'Queued', running: 'Running', succeeded: 'Succeeded', failed: 'Failed', unknown: 'Unknown sync state' },
  validation: {
    identity: 'A valid node and scope ID are required', monthlyLimit: 'Traffic limit must be a non-negative safe integer',
    timezone: 'Enter a valid IANA timezone', minute: 'Minutes must be 0 through 1439 and cannot be equal',
    overrideExpiry: 'A future expiry is required when an override is enabled',
  },
  errors: {
    forbidden: 'You cannot view node traffic policy', load: 'Node traffic policy is temporarily unavailable',
    write: 'Failed to save node traffic policy', permissionDenied: 'You cannot change node traffic policy',
    conflict: 'The policy changed elsewhere. Refresh and try again.', evaluate: 'Evaluation failed; existing node state was preserved',
  },
  notices: { saved: 'Node traffic policy saved', evaluated: 'Node traffic policy evaluated' },
} satisfies TranslationTree

function pseudo(value: string | TranslationTree): string | TranslationTree {
  if (typeof value === 'string') return `［${value.replace(/\S/g, '$&~')}］`
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, pseudo(item)]))
}

export const nodeTrafficPolicyResources = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudo(zhCN),
  'qps-Ploc': pseudo(zhCN),
}

for (const [locale, messages] of Object.entries(nodeTrafficPolicyResources)) {
  i18n.addResourceBundle(locale, 'nodeTrafficPolicy', messages, true, true)
}

export { enUS, zhCN }
