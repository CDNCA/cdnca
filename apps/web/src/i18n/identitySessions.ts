import i18n from './index'

const zhCN = {
  title: '登录设备',
  description: '查看当前账户的登录设备，并撤销不再使用的会话。',
  loading: '正在加载登录设备',
  empty: '暂无登录设备',
  columns: {
    device: '设备', network: '登录网络', lastActive: '最近活跃', sessions: '会话数', status: '状态', actions: '操作',
  },
  values: {
    current: '当前设备', active: '活跃', expired: '已过期', revoked: '已撤销', unknownNetwork: '未知网络', count: '{{count}} 个',
  },
  actions: {
    refresh: '刷新', retry: '重试', previous: '上一页', next: '下一页', revoke: '撤销设备',
    confirmRevoke: '确认撤销', cancel: '取消', retrySame: '使用同一请求重试', abandonRefresh: '放弃并刷新',
  },
  confirmation: {
    title: '确认撤销设备', other: '撤销后，该设备上的所有会话将立即失效。', current: '撤销当前设备后，您需要重新登录。',
  },
  uncertainty: {
    title: '撤销结果待确认', description: '只能使用完全相同的设备、版本、幂等键和请求标识重试，或放弃并完成一次权威刷新。',
  },
  errors: {
    forbiddenTitle: '无权查看登录设备', forbiddenDescription: '当前身份不能访问该账户的登录设备。',
    unavailable: '登录设备服务暂不可用，请稍后重试。', unauthenticated: '登录状态已失效，请重新登录。',
    revisionConflict: '设备会话已更新，请刷新后重试。', idempotencyConflict: '请求标识与原操作不一致，请放弃并刷新。',
    notFound: '设备会话不存在或已不可访问。', alreadyRevoked: '该设备会话已经撤销。', requestFailed: '无法完成登录设备操作，请稍后重试。',
  },
} as const

const enUS = {
  title: 'Signed-in devices',
  description: 'Review devices signed in to this account and revoke sessions you no longer use.',
  loading: 'Loading signed-in devices',
  empty: 'No signed-in devices',
  columns: {
    device: 'Device', network: 'Sign-in network', lastActive: 'Last active', sessions: 'Sessions', status: 'Status', actions: 'Actions',
  },
  values: {
    current: 'Current device', active: 'Active', expired: 'Expired', revoked: 'Revoked', unknownNetwork: 'Unknown network', count: '{{count}}',
  },
  actions: {
    refresh: 'Refresh', retry: 'Retry', previous: 'Previous', next: 'Next', revoke: 'Revoke device',
    confirmRevoke: 'Confirm revoke', cancel: 'Cancel', retrySame: 'Retry the same request', abandonRefresh: 'Abandon and refresh',
  },
  confirmation: {
    title: 'Confirm device revocation', other: 'All sessions on this device will become invalid immediately.', current: 'Revoking this device will require you to sign in again.',
  },
  uncertainty: {
    title: 'Revocation outcome unconfirmed', description: 'Retry only with the exact device, revision, idempotency key, and request identity, or abandon and complete an authoritative refresh.',
  },
  errors: {
    forbiddenTitle: 'Device access denied', forbiddenDescription: 'The current identity cannot access this account\'s signed-in devices.',
    unavailable: 'The device session service is temporarily unavailable. Try again later.', unauthenticated: 'Your sign-in has expired. Sign in again.',
    revisionConflict: 'The device session changed. Refresh and try again.', idempotencyConflict: 'The request identity differs from the original operation. Abandon and refresh.',
    notFound: 'The device session does not exist or is no longer accessible.', alreadyRevoked: 'This device session has already been revoked.', requestFailed: 'The device session operation could not be completed. Try again later.',
  },
} as const

type MessageTree = { [key: string]: string | MessageTree }
function pseudoText(value: string): string {
  const expanded = value.split(/({{[^}]+}})/g).map((part) => part.startsWith('{{')
    ? part
    : [...part].map((character) => /\s/u.test(character) ? character : `${character}~`).join('')).join('')
  return `［${expanded}］`
}
function pseudoTree(value: unknown): unknown {
  return typeof value === 'string'
    ? pseudoText(value)
    : Object.fromEntries(Object.entries(value as Record<string, unknown>)
      .map(([key, child]) => [key, pseudoTree(child)]))
}

const pseudoCN = pseudoTree(zhCN) as MessageTree
export const identitySessionMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', MessageTree> = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudoCN,
  'qps-Ploc': pseudoCN,
}
for (const [locale, messages] of Object.entries(identitySessionMessages)) {
  i18n.addResourceBundle(locale, 'identitySessions', messages, true, true)
}
