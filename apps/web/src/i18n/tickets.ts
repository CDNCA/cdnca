import i18n from './index'

const zhCN = {
  title: '工单',
  adminTitle: '工单管理',
  subtitle: '遇到问题可以提交工单，客服回复后会按你的消息订阅通知你。',
  adminSubtitle: '处理用户工单：认领、回复、内部备注、改状态和优先级。超过 24 小时未首次回复的工单标为超时。',
  columns: { number: '编号', subject: '标题', category: '分类', status: '状态', priority: '优先级', user: '用户',
    assignee: '处理人', lastReply: '最后回复人', updated: '最近更新', actions: '操作' },
  status: { open: '待处理', processing: '处理中', pending_customer: '待用户回复', resolved: '已解决', closed: '已关闭' },
  categories: { technical: '技术问题', billing: '财务问题', account: '账户问题', abuse: '投诉举报', other: '其他' },
  priorities: { low: '低', normal: '普通', high: '高', urgent: '紧急' },
  filters: { status: '状态', category: '分类', priority: '优先级', assignee: '处理人', search: '编号或标题',
    all: '全部', mine: '我负责的', unassigned: '未分配', slaBreached: '只看超时', reset: '重置', on: '是' },
  summary: { unread: '未读 {{count}}', pending: '待处理 {{count}}', mine: '我负责 {{count}}', sla: '超时 {{count}}' },
  badges: { unread: '新回复', sla: '超时' },
  create: {
    open: '提交工单', title: '提交工单', category: '分类', subject: '标题', body: '问题描述', priority: '紧急程度',
    site: '关联站点 ID（可选）', order: '关联订单 ID（可选）', submit: '提交', cancel: '取消', created: '工单 #{{no}} 已提交',
    badID: '请填写完整的 ID（形如 0190a1b2-…，小写）', relatedNotFound: '找不到该 ID，或它不属于当前账户',
    // p1-tickets：结果未知时只能用同一个幂等键查询/重试，不会重复创建。
    unknown: '提交结果未知（网络中断或服务暂时不可用），工单可能已经提交。点“查询结果/重试”会重放同一次提交，不会重复创建；改了内容再提交则算新工单。',
    checkResult: '查询结果/重试',
  },
  detail: {
    back: '返回列表', meta: '#{{no}} · {{category}} · 创建于 {{created}}', site: '站点：{{domain}}', order: '订单：{{id}}',
    customer: '用户', staff: '客服', internal: '内部备注', empty: '暂无消息',
    reply: '回复', replyPlaceholder: '输入回复内容（纯文本）', note: '作为内部备注（用户不可见）', send: '发送', sent: '已发送',
    close: '关闭工单', closeConfirm: '确认关闭这个工单？', reopen: '重新打开', reopenUntil: '可在 {{until}} 前重新打开',
    closedHint: '工单已结束，如问题仍未解决可以重新打开。', staffClosedHint: '工单已关闭，只能添加内部备注。',
    assignee: '处理人', unassigned: '未分配', claim: '认领', status: '状态', priority: '优先级', updated: '已更新',
    firstResponse: '首次回复：{{time}}', sla: '已超过 24 小时未首次回复',
    unknown: '发送结果未知（网络中断或服务暂时不可用），回复可能已经发出。点“查询结果/重试”会重放同一次发送，不会重复回复；改了内容再发送则算新回复。',
    checkResult: '查询结果/重试',
  },
  // redesign-a：聊天气泡详情、侧栏和列表摘要。
  chat: {
    timeline: '对话', info: '工单信息', summary: '工单概况', filed: '{{name}} 提交了工单', resolved: '工单已解决', closed: '工单已关闭',
    statusChanged: '{{name}} 将状态从「{{from}}」改为「{{to}}」', priorityChanged: '{{name}} 将优先级从「{{from}}」改为「{{to}}」',
    assigneeChanged: '{{name}} 将处理人改为「{{to}}」', assigneeCleared: '{{name}} 取消了处理人', closedBy: '{{name}} 关闭了工单',
    reopenedBy: '{{name}} 重新打开了工单',
    internalOnly: '仅客服可见', notePlaceholder: '写一条内部备注，仅客服可见', drop: '松开即可上传附件',
    shortcut: 'Ctrl/⌘ + Enter 发送', viewUser: '查看用户', site: '关联站点', order: '关联订单', created: '创建时间',
    firstResponse: '首次回复', unread: '未读', pending: '待处理', mine: '我负责', sla: '超时',
    justNow: '刚刚', minutesAgo: '{{count}} 分钟前', hoursAgo: '{{count}} 小时前', daysAgo: '{{count}} 天前',
  },
  // fix-ticket2：管理端代用户新建工单。
  staffCreate: {
    open: '新建工单', title: '新建工单', user: '目标用户', userPlaceholder: '输入用户名、邮箱、手机号或用户 ID 搜索',
    userRequired: '请选择目标用户', userNotFound: '没有匹配的用户', userFailed: '用户列表读取失败',
    body: '首条内容', bodyHint: '以客服身份发出，用户会在工单列表看到并可回复；工单状态为“待用户回复”。',
    assignee: '处理人（可选）', assigneeSelf: '默认由我处理', created: '工单 #{{no}} 已创建',
  },
  // fix-ticket2：工单通知设置（按事件选择站内信/邮件/短信，个人设置）。
  notify: {
    open: '工单通知', title: '工单通知',
    userHint: '选择工单有新回复、状态变化时用哪些方式通知你，可多选，全部关闭即不通知。',
    staffHint: '你个人的工单提醒：新工单、用户回复、超过 24 小时未回复。只影响你自己，不影响其他客服。',
    event: '事件', inbox: '站内信', email: '邮件', sms: '短信', unsupported: '平台未开通',
  },
  // fix-ticketops：管理员改状态、关闭、删除（单个与批量）。
  ops: {
    changeStatus: '改状态', close: '关闭', delete: '删除', closeTicket: '关闭工单', deleteTicket: '删除工单',
    closeConfirm: '关闭工单 #{{no}}？', closeImpact: '用户会收到状态变更通知，可在 7 天内重新打开；关闭后客服只能添加内部备注。',
    deleteConfirm: '删除工单 #{{no}}？', deleteImpact: '删除后用户和客服都看不到这个工单，附件也不能再下载，且无法恢复。对话记录仍保留在数据库供审计。',
    selected: '已选 {{count}} 个', batchClose: '批量关闭', batchDelete: '批量删除', clearSelection: '取消选择',
    batchCloseConfirm: '关闭选中的 {{count}} 个工单？', batchDeleteConfirm: '删除选中的 {{count}} 个工单？',
    closed: '工单已关闭', deleted: '工单已删除', batchDone: '已处理 {{ok}} 个', batchPartial: '已处理 {{ok}} 个，{{failed}} 个失败：{{codes}}',
    confirmOk: '确认', confirmCancel: '取消',
  },
  attachments: {
    preview: '预览',
    add: '添加附件', hint: '最多 {{count}} 个，单个不超过 1 MB；支持 PNG、JPEG、GIF、WebP、PDF、TXT。选择后立即上传，未随工单提交的附件约 24 小时后自动清理', remove: '移除',
    uploading: '上传中…', download: '下载', badType: '不支持的文件类型：{{name}}', badSize: '文件超过 1 MB：{{name}}',
    tooMany: '附件最多 {{count}} 个',
  },
  subscriptions: {
    events: {
      package_monitor_traffic_triggered: '流量超限', package_monitor_traffic_recovered: '流量超限恢复',
      package_monitor_bandwidth_triggered: '带宽超限', package_monitor_bandwidth_recovered: '带宽超限恢复',
      package_monitor_connections_triggered: '连接数超限', package_monitor_connections_recovered: '连接数超限恢复',
      package_monitor_expiration_triggered: '套餐即将到期', package_monitor_expiration_recovered: '套餐到期提醒解除',
      package_auto_renew_failed: '自动续费失败', package_auto_renew_succeeded: '自动续费成功',
      package_monitor_cc_rule_auto_switch: 'CC 防护自动切换',
      security_attack_detected: '网站攻击告警（5 分钟内 WAF/CC 处理达 1000 次，同站 1 小时内不重复）',
      security_waf_auto_exclusion_active: 'WAF 自动排除已生效', security_waf_auto_exclusion_revoked: 'WAF 自动排除已撤销',
      security_waf_auto_exclusion_expired: 'WAF 自动排除已到期',
      certificate_expiring: '证书即将到期', certificate_expired: '证书已过期', certificate_renew_failed: '证书自动续期失败',
      ticket_created: '工单已提交', ticket_replied: '客服回复', ticket_status_changed: '工单状态变化',
      ticket_staff_created: '有新工单', ticket_staff_replied: '用户回复了工单', ticket_staff_overdue: '工单超时未响应',
    },
    // fix-notifsub：消息订阅的 6 个消息类型。
    groups: {
      expiration: { label: '套餐到期', hint: '套餐即将到期或已经到期时通知。' },
      traffic: { label: '流量超限', hint: '套餐流量接近或超过限制时通知。' },
      ccSwitch: { label: '防护规则切换', hint: 'CC 防护规则自动切换时通知。' },
      bandwidth: { label: '带宽超限', hint: '带宽使用超过阈值时通知。' },
      connections: { label: '连接数超限', hint: '连接数超过阈值时通知。' },
      certificate: { label: '证书到期', hint: '证书即将到期、已过期或自动续期失败时通知。' },
    },
    // notif-sub A7：读取失败的行保留并可重试；自动重试成功后恢复显示。
    loading: '加载中…', loadFailed: '读取失败（{{code}}）', saveFailed: '部分保存失败（{{code}}）', retry: '重试',
  },
  errors: {
    forbidden: '需要工单权限', load: '加载失败：{{code}}', failed: '操作失败：{{code}}',
    unavailable: '本主控版本还没有工单系统，升级后可用。', notFound: '工单不存在或无权查看',
    invalidState: '工单当前状态不允许这个操作', reopenExpired: '已超过可重新打开的期限，请提交新工单',
    revisionConflict: '工单刚被别人改过，已重新加载', attachmentsDisabled: '附件存储未配置，暂不能上传附件',
    attachmentRejected: '附件未通过安全扫描', attachmentType: '不支持的附件类型', attachmentSize: '附件超过 1 MB',
    attachmentLimit: '未提交的附件太多，请稍后再试', invalid: '内容有误，请检查后重试',
    stateChanged: '工单状态已变化，已重新读取最新详情',
  },
}

type MessageShape<T> = { [K in keyof T]: T[K] extends string ? string : MessageShape<T[K]> }
type Messages = MessageShape<typeof zhCN>

const enUS: Messages = {
  title: 'Tickets',
  adminTitle: 'Ticket management',
  subtitle: 'File a ticket when you need help. You are notified of replies according to your message subscriptions.',
  adminSubtitle: 'Work customer tickets: claim, reply, add internal notes, change status and priority. Tickets without a first reply after 24 hours are flagged.',
  columns: { number: 'No.', subject: 'Subject', category: 'Category', status: 'Status', priority: 'Priority', user: 'User',
    assignee: 'Assignee', lastReply: 'Last reply by', updated: 'Last update', actions: 'Actions' },
  status: { open: 'Open', processing: 'In progress', pending_customer: 'Awaiting customer', resolved: 'Resolved', closed: 'Closed' },
  categories: { technical: 'Technical', billing: 'Billing', account: 'Account', abuse: 'Abuse report', other: 'Other' },
  priorities: { low: 'Low', normal: 'Normal', high: 'High', urgent: 'Urgent' },
  filters: { status: 'Status', category: 'Category', priority: 'Priority', assignee: 'Assignee', search: 'Number or subject',
    all: 'All', mine: 'Mine', unassigned: 'Unassigned', slaBreached: 'Overdue only', reset: 'Reset', on: 'Yes' },
  summary: { unread: 'Unread {{count}}', pending: 'Open {{count}}', mine: 'Mine {{count}}', sla: 'Overdue {{count}}' },
  badges: { unread: 'New reply', sla: 'Overdue' },
  create: {
    open: 'New ticket', title: 'New ticket', category: 'Category', subject: 'Subject', body: 'Description', priority: 'Urgency',
    site: 'Related site ID (optional)', order: 'Related order ID (optional)', submit: 'Submit', cancel: 'Cancel',
    created: 'Ticket #{{no}} submitted',
    badID: 'Enter the full lowercase ID (like 0190a1b2-…)', relatedNotFound: 'This ID was not found or is not in this account',
    unknown: 'The result is unknown (network error or service unavailable); the ticket may already be filed. "Check result / retry" replays the same submission and never files it twice; changing the content files a new ticket.',
    checkResult: 'Check result / retry',
  },
  detail: {
    back: 'Back to list', meta: '#{{no}} · {{category}} · created {{created}}', site: 'Site: {{domain}}', order: 'Order: {{id}}',
    customer: 'Customer', staff: 'Support', internal: 'Internal note', empty: 'No messages',
    reply: 'Reply', replyPlaceholder: 'Write a reply (plain text)', note: 'Internal note (hidden from the customer)', send: 'Send',
    sent: 'Sent', close: 'Close ticket', closeConfirm: 'Close this ticket?', reopen: 'Reopen', reopenUntil: 'Can be reopened until {{until}}',
    closedHint: 'This ticket is finished. Reopen it if the problem persists.', staffClosedHint: 'This ticket is closed; only internal notes can be added.',
    assignee: 'Assignee', unassigned: 'Unassigned', claim: 'Claim', status: 'Status', priority: 'Priority', updated: 'Updated',
    firstResponse: 'First reply: {{time}}', sla: 'No first reply for more than 24 hours',
    unknown: 'The result is unknown (network error or service unavailable); the reply may already be posted. "Check result / retry" replays the same reply and never posts it twice; changing the content sends a new reply.',
    checkResult: 'Check result / retry',
  },
  chat: {
    timeline: 'Conversation', info: 'Ticket details', summary: 'Ticket overview', filed: '{{name}} filed the ticket', resolved: 'Ticket resolved',
    closed: 'Ticket closed',
    statusChanged: '{{name}} changed the status from "{{from}}" to "{{to}}"', priorityChanged: '{{name}} changed the priority from "{{from}}" to "{{to}}"',
    assigneeChanged: '{{name}} assigned the ticket to "{{to}}"', assigneeCleared: '{{name}} unassigned the ticket', closedBy: '{{name}} closed the ticket',
    reopenedBy: '{{name}} reopened the ticket',
    internalOnly: 'Visible to support only', notePlaceholder: 'Write an internal note, visible to support only',
    drop: 'Drop to attach', shortcut: 'Ctrl/⌘ + Enter to send', viewUser: 'View user', site: 'Site', order: 'Order', created: 'Created',
    firstResponse: 'First reply', unread: 'Unread', pending: 'Open', mine: 'Mine', sla: 'Overdue',
    justNow: 'Just now', minutesAgo: '{{count}} min ago', hoursAgo: '{{count}} h ago', daysAgo: '{{count}} d ago',
  },
  staffCreate: {
    open: 'New ticket', title: 'New ticket', user: 'Target user', userPlaceholder: 'Search by username, email, phone or user ID',
    userRequired: 'Choose the target user', userNotFound: 'No matching user', userFailed: 'Failed to load users',
    body: 'First message', bodyHint: 'Sent as support. The user sees it in their ticket list and can reply; the ticket waits for the user.',
    assignee: 'Assignee (optional)', assigneeSelf: 'Me by default', created: 'Ticket #{{no}} created',
  },
  notify: {
    open: 'Ticket notifications', title: 'Ticket notifications',
    userHint: 'Choose how you hear about replies and status changes. Pick any; turn all off to stop.',
    staffHint: 'Your own ticket alerts: new tickets, customer replies, and tickets unanswered for 24 hours. Other staff are not affected.',
    event: 'Event', inbox: 'In-app', email: 'Email', sms: 'SMS', unsupported: 'Not enabled on this platform',
  },
  ops: {
    changeStatus: 'Change status', close: 'Close', delete: 'Delete', closeTicket: 'Close ticket', deleteTicket: 'Delete ticket',
    closeConfirm: 'Close ticket #{{no}}?', closeImpact: 'The customer is notified of the status change and can reopen it within 7 days; afterwards support can only add internal notes.',
    deleteConfirm: 'Delete ticket #{{no}}?', deleteImpact: 'Neither the customer nor support will see this ticket again and its attachments can no longer be downloaded. This cannot be undone; the conversation stays in the database for audit.',
    selected: '{{count}} selected', batchClose: 'Close selected', batchDelete: 'Delete selected', clearSelection: 'Clear selection',
    batchCloseConfirm: 'Close {{count}} selected tickets?', batchDeleteConfirm: 'Delete {{count}} selected tickets?',
    closed: 'Ticket closed', deleted: 'Ticket deleted', batchDone: '{{ok}} done', batchPartial: '{{ok}} done, {{failed}} failed: {{codes}}',
    confirmOk: 'Confirm', confirmCancel: 'Cancel',
  },
  attachments: {
    preview: 'Preview',
    add: 'Add attachment', hint: 'Up to {{count}} files, 1 MB each; PNG, JPEG, GIF, WebP, PDF, TXT. Files upload when selected; attachments not submitted with a ticket are removed after about 24 hours', remove: 'Remove',
    uploading: 'Uploading…', download: 'Download', badType: 'Unsupported file type: {{name}}', badSize: 'File exceeds 1 MB: {{name}}',
    tooMany: 'At most {{count}} attachments',
  },
  subscriptions: {
    events: {
      package_monitor_traffic_triggered: 'Traffic limit exceeded', package_monitor_traffic_recovered: 'Traffic limit recovered',
      package_monitor_bandwidth_triggered: 'Bandwidth limit exceeded', package_monitor_bandwidth_recovered: 'Bandwidth limit recovered',
      package_monitor_connections_triggered: 'Connection limit exceeded', package_monitor_connections_recovered: 'Connection limit recovered',
      package_monitor_expiration_triggered: 'Package expiring soon', package_monitor_expiration_recovered: 'Expiration alert cleared',
      package_auto_renew_failed: 'Auto-renewal failed', package_auto_renew_succeeded: 'Auto-renewal succeeded',
      package_monitor_cc_rule_auto_switch: 'CC protection auto switch',
      security_attack_detected: 'Website attack alert (1000 WAF/CC actions in 5 minutes, at most hourly per site)',
      security_waf_auto_exclusion_active: 'WAF automatic exclusion in force', security_waf_auto_exclusion_revoked: 'WAF automatic exclusion revoked',
      security_waf_auto_exclusion_expired: 'WAF automatic exclusion expired',
      certificate_expiring: 'Certificate expiring', certificate_expired: 'Certificate expired', certificate_renew_failed: 'Certificate renewal failed',
      ticket_created: 'Ticket submitted', ticket_replied: 'Support reply', ticket_status_changed: 'Status changed',
      ticket_staff_created: 'New ticket', ticket_staff_replied: 'Customer replied', ticket_staff_overdue: 'Ticket overdue',
    },
    groups: {
      expiration: { label: 'Package expiration', hint: 'Notifies you when a package is about to expire or has expired.' },
      traffic: { label: 'Traffic limit exceeded', hint: 'Notifies you when package traffic nears or exceeds its limit.' },
      ccSwitch: { label: 'Protection rule switch', hint: 'Notifies you when CC protection rules switch automatically.' },
      bandwidth: { label: 'Bandwidth limit exceeded', hint: 'Notifies you when bandwidth usage exceeds the threshold.' },
      connections: { label: 'Connection limit exceeded', hint: 'Notifies you when connections exceed the threshold.' },
      certificate: { label: 'Certificate expiration', hint: 'Notifies you when a certificate is about to expire, has expired, or failed to renew.' },
    },
    loading: 'Loading…', loadFailed: 'Failed to load ({{code}})', saveFailed: 'Some changes were not saved ({{code}})', retry: 'Retry',
  },
  errors: {
    forbidden: 'Ticket permission required', load: 'Failed to load: {{code}}', failed: 'Action failed: {{code}}',
    unavailable: 'This controller version has no ticket system yet; upgrade to use it.', notFound: 'Ticket not found or not visible to you',
    invalidState: 'The ticket status does not allow this action', reopenExpired: 'The reopen period has passed; please file a new ticket',
    revisionConflict: 'The ticket was just changed by someone else and has been reloaded',
    attachmentsDisabled: 'Attachment storage is not configured', attachmentRejected: 'The attachment failed the security scan',
    attachmentType: 'Unsupported attachment type', attachmentSize: 'The attachment exceeds 1 MB',
    attachmentLimit: 'Too many pending attachments; try again later', invalid: 'Some input is invalid; please check and retry',
    stateChanged: 'The ticket status has changed; the latest details were reloaded',
  },
}

function pseudoTree(value: unknown): unknown {
  if (typeof value === 'string') return `［${value} · ${value}］`
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudoTree(child)]))
}

const pseudo = pseudoTree(zhCN) as Messages

export const ticketsMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', Messages> = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudo,
  'qps-Ploc': pseudo,
}

for (const [locale, messages] of Object.entries(ticketsMessages)) {
  i18n.addResourceBundle(locale, 'tickets', messages, true, true)
}
