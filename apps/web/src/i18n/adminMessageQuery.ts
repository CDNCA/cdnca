import i18n from './index'

type TranslationTree = { [key: string]: string | TranslationTree }

const zhCN = {
  title: '消息查询',
  filters: {
    type: '类型', allTypes: '所有类型',
    userId: '用户', userPlaceholder: '用户名或用户ID',
    packageId: '用户套餐', packagePlaceholder: '套餐名或套餐ID',
    siteId: '网站', sitePlaceholder: '域名或网站ID',
    pageSize: '每页条数',
    otherType: '其他消息（{{type}}）', byId: '按 ID 查询：{{id}}',
    notFound: '没有匹配项', idOnly: '无权搜索名称，请粘贴完整 ID',
  },
  actions: {
    refresh: '刷新', retry: '重试', previous: '上一页', next: '下一页', details: '详情',
  },
  columns: {
    user: '所属用户', type: '类型', title: '标题', package: '用户套餐', site: '网站',
    createdAt: '创建时间', actions: '操作',
    packageUnlinked: '该消息未关联套餐', siteUnlinked: '该消息未关联网站',
  },
  types: {
    announcementPublished: '公告', trafficTriggered: '流量告警', trafficRecovered: '流量恢复',
    bandwidthTriggered: '带宽告警', bandwidthRecovered: '带宽恢复',
    connectionsTriggered: '连接数告警', connectionsRecovered: '连接数恢复',
    expirationTriggered: '套餐到期告警', expirationRecovered: '套餐到期恢复',
    autoRenewSucceeded: '套餐自动续费成功', autoRenewFailed: '套餐自动续费失败', other: '其他消息',
    packageExpiring: '套餐即将到期', packageExpired: '套餐已到期',
    trafficExpiring: '流量即将用尽', trafficExceeded: '流量已用尽',
    ccRuleSwitch: 'CC规则组自动切换', attackDetected: '网站攻击告警', bandwidthExceeded: '套餐带宽超限',
    wafAutoExclusionActive: 'WAF 自动排除已生效', wafAutoExclusionRevoked: 'WAF 自动排除已撤销', wafAutoExclusionExpired: 'WAF 自动排除已到期',
    connectionsExceeded: '套餐连接数超限', certificateExpired: '证书已过期',
    certificateExpiring: '证书即将过期', certificateRenewFailed: '证书自动续期失败', secondaryVerification: '二次实名',
    nodeOffline: '节点离线告警', nodeRecovered: '节点恢复通知', nodeBandwidthExceeded: '节点带宽超限停用', nodeBandwidthRecovered: '节点带宽恢复',
    lineBackupActivated: '线路组启用备用 IP', lineBackupRestored: '线路组恢复主 IP',
    http01EpochDrift: 'HTTP-01 验证期间节点暂不参与解析',
    paymentReconcileMismatch: '支付对账差异', paymentPluginAlert: '支付插件告警', nodeSecurityEvent: '节点安全事件', wafAutoBan: 'WAF 自动封禁', listTruncated: '节点名单超限裁剪', installationBanRejected: '节点拒绝授权状态', nodeInstallTrustFailed: '节点安装信任文档无法自动更新', nodeCertificateRecovered: '节点证书过期自动恢复',
    aggregatedEdgeScheduleAlert: '聚合边缘调度告警', dnspupProbeDegraded: 'dnspup 拨测暂停',
    marketLimitWarn80: '节点市场：限额达到 80%', marketLimitWarn95: '节点市场：限额达到 95%', marketLimitReached: '节点市场：限额已到（暂停/停止）', marketLimitRecovered: '节点市场：限额已恢复', marketPrepaidLow: '节点市场：预付余额低于预警线', marketPrepaidExhausted: '节点市场：预付已用完', marketPrepaidRestored: '节点市场：付款后已恢复', marketOverdraftWarn: '节点市场：透支接近封顶', marketOverdraftCapped: '节点市场：透支已到封顶', marketNodeOverloaded: '节点市场：节点过载已摘除', marketNodeRecovered: '节点市场：节点负载已恢复', marketAllOverloaded: '节点市场：节点池全部过载', marketPluginUnavailable: '节点市场：插件不再提供（退回基础防护）', marketPluginRestored: '节点市场：插件已恢复提供', marketTermsChanged: '节点市场：订阅的供给改价或限额变更（续费前）', marketRenewalStopped: '节点市场：订阅已停止续费（冻结或上游失效）', marketRenewalResumed: '节点市场：订阅已恢复续费', marketRenewalCompensated: '节点市场：上游暂停补偿', marketSupplyReceiptUnconfirmed: '节点市场：订阅配置未能确认', marketFeedbackOpened: '节点市场：收到订阅故障反馈', marketFeedbackUpdated: '节点市场：故障反馈有更新', marketPluginPromoCharge: '插件市场：限免插件即将转为按月收费', marketDownstreamAttacked: '节点市场：下游站点受到攻击', marketComplaintResolved: '节点市场：停止工单已处理', marketComplaintActioned: '节点市场：订阅被平台处置', marketNodeAction: '节点市场：供给节点发生整节点处置', marketSitePaused: '节点市场：站点在供给上已自动暂停', marketSiteResumed: '节点市场：站点已恢复调度', marketCommissionLow: '节点市场：抽成预付余额低于预警线', marketCommissionExhausted: '节点市场：抽成预付余额已用完', marketCommissionRestored: '节点市场：抽成预付已恢复', marketSupplyOutage: '节点市场：供给无在线可用节点', marketSupplyRestored: '节点市场：供给已恢复', marketSupplyCancelAvailable: '节点市场：供给可无责取消', marketDirectTopupPaid: '节点市场：供货方充值已到账', marketDirectTopupReceived: '节点市场：收到订阅方充值', marketSellerDepositMode: '节点市场：保证金设置已调整', marketSellerDepositShortfall: '节点市场：保证金不足', marketSellerDefaultCompensated: '节点市场：失联赔付已到账', marketSellerDefaulted: '节点市场：你已被判定失联', marketSupplyNodeDeliveryFailed: '节点市场：订阅配置未在节点生效',
    originFailover: '回源级别自动切换', originRecovered: '源站已恢复（可手动切回）', paymentMarketTopupRejected: '直结充值到账报告被市场拒收', migratedAccount: '账号已迁移到新平台',
    dnspupNodeUnreachable: 'dnspup 拨测节点不可达', dnspupNodeRecovered: 'dnspup 拨测节点已恢复',
    dnspupBalanceLow: 'dnspup 额度不足预警', dnspupBalanceExhausted: 'dnspup 额度已用完',
    resellerPrepaidLow: '代理商预付余额不足', escalateBlackhole: '攻击自动升级：站点进入黑洞',
    escalateBlackholeDropConfirmed: '攻击自动升级：节点已确认丢弃', escalateCnameChangeRequired: '攻击自动升级：需手动修改 CNAME 解析', escalateUnlimited: '攻击自动升级：站点切到无限防线路组',
    trafficWarning: '流量即将超限', bandwidthOverLimit: '套餐带宽超限', connectionsOverLimit: '套餐连接数超限', ticketCreated: '工单已提交', ticketReplied: '工单有新回复', ticketStatusChanged: '工单状态变化', ticketStaffCreated: '新工单（运营）', ticketStaffReplied: '工单用户回复（运营）', ticketStaffOverdue: '工单超时未响应（运营）',
  },
  details: {
    title: '消息详情', type: '类型', user: '用户', userId: '用户ID', createdAt: '创建时间', messageTitle: '标题',
    email: '邮件内容', sms: '短信内容', empty: '暂无内容',
    packageId: '用户套餐', siteId: '网站', messageId: '消息ID', noSubject: '事件未关联',
    deliveryHint: '下面按渠道显示：是否为该事件生成了消息、当前投递状态和原始内容。重试与失败原因见日志中心的「发送记录」页（按消息ID筛选）。',
    notGenerated: '未生成', notGeneratedHelp: '该事件没有生成这个渠道的消息（渠道未开启、用户未订阅或事件只发其他渠道），不是发送失败。',
  },
  deliveryStates: {
    pending: '等待发送', dispatching: '发送中', retry_wait: '等待重试', accepted: '供应商已接受', unknown: '结果待确认',
    delivered: '已送达', permanent_failed: '永久失败', exhausted: '重试耗尽', cancelled: '已取消',
  },
  pagination: { total: '共 {{total}} 条', pageSize: '{{count}} 条/页' },
  empty: '暂无消息',
  unknown: '未知',
  titleFallback: '{{type}}（无邮件标题）',
  titleFallbackHelp: '该事件没有生成邮件，没有标题；这里显示的是消息类型。',
  errors: {
    forbidden: '无权查询消息', options: '候选项读取失败',
    load: '消息加载失败',
    catalog: '事件目录读取失败，类型筛选暂时无法列出；可刷新页面重试。',
  },
} satisfies TranslationTree

const enUS = {
  title: 'Message Query',
  filters: {
    type: 'Type', allTypes: 'All Types',
    userId: 'User', userPlaceholder: 'Username or user ID',
    packageId: 'User package', packagePlaceholder: 'Package name or ID',
    siteId: 'Site', sitePlaceholder: 'Domain or site ID',
    pageSize: 'Rows per page',
    otherType: 'Other message ({{type}})', byId: 'By ID: {{id}}',
    notFound: 'No match', idOnly: 'No permission to search names; paste the full ID',
  },
  actions: {
    refresh: 'Refresh', retry: 'Retry', previous: 'Previous page', next: 'Next page', details: 'Details',
  },
  columns: {
    user: 'Owner', type: 'Type', title: 'Title', package: 'User package', site: 'Site',
    createdAt: 'Created', actions: 'Actions',
    packageUnlinked: 'This message is not linked to a package', siteUnlinked: 'This message is not linked to a site',
  },
  types: {
    announcementPublished: 'Announcement', trafficTriggered: 'Traffic alert', trafficRecovered: 'Traffic recovered',
    bandwidthTriggered: 'Bandwidth alert', bandwidthRecovered: 'Bandwidth recovered',
    connectionsTriggered: 'Connection alert', connectionsRecovered: 'Connections recovered',
    expirationTriggered: 'Expiration alert', expirationRecovered: 'Expiration recovered',
    autoRenewSucceeded: 'Package auto-renewed', autoRenewFailed: 'Package auto-renew failed', other: 'Other message',
    packageExpiring: 'Package expiring', packageExpired: 'Package expired',
    trafficExpiring: 'Traffic almost exhausted', trafficExceeded: 'Traffic exhausted',
    ccRuleSwitch: 'Automatic CC rule group switch', attackDetected: 'Website attack alert', bandwidthExceeded: 'Package bandwidth exceeded',
    wafAutoExclusionActive: 'WAF automatic exclusion in force', wafAutoExclusionRevoked: 'WAF automatic exclusion revoked', wafAutoExclusionExpired: 'WAF automatic exclusion expired',
    connectionsExceeded: 'Package connections exceeded', certificateExpired: 'Certificate expired',
    certificateExpiring: 'Certificate expiring', certificateRenewFailed: 'Certificate renewal failed', secondaryVerification: 'Secondary identity verification',
    nodeOffline: 'Node offline alert', nodeRecovered: 'Node recovered', nodeBandwidthExceeded: 'Node disabled for bandwidth', nodeBandwidthRecovered: 'Node bandwidth recovered',
    lineBackupActivated: 'Line group switched to backup IPs', lineBackupRestored: 'Line group back on primary IPs',
    http01EpochDrift: 'Nodes held out during HTTP-01 validation',
    paymentReconcileMismatch: 'Payment reconciliation differences', paymentPluginAlert: 'Payment plugin alert', nodeSecurityEvent: 'Node security event', wafAutoBan: 'WAF automatic ban', listTruncated: 'Node list cut to the limit', installationBanRejected: 'Node refused the license state', nodeInstallTrustFailed: 'Node install trust cannot be updated', nodeCertificateRecovered: 'Expired node certificate recovered',
    aggregatedEdgeScheduleAlert: 'Aggregated edge scheduling alert', dnspupProbeDegraded: 'dnspup probing paused',
    marketLimitWarn80: 'Node market: limit at 80%', marketLimitWarn95: 'Node market: limit at 95%', marketLimitReached: 'Node market: limit reached (paused / stopped)', marketLimitRecovered: 'Node market: limit recovered', marketPrepaidLow: 'Node market: prepaid balance below alert line', marketPrepaidExhausted: 'Node market: prepaid exhausted', marketPrepaidRestored: 'Node market: restored after payment', marketOverdraftWarn: 'Node market: overdraft near cap', marketOverdraftCapped: 'Node market: overdraft cap reached', marketNodeOverloaded: 'Node market: node overloaded, removed', marketNodeRecovered: 'Node market: node load recovered', marketAllOverloaded: 'Node market: every pool node overloaded', marketPluginUnavailable: 'Node market: plugin no longer provided (base protection)', marketPluginRestored: 'Node market: plugin provided again', marketTermsChanged: 'Node market: subscribed supply changed price or limits (before renewal)', marketRenewalStopped: 'Node market: subscription stopped renewing (frozen or upstream lost)', marketRenewalResumed: 'Node market: subscription renews again', marketRenewalCompensated: 'Node market: upstream pause compensated', marketSupplyReceiptUnconfirmed: 'Node market: subscription config not confirmed', marketFeedbackOpened: 'Node market: subscription fault report received', marketFeedbackUpdated: 'Node market: fault report updated', marketPluginPromoCharge: 'Plugin market: free-for-now plugin turns monthly', marketDownstreamAttacked: 'Node market: downstream site attacked', marketComplaintResolved: 'Node market: stop ticket resolved', marketComplaintActioned: 'Node market: subscription actioned by the platform', marketNodeAction: 'Node market: whole-node action on a supply node', marketSitePaused: 'Node market: site auto-paused on a supply', marketSiteResumed: 'Node market: site resumed', marketCommissionLow: 'Node market: commission prepaid below alert line', marketCommissionExhausted: 'Node market: commission prepaid exhausted', marketCommissionRestored: 'Node market: commission prepaid restored', marketSupplyOutage: 'Node market: supply has no online node', marketSupplyRestored: 'Node market: supply restored', marketSupplyCancelAvailable: 'Node market: supply can be cancelled without penalty', marketDirectTopupPaid: 'Node market: top-up to supplier credited', marketDirectTopupReceived: 'Node market: top-up received from subscriber', marketSellerDepositMode: 'Node market: deposit setting changed', marketSellerDepositShortfall: 'Node market: deposit shortfall', marketSellerDefaultCompensated: 'Node market: default compensation credited', marketSellerDefaulted: 'Node market: you were judged in default', marketSupplyNodeDeliveryFailed: 'Node market: subscription config not in effect on nodes',
    originFailover: 'Origin level switched automatically', originRecovered: 'Origin recovered (manual failback available)', paymentMarketTopupRejected: 'Direct top-up paid report refused by the market', migratedAccount: 'Account migrated to the new platform',
    dnspupNodeUnreachable: 'dnspup probe node unreachable', dnspupNodeRecovered: 'dnspup probe node recovered',
    dnspupBalanceLow: 'dnspup quota running low', dnspupBalanceExhausted: 'dnspup quota exhausted',
    resellerPrepaidLow: 'Reseller prepaid balance low', escalateBlackhole: 'Attack escalation: site blackholed',
    escalateBlackholeDropConfirmed: 'Attack escalation: nodes confirmed dropping', escalateCnameChangeRequired: 'Attack escalation: CNAME change required', escalateUnlimited: 'Attack escalation: moved to the unlimited line group',
    trafficWarning: 'Traffic limit approaching', bandwidthOverLimit: 'Package bandwidth exceeded', connectionsOverLimit: 'Package connections exceeded', ticketCreated: 'Ticket submitted', ticketReplied: 'Ticket reply', ticketStatusChanged: 'Ticket status changed', ticketStaffCreated: 'New ticket (operators)', ticketStaffReplied: 'Customer ticket reply (operators)', ticketStaffOverdue: 'Ticket overdue (operators)',
  },
  details: {
    title: 'Message details', type: 'Type', user: 'User', userId: 'User ID', createdAt: 'Created', messageTitle: 'Title',
    email: 'Email content', sms: 'SMS content', empty: 'No content',
    packageId: 'User package', siteId: 'Site', messageId: 'Message ID', noSubject: 'Not linked to this event',
    deliveryHint: 'Per channel: whether a message was generated for this event, its delivery state and the original content. Retries and failure reasons are in the Sent messages tab of the log center (filter by message ID).',
    notGenerated: 'Not generated', notGeneratedHelp: 'No message was generated for this channel (channel off, user not subscribed, or the event uses another channel). This is not a delivery failure.',
  },
  deliveryStates: {
    pending: 'Pending', dispatching: 'Dispatching', retry_wait: 'Waiting to retry', accepted: 'Accepted by provider', unknown: 'Outcome unknown',
    delivered: 'Delivered', permanent_failed: 'Permanent failure', exhausted: 'Retries exhausted', cancelled: 'Cancelled',
  },
  pagination: { total: '{{total}} total', pageSize: '{{count}} / page' },
  empty: 'No messages',
  unknown: 'UNKNOWN',
  titleFallback: '{{type}} (no email title)',
  titleFallbackHelp: 'No email was generated for this event, so it has no title; the message type is shown instead.',
  errors: {
    forbidden: 'You cannot query messages', options: 'Could not load options',
    catalog: 'Could not read the event catalog, so the type filter cannot list types. Refresh to retry.',
    load: 'Failed to load messages',
  },
} satisfies TranslationTree

function pseudo(value: string | TranslationTree): string | TranslationTree {
  if (typeof value === 'string') {
    return `［${value.split(/({{[^}]+}})/g).map((part) => (
      part.startsWith('{{') ? part : part.replace(/\S/g, '$&~')
    )).join('')}］`
  }
  return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, pseudo(child)]))
}

for (const [locale, messages] of Object.entries({
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudo(zhCN),
  'qps-Ploc': pseudo(zhCN),
})) {
  i18n.addResourceBundle(locale, 'adminMessageQuery', messages, true, true)
}

export { enUS, zhCN }
