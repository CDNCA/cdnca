import i18n from './index'

const zh = {
  title: '通知策略', loading: '正在加载通知策略', window: '通知时间段', allDay: '全天', custom: '自定义',
  windowHint: '例如 8-22；也支持 08:30-22:15，跨午夜时段可填写 22-8。', timezone: '时区：{{timezone}}',
  expandAll: '全部展开', collapseAll: '全部收起', enabled: '开关', email: '邮件', sms: '短信',
  channels: '通知方式', emailChannel: '电子邮件', smsChannel: '手机短信', intervalLabel: '间隔时间', hours: '小时',
  eventTitle: '{{event}}通知', statusOn: '已开启', statusOff: '已关闭', noChannels: '未选择通知渠道',
  repeat: '连续通知次数', interval: '间隔小时', save: '保存通知策略', refresh: '刷新策略',
  revision: '修订版本 {{revision}}', saved: '通知策略已保存', empty: '暂无通知事件',
  unsupported: '未接入', unsupportedDescription: '该事件尚未接入通知发送，当前配置不可启用。',
  templateBoundary: '邮件和短信模板版本在下方单独管理，当前策略尚不支持逐事件绑定模板。',
  unknownEvent: '其它通知事件（{{event}}）',
  uncertainty: '保存结果待确认', uncertaintyDescription: '请使用同一请求重试，或关闭并刷新确认服务端结果。确认前无法修改此策略。',
  retrySame: '使用同一请求重试', closeAndRefresh: '关闭并刷新',
  errors: {
    forbidden: '无权访问通知策略', read: '通知策略加载失败，请刷新重试。', write: '通知策略保存失败，请检查后重试。',
    conflict: '通知策略版本已变化，请刷新后重新编辑。', validation: '通知策略字段无效，请检查后重试。',
    window: '请输入有效的时间段，例如 8-22 或 08:30-22:15。',
    numbers: '连续通知次数须为 1–10 的整数，间隔小时须为 1–168 的整数。',
    session: '登录状态已变化，请重新登录或刷新页面。',
  },
  events: {
    announcement: '公告发布', trafficTriggered: '流量已超限', trafficWarning: '流量即将超限', trafficRecovered: '流量超限恢复',
    bandwidthTriggered: '套餐带宽预警', bandwidthRecovered: '套餐带宽恢复', bandwidthOverLimit: '套餐带宽超限',
    connectionsTriggered: '套餐连接数预警', connectionsRecovered: '套餐连接数恢复', connectionsOverLimit: '套餐连接数',
    expirationTriggered: '套餐到期预警', expirationRecovered: '套餐到期预警恢复',
    autoRenewSucceeded: '套餐自动续费成功', autoRenewFailed: '套餐自动续费失败', ccSwitch: '网站CC规则自动切换', attackDetected: '网站攻击告警',
    wafAutoExclusionActive: 'WAF 自动排除已生效', wafAutoExclusionRevoked: 'WAF 自动排除已撤销', wafAutoExclusionExpired: 'WAF 自动排除已到期',
    certificateExpired: '证书已过期', certificateExpiring: '证书即将过期', certificateRenewFailed: '证书自动续期失败', secondaryVerification: '二次实名',
    nodeOffline: '节点监控离线', nodeRecovered: '节点监控恢复', nodeBandwidthExceeded: '节点带宽超限自动停用', nodeBandwidthRecovered: '节点带宽恢复自动启用', http01EpochDrift: 'HTTP-01 验证期间节点暂不参与解析', lineBackupActivated: '线路组启用备用 IP', lineBackupRestored: '线路组恢复主 IP',
    paymentReconcileMismatch: '支付对账差异', paymentPluginAlert: '支付插件告警', nodeSecurityEvent: '节点安全事件（内核封禁、XDP 回落/重挂）', wafAutoBan: 'WAF 自动封禁（同 IP 超阈值拉黑）', listTruncated: '节点名单超限裁剪', installationBanRejected: '节点拒绝授权状态（同一修订不再重发）', nodeInstallTrustFailed: '节点安装信任文档无法自动更新（连续 3 次）', nodeCertificateRecovered: '节点证书过期自动恢复',
    aggregatedEdgeScheduleAlert: '聚合边缘调度告警', dnspupProbeDegraded: 'dnspup 拨测暂停',
    marketLimitWarn80: '节点市场：限额达到 80%', marketLimitWarn95: '节点市场：限额达到 95%', marketLimitReached: '节点市场：限额已到（暂停/停止）', marketLimitRecovered: '节点市场：限额已恢复', marketPrepaidLow: '节点市场：预付余额低于预警线', marketPrepaidExhausted: '节点市场：预付已用完', marketPrepaidRestored: '节点市场：付款后已恢复', marketOverdraftWarn: '节点市场：透支接近封顶', marketOverdraftCapped: '节点市场：透支已到封顶', marketNodeOverloaded: '节点市场：节点过载已摘除', marketNodeRecovered: '节点市场：节点负载已恢复', marketAllOverloaded: '节点市场：节点池全部过载', marketPluginUnavailable: '节点市场：插件不再提供（退回基础防护）', marketPluginRestored: '节点市场：插件已恢复提供', marketTermsChanged: '节点市场：订阅的供给改价或限额变更（续费前）', marketRenewalStopped: '节点市场：订阅已停止续费（冻结或上游失效）', marketRenewalResumed: '节点市场：订阅已恢复续费', marketRenewalCompensated: '节点市场：上游暂停补偿', marketSupplyReceiptUnconfirmed: '节点市场：订阅配置未能确认', marketFeedbackOpened: '节点市场：收到订阅故障反馈', marketFeedbackUpdated: '节点市场：故障反馈有更新', marketPluginPromoCharge: '插件市场：限免插件即将转为按月收费', marketDownstreamAttacked: '节点市场：下游站点受到攻击', marketComplaintResolved: '节点市场：停止工单已处理', marketComplaintActioned: '节点市场：订阅被平台处置', marketNodeAction: '节点市场：供给节点发生整节点处置', marketSitePaused: '节点市场：站点在供给上已自动暂停', marketSiteResumed: '节点市场：站点已恢复调度', marketCommissionLow: '节点市场：抽成预付余额低于预警线', marketCommissionExhausted: '节点市场：抽成预付余额已用完', marketCommissionRestored: '节点市场：抽成预付已恢复', marketSupplyOutage: '节点市场：供给无在线可用节点', marketSupplyRestored: '节点市场：供给已恢复', marketSupplyCancelAvailable: '节点市场：供给可无责取消', marketDirectTopupPaid: '节点市场：供货方充值已到账', marketDirectTopupReceived: '节点市场：收到订阅方充值', marketSellerDepositMode: '节点市场：保证金设置已调整', marketSellerDepositShortfall: '节点市场：保证金不足', marketSellerDefaultCompensated: '节点市场：失联赔付已到账', marketSellerDefaulted: '节点市场：你已被判定失联', marketSupplyNodeDeliveryFailed: '节点市场：订阅配置未在节点生效',
    originFailover: '回源级别自动切换', originRecovered: '源站已恢复（可手动切回）', paymentMarketTopupRejected: '直结充值到账报告被市场拒收', migratedAccount: '账号已迁移到新平台',
    ticketCreated: '工单已提交', ticketReplied: '工单有新回复', ticketStatusChanged: '工单状态变化',
    ticketStaffCreated: '新工单（运营）', ticketStaffReplied: '工单用户回复（运营）', ticketStaffOverdue: '工单超时未响应（运营）',
  },
}

const en = {
  title: 'Notification policy', loading: 'Loading notification policy', window: 'Notification window', allDay: 'All day', custom: 'Custom',
  windowHint: 'For example, 8-22 or 08:30-22:15. Use 22-8 for an overnight window.', timezone: 'Time zone: {{timezone}}',
  expandAll: 'Expand all', collapseAll: 'Collapse all', enabled: 'Enabled', email: 'Email', sms: 'SMS',
  channels: 'Notification channels', emailChannel: 'Email', smsChannel: 'SMS', intervalLabel: 'Interval', hours: 'hours',
  eventTitle: '{{event}} notification', statusOn: 'Enabled', statusOff: 'Disabled', noChannels: 'No delivery channels selected',
  repeat: 'Consecutive notifications', interval: 'Interval in hours', save: 'Save notification policy', refresh: 'Refresh policy',
  revision: 'Revision {{revision}}', saved: 'Notification policy saved', empty: 'No notification events',
  unsupported: 'Not connected', unsupportedDescription: 'This event is not connected to notification delivery and cannot be enabled.',
  templateBoundary: 'Email and SMS template versions are managed separately below. Event-specific template binding is not available in this policy.',
  unknownEvent: 'Other notification event ({{event}})',
  uncertainty: 'Save outcome unconfirmed', uncertaintyDescription: 'Retry the same request, or close and refresh to check the server result. This policy cannot be edited until the outcome is resolved.',
  retrySame: 'Retry the same request', closeAndRefresh: 'Close and refresh',
  errors: {
    forbidden: 'You cannot access this notification policy', read: 'The notification policy could not be loaded. Refresh to retry.',
    write: 'The notification policy could not be saved. Check it and retry.', conflict: 'The policy revision has changed. Refresh before editing again.',
    validation: 'The notification policy contains invalid fields. Check them and retry.',
    window: 'Enter a valid window such as 8-22 or 08:30-22:15.',
    numbers: 'Consecutive notifications must be an integer from 1 to 10, and the interval must be an integer from 1 to 168 hours.',
    session: 'Your sign-in state has changed. Sign in again or refresh the page.',
  },
  events: {
    announcement: 'Announcement published', trafficTriggered: 'Traffic limit exceeded', trafficWarning: 'Traffic limit approaching', trafficRecovered: 'Traffic limit recovered',
    bandwidthTriggered: 'Package bandwidth alert', bandwidthRecovered: 'Package bandwidth recovered', bandwidthOverLimit: 'Package bandwidth exceeded',
    connectionsTriggered: 'Package connection alert', connectionsRecovered: 'Package connections recovered', connectionsOverLimit: 'Package connections',
    expirationTriggered: 'Package expiration alert', expirationRecovered: 'Package expiration alert recovered',
    autoRenewSucceeded: 'Package auto-renewed', autoRenewFailed: 'Package auto-renew failed', ccSwitch: 'Automatic website CC rule switch', attackDetected: 'Website attack alert',
    wafAutoExclusionActive: 'WAF automatic exclusion in force', wafAutoExclusionRevoked: 'WAF automatic exclusion revoked', wafAutoExclusionExpired: 'WAF automatic exclusion expired',
    certificateExpired: 'Certificate expired', certificateExpiring: 'Certificate expiring', certificateRenewFailed: 'Certificate renewal failed', secondaryVerification: 'Secondary identity verification',
    nodeOffline: 'Node monitoring offline', nodeRecovered: 'Node monitoring recovered', nodeBandwidthExceeded: 'Node auto-disabled for bandwidth', nodeBandwidthRecovered: 'Node re-enabled after bandwidth recovery', http01EpochDrift: 'Nodes held out during HTTP-01 validation', lineBackupActivated: 'Line group switched to backup IPs', lineBackupRestored: 'Line group back on primary IPs',
    paymentReconcileMismatch: 'Payment reconciliation differences', paymentPluginAlert: 'Payment plugin alert', nodeSecurityEvent: 'Node security events (kernel bans, XDP fallback / reattach)', wafAutoBan: 'WAF automatic bans (per-IP threshold)', listTruncated: 'Node list cut to the limit', installationBanRejected: 'Node refused the license state (the revision is not sent again)', nodeInstallTrustFailed: 'Node install trust cannot be updated automatically (3 checks in a row)', nodeCertificateRecovered: 'Expired node certificate recovered',
    aggregatedEdgeScheduleAlert: 'Aggregated edge scheduling alert', dnspupProbeDegraded: 'dnspup probing paused',
    marketLimitWarn80: 'Node market: limit at 80%', marketLimitWarn95: 'Node market: limit at 95%', marketLimitReached: 'Node market: limit reached (paused / stopped)', marketLimitRecovered: 'Node market: limit recovered', marketPrepaidLow: 'Node market: prepaid balance below alert line', marketPrepaidExhausted: 'Node market: prepaid exhausted', marketPrepaidRestored: 'Node market: restored after payment', marketOverdraftWarn: 'Node market: overdraft near cap', marketOverdraftCapped: 'Node market: overdraft cap reached', marketNodeOverloaded: 'Node market: node overloaded, removed', marketNodeRecovered: 'Node market: node load recovered', marketAllOverloaded: 'Node market: every pool node overloaded', marketPluginUnavailable: 'Node market: plugin no longer provided (base protection)', marketPluginRestored: 'Node market: plugin provided again', marketTermsChanged: 'Node market: subscribed supply changed price or limits (before renewal)', marketRenewalStopped: 'Node market: subscription stopped renewing (frozen or upstream lost)', marketRenewalResumed: 'Node market: subscription renews again', marketRenewalCompensated: 'Node market: upstream pause compensated', marketSupplyReceiptUnconfirmed: 'Node market: subscription config not confirmed', marketFeedbackOpened: 'Node market: subscription fault report received', marketFeedbackUpdated: 'Node market: fault report updated', marketPluginPromoCharge: 'Plugin market: free-for-now plugin turns monthly', marketDownstreamAttacked: 'Node market: downstream site attacked', marketComplaintResolved: 'Node market: stop ticket resolved', marketComplaintActioned: 'Node market: subscription actioned by the platform', marketNodeAction: 'Node market: whole-node action on a supply node', marketSitePaused: 'Node market: site auto-paused on a supply', marketSiteResumed: 'Node market: site resumed', marketCommissionLow: 'Node market: commission prepaid below alert line', marketCommissionExhausted: 'Node market: commission prepaid exhausted', marketCommissionRestored: 'Node market: commission prepaid restored', marketSupplyOutage: 'Node market: supply has no online node', marketSupplyRestored: 'Node market: supply restored', marketSupplyCancelAvailable: 'Node market: supply can be cancelled without penalty', marketDirectTopupPaid: 'Node market: top-up to supplier credited', marketDirectTopupReceived: 'Node market: top-up received from subscriber', marketSellerDepositMode: 'Node market: deposit setting changed', marketSellerDepositShortfall: 'Node market: deposit shortfall', marketSellerDefaultCompensated: 'Node market: default compensation credited', marketSellerDefaulted: 'Node market: you were judged in default', marketSupplyNodeDeliveryFailed: 'Node market: subscription config not in effect on nodes',
    originFailover: 'Origin level switched automatically', originRecovered: 'Origin recovered (manual failback available)', paymentMarketTopupRejected: 'Direct top-up paid report refused by the market', migratedAccount: 'Account migrated to the new platform',
    ticketCreated: 'Ticket submitted', ticketReplied: 'Ticket reply', ticketStatusChanged: 'Ticket status changed',
    ticketStaffCreated: 'New ticket (operators)', ticketStaffReplied: 'Customer ticket reply (operators)', ticketStaffOverdue: 'Ticket overdue (operators)',
  },
}

export const notificationPolicyMessages = { 'zh-CN': zh, 'en-US': en }
for (const [locale, messages] of Object.entries(notificationPolicyMessages)) {
  i18n.addResourceBundle(locale, 'notificationPolicy', messages, true, true)
}

if (import.meta.env.MODE === 'test') {
  type Messages = { [key: string]: string | Messages }
  const expand = (messages: Messages): Messages => Object.fromEntries(Object.entries(messages).map(([key, value]) => [key,
    typeof value === 'string'
      ? `［${value.split(/({{[^}]+}})/g).map((part) => part.startsWith('{{') ? part : [...part].map((character) => /\s/u.test(character) ? character : `${character}~`).join('')).join('')}］`
      : expand(value),
  ]))
  for (const locale of ['qps-ploc', 'qps-Ploc']) i18n.addResourceBundle(locale, 'notificationPolicy', expand(zh), true, true)
}
