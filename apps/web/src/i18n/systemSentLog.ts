import i18n from './index'

const zhCN = {
  recipient: '收件人', messageID: '消息ID', content: '标题/内容', channel: '媒介', failureCount: '失败次数', status: '状态', reason: '原因', initiatedAt: '发送时间', notRecorded: '未记录', recordedTime: '记录时间：{{time}}', summary: '共 {{count}} 条记录',
  messagePlaceholder: '请输入消息ID', allTypes: '所有类型', allChannels: '所有媒介', allStates: '所有状态', success: '成功', failure: '失败',
  empty: '暂无数据', noSnapshot: '暂无历史快照', user: '用户 {{id}}', anonymous: '匿名收件人', unknownRecipient: '未记录用户', unknownReason: '原因未识别（{{code}}）',
  invalidMessage: '请输入规范的小写消息 UUID', loadFailed: '发信日志加载失败，请刷新重试', permissionDenied: '没有发信日志查看权限',
  sessionExpired: '登录状态已变化，请重新登录',
  events: { accountRecovery: '找回密码', registrationVerification: '注册验证', loginVerification: '登录验证', registrationSuccess: '注册成功' },
  reasons: { cancelled: '发送已取消', provider_outcome_unknown: '发送结果尚未确认', provider_unavailable: '发送服务暂不可用', recipient_unavailable: '未找到可用收件地址', resolver_contract_invalid: '收件地址解析失败', provider_cancelled: '发送已中止', provider_contract_invalid: '发送服务返回异常结果', dispatch_unavailable: '发送服务暂不可用', dispatch_contract_invalid: '发送数据不完整', sender_contract_invalid: '发送结果不符合协议' },
}

const zhTW = {
  recipient: '收件人', messageID: '訊息ID', content: '標題/內容', channel: '媒介', failureCount: '失敗次數', status: '狀態', reason: '原因', initiatedAt: '發送時間', notRecorded: '未記錄', recordedTime: '記錄時間：{{time}}', summary: '共 {{count}} 條記錄',
  messagePlaceholder: '請輸入訊息ID', allTypes: '所有類型', allChannels: '所有媒介', allStates: '所有狀態', success: '成功', failure: '失敗',
  empty: '暫無資料', noSnapshot: '暫無歷史快照', user: '使用者 {{id}}', anonymous: '匿名收件人', unknownRecipient: '未記錄使用者', unknownReason: '原因未識別（{{code}}）',
  invalidMessage: '請輸入規範的小寫訊息 UUID', loadFailed: '發信日誌載入失敗，請重新整理後重試', permissionDenied: '沒有發信日誌檢視權限',
  sessionExpired: '登入狀態已變更，請重新登入',
  events: { accountRecovery: '找回密碼', registrationVerification: '註冊驗證', loginVerification: '登入驗證', registrationSuccess: '註冊成功' },
  reasons: { cancelled: '發送已取消', provider_outcome_unknown: '發送結果尚未確認', provider_unavailable: '發送服務暫不可用', recipient_unavailable: '未找到可用收件地址', resolver_contract_invalid: '收件地址解析失敗', provider_cancelled: '發送已中止', provider_contract_invalid: '發送服務回傳異常結果', dispatch_unavailable: '發送服務暫不可用', dispatch_contract_invalid: '發送資料不完整', sender_contract_invalid: '發送結果不符合協定' },
}

const enUS = {
  recipient: 'Recipient', messageID: 'Message ID', content: 'Title/content', channel: 'Channel', failureCount: 'Failures', status: 'Status', reason: 'Reason', initiatedAt: 'Sent at', notRecorded: 'Not recorded', recordedTime: 'Recorded at: {{time}}', summary: '{{count}} records',
  messagePlaceholder: 'Enter message ID', allTypes: 'All types', allChannels: 'All channels', allStates: 'All statuses', success: 'Succeeded', failure: 'Failed',
  empty: 'No data', noSnapshot: 'Historical snapshot unavailable', user: 'User {{id}}', anonymous: 'Anonymous recipient', unknownRecipient: 'User not recorded', unknownReason: 'Unrecognized reason ({{code}})',
  invalidMessage: 'Enter a canonical lowercase message UUID', loadFailed: 'Sent logs could not be loaded. Refresh to retry.', permissionDenied: 'You cannot view sent logs',
  sessionExpired: 'Your sign-in state has changed. Sign in again.',
  events: { accountRecovery: 'Password recovery', registrationVerification: 'Registration verification', loginVerification: 'Login verification', registrationSuccess: 'Registration completed' },
  reasons: { cancelled: 'Delivery cancelled', provider_outcome_unknown: 'Delivery result not yet confirmed', provider_unavailable: 'Delivery service unavailable', recipient_unavailable: 'No recipient address available', resolver_contract_invalid: 'Recipient address lookup failed', provider_cancelled: 'Delivery stopped', provider_contract_invalid: 'Invalid delivery service response', dispatch_unavailable: 'Delivery service unavailable', dispatch_contract_invalid: 'Incomplete delivery data', sender_contract_invalid: 'Invalid delivery response' },
}

for (const [locale, messages] of Object.entries({ 'zh-CN': zhCN, 'zh-TW': zhTW, 'en-US': enUS })) {
  i18n.addResourceBundle(locale, 'systemSentLog', messages, true, true)
}

if (import.meta.env.MODE === 'test') {
  type Messages = { [key: string]: string | Messages }
  const expand = (messages: Messages): Messages => Object.fromEntries(Object.entries(messages).map(([key, value]) => [key,
    typeof value === 'string' ? `［${value.split(/({{[^}]+}})/g).map((part) => part.startsWith('{{') ? part : part.replace(/\S/g, '$&~')).join('')}］` : expand(value),
  ]))
  for (const locale of ['qps-ploc', 'qps-Ploc']) i18n.addResourceBundle(locale, 'systemSentLog', expand(zhCN), true, true)
}
