const messages = {
  'zh-CN': {
    backup_reason_terminal_recorded: '已取得可验证的结束记录', backup_reason_terminal_unavailable: '尚未取得可验证的结束记录', backup_reason_binding_conflict: '备份记录与当前主控不匹配', backup_reason_signature_invalid: '备份记录签名或完整性校验失败', backup_reason_legacy_untracked: '缺少受信任的备份运行记录', backup_reason_start_unavailable: '备份开始记录不可用',
    backup_result_backup_succeeded: '备份成功', backup_result_backup_outcome_unknown: '结果未知', backup_result_backup_invalid_config: '备份配置无效', backup_result_backup_capture_failed: '备份数据采集失败', backup_result_backup_invalid_result: '备份结果未通过校验', backup_result_backup_manifest_failed: '备份清单生成失败', backupUnknownCode: '未识别的记录代码（{{code}}）',
    backup: '备份日志', sent: '发信日志',
    viewDetails: '查看详情', close: '关闭',
    userIDColumn: '用户ID',
    backupTimeColumn: '备份时间', completionTimeColumn: '完成时间', backupStateColumn: '状态', backupResultColumn: '结果', backupID: '备份 ID', backupStateSucceeded: '成功', backupStateFailed: '失败', backupStateUnknown: '未知', backupResultSucceeded: '备份成功', backupResultFailed: '备份失败', backupResultUnknown: '结果未知', backupOutcomeUnknown: '终态未记录', backupDetails: '备份详情', backupReason: '判定原因', backupSignature: '签名校验', backupSignatureValid: '有效', backupSignatureInvalid: '无效或不可用', backupTerminalState: '终态', backupManifest: '清单摘要', backupRecoveryPoint: '恢复点', backupObservedRPO: '观测 RPO', backupPermissionDenied: '没有备份历史查看权限', backupUnavailable: '备份历史暂不可用，请检查受保护的运行目录和签名信任是否已挂载。', backupLoadFailed: '备份历史加载失败，请稍后重试。',
    notRecorded: '未记录', backupStateCompleted: '已完成', backupSummary: '共 {{count}} 条记录，当前页 {{page}} 条', userPlaceholder: '请输入用户ID', refresh: '刷新',
    total: '共 {{count}} 条', pageSize: '条/页', perPage: '条/页', pagination: '分页', previous: '上一页', next: '下一页', emptyBackup: '暂无备份日志', backupUnconfigured: '尚未配置备份目标，没有历史', invalidUser: '请输入用户 ID 或规范的小写用户 UUID'
  },
  'zh-TW': {
    backup_reason_terminal_recorded: '已取得可驗證的結束記錄', backup_reason_terminal_unavailable: '尚未取得可驗證的結束記錄', backup_reason_binding_conflict: '備份記錄與目前主控不符', backup_reason_signature_invalid: '備份記錄簽名或完整性驗證失敗', backup_reason_legacy_untracked: '缺少受信任的備份執行記錄', backup_reason_start_unavailable: '備份開始記錄不可用',
    backup_result_backup_succeeded: '備份成功', backup_result_backup_outcome_unknown: '結果未知', backup_result_backup_invalid_config: '備份設定無效', backup_result_backup_capture_failed: '備份資料收集失敗', backup_result_backup_invalid_result: '備份結果未通過驗證', backup_result_backup_manifest_failed: '備份清單產生失敗', backupUnknownCode: '未識別的記錄代碼（{{code}}）',
    backup: '備份日誌', sent: '發信日誌',
    viewDetails: '查看詳情', close: '關閉',
    userIDColumn: '使用者 ID',
    backupTimeColumn: '備份時間', completionTimeColumn: '完成時間', backupStateColumn: '狀態', backupResultColumn: '結果', backupID: '備份 ID', backupStateSucceeded: '成功', backupStateFailed: '失敗', backupStateUnknown: '未知', backupResultSucceeded: '備份成功', backupResultFailed: '備份失敗', backupResultUnknown: '結果未知', backupOutcomeUnknown: '終態未記錄', backupDetails: '備份詳情', backupReason: '判定原因', backupSignature: '簽名驗證', backupSignatureValid: '有效', backupSignatureInvalid: '無效或不可用', backupTerminalState: '終態', backupManifest: '清單摘要', backupRecoveryPoint: '復原點', backupObservedRPO: '觀測 RPO', backupPermissionDenied: '沒有備份歷史檢視權限', backupUnavailable: '備份歷史暫不可用，請檢查受保護的執行目錄和簽名信任是否已掛載。', backupLoadFailed: '備份歷史載入失敗，請稍後重試。',
    notRecorded: '未記錄', backupStateCompleted: '已完成', backupSummary: '共 {{count}} 筆記錄，當前頁 {{page}} 筆', userPlaceholder: '請輸入使用者 ID', refresh: '重新整理',
    total: '共 {{count}} 筆', pageSize: '筆/頁', perPage: '筆/頁', pagination: '分頁', previous: '上一頁', next: '下一頁', emptyBackup: '暫無備份日誌', backupUnconfigured: '尚未設定備份目標，沒有歷史', invalidUser: '請輸入使用者 ID 或標準的小寫使用者 UUID'
  },
  'en-US': {
    backup_reason_terminal_recorded: 'A verified completion record is available', backup_reason_terminal_unavailable: 'A verified completion record is not yet available', backup_reason_binding_conflict: 'The backup record does not match this controller', backup_reason_signature_invalid: 'Backup record signature or integrity verification failed', backup_reason_legacy_untracked: 'No trusted backup run record is available', backup_reason_start_unavailable: 'The backup start record is unavailable',
    backup_result_backup_succeeded: 'Backup succeeded', backup_result_backup_outcome_unknown: 'Outcome unknown', backup_result_backup_invalid_config: 'Backup configuration is invalid', backup_result_backup_capture_failed: 'Backup data capture failed', backup_result_backup_invalid_result: 'Backup result validation failed', backup_result_backup_manifest_failed: 'Backup manifest creation failed', backupUnknownCode: 'Unrecognized record code ({{code}})',
    backup: 'Backup logs', sent: 'Sent logs',
    viewDetails: 'View details', close: 'Close',
    userIDColumn: 'User ID',
    backupTimeColumn: 'Backup time', completionTimeColumn: 'Completion time', backupStateColumn: 'Status', backupResultColumn: 'Result', backupID: 'Backup ID', backupStateSucceeded: 'Succeeded', backupStateFailed: 'Failed', backupStateUnknown: 'Unknown', backupResultSucceeded: 'Backup succeeded', backupResultFailed: 'Backup failed', backupResultUnknown: 'Outcome unknown', backupOutcomeUnknown: 'Terminal fact unavailable', backupDetails: 'Backup details', backupReason: 'Decision reason', backupSignature: 'Signature verification', backupSignatureValid: 'Valid', backupSignatureInvalid: 'Invalid or unavailable', backupTerminalState: 'Terminal state', backupManifest: 'Manifest digest', backupRecoveryPoint: 'Recovery point', backupObservedRPO: 'Observed RPO', backupPermissionDenied: 'You do not have permission to view backup history', backupUnavailable: 'Backup history is unavailable. Check the protected run directory and signing trust mount.', backupLoadFailed: 'Backup history could not be loaded. Try again later.',
    notRecorded: 'Not recorded', backupStateCompleted: 'Completed', backupSummary: '{{count}} records, {{page}} on this page', userPlaceholder: 'Enter user ID', refresh: 'Refresh',
    total: '{{count}} total', pageSize: 'per page', perPage: 'per page', pagination: 'Pagination', previous: 'Previous page', next: 'Next page', emptyBackup: 'No backup logs', backupUnconfigured: 'No backup target is configured, so there is no history', invalidUser: 'Enter a display ID or canonical lowercase user UUID'
  },
} as const

type Key = keyof typeof messages['zh-CN']
const pseudo = Object.fromEntries(Object.entries(messages['zh-CN']).map(([key, value]) => [key, `［${[...value].map((character) => /\s|\d/.test(character) ? character : `${character}~`).join('')}］`])) as Record<Key, string>
export const systemLogMessages = { ...messages, 'qps-ploc': pseudo, 'qps-Ploc': pseudo } as const

export function systemLogCodeMessage(language: string, category: 'backup_reason' | 'backup_result', code: string): string {
  const key = `${category}_${code}`
  if (Object.hasOwn(messages['zh-CN'], key)) return systemLogMessage(language, key as Key)
  return systemLogMessage(language, 'backupUnknownCode', { code })
}

export function systemLogMessage(language: string, key: Key, variables: Record<string, string | number> = {}): string {
  const normalized = language.toLowerCase()
  const locale = normalized === 'en-us' ? 'en-US' : normalized === 'zh-tw' ? 'zh-TW' : normalized === 'qps-ploc' ? 'qps-ploc' : 'zh-CN'
  return systemLogMessages[locale][key].replace(/{{(\w+)}}/g, (_, name) => String(variables[name] ?? ''))
}
