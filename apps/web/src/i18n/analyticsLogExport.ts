const messages = {
  'zh-CN': {
    create: '申请下载', title: '访问日志导出', refresh: '刷新导出状态', download: '下载',
    empty: '暂无导出任务', pending: '等待处理', running: '正在生成', completed: '可下载', failed: '生成失败',
    createFailed: '创建导出失败，请稍后重试。', downloadFailed: '下载授权已过期或不可用，请重新申请。',
    tenantRequired: '下载前请先在高级筛选中填写租户 ID 并查询', exportId: '导出 ID',
    upstreamResult: '源站结果', contentType: '内容类型', userAgent: 'User-Agent',
    requestBytesMin: '请求字节下限', requestBytesMax: '请求字节上限',
    responseBytesMin: '响应字节下限', responseBytesMax: '响应字节上限',
    createUnknown: '申请结果未知：可能已经提交。请用原请求重试或查看申请记录核对，不会重复生成。',
    createForbidden: '当前账号无权申请下载访问日志。', createThrottled: '申请过于频繁，请稍后再试。',
    createInvalid: '查询条件不被接受，请调整筛选条件后重新申请。', listFailed: '申请记录加载失败。',
    retrySame: '用原请求重试', viewRecords: '查看申请记录', requestAgain: '按当前条件重新申请',
    createdAt: '申请时间', rows: '条数 / 大小', expiresAt: '下载到期', expired: '已过期',
    reasonInvalidFilter: '查询条件无效，请调整后重新申请', reasonRejected: '生成被拒绝（超出范围或数据不可用），请缩小时间范围后重试',
    reasonOther: '生成失败，请稍后重新申请', noRows: '当前条件没有日志，文件只有表头',
    filterSummary: '原查询条件', filterAll: '全部日志',
    scopeExisting: '当前条件已有下载申请：', retryThis: '重试这次申请',
  },
  'en-US': {
    create: 'Request download', title: 'Access log exports', refresh: 'Refresh export status', download: 'Download',
    empty: 'No export jobs', pending: 'Pending', running: 'Generating', completed: 'Ready', failed: 'Failed',
    createFailed: 'The export could not be created. Try again later.', downloadFailed: 'The download grant expired or is unavailable.',
    tenantRequired: 'Before downloading, enter a tenant ID in advanced filters and query', exportId: 'Export ID',
    upstreamResult: 'Upstream result', contentType: 'Content type', userAgent: 'User-Agent',
    requestBytesMin: 'Minimum request bytes', requestBytesMax: 'Maximum request bytes',
    responseBytesMin: 'Minimum response bytes', responseBytesMax: 'Maximum response bytes',
    createUnknown: 'The request outcome is unknown and may have been submitted. Retry the same request or check the records; nothing is duplicated.',
    createForbidden: 'This account cannot request access log downloads.', createThrottled: 'Too many requests; try again later.',
    createInvalid: 'The query was not accepted; adjust the filters and request again.', listFailed: 'Could not load the export records.',
    retrySame: 'Retry the same request', viewRecords: 'View records', requestAgain: 'Request again with current filters',
    createdAt: 'Requested at', rows: 'Rows / size', expiresAt: 'Download expires', expired: 'Expired',
    reasonInvalidFilter: 'The query is invalid; adjust it and request again', reasonRejected: 'Generation was rejected (out of range or data unavailable); narrow the time range and retry',
    reasonOther: 'Generation failed; request again later', noRows: 'No logs match; the file has only the header',
    filterSummary: 'Original query', filterAll: 'All logs',
    scopeExisting: 'A download request already exists for these filters: ', retryThis: 'Retry this request',
  },
  'qps-ploc': {
    create: '[!! Rêqüêsţ ðöwñlöåð !!]', title: '[!! Åççêss lög êxþörţs !!]', refresh: '[!! Rêfrêsh êxþörţ sţåţüs !!]', download: '[!! Ðöwñlöåð !!]',
    empty: '[!! Ñö êxþörţ jößs !!]', pending: '[!! Þêñðïñg !!]', running: '[!! Gêñêråţïñg !!]', completed: '[!! Rêåðÿ !!]', failed: '[!! Fåïlêð !!]',
    createFailed: '[!! Êxþörţ çöülð ñöţ ßê çrêåţêð. !!]', downloadFailed: '[!! Ðöwñlöåð gråñţ êxþïrêð ör ïs üñåvåïlåßlê. !!]',
    tenantRequired: '[!! Bêƒörê ðöwñlöåðïñg, êñţêr å ţêñåñţ ÏÐ !!]', exportId: '[!! Êxþörţ ÏÐ !!]',
    upstreamResult: '[!! Üþsţrêåm rêsülţ !!]', contentType: '[!! Çöñţêñţ ţÿþê !!]', userAgent: '[!! Üsêr-Ågêñţ !!]',
    requestBytesMin: '[!! Mïñ rêqüêsţ ßÿţês !!]', requestBytesMax: '[!! Måx rêqüêsţ ßÿţês !!]',
    responseBytesMin: '[!! Mïñ rêsþöñsê ßÿţês !!]', responseBytesMax: '[!! Måx rêsþöñsê ßÿţês !!]',
    createUnknown: '[!! Rêqüêsţ öüţçömê üñkñöwñ !!]', createForbidden: '[!! Ñöţ ållöwêð !!]', createThrottled: '[!! Ţöö måñÿ rêqüêsţs !!]',
    createInvalid: '[!! Qüêrÿ ñöţ åççêþţêð !!]', listFailed: '[!! Rêçörðs ƒåïlêð !!]',
    retrySame: '[!! Rêţrÿ såmê rêqüêsţ !!]', viewRecords: '[!! Vïêw rêçörðs !!]', requestAgain: '[!! Rêqüêsţ ågåïñ !!]',
    createdAt: '[!! Rêqüêsţêð åţ !!]', rows: '[!! Röws / sïzê !!]', expiresAt: '[!! Êxþïrês !!]', expired: '[!! Êxþïrêð !!]',
    reasonInvalidFilter: '[!! Ïñvålïð qüêrÿ !!]', reasonRejected: '[!! Rêjêçţêð !!]', reasonOther: '[!! Fåïlêð !!]', noRows: '[!! Ñö lögs måţçh !!]',
    filterSummary: '[!! Örïgïñål qüêrÿ !!]', filterAll: '[!! Åll lögs !!]',
    scopeExisting: '[!! Rêqüêsţ êxïsţs: !!]', retryThis: '[!! Rêţrÿ ţhïs rêqüêsţ !!]',
  },
} as const

export const analyticsLogExportMessages = {
  ...messages,
  'qps-Ploc': messages['qps-ploc'],
} as const

export type AnalyticsLogExportMessageKey = keyof typeof analyticsLogExportMessages['zh-CN']

type AnalyticsLogExportLocale = 'zh-CN' | 'en-US' | 'qps-ploc'

function localeFor(language: string): AnalyticsLogExportLocale {
  const normalized = language.trim().toLowerCase()
  if (normalized === 'qps-ploc') return 'qps-ploc'
  return normalized === 'en-us' ? 'en-US' : 'zh-CN'
}

export function analyticsLogExportMessage(language: string, key: AnalyticsLogExportMessageKey): string {
  return analyticsLogExportMessages[localeFor(language)][key]
}
