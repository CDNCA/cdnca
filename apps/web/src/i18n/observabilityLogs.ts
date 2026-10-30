const messages = {
  'zh-CN': { query:'查询', ipInvalid:'请输入正确的 IP 地址，例如 203.0.113.7', rangeFuture:'结束时间不能晚于当前时间', invalidRequest:'查询条件无效，请检查 IP 地址和时间范围', unavailable:'日志服务暂不可用，请稍后重试', permissionDenied:'没有查看日志的权限', cursorExpired:'查询位置已失效，已保留筛选并从第一页重新查询。', title:'日志查询', loginTitle:'日志查询', frontendTitle:'前端日志', loginView:'登录日志', auditView:'事件审计', kind:'类型', result:'结果', action:'操作', sourceIp:'IP 地址', ipAddress:'IP地址', ipAddressPlaceholder:'请输入IP地址', userId:'用户ID', userIdPlaceholder:'请输入用户ID', from:'开始时间', to:'结束时间', geo:'地理位置', time:'时间', loginTime:'登录时间', loginStatus:'登录状态', info:'信息', triggerPage:'触发页面', detail:'详细信息', reason:'原因', refresh:'刷新', export:'导出 CSV', empty:'暂无日志', failed:'日志加载失败，请稍后重试。', exportFailed:'导出失败，请稍后重试。', targetScope:'目标租户作用域', targetScopePlaceholder:'租户作用域 UUID', targetScopeRequired:'请先输入目标租户作用域。', targetScopeInvalid:'请输入有效的小写租户作用域 UUID。', all:'全部', login:'登录', operation:'关键操作', notification:'消息发送', frontend:'前端', previous:'上一页', next:'下一页', unknown:'未知', operationView:'操作日志', userAgent:'浏览器UA', allStatus:'所有状态', statusSuccess:'成功', statusFailed:'失败', allActions:'所有动作', verbCreate:'新增', verbUpdate:'更新', verbDelete:'删除', rangePlaceholder:'请选择时间范围', rangeTooLong:'时间范围最长 31 天', category:'类别', categoryPlaceholder:'请选择类别', object:'对象', objectPlaceholder:'请输入对象', change:'变更', changePlaceholder:'请输入变更内容', categoryObject:'类别/对象', verb:'动作', changeContent:'变更内容', ipLocation:'IP/位置', operationTime:'操作时间', noChange:'无变更内容', total:'共 {count} 条', logTabs:'日志类型', pagination:'分页', pageSize:'每页条数', deletedObject:'已删除的对象（{id}）' },
  'zh-TW': { query:'查詢', ipInvalid:'請輸入正確的 IP 位址，例如 203.0.113.7', rangeFuture:'結束時間不能晚於目前時間', invalidRequest:'查詢條件無效，請檢查 IP 位址和時間範圍', unavailable:'日誌服務暫不可用，請稍後重試', permissionDenied:'沒有檢視日誌的權限', cursorExpired:'查詢位置已失效，已保留篩選並從第一頁重新查詢。', title:'日誌查詢', loginTitle:'日誌查詢', frontendTitle:'前端日誌', loginView:'登入日誌', auditView:'事件稽核', kind:'類型', result:'結果', action:'操作', sourceIp:'IP 位址', ipAddress:'IP位址', ipAddressPlaceholder:'請輸入IP位址', userId:'使用者ID', userIdPlaceholder:'請輸入使用者ID', from:'開始時間', to:'結束時間', geo:'地理位置', time:'時間', loginTime:'登入時間', loginStatus:'登入狀態', info:'資訊', triggerPage:'觸發頁面', detail:'詳細資訊', reason:'原因', refresh:'重新整理', export:'匯出 CSV', empty:'暫無日誌', failed:'日誌載入失敗，請稍後重試。', exportFailed:'匯出失敗，請稍後重試。', targetScope:'目標租戶作用域', targetScopePlaceholder:'租戶作用域 UUID', targetScopeRequired:'請先輸入目標租戶作用域。', targetScopeInvalid:'請輸入有效的小寫租戶作用域 UUID。', all:'全部', login:'登入', operation:'關鍵操作', notification:'訊息傳送', frontend:'前端', previous:'上一頁', next:'下一頁', unknown:'未知', operationView:'操作日誌', userAgent:'瀏覽器UA', allStatus:'所有狀態', statusSuccess:'成功', statusFailed:'失敗', allActions:'所有動作', verbCreate:'新增', verbUpdate:'更新', verbDelete:'刪除', rangePlaceholder:'請選擇時間範圍', rangeTooLong:'時間範圍最長 31 天', category:'類別', categoryPlaceholder:'請選擇類別', object:'對象', objectPlaceholder:'請輸入對象', change:'變更', changePlaceholder:'請輸入變更內容', categoryObject:'類別/對象', verb:'動作', changeContent:'變更內容', ipLocation:'IP/位置', operationTime:'操作時間', noChange:'無變更內容', total:'共 {count} 條', logTabs:'日誌類型', pagination:'分頁', pageSize:'每頁條數', deletedObject:'已刪除的對象（{id}）' },
  'en-US': { query:'Search', ipInvalid:'Enter a valid IP address, e.g. 203.0.113.7', rangeFuture:'The end time cannot be in the future', invalidRequest:'Invalid filters. Check the IP address and time range.', unavailable:'The log service is unavailable. Try again later.', permissionDenied:'You do not have permission to view logs', cursorExpired:'The page position expired. Filters were kept and the first page was reloaded.', title:'Event logs', loginTitle:'Login logs', frontendTitle:'Frontend logs', loginView:'Login logs', auditView:'Event audit', kind:'Type', result:'Result', action:'Action', sourceIp:'IP address', ipAddress:'IP address', ipAddressPlaceholder:'Enter IP address', userId:'User ID', userIdPlaceholder:'Enter user ID', from:'From', to:'To', geo:'Location', time:'Time', loginTime:'Login time', loginStatus:'Login status', info:'Information', triggerPage:'Triggered page', detail:'Details', reason:'Reason', refresh:'Refresh', export:'Export CSV', empty:'No log facts', failed:'Logs could not be loaded.', exportFailed:'Export failed.', targetScope:'Target tenant scope', targetScopePlaceholder:'Tenant scope UUID', targetScopeRequired:'Enter a target tenant scope first.', targetScopeInvalid:'Enter a valid lowercase tenant scope UUID.', all:'All', login:'Login', operation:'Critical operation', notification:'Notification', frontend:'Frontend', previous:'Previous', next:'Next', unknown:'Unknown', operationView:'Operation logs', userAgent:'Browser UA', allStatus:'All statuses', statusSuccess:'Success', statusFailed:'Failed', allActions:'All actions', verbCreate:'Create', verbUpdate:'Update', verbDelete:'Delete', rangePlaceholder:'Select a time range', rangeTooLong:'The time range is at most 31 days', category:'Category', categoryPlaceholder:'Select a category', object:'Object', objectPlaceholder:'Enter object', change:'Change', changePlaceholder:'Enter change content', categoryObject:'Category/Object', verb:'Action', changeContent:'Change content', ipLocation:'IP/Location', operationTime:'Operation time', noChange:'No changes', total:'{count} in total', logTabs:'Log type', pagination:'Pagination', pageSize:'Page size', deletedObject:'Deleted object ({id})' },
  'qps-ploc': { query:'[!! Šêårçh !!]', ipInvalid:'[!! Êñţêr å vålïð ÏÞ åððrêšš !!]', rangeFuture:'[!! Ţhê êñð ţïmê çåññöţ ßê ïñ ţhê füţürê !!]', invalidRequest:'[!! Ïñvålïð fïlţêrš !!]', unavailable:'[!! Ţhê lög šêrvïçê ïš üñåvåïlåßlê !!]', permissionDenied:'[!! Ñö þêrmïššïöñ ţö vïêw lögš !!]', cursorExpired:'[!! Ţhê þågê þöšïţïöñ êxþïrêð. Fïlţêrš wêrê kêþţ åñð ţhê fïršţ þågê wåš rêlöåðêð. !!]', title:'[!! Êvêñţ lögš !!]', loginTitle:'[!! Lögïñ lögš !!]', frontendTitle:'[!! Fröñţêñð lögš !!]', loginView:'[!! Lögïñ lögš !!]', auditView:'[!! Êvêñţ åüðïţ !!]', kind:'[!! Ţÿþê !!]', result:'[!! Rêšülţ !!]', action:'[!! Åçţïöñ !!]', sourceIp:'[!! ÏÞ åððrêšš !!]', ipAddress:'[!! ÏÞ åððrêšš !!]', ipAddressPlaceholder:'[!! Êñţêr ÏÞ !!]', userId:'[!! Üšêr ÏÐ !!]', userIdPlaceholder:'[!! Êñţêr Üšêr ÏÐ !!]', from:'[!! Fröm !!]', to:'[!! Ţö !!]', geo:'[!! Löçåţïöñ !!]', time:'[!! Ţïmë !!]', loginTime:'[!! Lögïñ ţïmë !!]', loginStatus:'[!! Lögïñ šţåţüš !!]', info:'[!! Ïñfð !!]', triggerPage:'[!! Ţrïggêrêð þågê !!]', detail:'[!! Ðêţåïl !!]', reason:'[!! Rêåšöñ !!]', refresh:'[!! Rêfrêšh !!]', export:'[!! Êxþörţ ÇŠV !!]', empty:'[!! Ñö lög fåçţš !!]', failed:'[!! Lögš çöülð ñöţ ßê löåðêð. !!]', exportFailed:'[!! Êxþörţ fåïlêð. !!]', targetScope:'[!! Ţårgêţ ţêñåñţ šçöþê !!]', targetScopePlaceholder:'[!! Ţêñåñţ šçöþê ÜÜÏÐ !!]', targetScopeRequired:'[!! Êñţêr å ţårgêţ ţêñåñţ šçöþê fïršţ. !!]', targetScopeInvalid:'[!! Êñţêr å vålïð löwêrçåšê ţêñåñţ šçöþê ÜÜÏÐ. !!]', all:'[!! Åll !!]', login:'[!! Lögïñ !!]', operation:'[!! Çrïţïçål öþêråţïöñ !!]', notification:'[!! Ñöţïfïçåţïöñ !!]', frontend:'[!! Fröñţêñð !!]', previous:'[!! Þrêvïöüš !!]', next:'[!! Ñêxţ !!]', unknown:'[!! Üñkñöwñ !!]', operationView:'[!! Öþêråţïöñ lögš !!]', userAgent:'[!! ßröwšêr ÜÅ !!]', allStatus:'[!! Åll šţåţüšêš !!]', statusSuccess:'[!! Šüççêšš !!]', statusFailed:'[!! Fåïlêð !!]', allActions:'[!! Åll åçţïöñš !!]', verbCreate:'[!! Çrêåţê !!]', verbUpdate:'[!! Üþðåţê !!]', verbDelete:'[!! Ðêlêţê !!]', rangePlaceholder:'[!! Šêlêçţ å ţïmê råñgê !!]', rangeTooLong:'[!! Ţhê ţïmê råñgê ïš åţ möšţ 31 ðåÿš !!]', category:'[!! Çåţêgörÿ !!]', categoryPlaceholder:'[!! Šêlêçţ å çåţêgörÿ !!]', object:'[!! Ößjêçţ !!]', objectPlaceholder:'[!! Êñţêr ößjêçţ !!]', change:'[!! Çhåñgê !!]', changePlaceholder:'[!! Êñţêr çhåñgê !!]', categoryObject:'[!! Çåţêgörÿ/Ößjêçţ !!]', verb:'[!! Åçţïöñ !!]', changeContent:'[!! Çhåñgê çöñţêñţ !!]', ipLocation:'[!! ÏÞ/Löçåţïöñ !!]', operationTime:'[!! Öþêråţïöñ ţïmê !!]', noChange:'[!! Ñö çhåñgêš !!]', total:'[!! {count} ïñ ţöţål !!]', logTabs:'[!! Lög ţÿþê !!]', pagination:'[!! Þågïñåţïöñ !!]', pageSize:'[!! Þågê šïžê !!]', deletedObject:'[!! Ðêlêţêð ößjêçţ ({id}) !!]' },
} as const

export const observabilityLogMessages = {
  ...messages,
  'qps-Ploc': messages['qps-ploc'],
} as const

type ObservabilityLogLocale = keyof typeof observabilityLogMessages
export type ObservabilityLogCodeCategory = 'action' | 'reason' | 'result'

const announcementActions = {
  'zh-CN': {
    'announcement.create': '创建公告', 'announcement.update': '更新公告', 'announcement.schedule': '定时发布公告',
    'announcement.publish': '发布公告', 'announcement.revise': '修订公告', 'announcement.withdraw': '撤回公告',
    'announcement.archive': '归档公告', 'announcement.restore': '恢复公告', 'announcement.deliver': '公告已送达', 'announcement.read': '公告已读',
    'announcement.global.create': '创建全局公告', 'announcement.global.update': '更新全局公告',
    'announcement.global.publish': '发布全局公告', 'announcement.global.withdraw': '撤回全局公告',
    'announcement.global.archive': '归档全局公告', 'announcement.global.restore': '恢复全局公告',
  },
  'zh-TW': {
    'announcement.create': '建立公告', 'announcement.update': '更新公告', 'announcement.schedule': '排程發布公告',
    'announcement.publish': '發布公告', 'announcement.revise': '修訂公告', 'announcement.withdraw': '撤回公告',
    'announcement.archive': '封存公告', 'announcement.restore': '還原公告', 'announcement.deliver': '公告已送達', 'announcement.read': '公告已讀',
    'announcement.global.create': '建立全域公告', 'announcement.global.update': '更新全域公告',
    'announcement.global.publish': '發布全域公告', 'announcement.global.withdraw': '撤回全域公告',
    'announcement.global.archive': '封存全域公告', 'announcement.global.restore': '還原全域公告',
  },
  'en-US': {
    'announcement.create': 'Create announcement', 'announcement.update': 'Update announcement', 'announcement.schedule': 'Schedule announcement',
    'announcement.publish': 'Publish announcement', 'announcement.revise': 'Revise announcement', 'announcement.withdraw': 'Withdraw announcement',
    'announcement.archive': 'Archive announcement', 'announcement.restore': 'Restore announcement', 'announcement.deliver': 'Announcement delivered', 'announcement.read': 'Announcement read',
    'announcement.global.create': 'Create global announcement', 'announcement.global.update': 'Update global announcement',
    'announcement.global.publish': 'Publish global announcement', 'announcement.global.withdraw': 'Withdraw global announcement',
    'announcement.global.archive': 'Archive global announcement', 'announcement.global.restore': 'Restore global announcement',
  },
} as const
const pseudoAnnouncementActions = Object.fromEntries(Object.entries(announcementActions['en-US']).map(([key, value]) => [key, `[!! ${value} ${value} !!]`]))

const canonicalCodeMessages: Record<Exclude<ObservabilityLogLocale, 'qps-Ploc'>, Record<ObservabilityLogCodeCategory, Record<string, string>>> = {
  'zh-CN': {
    action: {
      ...announcementActions['zh-CN'],
      'auth.login': '用户登录',
      'auth.refresh': '刷新会话',
      'identity.bootstrap_user': '初始化用户',
      'package.group.create': '创建套餐分组',
      'package.product.create': '创建套餐商品',
      'platform_brand_asset.upload': '上传平台品牌资源',
      'site.update': '网站更新',
      'stream.create': '创建四层转发流',
      'stream_group.create': '创建四层转发分组',
      'notification.delivered': '消息已送达',
      'notification.provider_delivered': '服务商已送达',
      'notification.dispatch_started': '开始发送',
      'notification.provider_accepted': '服务商已接受',
      'notification.provider_unknown': '服务商结果未知',
      'notification.retry_scheduled': '已安排重试',
      'notification.permanent_failed': '永久失败',
      'notification.exhausted': '重试已用尽',
      'notification.lease_unknown': '租约结果未知',
      'notification.provider_receipt': '收到服务商回执',
      'notification.cancelled': '已取消发送',
      'notification.replay_created': '已创建重发',
      'frontend.route_error': '前端路由错误',
      'frontend.api_error': '前端接口错误',
      'frontend.render_error': '前端渲染错误',
    },
    reason: {
      ...announcementActions['zh-CN'],
      credentials_accepted: '登录凭据已接受',
      'site.update': '网站更新',
      delivered: '已送达',
      provider_delivered: '服务商已送达',
      dispatch_started: '开始发送', provider_accepted: '服务商已接受', provider_unknown: '服务商结果未知',
      retry_scheduled: '已安排重试', permanent_failed: '永久失败', exhausted: '重试已用尽',
      lease_unknown: '租约结果未知', provider_receipt: '收到服务商回执', cancelled: '已取消发送', replay_created: '已创建重发',
      component_failed: '组件执行失败',
    },
    result: {
      success: '成功', denied: '已拒绝', failure: '失败', delivered: '已送达', accepted: '已接受',
      unknown: '结果未知', permanent_failed: '永久失败', exhausted: '重试已用尽', cancelled: '已取消',
    },
  },
  'en-US': {
    action: {
      ...announcementActions['en-US'],
      'auth.login': 'User login',
      'auth.refresh': 'Session refresh',
      'identity.bootstrap_user': 'Bootstrap user identity',
      'package.group.create': 'Create package group',
      'package.product.create': 'Create package product',
      'platform_brand_asset.upload': 'Upload platform brand asset',
      'site.update': 'Site update',
      'stream.create': 'Create L4 stream',
      'stream_group.create': 'Create L4 stream group',
      'notification.delivered': 'Notification delivered',
      'notification.provider_delivered': 'Provider delivery',
      'notification.dispatch_started': 'Dispatch started', 'notification.provider_accepted': 'Provider accepted',
      'notification.provider_unknown': 'Provider result unknown', 'notification.retry_scheduled': 'Retry scheduled',
      'notification.permanent_failed': 'Permanently failed', 'notification.exhausted': 'Retries exhausted',
      'notification.lease_unknown': 'Lease result unknown', 'notification.provider_receipt': 'Provider receipt',
      'notification.cancelled': 'Delivery cancelled', 'notification.replay_created': 'Replay created',
      'frontend.route_error': 'Frontend route error',
      'frontend.api_error': 'Frontend API error',
      'frontend.render_error': 'Frontend render error',
    },
    reason: {
      ...announcementActions['en-US'],
      credentials_accepted: 'Login credentials accepted',
      'site.update': 'Site update',
      delivered: 'Delivered',
      provider_delivered: 'Delivered by provider',
      dispatch_started: 'Dispatch started', provider_accepted: 'Accepted by provider', provider_unknown: 'Provider result unknown',
      retry_scheduled: 'Retry scheduled', permanent_failed: 'Permanently failed', exhausted: 'Retries exhausted',
      lease_unknown: 'Lease result unknown', provider_receipt: 'Provider receipt', cancelled: 'Delivery cancelled', replay_created: 'Replay created',
      component_failed: 'Component failed',
    },
    result: {
      success: 'Succeeded', denied: 'Denied', failure: 'Failed', delivered: 'Delivered', accepted: 'Accepted',
      unknown: 'Result unknown', permanent_failed: 'Permanently failed', exhausted: 'Retries exhausted', cancelled: 'Cancelled',
    },
  },
  'zh-TW': {
    action: {
      ...announcementActions['zh-TW'],
      'auth.login': '使用者登入', 'auth.refresh': '重新整理工作階段', 'identity.bootstrap_user': '初始化使用者',
      'package.group.create': '建立方案分組', 'package.product.create': '建立方案商品', 'platform_brand_asset.upload': '上傳平台品牌資源',
      'site.update': '網站更新', 'stream.create': '建立四層轉發流', 'stream_group.create': '建立四層轉發分組',
      'notification.delivered': '訊息已送達', 'notification.provider_delivered': '服務商已送達',
      'notification.dispatch_started': '開始傳送', 'notification.provider_accepted': '服務商已接受',
      'notification.provider_unknown': '服務商結果未知', 'notification.retry_scheduled': '已安排重試',
      'notification.permanent_failed': '永久失敗', 'notification.exhausted': '重試已用盡', 'notification.lease_unknown': '租約結果未知',
      'notification.provider_receipt': '收到服務商回執', 'notification.cancelled': '已取消傳送', 'notification.replay_created': '已建立重送',
      'frontend.route_error': '前端路由錯誤', 'frontend.api_error': '前端介面錯誤', 'frontend.render_error': '前端呈現錯誤',
    },
    reason: {
      ...announcementActions['zh-TW'],
      credentials_accepted: '登入憑證已接受', 'site.update': '網站更新', delivered: '已送達', provider_delivered: '服務商已送達',
      dispatch_started: '開始傳送', provider_accepted: '服務商已接受', provider_unknown: '服務商結果未知',
      retry_scheduled: '已安排重試', permanent_failed: '永久失敗', exhausted: '重試已用盡', lease_unknown: '租約結果未知',
      provider_receipt: '收到服務商回執', cancelled: '已取消傳送', replay_created: '已建立重送', component_failed: '元件執行失敗',
    },
    result: {
      success: '成功', denied: '已拒絕', failure: '失敗', delivered: '已送達', accepted: '已接受',
      unknown: '結果未知', permanent_failed: '永久失敗', exhausted: '重試已用盡', cancelled: '已取消',
    },
  },
  'qps-ploc': {
    action: {
      ...pseudoAnnouncementActions,
      'auth.login': '[!! Üšêr lögïñ !!]',
      'auth.refresh': '[!! Šêššïöñ rêfrêšh !!]',
      'identity.bootstrap_user': '[!! ßöøţšţråþ üšêr ïðêñţïţÿ !!]',
      'package.group.create': '[!! Çrêåţê þåçķågê grøüþ !!]',
      'package.product.create': '[!! Çrêåţê þåçķågê þrøðüçţ !!]',
      'platform_brand_asset.upload': '[!! Üþlketøyð þlåţførm ßråñð åššêţ !!]',
      'site.update': '[!! Šïţê üþðåţê !!]',
      'stream.create': '[!! Çrêåţê L4 šţrêåm !!]',
      'stream_group.create': '[!! Çrêåţê L4 šţrêåm grøüþ !!]',
      'notification.delivered': '[!! Ñöţïfïçåţïöñ ðêlïvêrêð !!]',
      'notification.provider_delivered': '[!! Þrövïðêr ðêlïvêrÿ !!]',
      'frontend.route_error': '[!! Fröñţêñð röüţê êrrör !!]',
      'frontend.api_error': '[!! Fröñţêñð ÅÞÏ êrrör !!]',
      'frontend.render_error': '[!! Fröñţêñð rêñðêr êrrör !!]',
    },
    reason: {
      ...pseudoAnnouncementActions,
      credentials_accepted: '[!! Lögïñ çrêðêñţïålš åççêþţêð !!]',
      'site.update': '[!! Šïţê üþðåţê !!]',
      delivered: '[!! Ðêlïvêrêð !!]',
      provider_delivered: '[!! Ðêlïvêrêð ßÿ þrövïðêr !!]',
      component_failed: '[!! Çömþöñêñţ fåïlêð !!]',
    },
    result: {
      success: '[!! Šüççêêðêð !!]', denied: '[!! Ðêñïêð !!]', failure: '[!! Fåïlêð !!]',
      delivered: '[!! Ðêlïvêrêð !!]', accepted: '[!! Åççêþţêð !!]', unknown: '[!! Rêšülţ üñkñöwñ !!]',
      permanent_failed: '[!! Þêrmåñêñţlÿ fåïlêð !!]', exhausted: '[!! Rêţrïêš êx håüšţêð !!]', cancelled: '[!! Çåñçêllêð !!]',
    },
  },
}

const codeMessages: Record<ObservabilityLogLocale, Record<ObservabilityLogCodeCategory, Record<string, string>>> = {
  ...canonicalCodeMessages,
  'qps-Ploc': canonicalCodeMessages['qps-ploc'],
}

const canonicalUnknownCodeMessages: Record<Exclude<ObservabilityLogLocale, 'qps-Ploc'>, Record<ObservabilityLogCodeCategory, string>> = {
  'zh-CN': { action: '未知操作', reason: '未知原因', result: '未知结果' },
  'zh-TW': { action: '未知操作', reason: '未知原因', result: '未知結果' },
  'en-US': { action: 'Unknown action', reason: 'Unknown reason', result: 'Unknown result' },
  'qps-ploc': { action: '[!! Üñkñöwñ åçţïöñ !!]', reason: '[!! Üñkñöwñ rêåšöñ !!]', result: '[!! Üñkñöwñ rêšülţ !!]' },
}

const unknownCodeMessages: Record<ObservabilityLogLocale, Record<ObservabilityLogCodeCategory, string>> = {
  ...canonicalUnknownCodeMessages,
  'qps-Ploc': canonicalUnknownCodeMessages['qps-ploc'],
}

function localeFor(language: string): ObservabilityLogLocale {
  const normalized = language.trim().toLowerCase()
  if (normalized === 'qps-ploc') return 'qps-ploc'
  return normalized === 'en-us' ? 'en-US' : normalized === 'zh-tw' ? 'zh-TW' : 'zh-CN'
}

export type ObservabilityLogMessageKey = keyof typeof observabilityLogMessages['zh-CN']
export function observabilityLogMessage(language: string, key: ObservabilityLogMessageKey): string {
  return observabilityLogMessages[localeFor(language)][key]
}

export function observabilityLogCodeMessage(
  language: string,
  category: ObservabilityLogCodeCategory,
  code: string,
): string {
  const locale = localeFor(language)
  return codeMessages[locale][category][code] ?? unknownCodeMessages[locale][category]
}
