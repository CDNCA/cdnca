import i18n from './index'

const zhCN = {
  title: '其它',
  fields: {
    searchEngineOrigin: '搜索引擎回源',
    acmePassthrough: '源站申请证书',
    responseRealtime: '数据实时返回',
    requestRealtime: '数据实时发送',
    defaultSite: '默认站点',
    l2: 'L2 配置',
    l2Mode: 'L2 回源',
    l2Config: 'L2 节点组',
    websocket: 'WebSocket',
    websocketOrigins: 'Origin 白名单',
    searchEngineAddress: '回源地址',
    rum: '真实用户体验上报',
    rumSample: '采样率',
  },
  short: {
    websocket: '允许站点使用 WebSocket 长连接。',
    searchEngineOrigin: '搜索引擎爬虫请求固定回到指定源 IP。',
    rum: '在 HTML 页面注入一行同源脚本，采集访客浏览器的性能指标和加载错误，在「统计 → 真实用户体验」查看。',
    acmePassthrough: '允许源站通过 CDN 代理完成证书申请校验。',
    responseRealtime: '节点收到源站数据后立即返回给客户端。',
    requestRealtime: '节点收到客户端数据后立即发送给源站。',
    defaultSite: '未匹配域名的请求都使用此站点。',
  },
  help: {
    websocket: '开启后节点转发 Upgrade 请求，连接保持到任一方关闭。',
    websocketOrigins: '只允许这些 Origin 发起 WebSocket 握手，每行一个；留空不限制。',
    searchEngineOrigin: '搜索引擎爬虫（按 User-Agent 识别）请求固定回到这个源站，格式 host[:port]，留空关闭；爬虫请求不读也不写缓存。',
    acmePassthrough: '把 /.well-known/acme-challenge/ 请求透传给源站，让源站自己申请证书。本平台正在为该域名签证书时，以本平台的验证文件为准。',
    responseRealtime: '节点收到源站数据后立即返回给客户端。只对不走缓存的请求生效，缓存命中的请求仍按缓冲处理；需要实时返回的路径请不要配置缓存。',
    requestRealtime: '节点收到客户端数据后立即发送给源站。只对不走缓存的请求生效；请求体已开始发送后不会再换源重试。',
    defaultSite: '未匹配域名（含无 SNI 的 HTTPS，可用于 IP 证书）都使用此站点。全系统只有一个默认站点，开启后会自动取消原来的默认站点。仅管理员可设。',
    l2: '当前套餐：按线路组的 L2 配置回源；不配置：直接回源站；自定义：只使用所选 L2 配置中的节点。仅管理员可设。下发到节点市场供给的网站：当前套餐 = 使用卖家的 L2（卖家未提供时直连回源）；自定义不能下发到市场供给。',
  },
  rum: {
    sampleHint: '节点每 100 次页面请求约注入 {{percent}} 次',
    privacy: '不采集 query string、IP、cookie，不生成访客标识。需要节点支持 SITE_RUM。',
  },
  options: { package: '当前套餐配置', off: '不配置 L2', custom: '自定义 L2' },
  capability: '以上选项需要节点支持 SITE_EDGE_OPTIONS，未升级的节点会拒绝发布并给出原因。',
  // saved on its own (ServerTimingSwitch)
  serverTiming: {
    label: 'Server-Timing 响应头',
    help: '在响应里加上缓存状态、命中的缓存层、回源建连和首包耗时，方便在浏览器开发者工具里排查。默认关闭',
    tip: '跨域脚本要读取时，在 HTTP 策略的响应头里加 Timing-Allow-Origin',
    saved: '已保存，下次发布后生效',
    saveFailed: 'Server-Timing 响应头保存失败',
    errors: {
      version_conflict: '网站配置已被其他操作修改，请刷新页面后重试。', site_locked: '网站已被锁定，不能修改。',
      permission_denied: '当前账号缺少网站管理权限。', request_failed: '保存失败，请稍后重试。',
    },
  },
}

const enUS: typeof zhCN = {
  title: 'Other',
  fields: {
    searchEngineOrigin: 'Search engine origin',
    acmePassthrough: 'Origin certificate requests',
    responseRealtime: 'Stream responses',
    requestRealtime: 'Stream requests',
    defaultSite: 'Default site',
    l2: 'L2',
    l2Mode: 'L2 origin',
    l2Config: 'L2 node group',
    websocket: 'WebSocket',
    websocketOrigins: 'Origin allowlist',
    searchEngineAddress: 'Origin address',
    rum: 'Real user monitoring',
    rumSample: 'Sample rate',
  },
  short: {
    websocket: 'Allow WebSocket connections to this site.',
    searchEngineOrigin: 'Search engine crawlers always go to a fixed origin.',
    rum: 'Injects one same-origin script into HTML pages to collect visitors\' browser performance and loading errors; see Analytics → Real user monitoring.',
    acmePassthrough: 'Let the origin pass certificate challenges through the CDN.',
    responseRealtime: 'Send origin data to the client as it arrives.',
    requestRealtime: 'Send client data to the origin as it arrives.',
    defaultSite: 'Requests for unknown hosts use this site.',
  },
  help: {
    websocket: 'Nodes forward Upgrade requests; the connection lasts until either side closes it.',
    websocketOrigins: 'Only these Origins may open a WebSocket, one per line; empty: any.',
    searchEngineOrigin: 'Search engine crawlers (by User-Agent) are always proxied to this origin (host[:port], empty: off); their requests bypass the cache.',
    acmePassthrough: 'Pass /.well-known/acme-challenge/ requests to the origin so it can get its own certificate. While this platform issues a certificate for the host, its own token wins.',
    responseRealtime: 'Send the origin response to the client as it arrives. Requests the cache does not serve only; cached requests stay buffered.',
    requestRealtime: 'Send the request body to the origin as it arrives. Requests the cache does not serve only; no retry once the body is sent.',
    defaultSite: 'Serves every unknown host (and HTTPS without SNI, for IP certificates). One default site in the system: enabling it clears the previous one. Administrators only.',
    l2: 'Package: the line group L2; off: straight to the origin; custom: only the nodes of the chosen L2 configuration. Administrators only. A site rolled out to a node market supply: package = the seller\'s L2 (straight to the origin when the seller provides none); custom cannot be rolled out to a market supply.',
  },
  rum: {
    sampleHint: 'The node injects about {{percent}} of every 100 page requests',
    privacy: 'No query string, IP address or cookie is collected and no visitor identifier is made. Needs nodes with SITE_RUM.',
  },
  options: { package: 'Package', off: 'No L2', custom: 'Custom L2' },
  capability: 'These options need nodes with SITE_EDGE_OPTIONS; nodes without it refuse the publication with the reason.',
  serverTiming: {
    label: 'Server-Timing header',
    help: 'Adds the cache status, the cache layer that served the response, and the origin connect and first-byte times, for debugging in browser developer tools. Off by default.',
    tip: 'For cross-origin scripts, add Timing-Allow-Origin in the HTTP policy response headers.',
    saved: 'Saved. Takes effect after the next publication.',
    saveFailed: 'Could not save the Server-Timing header setting',
    errors: {
      version_conflict: 'The site was changed by another operation. Refresh the page and try again.', site_locked: 'The site is locked and cannot be changed.',
      permission_denied: 'The current account lacks site management permission.', request_failed: 'Save failed. Try again later.',
    },
  },
}

type Messages = { [key: string]: string | Messages }

function pseudoText(value: string): string {
  return `［${[...value].map((character) => /\s/u.test(character) ? character : `${character}~`).join('')}］`
}

function pseudo(value: Messages): Messages {
  return Object.fromEntries(Object.entries(value).map(([key, child]) => [
    key,
    typeof child === 'string' ? pseudoText(child) : pseudo(child),
  ]))
}

const pseudoCN = pseudo(zhCN)

export const siteEdgeOptionsMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', Messages> = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudoCN,
  'qps-Ploc': pseudoCN,
}

for (const [locale, messages] of Object.entries(siteEdgeOptionsMessages)) {
  i18n.addResourceBundle(locale, 'siteEdgeOptions', messages, true, true)
}
