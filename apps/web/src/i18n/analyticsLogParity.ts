import i18n from './index'

const messages = {
  'zh-CN': {
    clientIp: '客户端IP', clientIpPlaceholder: '输入客户端IP', requestAddress: '请求地址', requestAddressPlaceholder: '输入请求地址',
    tlsFingerprint: 'TLS指纹', tlsFingerprintPlaceholder: '输入TLS指纹', nodeId: '节点ID', nodeIdPlaceholder: '输入节点ID',
    country: '国家', countryPlaceholder: '输入国家', carrier: '运营商', carrierPlaceholder: '输入运营商',
    methodPlaceholder: '输入请求方法', statusPlaceholder: '输入状态码', hit: '命中', miss: '未命中',
    uriPathMatch: '路径匹配', uriPathExact: '精确匹配', uriPathPrefix: '前缀匹配',
  },
  'en-US': {
    clientIp: 'Client IP', clientIpPlaceholder: 'Enter a client IP', requestAddress: 'Request address', requestAddressPlaceholder: 'Enter a request address',
    tlsFingerprint: 'TLS fingerprint', tlsFingerprintPlaceholder: 'Enter a TLS fingerprint', nodeId: 'Node ID', nodeIdPlaceholder: 'Enter a node ID',
    country: 'Country', countryPlaceholder: 'Enter a country', carrier: 'Carrier', carrierPlaceholder: 'Enter a carrier',
    methodPlaceholder: 'Enter a request method', statusPlaceholder: 'Enter a status code', hit: 'Hit', miss: 'Miss',
    uriPathMatch: 'Path match', uriPathExact: 'Exact', uriPathPrefix: 'Prefix',
  },
  'qps-ploc': {
    clientIp: '[!! Çlïêñţ ÏÞ !!]', clientIpPlaceholder: '[!! Êñţêr å çlïêñţ ÏÞ !!]', requestAddress: '[!! Rêqüêsţ åððrêss !!]', requestAddressPlaceholder: '[!! Êñţêr å rêqüêsţ åððrêss !!]',
    tlsFingerprint: '[!! ŢLS fïñgêrþrïñţ !!]', tlsFingerprintPlaceholder: '[!! Êñţêr å ŢLS fïñgêrþrïñţ !!]', nodeId: '[!! Ñöðê ÏÐ !!]', nodeIdPlaceholder: '[!! Êñţêr å ñöðê ÏÐ !!]',
    country: '[!! Çöüñţrÿ !!]', countryPlaceholder: '[!! Êñţêr å çöüñţrÿ !!]', carrier: '[!! Çårrïêr !!]', carrierPlaceholder: '[!! Êñţêr å çårrïêr !!]',
    methodPlaceholder: '[!! Êñţêr å rêqüêsţ mêţhöð !!]', statusPlaceholder: '[!! Êñţêr å sţåţüs çöðê !!]', hit: '[!! Hïţ !!]', miss: '[!! Mïss !!]',
    uriPathMatch: '[!! Þåţh måţçh !!]', uriPathExact: '[!! Êxåçţ !!]', uriPathPrefix: '[!! Þrêfïx !!]',
  },
} as const

const supplements: Record<string, Record<string, unknown>> = {
  'zh-CN': {
    tabs: { logs: '日志查询', exports: '申请记录' },
    actions: { clear: '清除', advancedSearch: '高级搜索', copyId: '复制完整 ID', backToAnalysis: '返回数据分析' },
    detail: { siteDomain: '站点域名', ruleName: '规则名称' },
    filters: {
      label: '日志筛选', timeRange: '时间范围', domain: '域名', domainMode: '筛选维度',
      domainPlaceholder: '输入域名', sitePlaceholder: '输入站点 UUID（可选）',
    },
    table: {
      port: '端口', protocol: '协议', uri: 'URI', tls: 'TLS指纹', region: '地理位置',
      carrier: '运营商', origin: '源地址', contentType: '内容类型', referer: '来源',
      userAgent: '浏览器', nodeId: '节点ID', action: '动作', accessTime: '时间', accessClientIp: '客户IP', originDuration: '回源耗时', returnBytes: '返回字节', cacheHit: '缓存命中',
    },
    pagination: { currentPage: '共 {{count}} 条', currentPageMore: '已加载 {{count}} 条，还有更多，总数未统计', pageSizeLabel: '每页数量', pageSize: '{{size}} 条/页' },
    states: { invalidDomain: '请输入有效的域名。', accessEmpty: '暂无数据' },
  },
  'en-US': {
    tabs: { logs: 'Log query', exports: 'Requests' },
    actions: { clear: 'Clear', advancedSearch: 'Advanced search', copyId: 'Copy full ID', backToAnalysis: 'Back to analysis' },
    detail: { siteDomain: 'Site domain', ruleName: 'Rule name' },
    filters: {
      label: 'Log filters', timeRange: 'Time range', domain: 'Domain', domainMode: 'Filter dimension',
      domainPlaceholder: 'Enter a domain', sitePlaceholder: 'Enter a site UUID (optional)',
    },
    table: {
      port: 'Port', protocol: 'Protocol', uri: 'URI', tls: 'TLS fingerprint', region: 'Location',
      carrier: 'Carrier', origin: 'Origin', contentType: 'Content type', referer: 'Referer',
      userAgent: 'Browser', nodeId: 'Node ID', action: 'Action', accessTime: 'Time', accessClientIp: 'Client IP', originDuration: 'Origin duration', returnBytes: 'Returned bytes', cacheHit: 'Cache hit',
    },
    pagination: { currentPage: '{{count}} total', currentPageMore: '{{count}} loaded, more available (total not counted)', pageSizeLabel: 'Items per page', pageSize: '{{size}} per page' },
    states: { invalidDomain: 'Enter a valid domain.', accessEmpty: 'No data' },
  },
  'qps-ploc': {
    tabs: { logs: '[!! Lög qüêrÿ !!]', exports: '[!! Rêqüêsţs !!]' },
    actions: { clear: '[!! Çlêår !!]', advancedSearch: '[!! Åðvåñçêð sêårçh !!]', copyId: '[!! Çöþÿ füll ÏÐ !!]', backToAnalysis: '[!! Båçk ţö åñålÿšïš !!]' },
    detail: { siteDomain: '[!! Sïţê ðömåïñ !!]', ruleName: '[!! Rülê ñåmê !!]' },
    filters: {
      label: '[!! Lög fïlţêrs !!]', timeRange: '[!! Ţïmê råñgê !!]', domain: '[!! Ðömåïñ !!]', domainMode: '[!! Fïlţêr ðïmêñsïöñ !!]',
      domainPlaceholder: '[!! Êñţêr å ðömåïñ !!]', sitePlaceholder: '[!! Êñţêr å sïţê ÜÜÏÐ (öþţïöñål) !!]',
    },
    table: {
      port: '[!! Þörţ !!]', protocol: '[!! Þröţöçöl !!]', uri: '[!! ÜRÏ !!]', tls: '[!! ŢLS fïñgêrþrïñţ !!]',
      region: '[!! Löçåţïöñ !!]', carrier: '[!! Çårrïêr !!]', origin: '[!! Örïgïñ !!]',
      contentType: '[!! Çöñţêñţ ţÿþê !!]', referer: '[!! Rêfêrêr !!]', userAgent: '[!! Bröwsêr !!]',
      nodeId: '[!! Ñöðê ÏÐ !!]', action: '[!! Åçţïöñ !!]', accessTime: '[!! Ţïmê !!]', accessClientIp: '[!! Çlïêñţ ÏÞ !!]', originDuration: '[!! Örïgïñ ðüråţïöñ !!]', returnBytes: '[!! Rêţürñêð ßÿţês !!]', cacheHit: '[!! Çåçhê hïţ !!]',
    },
    pagination: { currentPage: '[!! {{count}} ţöţål !!]', currentPageMore: '[!! {{count}} löåðêð, möřê åvåïlåþlê (ţöţål ñöţ çöüñţêð) !!]', pageSizeLabel: '[!! Ïţêms þêr þågê !!]', pageSize: '[!! {{size}} þêr þågê !!]' },
    states: { invalidDomain: '[!! Êñţêr å vålïð ðömåïñ. !!]', accessEmpty: '[!! Ñö ðåţå !!]' },
  },
  'qps-Ploc': {
    tabs: { logs: '[!! Lög qüêrÿ !!]', exports: '[!! Rêqüêsţs !!]' },
    actions: { clear: '[!! Çlêår !!]', advancedSearch: '[!! Åðvåñçêð sêårçh !!]', copyId: '[!! Çöþÿ füll ÏÐ !!]', backToAnalysis: '[!! Båçk ţö åñålÿšïš !!]' },
    detail: { siteDomain: '[!! Sïţê ðömåïñ !!]', ruleName: '[!! Rülê ñåmê !!]' },
    filters: {
      label: '[!! Lög fïlţêrs !!]', timeRange: '[!! Ţïmê råñgê !!]', domain: '[!! Ðömåïñ !!]', domainMode: '[!! Fïlţêr ðïmêñsïöñ !!]',
      domainPlaceholder: '[!! Êñţêr å ðömåïñ !!]', sitePlaceholder: '[!! Êñţêr å sïţê ÜÜÏÐ (öþţïöñål) !!]',
    },
    table: {
      port: '[!! Þörţ !!]', protocol: '[!! Þröţöçöl !!]', uri: '[!! ÜRÏ !!]', tls: '[!! ŢLS fïñgêrþrïñţ !!]',
      region: '[!! Löçåţïöñ !!]', carrier: '[!! Çårrïêr !!]', origin: '[!! Örïgïñ !!]',
      contentType: '[!! Çöñţêñţ ţÿþê !!]', referer: '[!! Rêfêrêr !!]', userAgent: '[!! Bröwsêr !!]',
      nodeId: '[!! Ñöðê ÏÐ !!]', action: '[!! Åçţïöñ !!]', accessTime: '[!! Ţïmê !!]', accessClientIp: '[!! Çlïêñţ ÏÞ !!]', originDuration: '[!! Örïgïñ ðüråţïöñ !!]', returnBytes: '[!! Rêţürñêð ßÿţês !!]', cacheHit: '[!! Çåçhê hïţ !!]',
    },
    pagination: { currentPage: '[!! {{count}} ţöţål !!]', currentPageMore: '[!! {{count}} löåðêð, möřê åvåïlåþlê (ţöţål ñöţ çöüñţêð) !!]', pageSizeLabel: '[!! Ïţêms þêr þågê !!]', pageSize: '[!! {{size}} þêr þågê !!]' },
    states: { invalidDomain: '[!! Êñţêr å vålïð ðömåïñ. !!]', accessEmpty: '[!! Ñö ðåţå !!]' },
  },
}

for (const [locale, parity] of Object.entries({ ...messages, 'qps-Ploc': messages['qps-ploc'] })) {
  i18n.addResourceBundle(locale, 'analyticsLogs', { ...supplements[locale], parity }, true, true)
}
