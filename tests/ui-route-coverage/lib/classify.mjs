// 路由归类：哪些后端路由本来就不该有页面（机器对机器/节点/内部/健康检查/代理上游），每类写明理由。
// 归入这些类的路由不进表①；其余按业务模块归类后进表①（"没按钮"候选）。

export const NON_UI_CLASSES = [
  { id: 'health', reason: '健康检查/存活探针，由 systemd/负载均衡调用，不是用户功能', test: (r) => /^\/(health|healthz)(\/|$)/.test(r.path) },
  { id: 'internal', reason: '控制面内部接口（/v1/internal/*），由 agent-gateway/worker 用 mTLS 调用', test: (r) => r.path.startsWith('/v1/internal/') },
  { id: 'workload', reason: '工作负载身份接口（/workload/*），节点或插件进程以 mTLS 调用', test: (r) => r.path.startsWith('/workload/') },
  { id: 'payments-callback', reason: '支付渠道异步通知回调，由第三方支付平台服务器调用', test: (r) => /^\/payments\/v1\//.test(r.path) || /\/(provider-callbacks|notify|callbacks)\b/.test(r.path) && !r.path.startsWith('/operator/v1/billing-provider-callbacks') },
  { id: 'billing-provider', reason: '计费服务商事件推送入口，由外部计费系统调用', test: (r) => r.path.startsWith('/billing-provider/v1/') },
  { id: 'installation', reason: '主控安装实例对授权端的机器接口（激活/续租/升级授权/用量上报），由主控进程签名调用', test: (r) => /^\/(activation|installation|control|download-authorization)\/v\d\//.test(r.path) },
  { id: 'service-mtls', reason: '服务间 mTLS 接口（/service/v1），授权端与市场互调', test: (r) => r.path.startsWith('/service/v1/') },
  { id: 'public-keys', reason: '公开签名公钥/目录清单，由节点、主控或安装脚本拉取', test: (r) => /^\/(public|catalog)\/v1\//.test(r.path) || r.path.startsWith('/.well-known/') },
  { id: 'market-upstream', reason: '市场服务上游 API（/admin/v1 与 /v1 成员接口），浏览器不直连：运营端经授权端 /operator/v1/market/* 代理、主控经 /v1/admin/market/* 代理调用，按代理路由对账', test: (r) => r.service === 'market-service' && (/^\/admin\/v1\//.test(r.path) || /^\/v1\//.test(r.path)) },
  { id: 'node-agent', reason: '节点 agent/安装器调用（节点注册、遥测上报、隔离结果；独立网关 agent-gateway bind 用绑定令牌完成绑定）', test: (r) => /^\/v1\/(node-registrations|nodes\/[^/]+\/(heartbeat|telemetry)|gateway-bindings\/complete$)/.test(r.path) || /\/edge-snapshot$/.test(r.path) },
  { id: 'theme-public', reason: '公开主题/品牌资源，由登录页等匿名页面以 <link>/<img> 加载而非 API 调用', test: (r) => /^\/v1\/theme\//.test(r.path) || /^\/v1\/brand-assets\/[^/]+$/.test(r.path) },
  { id: 'unilogin', reason: '统一登录跳转端点，由浏览器整页跳转（非 fetch）', test: (r) => r.service === 'license-service' && /^\/auth\/v1\/(sso|callback|authorize)/.test(r.path) },
]

export function nonUIClass(route) {
  return NON_UI_CLASSES.find((c) => c.test(route))
}

// 业务模块：取路径前两段（去掉 admin 与 tenant-scopes/{}）。
export function moduleOf(route) {
  const segs = route.path.split('/').filter(Boolean)
  let i = 0
  if (/^(v1|operator|portal|seller|auth|admin)$/.test(segs[i])) i++
  if (segs[i] === 'v1') i++
  if (segs[i] === 'admin') i++
  if (segs[i] === 'tenant-scopes') i += 2
  if (segs[i] === 'market' && route.path.startsWith('/operator/v1/market/')) return `market/${segs[i + 1] ?? ''}`
  if (segs[i] === 'market') return `market/${segs[i + 1] ?? ''}`
  return segs[i] ?? '/'
}
