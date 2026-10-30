// 结果后处理：把 click.mjs 采集后才确定的环境项/噪声项（同 click.mjs ENV/NOISE）从失败里剔除并重算页面状态，
// 让早先批次与后来批次口径一致。summarize.mjs、index.mjs 共用。
const ENV = [/\/v1\/(admin\/)?brand-assets(\/\w+)? → 404/, /\/v1\/admin\/entitlement\/refresh → 404/, /analytics_realtime_evidence_unavailable/,
  /\/v1\/(admin\/)?certificate-assets[^ ]* → 404 404 page not found/, /\/v1\/(admin\/)?error-pages[^ ]* → 404 404 page not found/,
  /\/v1\/(admin\/|tenant\/)?market\/[^ ]* → 404 404 page not found/, /\/v1\/observability\/frontend-events → 0/]
const isEnv = (s) => ENV.some((re) => re.test(s))
export function reclassify(r) {
  r.issues = (r.issues ?? []).map((i) => (i.level !== 'info' && isEnv(i.what) ? { ...i, level: 'env' } : i))
    .filter((i) => !(i.level === 'error' && /占位文案：未开放/.test(i.what) && /^\/account\/theme/.test(r.path)))
  for (const c of r.clicks ?? []) {
    if (c.level !== 'error' && c.level !== 'warn') continue
    const all = [...(c.requests ?? []), ...(c.submit?.requests ?? [])].filter((x) => !isEnv(x))
    const bad = all.filter((x) => / → (0|404|405|501|5\d\d)\b/.test(x))
    if (c.level === 'error' && !bad.length && !c.console?.length && !/占位/.test(c.result ?? '')) c.level = all.some((x) => / → 4\d\d\b/.test(x)) ? 'warn' : 'ok'
  }
  if (r.status !== 'manual') r.status = r.issues.some((i) => i.level === 'error') || r.clicks.some((c) => c.level === 'error') ? 'error'
    : r.issues.some((i) => i.level === 'warn') || r.clicks.some((c) => c.level === 'warn') ? 'warn' : 'ok'
  return r
}
