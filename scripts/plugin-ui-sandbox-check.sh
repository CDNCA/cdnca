#!/usr/bin/env bash
# PA-19 ui_page 沙箱真实浏览器检查：宿主页写入 Cookie 与 localStorage 后，用与主控完全相同的
# <iframe sandbox="allow-scripts allow-forms">（无 allow-same-origin）挂两个插件页：一个与宿主同源、
# 一个跨源。框内脚本尝试读自身与宿主的 Cookie / localStorage / sessionStorage / IndexedDB / 宿主 DOM，
# 并把结果 postMessage 回宿主；宿主同时检查 event.origin 是否为 "null"。
# 用法：scripts/plugin-ui-sandbox-check.sh [chrome 路径]；需要 python3 与 Chrome/Chromium。
set -euo pipefail
CHROME=${1:-"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}
work=$(mktemp -d)
cleanup() { kill "${pids[@]}" 2>/dev/null || true; rm -rf "$work"; }
pids=()
trap cleanup EXIT

port_a=$((20000 + RANDOM % 20000)) port_b=$((port_a + 1))
cat >"$work/frame.html" <<'HTML'
<!doctype html><meta charset="utf-8"><script>
const out = {}
const probe = (name, read) => { try { out[name] = { ok: true, value: String(read()) } } catch (e) { out[name] = { ok: false, error: e.name } } }
probe('own_cookie', () => document.cookie)
probe('own_localStorage', () => localStorage.getItem('host_token'))
probe('own_sessionStorage', () => sessionStorage.getItem('host_session'))
probe('own_indexedDB', () => indexedDB.open('x') && 'opened')
probe('parent_cookie', () => parent.document.cookie)
probe('parent_localStorage', () => parent.localStorage.getItem('host_token'))
probe('parent_dom', () => parent.document.body.innerHTML.length)
probe('top_navigation', () => { top.location.href = 'about:blank'; return 'navigated' })
parent.postMessage({ frame: location.port, results: out }, '*')
</script>
HTML
cat >"$work/host.html" <<HTML
<!doctype html><meta charset="utf-8"><body><pre id="result">pending</pre><script>
document.cookie = 'host_secret=cookie-value; path=/'
localStorage.setItem('host_token', 'storage-value')
sessionStorage.setItem('host_session', 'session-value')
const results = {}
addEventListener('message', (event) => {
  results[event.data.frame === '$port_a' ? 'same_origin_frame' : 'cross_origin_frame'] = { event_origin: event.origin, ...event.data.results }
  if (Object.keys(results).length === 2) document.getElementById('result').textContent = JSON.stringify(results)
})
for (const src of ['http://127.0.0.1:$port_a/frame.html', 'http://localhost:$port_b/frame.html']) {
  const frame = document.createElement('iframe')
  frame.setAttribute('sandbox', 'allow-scripts allow-forms')
  frame.setAttribute('referrerpolicy', 'no-referrer')
  frame.src = src
  document.body.appendChild(frame)
}
</script>
HTML
(cd "$work" && exec python3 -m http.server "$port_a" --bind 127.0.0.1 >/dev/null 2>&1) & pids+=($!)
(cd "$work" && exec python3 -m http.server "$port_b" --bind 127.0.0.1 >/dev/null 2>&1) & pids+=($!)
sleep 1
dom=$("$CHROME" --headless=new --disable-gpu --no-first-run --no-default-browser-check \
  --user-data-dir="$work/profile" --virtual-time-budget=5000 --dump-dom "http://127.0.0.1:$port_a/host.html" 2>/dev/null)
json=$(printf '%s' "$dom" | sed -n 's/.*<pre id="result">\(.*\)<\/pre>.*/\1/p' | sed 's/&quot;/"/g')
[[ -n "$json" && "$json" != pending ]] || { echo "PLUGIN_UI_SANDBOX FAIL: no result"; exit 1; }
printf '%s\n' "$json"
python3 - "$json" <<'PY'
import json, sys
results = json.loads(sys.argv[1])
failures = []
for frame, probes in results.items():
    if probes.pop('event_origin') != 'null':
        failures.append(f'{frame}: origin is not opaque')
    for name, outcome in probes.items():
        leaked = outcome['ok'] and any(secret in outcome['value'] for secret in ('cookie-value', 'storage-value', 'session-value'))
        reached = outcome['ok'] and name in ('parent_dom', 'parent_cookie', 'parent_localStorage', 'top_navigation', 'own_indexedDB')
        if leaked or reached:
            failures.append(f'{frame}.{name}: {outcome}')
if failures:
    print('PLUGIN_UI_SANDBOX FAIL', *failures, sep='\n  ')
    sys.exit(1)
print('PLUGIN_UI_SANDBOX PASS: frames are opaque-origin, read no host cookie/localStorage/sessionStorage, cannot reach host DOM or navigate top')
PY
