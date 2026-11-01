// 主控/节点两个安装器与共享库在 --lang en 下的屏幕文案不含中文。
// 静态扫描：去掉嵌入库标记块、注释、写入文件/喂给解释器的 heredoc、已有英文分支的中文 heredoc 与 msg 的中文参数后，
// 剩下的代码里不得出现汉字。允许保留的中文只有：内部记录键（预检项目名、端口用途、进度阶段表的中文半边，
// 屏幕上经 preflight_label / progress_name 翻译）和写进配置文件的注释，下方逐条列出。
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { spawnSync } from './helpers/large-bash-script.mjs'

const read = (relative) => readFileSync(new URL(`../${relative}`, import.meta.url), 'utf8')
const han = /\p{Script=Han}/u
// 英文输出里也不应出现中文全角标点（、，；：（）“”。）。
const cjk = /[\p{Script=Han}、，；：（）“”。]/u
const files = ['scripts/install-control.sh', 'scripts/install-node.sh',
  'scripts/lib/install-i18n.sh', 'scripts/lib/install-preflight.sh', 'scripts/lib/install-progress.sh',
  'scripts/lib/ssh-guard.sh', 'scripts/lib/package-automation.sh']

// 跳过一个 shell 词：单双引号、$(…)/${…} 嵌套与相邻拼接（'a'"b"）都算同一个词，返回词尾下标。
function skipWord(text, i) {
  const stack = []
  for (let j = i; j < text.length; j++) {
    const c = text[j], top = stack.at(-1)
    if (top === "'") { if (c === "'") stack.pop(); continue }
    if (c === '\\') { j++; continue }
    if (top === '"' && c === '"') { stack.pop(); continue }
    if (c === '$' && (text[j + 1] === '(' || text[j + 1] === '{')) { stack.push(text[j + 1]); j++; continue }
    if ((c === ')' && top === '(') || (c === '}' && top === '{')) { stack.pop(); continue }
    if (top === '"') continue
    if (c === "'" || c === '"') { stack.push(c); continue }
    if (top === '(' && c === '(') { stack.push('('); continue }
    if (!stack.length && /[\s;)]/.test(c)) return j
  }
  return text.length
}

// 行尾注释：" # " 之前引号成对时视为注释。
function stripComment(line) {
  const at = line.search(/\s#\s/)
  if (at < 0) return line
  const before = line.slice(0, at)
  return (before.split("'").length % 2 === 1 && before.split('"').length % 2 === 1) ? before : line
}

// 删掉每个 msg 调用的第一个参数（中文）。
function dropChinese(text) {
  let out = '', i = 0
  for (const m of text.matchAll(/\bmsg[ \t]+/g)) {
    if (m.index < i) continue
    const start = m.index + m[0].length
    out += text.slice(i, start) + 'ZH'
    i = skipWord(text, start)
  }
  return out + text.slice(i)
}

// 允许保留的中文（内部键、配置文件内容），逐条说明。
const allowed = [
  /^\s*'[^'^]*\^[^']*\|\d+\|\d+\|[a-z]*'$/, // 进度阶段表：'中文^English|…'，屏幕经 progress_name 取英文
  /^\s*\S+\) printf '[^']*' ;;/, // preflight_label 翻译表
  /^\s*连通性（\*）\) .*'Connectivity/, // preflight_label：连通性（标签）
  /printf '%s\\n' '# cdnca：SSH/, // 写入 jail.d 的注释
  /^\s*printf '#/, // 写入 runtime.env / 生成脚本的注释
  /grep -Eo '公网 IP/, // 解析授权端 403 正文，不输出
  /printf 'Language \/ 语言:/, // 首屏语言选择本身就是双语
  /ce_location='# \/downloads\/ce\/ 未启用/, // install-site 写进 nginx 配置的注释
  /: "\s*正在(安装|下载)|: "\s*下载 %s/, // awk 进度：en ? 英文 : 中文
  /printf '\\n# cdnca-market：/, // install-market 追加进 nginx.conf 的注释
  /seller_route="# @DOMAIN@：/, // install-market 写进 stream.conf 的注释
  /^\s*(for key in )?MARKET_\w+:m?tls:[^/\s]+\/[a-z]+ /, // install-market check 接口表：KEY:mtls:中文/english，屏幕经 msg 取一半
]
function residue(source) {
  const text = dropChinese(source.replace(/^# >>> BEGIN [\s\S]*?^# <<< END .*$/gm, ''))
  const lines = text.split('\n'), out = []
  let heredoc = null, screen = false, enBranch = false
  for (let i = 0; i < lines.length; i++) {
    let line = lines[i]
    if (/^[a-z_]+\(\) \{/.test(line)) enBranch = false
    if (heredoc) {
      if (line.trim() === heredoc) heredoc = null
      else if (/^\s*#/.test(line)) continue // 配置片段里的注释
      else if (screen && !enBranch && han.test(line.replace(/\$\(msg [^)]*\)/g, ''))) out.push(`${i + 1}: ${line}`)
      continue
    }
    if (/"\$\{INSTALL_LANG:-zh\}" = en \]/.test(line)) enBranch = true
    const start = !/<<</.test(line) && line.match(/<<-?\s*'?([A-Z_]+)'?/)
    // RENEW：写进 9448 证书续签脚本（systemd timer 运行，输出进 journal）；WRAP：install-market 生成的 cdnca-market-admin
    // 包装脚本（安装后由运维运行）。两者都不是安装器屏幕。
    if (start) { heredoc = start[1]; screen = /\bcat( >&2)? <</.test(line) && heredoc !== 'RENEW' && heredoc !== 'WRAP' }
    if (/^\s*#/.test(line)) continue
    line = stripComment(line)
      .replace(/preflight_record (pass|warn|fail) ("[^"]*"|\S+)/g, 'preflight_record $1 KEY') // 预检项目名（内部键）
      .replace(/preflight_check_remote \S+/g, 'preflight_check_remote KEY')
      .replace(/(\$\{?\w+(:-\d+)?\}?|\b\d+):[^\s"';$]+/g, 'PORT:LABEL') // 端口:用途（经 preflight_label 翻译）
      .replace(/\$\(preflight_label "\$label"\)/g, '')
    if (!han.test(line) || allowed.some((pattern) => pattern.test(line))) continue
    out.push(`${i + 1}: ${line.trim().slice(0, 160)}`)
  }
  return out
}

test('--lang en: no Chinese is left in screen messages of the installers and shared libraries', () => {
  for (const file of files) assert.deepEqual(residue(read(file)), [], `${file} still prints Chinese with --lang en`)
})

test('the scan itself catches untranslated messages', () => {
  assert.deepEqual(residue("log '未翻译'\nlog \"$(msg '已翻译' 'translated')\"\n"), ["1: log '未翻译'"])
  assert.equal(residue('f() {\n  cat <<EOF\n中文\nEOF\n}\n').length, 1)
  assert.equal(residue('f() {\n  if [ "${INSTALL_LANG:-zh}" = en ]; then\n    cat <<EOF\nEnglish\nEOF\n    return 0\n  fi\n  cat <<EOF\n中文\nEOF\n}\n').length, 0)
})

function block(source, name) {
  const lines = source.split('\n')
  const start = lines.findIndex((line) => line.startsWith(`${name}() {`))
  assert.notEqual(start, -1, `missing ${name}`)
  const end = lines.findIndex((line, index) => index > start && line === '}')
  return lines.slice(start, end + 1).join('\n')
}
const library = read('scripts/lib/install-i18n.sh')
const run = (parts, args) => spawnSync('bash', ['-c', [library, 'install_lang_init "$@"', ...parts].join('\n'), 'x', ...args],
  { encoding: 'utf8', env: { PATH: process.env.PATH } })

test('control --cleanup-failed list and BaoTa steps are English with --lang en', () => {
  const control = read('scripts/install-control.sh')
  const report = [block(control, 'cleanup_failed_report'), 'CONTROL_INSTALL_STATE_FILE=/s/state CONTROL_INSTALL_STATE_DIR=/s',
    'CLEANUP_UNITS=(a.service) CLEANUP_PATHS=(/p) CLEANUP_DEPENDENCY_PATHS=(/d) CLEANUP_REDIS_INCLUDES=(/r) CLEANUP_PG=5432 CLEANUP_CH=9000',
    'CLEANUP_ACCOUNT=true CONTROL_INSTALL_ACCOUNT=cdnca CLEANUP_NFT=true CLEANUP_SERVICES=(redis-server.service) CLEANUP_SERVICES_MANUAL=(valkey.service)',
    'cleanup_failed_report']
  const en = run(report, ['--lang', 'en'])
  assert.equal(en.status, 0, en.stderr)
  assert.match(en.stderr, /systemd unit \(stop, disable, delete\): a\.service/)
  assert.match(en.stderr, /PostgreSQL \(port 5432\): database cdnca and roles cdnca, cdnca_control_app/)
  assert.doesNotMatch(en.stderr, cjk)
  assert.match(run(report, ['--lang', 'zh']).stderr, /systemd 单元（停止、停用、删除）：a\.service/)
  const bt = [block(control, 'bt_proxy_config'), block(control, 'bt_web_server'), block(control, 'bt_report'), 'log() { printf "%s\\n" "$*"; }',
    'TMP=$(mktemp -d); CONFIG_DIR=$TMP BT_ROOT=$TMP INSTALL_ENV=bt BT_PROXY=false CONTROL_DOMAIN=cdnca.example WEB_PORT=18443',
    'MASTER_PORT=443 GATEWAY_ENROLLMENT_PORT=21443 GATEWAY_AGENT_PORT=21444 NODE_DOWNLOAD_PORT=19445 WEB_REAL_IP=', 'bt_report; rm -rf "$TMP"']
  const steps = run(bt, ['--lang', 'en'])
  assert.equal(steps.status, 0, steps.stderr)
  assert.match(steps.stderr, /BaoTa environment: the console web listens only on 127\.0\.0\.1:18443/)
  assert.doesNotMatch(steps.stderr, cjk)
})

test('preflight labels with full-width brackets translate in English and stay Chinese by default', () => {
  const preflight = read('scripts/lib/install-preflight.sh')
  const label = (lang, value) => run([preflight, `preflight_label '${value}'`], ['--lang', lang]).stdout
  assert.equal(label('en', '连通性（授权端）'), 'Connectivity (licensing server)')
  assert.equal(label('en', '管理端网页（本机回环）'), 'management web (loopback)')
  assert.equal(label('zh', '管理端网页（本机回环）'), '管理端网页（本机回环）')
})
