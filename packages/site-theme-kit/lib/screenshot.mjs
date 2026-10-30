// preview --screenshot：用本机 Chrome（headless）截首屏，生成主题卡片预览图。
//   1440×900 截图 → 有 cwebp 时转 preview.webp（缩到 1200×750、q80），否则保存 preview.png；
//   超过 512 KiB 时只提示，不覆盖已有文件以外的东西。
// 不引入新依赖：只调用 Chrome 自带的 --headless --screenshot 与可选的 cwebp。
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { existsSync, mkdtempSync, renameSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { PREVIEW_MAX_BYTES } from './rules.mjs'

// 异步执行：预览服务与截图在同一进程，同步调用会卡住服务、Chrome 拿不到页面。
const run = promisify(execFile)

const CHROME_PATHS = [
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/Applications/Chromium.app/Contents/MacOS/Chromium',
  '/usr/bin/google-chrome', '/usr/bin/google-chrome-stable', '/usr/bin/chromium', '/usr/bin/chromium-browser',
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
]

/** 找本机 Chrome：环境变量 CHROME_PATH 优先，其次常见安装位置。找不到返回 null。 */
export function locateChrome() {
  const named = process.env.CHROME_PATH
  if (named) return existsSync(named) ? named : null
  return CHROME_PATHS.find((path) => existsSync(path)) ?? null
}

function onPath(command) {
  for (const dir of (process.env.PATH ?? '').split(':')) if (dir && existsSync(join(dir, command))) return join(dir, command)
  return null
}

/**
 * 截 url 的首屏写到 root/preview.webp（或 preview.png）。返回 {path, bytes, oversize}。
 * 页面里的动画给 2 秒（--virtual-time-budget）稳定下来。
 */
export async function captureScreenshot(url, root, { chrome = locateChrome(), log = console.log } = {}) {
  if (!chrome) throw new Error('没有找到 Chrome：安装 Google Chrome，或用环境变量 CHROME_PATH 指定可执行文件')
  const dir = mkdtempSync(join(tmpdir(), 'cdnca-preview-'))
  try {
    const png = join(dir, 'shot.png')
    await run(chrome, ['--headless=new', '--disable-gpu', '--hide-scrollbars', '--no-first-run', '--no-default-browser-check',
      `--user-data-dir=${join(dir, 'profile')}`, '--window-size=1440,900', '--virtual-time-budget=2000', `--screenshot=${png}`, url],
    { timeout: 60_000 })
    if (!existsSync(png)) throw new Error('Chrome 没有生成截图')
    const cwebp = onPath('cwebp')
    let out
    if (cwebp) {
      out = join(root, 'preview.webp')
      await run(cwebp, ['-quiet', '-q', '80', '-resize', '1200', '750', png, '-o', out])
    } else {
      out = join(root, 'preview.png')
      renameSync(png, out)
      log('提示：本机没有 cwebp，已保存 PNG；装 cwebp（libwebp）后重跑可得到更小的 preview.webp')
    }
    const bytes = statSync(out).size
    return { path: out, bytes, oversize: bytes > PREVIEW_MAX_BYTES }
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}
