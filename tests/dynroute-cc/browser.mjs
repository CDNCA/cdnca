// Headless Chromium against the CC verification pages of a dynamic routing
// node (tests/dynroute-cc/run.sh BROWSER=1 starts cdnca-cc-check -only serve
// with the port published on loopback). A real browser solves every page
// the way a visitor does: runs the proof of work, waits, clicks, drags; its
// pass cookie must then open the site. Replaces the retired
// scripts/security/cc-browser-e2e.mjs (v7 release).
//   node browser.mjs <playwright-core dir> <base url> <cookie out file>
import { createRequire } from 'node:module'
import { writeFileSync } from 'node:fs'

const [playwrightDir, base, cookieFile] = process.argv.slice(2)
const { chromium } = createRequire(import.meta.url)(playwrightDir)
let failed = 0
const check = (id, expected, actual, note) => {
  const ok = expected === actual
  if (!ok) failed++
  console.log(`${ok ? 'PASS' : 'FAIL'} ${id} expected=${expected} actual=${actual} ${note}`)
}

// Every *.audit.example.test name resolves to the node, so the browser
// visits the real host names (Host header, cookies) like a visitor would.
const port = new URL(base).port
// CHROMIUM: an installed Chromium / headless shell when the package's own
// build is not downloaded.
const browser = await chromium.launch({ headless: true, executablePath: process.env.CHROMIUM || undefined,
  args: ['--host-resolver-rules=MAP *.audit.example.test 127.0.0.1'] })
try {
  // Each site gets its own context (own cookies).
  const visit = async (name, solve) => {
    const context = await browser.newContext()
    const page = await context.newPage()
    const site = `http://${name}.audit.example.test:${port}`
    const started = Date.now()
    const first = await page.goto(`${site}/article?id=7`)
    const mode = (await first.headerValue('x-cdnca-challenge')) ?? 'none'
    await solve(page)
    await page.waitForURL(`${site}/article?id=7`, { timeout: 60000 })
    await page.waitForFunction(() => document.body.innerText.includes('origin-ok'), null, { timeout: 60000 })
    const elapsed = (Date.now() - started) / 1000
    const pass = (await context.cookies()).find((cookie) => cookie.name === '__cdnca_cc_pass')
    const again = await page.goto(`${site}/list`)
    const body = (await again.text()).trim()
    const ua = await page.evaluate(() => navigator.userAgent)
    await context.close()
    return { mode, status: first.status(), elapsed, pass: pass?.value ?? '', again: again.status(), body, ua }
  }
  const auto = async () => {}

  const shield = await visit('cc', auto)
  check('BROWSER-5S-1', 'delay(503)', `${shield.mode}(${shield.status})`, '无头浏览器首次访问看到 5秒盾')
  check('BROWSER-5S-2', true, shield.elapsed >= 5, `浏览器自动完成 PoW 并等满 5 秒后进入原页面（用时 ${shield.elapsed.toFixed(1)} 秒）`)
  check('BROWSER-5S-3', true, shield.pass.startsWith('v2.'), '拿到 v2 通行 Cookie（HMAC-SHA256）')
  check('BROWSER-5S-4', '200 origin-ok', `${shield.again} ${shield.body}`, '带 Cookie 的后续请求直接放行')
  writeFileSync(cookieFile, shield.pass)
  writeFileSync(`${cookieFile}.ua`, shield.ua)

  const js = await visit('g1', auto)
  check('BROWSER-JS-1', 'js(503)', `${js.mode}(${js.status})`, '无感 JS 验证页')
  check('BROWSER-JS-2', 200, js.again, `浏览器自动完成 PoW 后放行（用时 ${js.elapsed.toFixed(1)} 秒）`)

  const click = await visit('g10004', async (page) => {
    await page.getByRole('button', { name: '点击继续访问' }).click()
  })
  check('BROWSER-CLICK', 200, click.again, '“点击继续访问”由真人点击后放行')

  const shapes = { 圆形: 0, 方形: 1, 三角形: 2, 菱形: 3 }
  const shape = await visit('g10000', async (page) => {
    const name = await page.locator('strong').first().innerText()
    await page.locator('.shape').nth(shapes[name]).click()
  })
  check('BROWSER-SHAPE', 200, shape.again, '点击页面要求的图形后放行')

  const slider = await visit('g2', async (page) => {
    const label = await page.locator('label[for="range"]').innerText()
    await page.locator('#range').fill(String(Number(/(\d+)%/.exec(label)?.[1])))
    await page.getByRole('button', { name: '提交' }).click()
  })
  check('BROWSER-SLIDER', 200, slider.again, '滑块拖到页面要求的位置后放行')

  const easySlider = await visit('g10005', async (page) => {
    await page.locator('#range').fill('100')
    await page.getByRole('button', { name: '提交' }).click()
  })
  check('BROWSER-EASY-SLIDER', 200, easySlider.again, '简单滑块拖到最右侧后放行')

  const rotate = await visit('g10003', async (page) => {
    const angle = Number(await page.locator('#arrow').getAttribute('data-base'))
    await page.locator('#range').fill(String(360 - angle))
    await page.getByRole('button', { name: '提交' }).click()
  })
  check('BROWSER-ROTATE', 200, rotate.again, '旋转箭头到朝上后放行')
} finally {
  await browser.close()
}
process.exit(failed === 0 ? 0 : 1)
