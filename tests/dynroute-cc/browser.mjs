// Headless Chromium against the CC verification pages of a dynamic routing
// node (tests/dynroute-cc/run.sh BROWSER=1 starts cdnca-cc-check -only serve
// with the port published on loopback). A real browser solves every page
// the way a visitor does: runs the proof of work, waits, clicks, drags; its
// pass cookie must then open the site. Replaces the retired
// scripts/security/cc-browser-e2e.mjs (v7 release).
// The click / rotate / slider / captcha answers are only in the picture; a
// person reads it, the test takes the token's answer from cdnca-cc-check's
// test-only answer server instead (the 4th argument).
//   node browser.mjs <playwright-core dir> <base url> <cookie out file> <answer url>
import { createRequire } from 'node:module'
import { writeFileSync } from 'node:fs'

const [playwrightDir, base, cookieFile, answerBase] = process.argv.slice(2)
const answerOf = async (page) => {
  const token = await page.locator('input[name="token"]').getAttribute('value')
  return (await (await fetch(`${answerBase}/answer?token=${token}`)).text()).trim()
}
// The picture must load in the page (same origin, bound to this browser).
const pictureLoaded = (page) => page.locator('img.pic').evaluate((img) => img.complete && img.naturalWidth > 0)
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

  let shown = true
  const shape = await visit('g10000', async (page) => {
    shown = shown && await pictureLoaded(page)
    if (process.env.CC_BROWSER_SHOTS) await page.screenshot({ path: `${process.env.CC_BROWSER_SHOTS}/click.png` })
    await page.locator(`.shape[data-id="${await answerOf(page)}"]`).click()
  })
  check('BROWSER-SHAPE', 200, shape.again, '点击页面要求的图形后放行')

  const slider = await visit('g2', async (page) => {
    shown = shown && await pictureLoaded(page)
    await page.locator('#range').fill(await answerOf(page))
    if (process.env.CC_BROWSER_SHOTS) await page.screenshot({ path: `${process.env.CC_BROWSER_SHOTS}/slider.png` })
    await page.getByRole('button', { name: '提交' }).click()
  })
  check('BROWSER-SLIDER', 200, slider.again, '滑块拖到页面要求的位置后放行')

  const easySlider = await visit('g10005', async (page) => {
    await page.locator('#range').fill('100')
    await page.getByRole('button', { name: '提交' }).click()
  })
  check('BROWSER-EASY-SLIDER', 200, easySlider.again, '简单滑块拖到最右侧后放行')

  const rotate = await visit('g10003', async (page) => {
    shown = shown && await pictureLoaded(page)
    await page.locator('#range').fill(await answerOf(page))
    if (process.env.CC_BROWSER_SHOTS) await page.screenshot({ path: `${process.env.CC_BROWSER_SHOTS}/rotate.png` })
    await page.getByRole('button', { name: '提交' }).click()
  })
  check('BROWSER-ROTATE', 200, rotate.again, '旋转箭头到朝上后放行')

  const captcha = await visit('g4', async (page) => {
    shown = shown && await pictureLoaded(page)
    if (process.env.CC_BROWSER_SHOTS) await page.screenshot({ path: `${process.env.CC_BROWSER_SHOTS}/captcha.png` })
    await page.locator('#code').fill((await answerOf(page)).toLowerCase())
    await page.getByRole('button', { name: '提交' }).click()
  })
  check('BROWSER-CAPTCHA', 200, captcha.again, '输入图中字符（小写）后放行')
  check('BROWSER-PICTURE', true, shown, '点击/滑块/旋转/验证码的图片都在页面里加载成功')

  const wait = await visit('g10003', async (page) => {
    await page.getByRole('button', { name: /改用等待验证/ }).click()
  })
  check('BROWSER-WAIT', true, wait.again === 200 && wait.elapsed >= 5,
    `读屏替代路径：改用等待验证后等满 5 秒放行（用时 ${wait.elapsed.toFixed(1)} 秒）`)
} finally {
  await browser.close()
}
process.exit(failed === 0 ? 0 : 1)
