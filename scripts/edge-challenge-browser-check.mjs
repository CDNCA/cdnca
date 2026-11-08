#!/usr/bin/env node
// Real Chrome against the challenge smoke's OpenResty: the built-in modes pass
// by running the page script (proof of work in Workers, or on the main thread
// when Workers are unavailable), with and without CPU throttling.
//
//   node scripts/edge-challenge-browser-check.mjs CHROME PORT ADMIN_PORT OUT_DIR [RUNS] [THROTTLE...]
//
// Uses its own headless Chrome and user data directory; prints one JSON object.
import { spawn } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const [chrome, port, adminPort, outDir, runsArg, ...throttleArgs] = process.argv.slice(2)
if (!chrome || !port || !adminPort || !outDir) {
  console.error('usage: edge-challenge-browser-check.mjs CHROME PORT ADMIN_PORT OUT_DIR [RUNS] [THROTTLE...]')
  process.exit(2)
}
const runs = Number(runsArg || 3)
const throttles = throttleArgs.length ? throttleArgs.map(Number) : [1, 6]
const hosts = { delay: 'delay.test', click: 'click.test', slider: 'slider.test', captcha: 'captcha.test' }
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

const profile = mkdtempSync(join(tmpdir(), 'cdnca-challenge-chrome.'))
const browser = spawn(chrome, ['--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profile}`,
  '--no-first-run', '--no-default-browser-check', '--no-proxy-server', '--ignore-certificate-errors',
  `--host-resolver-rules=MAP *.test 127.0.0.1`, 'about:blank'], { stdio: 'ignore' })
const cleanup = () => { try { browser.kill('SIGKILL') } catch {} ; rmSync(profile, { recursive: true, force: true }) }
process.on('exit', cleanup)

let file = join(profile, 'DevToolsActivePort')
for (let i = 0; i < 100 && !existsSync(file); i += 1) await sleep(100)
const [debugPort, debugPath] = readFileSync(file, 'utf8').trim().split('\n')
const socket = new WebSocket(`ws://127.0.0.1:${debugPort}${debugPath}`)
await new Promise((resolve, reject) => { socket.onopen = resolve; socket.onerror = reject })
let nextId = 0
const pending = new Map()
socket.onmessage = (event) => {
  const message = JSON.parse(event.data)
  if (message.id && pending.has(message.id)) {
    const { resolve, reject } = pending.get(message.id)
    pending.delete(message.id)
    message.error ? reject(new Error(message.error.message)) : resolve(message.result)
  }
}
const send = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
  const id = ++nextId
  pending.set(id, { resolve, reject })
  socket.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }))
})

// Records when the page script fills the proof of work (CDP scripts bypass CSP).
const hook = (noWorker) => `(() => {
  ${noWorker ? 'window.Worker = function () { throw new Error("no workers") };' : ''}
  const descriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
  Object.defineProperty(HTMLInputElement.prototype, 'value', { configurable: true, get: descriptor.get,
    set(value) { if (this.id === 'pow' && value) window.__powAt = performance.now(); descriptor.set.call(this, value) } });
})()`

const state = `(() => ({ body: document.body ? document.body.innerText.slice(0, 200) : '',
  powAt: window.__powAt ?? null, mode: document.getElementById('challenge-form')?.dataset.mode ?? null,
  nonce: document.querySelector('input[name=nonce]')?.value ?? null,
  disabled: document.getElementById('continue')?.disabled ?? null,
  workers: navigator.hardwareConcurrency, now: performance.now() }))()`

async function evaluate(sessionId, expression) {
  const result = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true }, sessionId)
  return result.result.value
}

async function until(sessionId, predicate, timeout, label) {
  const deadline = Date.now() + timeout
  let last
  while (Date.now() < deadline) {
    try {
      last = await evaluate(sessionId, state)
      if (last && predicate(last)) return last
    } catch { /* navigation in progress */ }
    await sleep(15)
  }
  throw new Error(`${label}: timed out, last=${JSON.stringify(last)}`)
}

async function answer(nonce) {
  const reply = await fetch(`http://127.0.0.1:${adminPort}/answer?nonce=${nonce}`)
  return (await reply.text()).trim()
}

async function run(mode, throttle, noWorker, alternative = false, screenshot = null) {
  const { browserContextId } = await send('Target.createBrowserContext', { disposeOnDetach: true })
  const { targetId } = await send('Target.createTarget', { url: 'about:blank', browserContextId })
  const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true })
  try {
    await send('Page.enable', {}, sessionId)
    await send('Runtime.enable', {}, sessionId)
    await send('Emulation.setCPUThrottlingRate', { rate: throttle }, sessionId)
    await send('Page.addScriptToEvaluateOnNewDocument', { source: hook(noWorker) }, sessionId)
    const started = Date.now()
    await send('Page.navigate', { url: `https://${hosts[mode]}:${port}/browser?mode=${mode}` }, sessionId)
    const solved = await until(sessionId, (s) => s.powAt !== null || s.body.includes('origin-ok'), 15000, `${mode} pow`)
    const powMs = solved.powAt
    // A person needs more than the server's 0.2 s minimum to interact.
    await until(sessionId, (s) => s.now > 300 || s.body.includes('origin-ok'), 5000, `${mode} human pause`)
    if (alternative) {
      await evaluate(sessionId, `document.getElementById('alt-start').click()`)
    } else if (mode === 'click') {
      await until(sessionId, (s) => s.disabled === false, 5000, 'click enable')
      await evaluate(sessionId, `document.getElementById('continue').click()`)
    } else if (mode === 'slider') {
      const target = await answer(solved.nonce)
      const left = await evaluate(sessionId, `(() => { const s = document.getElementById('slider-response'); s.value = ${target};
        s.dispatchEvent(new Event('input', { bubbles: true })); return document.getElementById('piece').style.left })()`)
      if (screenshot) writeFileSync(join(outDir, screenshot), Buffer.from((await send('Page.captureScreenshot', {}, sessionId)).data, 'base64'))
      await until(sessionId, (s) => s.disabled === false, 5000, 'slider enable')
      await evaluate(sessionId, `document.getElementById('continue').click()`)
      solved.pieceLeft = left
    } else if (mode === 'captcha') {
      const code = await answer(solved.nonce)
      if (screenshot) writeFileSync(join(outDir, screenshot), Buffer.from((await send('Page.captureScreenshot', {}, sessionId)).data, 'base64'))
      await evaluate(sessionId, `(() => { const c = document.getElementById('captcha-response'); c.value = ${JSON.stringify(code.toLowerCase())};
        c.dispatchEvent(new Event('input', { bubbles: true })) })()`)
      await until(sessionId, (s) => s.disabled === false, 5000, 'captcha enable')
      await evaluate(sessionId, `document.getElementById('continue').click()`)
    }
    await until(sessionId, (s) => s.body.includes('origin-ok'), 20000, `${mode} origin`)
    return { mode, throttle, noWorker, alternative, powMs: powMs === null ? null : Math.round(powMs),
      totalMs: Date.now() - started, workers: solved.workers, pieceLeft: solved.pieceLeft }
  } finally {
    await send('Target.closeTarget', { targetId }).catch(() => {})
    await send('Target.disposeBrowserContext', { browserContextId }).catch(() => {})
  }
}

const results = []
for (const throttle of throttles) {
  for (const noWorker of [false, true]) {
    for (const mode of ['click', 'delay', 'slider', 'captcha']) {
      for (let index = 0; index < runs; index += 1) {
        const shot = throttle === 1 && !noWorker && index === 0 && (mode === 'slider' || mode === 'captcha')
          ? `${mode}.png` : null
        results.push(await run(mode, throttle, noWorker, false, shot))
      }
    }
  }
}
for (const mode of ['slider', 'captcha']) results.push(await run(mode, 6, false, true))
const summary = {}
for (const result of results) {
  const key = `${result.mode}${result.alternative ? '-alt' : ''}/x${result.throttle}/${result.noWorker ? 'main' : 'workers'}`
  summary[key] ??= { runs: 0, powMs: [], totalMs: [] }
  summary[key].runs += 1
  summary[key].powMs.push(result.powMs)
  summary[key].totalMs.push(result.totalMs)
}
console.log(JSON.stringify({ chrome: (await send('Browser.getVersion')).product, workers: results[0].workers, summary }))
socket.close()
cleanup()
process.exit(0)
