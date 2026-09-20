#!/usr/bin/env node
// Behavioural check for the signature interaction: does changing language
// actually run the weather event and land on the other locale?
import { spawn } from 'node:child_process'

const CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
const PORT = 9334
const BASE = process.argv[2] || 'http://127.0.0.1:4173'
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

const chrome = spawn(
  CHROME,
  [
    '--headless=new',
    '--disable-gpu',
    '--no-first-run',
    `--remote-debugging-port=${PORT}`,
    '--user-data-dir=/tmp/cdp-behaviour-profile',
    'about:blank',
  ],
  { stdio: 'ignore' },
)

let id = 0
const pending = new Map()
let ws

const send = (method, params = {}) => {
  const msgId = ++id
  ws.send(JSON.stringify({ id: msgId, method, params }))
  return new Promise((resolve, reject) => pending.set(msgId, { resolve, reject }))
}

const evaluate = async (expression) => {
  const res = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true })
  return res.result?.value
}

try {
  for (let i = 0; i < 60; i++) {
    try {
      if ((await fetch(`http://127.0.0.1:${PORT}/json/version`)).ok) break
    } catch {}
    await sleep(250)
  }
  const target = await (
    await fetch(`http://127.0.0.1:${PORT}/json/new?about:blank`, { method: 'PUT' })
  ).json()
  ws = new WebSocket(target.webSocketDebuggerUrl)
  ws.addEventListener('message', (e) => {
    const m = JSON.parse(e.data)
    if (m.id && pending.has(m.id)) {
      const { resolve, reject } = pending.get(m.id)
      pending.delete(m.id)
      m.error ? reject(new Error(JSON.stringify(m.error))) : resolve(m.result)
    }
  })
  await new Promise((r) => ws.addEventListener('open', r, { once: true }))
  await send('Page.enable')
  await send('Runtime.enable')
  await send('Emulation.setDeviceMetricsOverride', {
    width: 1440,
    height: 900,
    deviceScaleFactor: 1,
    mobile: false,
  })

  // --- motion off: the control must still work -----------------------------
  await send('Emulation.setEmulatedMedia', {
    features: [{ name: 'prefers-reduced-motion', value: 'reduce' }],
  })
  await send('Page.navigate', { url: `${BASE}/` })
  await sleep(2500)
  const before = await evaluate('location.pathname')
  const label = await evaluate(
    "document.querySelector('.language-weather')?.textContent.trim() ?? 'MISSING'",
  )
  const disabled = await evaluate(
    "document.querySelector('.language-weather')?.disabled ?? 'MISSING'",
  )
  await evaluate("document.querySelector('.language-weather')?.click(); 'clicked'")
  await sleep(2000)
  const afterReduced = await evaluate('location.pathname')
  const canvasesReduced = await evaluate("document.querySelectorAll('canvas').length")

  // --- motion on: the weather event must run, then land ---------------------
  await send('Emulation.setEmulatedMedia', { features: [] })
  await send('Page.navigate', { url: `${BASE}/` })
  await sleep(2500)
  await evaluate("document.querySelector('.language-weather')?.click(); 'clicked'")
  await sleep(140)
  const canvasesDuring = await evaluate("document.querySelectorAll('canvas').length")
  const weathering = await evaluate("document.documentElement.classList.contains('is-weathering')")
  await sleep(2500)
  const afterMotion = await evaluate('location.pathname')
  const canvasesAfter = await evaluate("document.querySelectorAll('canvas').length")

  // --- back again, and via a deep module route ------------------------------
  await send('Page.navigate', { url: `${BASE}/modules/12-ad-attacks` })
  await sleep(2500)
  await evaluate("document.querySelector('.language-weather')?.click(); 'clicked'")
  await sleep(2600)
  const deepAfter = await evaluate('location.pathname')
  const deepTitle = await evaluate("document.querySelector('.vp-doc h1')?.textContent.trim().slice(0,28)")

  console.log(
    JSON.stringify(
      {
        startPath: before,
        controlLabel: label,
        controlDisabled: disabled,
        reducedMotion: { landedOn: afterReduced, canvases: canvasesReduced },
        motionOn: {
          canvasDuringEvent: canvasesDuring,
          weatheringClassDuringEvent: weathering,
          landedOn: afterMotion,
          canvasesAfterEvent: canvasesAfter,
        },
        deepLink: { landedOn: deepAfter, firstHeading: deepTitle },
      },
      null,
      2,
    ),
  )
} finally {
  chrome.kill('SIGKILL')
}
