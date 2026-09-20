#!/usr/bin/env node
// Capture the world's motion, which only exists while it is running.
// Reduced-motion captures are the right evidence for layout; they are useless
// as evidence for the signature interaction, so this drives it live over CDP.
//
// usage: node anim.mjs <base-url> <out-dir>
import { spawn } from 'node:child_process'
import { writeFileSync, mkdirSync } from 'node:fs'

const CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
const PORT = 9335
const BASE = process.argv[2] || 'http://127.0.0.1:4173'
const OUT = process.argv[3] || '.impeccable/review'
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

const chrome = spawn(
  CHROME,
  [
    '--headless=new',
    '--disable-gpu',
    '--hide-scrollbars',
    '--no-first-run',
    `--remote-debugging-port=${PORT}`,
    '--user-data-dir=/tmp/cdp-anim-profile',
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
const evaluate = async (expression) =>
  (await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true })).result
    ?.value

const shoot = async (name) => {
  const res = await send('Page.captureScreenshot', { format: 'png' })
  mkdirSync(OUT, { recursive: true })
  writeFileSync(`${OUT}/${name}`, Buffer.from(res.data, 'base64'))
  console.log(`ok ${OUT}/${name}`)
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
  // Motion explicitly ALLOWED: no reduced-motion emulation in this script.
  await send('Emulation.setDeviceMetricsOverride', {
    width: 1440,
    height: 900,
    deviceScaleFactor: 1,
    mobile: false,
  })

  // 1. The hero's letters leaving the page, ~700ms into the peel.
  await send('Page.navigate', { url: `${BASE}/` })
  await sleep(260 + 1150)
  await shoot('anim-hero-dissolve.png')
  const heroCanvas = await evaluate("document.querySelectorAll('canvas').length")

  // 2. The language switch as a weather event, ~300ms after the click.
  await sleep(2200)
  await evaluate("document.querySelector('.language-weather')?.click(); 'clicked'")
  await sleep(300)
  await shoot('anim-language-switch.png')
  const switchCanvas = await evaluate("document.querySelectorAll('canvas').length")
  const weathering = await evaluate("document.documentElement.classList.contains('is-weathering')")

  // 3. The same moment on a reading page.
  await send('Page.navigate', { url: `${BASE}/modules/12-ad-attacks` })
  await sleep(2600)
  await evaluate("document.querySelector('.language-weather')?.click(); 'clicked'")
  await sleep(300)
  await shoot('anim-language-switch-module.png')

  console.log(JSON.stringify({ heroCanvas, switchCanvas, weathering }))
} finally {
  chrome.kill('SIGKILL')
}
