#!/usr/bin/env node
// Capture a page at an exact viewport over the DevTools Protocol.
//
// Chrome's --screenshot flag refuses to lay out narrower than 500px, which makes
// every "mobile" capture a lie. This drives CDP directly so the emulated metrics
// are the real ones, and it can capture beyond the viewport for a full page.
//
// usage: node capture.mjs <url> <out.png> <width> [height] [--full] [--motion]
import { spawn } from 'node:child_process'
import { writeFileSync, mkdirSync } from 'node:fs'
import { dirname } from 'node:path'

const CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
const PORT = 9333

const [url, out, widthArg, heightArg] = process.argv.slice(2)
const flags = process.argv.slice(2).filter((a) => a.startsWith('--'))
const width = Number(widthArg) || 1440
const height = Number(heightArg) || 900
const fullPage = flags.includes('--full')
const allowMotion = flags.includes('--motion')

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

async function waitForDevtools() {
  for (let i = 0; i < 60; i++) {
    try {
      const res = await fetch(`http://127.0.0.1:${PORT}/json/version`)
      if (res.ok) return
    } catch {
      /* not up yet */
    }
    await sleep(250)
  }
  throw new Error('devtools endpoint never came up')
}

class Cdp {
  constructor(ws) {
    this.ws = ws
    this.id = 0
    this.pending = new Map()
    this.events = new Map()
    ws.addEventListener('message', (event) => {
      const msg = JSON.parse(event.data)
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id)
        this.pending.delete(msg.id)
        msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result)
      } else if (msg.method && this.events.has(msg.method)) {
        this.events.get(msg.method).forEach((fn) => fn(msg.params))
        this.events.delete(msg.method)
      }
    })
  }

  send(method, params = {}) {
    const id = ++this.id
    this.ws.send(JSON.stringify({ id, method, params }))
    return new Promise((resolve, reject) => this.pending.set(id, { resolve, reject }))
  }

  once(method) {
    return new Promise((resolve) => {
      const list = this.events.get(method) || []
      list.push(resolve)
      this.events.set(method, list)
    })
  }
}

const chrome = spawn(
  CHROME,
  [
    '--headless=new',
    '--disable-gpu',
    '--hide-scrollbars',
    '--no-first-run',
    '--no-default-browser-check',
    `--remote-debugging-port=${PORT}`,
    '--user-data-dir=/tmp/cdp-capture-profile',
    'about:blank',
  ],
  { stdio: 'ignore' },
)

try {
  await waitForDevtools()
  const target = await (await fetch(`http://127.0.0.1:${PORT}/json/new?about:blank`, { method: 'PUT' })).json()
  const ws = new WebSocket(target.webSocketDebuggerUrl)
  await new Promise((resolve, reject) => {
    ws.addEventListener('open', resolve)
    ws.addEventListener('error', reject)
  })

  const cdp = new Cdp(ws)
  await cdp.send('Page.enable')
  await cdp.send('Emulation.setDeviceMetricsOverride', {
    width,
    height,
    deviceScaleFactor: 1,
    mobile: width < 700,
  })
  if (!allowMotion) {
    // Settle entrance motion: an element hidden by animation timing reads as a
    // missing element and gets fixed into a regression.
    await cdp.send('Emulation.setEmulatedMedia', {
      features: [
        { name: 'prefers-reduced-motion', value: 'reduce' },
        ...(flags.includes('--dark') ? [{ name: 'prefers-color-scheme', value: 'dark' }] : []),
      ],
    })
  } else if (flags.includes('--dark')) {
    await cdp.send('Emulation.setEmulatedMedia', {
      features: [{ name: 'prefers-color-scheme', value: 'dark' }],
    })
  }

  const loaded = cdp.once('Page.loadEventFired')
  await cdp.send('Page.navigate', { url })
  await loaded
  await sleep(900)

  const shot = await cdp.send('Page.captureScreenshot', {
    format: 'png',
    captureBeyondViewport: fullPage,
    ...(fullPage ? {} : { clip: { x: 0, y: 0, width, height, scale: 1 } }),
  })

  mkdirSync(dirname(out), { recursive: true })
  writeFileSync(out, Buffer.from(shot.data, 'base64'))
  console.log(`ok ${out} ${width}x${fullPage ? 'full' : height}`)
} finally {
  chrome.kill('SIGKILL')
}
