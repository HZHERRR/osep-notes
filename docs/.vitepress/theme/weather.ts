// Letter-mass weather.
//
// The world's one technical move: type behaves as matter. Letters leave the page.
// A line is sampled character by character at its ink pixels, and each particle
// carries the glyph it came from, so the line breaks into readable letters
// drifting on a wind field rather than into anonymous dots.
//
// Bounded on purpose: a fixed particle ceiling, a hard time cap, one animation
// frame loop that stops itself, and nothing at all under prefers-reduced-motion.

const MAX_PARTICLES = 1500
const MAX_MS = 2800
const GLYPH_SIZE = 15

export interface WeatherOptions {
  /** Horizontal wind in px/s. Negative blows left. */
  wind?: number
  /** Seconds before a particle is fully spent. */
  life?: number
  /** Upper bound on sampled particles. */
  budget?: number
  /** Glyph sprite size in px. */
  glyphSize?: number
  /** Ink colour of the particles; defaults to the element's own colour. */
  color?: string
}

export function reducedMotion(): boolean {
  return (
    typeof window !== 'undefined' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches
  )
}

interface Particle {
  x: number
  y: number
  vx: number
  vy: number
  born: number
  life: number
  scale: number
  sprite: number
}

interface Atlas {
  canvas: HTMLCanvasElement
  /** Sprite index per character. */
  index: Map<string, number>
  /** Sprite width per index (height is the atlas height). */
  widths: number[]
  height: number
}

function cssFont(cs: CSSStyleDeclaration) {
  const stretch = cs.fontStretch && cs.fontStretch !== 'normal' ? `${cs.fontStretch} ` : ''
  return `${cs.fontStyle} ${cs.fontWeight} ${stretch}${cs.fontSize} ${cs.fontFamily}`
}

/**
 * One sprite strip holding every distinct glyph in the text, so the drift draws
 * real letters with one drawImage per particle.
 */
function buildAtlas(
  chars: string[],
  cs: CSSStyleDeclaration,
  size: number,
  dpr: number,
  ink: string,
): Atlas | null {
  const stretch = cs.fontStretch && cs.fontStretch !== 'normal' ? `${cs.fontStretch} ` : ''
  const font = `${cs.fontStyle} ${cs.fontWeight} ${stretch}${size}px ${cs.fontFamily}`
  const unique = [...new Set(chars.filter((c) => c.trim()))]
  if (!unique.length) return null

  const measure = document.createElement('canvas').getContext('2d')
  if (!measure) return null
  measure.font = font

  const pad = Math.ceil(size * 0.3)
  const widths = unique.map((c) => Math.ceil(measure.measureText(c).width) + pad)
  const height = Math.ceil(size * 1.45)
  const total = widths.reduce((a, b) => a + b, 0)

  const canvas = document.createElement('canvas')
  canvas.width = Math.ceil(total * dpr)
  canvas.height = Math.ceil(height * dpr)
  const ctx = canvas.getContext('2d')
  if (!ctx) return null
  ctx.scale(dpr, dpr)
  ctx.font = font
  // The sprite carries the ink it was cut from: a black atlas would leave the
  // letters invisible on the night appearance.
  ctx.fillStyle = ink
  ctx.textBaseline = 'middle'

  const index = new Map<string, number>()
  let cursor = 0
  unique.forEach((c, i) => {
    index.set(c, i)
    ctx.fillText(c, cursor + pad / 2, height / 2)
    cursor += widths[i]
  })

  return { canvas, index, widths, height }
}

/** Sample an element's ink, tagging every particle with the glyph it came from. */
function sample(element: HTMLElement, budget: number, glyphSize: number) {
  const rect = element.getBoundingClientRect()
  if (rect.width < 2 || rect.height < 2) return null

  const cs = getComputedStyle(element)
  const text = (element.textContent || '').trim()
  if (!text) return null

  const dpr = Math.min(window.devicePixelRatio || 1, 2)
  const font = cssFont(cs)
  const tracking = parseFloat(cs.letterSpacing)
  const track = Number.isFinite(tracking) ? tracking : 0

  const buffer = document.createElement('canvas')
  buffer.width = Math.ceil(rect.width * dpr)
  buffer.height = Math.ceil(rect.height * dpr)
  const ctx = buffer.getContext('2d', { willReadFrequently: true })
  if (!ctx) return null

  ctx.scale(dpr, dpr)
  ctx.font = font
  ctx.fillStyle = '#000'
  ctx.textBaseline = 'middle'

  // Lay the text out character by character so every glyph keeps its own box.
  const chars = [...text]
  const widths = chars.map((c) => ctx.measureText(c).width + track)
  const total = widths.reduce((a, b) => a + b, 0)
  const align = cs.textAlign
  let cursor = 0
  if (align === 'center') cursor = (rect.width - total) / 2
  else if (align === 'right' || align === 'end') cursor = rect.width - total

  ctx.textAlign = 'left'
  const boxes: { char: string; x: number; w: number }[] = []
  chars.forEach((char, i) => {
    ctx.fillText(char, cursor, rect.height / 2)
    boxes.push({ char, x: cursor, w: widths[i] })
    cursor += widths[i]
  })

  const atlas = buildAtlas(chars, cs, glyphSize, dpr, cs.color)
  if (!atlas) return null

  const data = ctx.getImageData(0, 0, buffer.width, buffer.height).data
  // Aim for enough glyphs that the line reads as mass, not as dust.
  const step = Math.max(2, Math.round(Math.sqrt(total / (budget * 0.35))))

  const points: { x: number; y: number; char: string }[] = []
  for (let py = 0; py < buffer.height; py += step) {
    const y = py / dpr
    for (let px = 0; px < buffer.width; px += step) {
      if (data[(py * buffer.width + px) * 4 + 3] <= 128) continue
      const x = px / dpr
      // Attribute the sample to the glyph whose box it falls inside.
      const box = boxes.find((b) => x >= b.x && x < b.x + b.w)
      points.push({ x: rect.left + x, y: rect.top + y, char: box ? box.char : chars[0] })
      if (points.length >= budget) break
    }
    if (points.length >= budget) break
  }

  return points.length ? { points, atlas, color: cs.color } : null
}

/**
 * Blow an element's letters across the viewport. Resolves when the weather has
 * settled or the time cap is reached, whichever comes first.
 */
export function weather(element: HTMLElement | null, options: WeatherOptions = {}): Promise<void> {
  return new Promise((resolve) => {
    if (!element || typeof window === 'undefined') return resolve()

    const fontSize = parseFloat(getComputedStyle(element).fontSize) || 16
    const {
      wind = 320,
      life = 1.6,
      budget = MAX_PARTICLES,
      // A 15px glyph is a readable letter beside 17px prose and a speck beside a
      // 5rem headline. Tie the sprite to the type it was cut from.
      glyphSize = Math.max(12, Math.min(30, fontSize * 0.3)),
      color,
    } = options

    if (reducedMotion()) return resolve()

    const sampled = sample(element, budget, glyphSize)
    if (!sampled) return resolve()

    const canvas = document.createElement('canvas')
    const dpr = Math.min(window.devicePixelRatio || 1, 2)
    canvas.width = window.innerWidth * dpr
    canvas.height = window.innerHeight * dpr
    Object.assign(canvas.style, {
      position: 'fixed',
      inset: '0',
      width: '100%',
      height: '100%',
      pointerEvents: 'none',
      zIndex: '60',
    })
    canvas.setAttribute('aria-hidden', 'true')
    document.body.appendChild(canvas)

    const ctx = canvas.getContext('2d')
    if (!ctx) {
      canvas.remove()
      return resolve()
    }
    ctx.scale(dpr, dpr)

    const { atlas } = sampled
    // Read left to right so the peel reads as a front moving with the wind.
    const ordered = sampled.points.sort((a, b) => a.x - b.x)
    const toward = Math.sign(wind) || 1
    const particles: Particle[] = ordered.map((point, i) => ({
      // Offset outward at birth: the cloud is already letters lifting off the
      // line, never an exact copy of it welded in place.
      x: point.x + toward * (7 + Math.random() * 26),
      y: point.y - 4 + Math.random() * 12,
      vx: wind * (0.45 + Math.random() * 0.85),
      vy: -30 + Math.random() * 38,
      born: (i / Math.max(ordered.length, 1)) * 0.5,
      life: life * (0.7 + Math.random() * 0.7),
      scale: (glyphSize / GLYPH_SIZE) * (0.72 + Math.random() * 0.5),
      sprite: atlas.index.get(point.char) ?? 0,
    }))

    ctx.fillStyle = color || sampled.color
    const start = performance.now()
    let frame = 0

    const tick = (now: number) => {
      const elapsed = (now - start) / 1000
      ctx.clearRect(0, 0, window.innerWidth, window.innerHeight)
      let alive = 0

      for (const p of particles) {
        const age = elapsed - p.born
        if (age > p.life) continue
        alive++
        if (age < 0) {
          // Not yet spent: the letter is still where it was set.
          continue
        }
        const x = p.x + p.vx * age
        const y = p.y + p.vy * age + 74 * age * age
        const alpha = 1 - age / p.life
        const w = atlas.widths[p.sprite] * p.scale
        const h = atlas.height * p.scale
        ctx.globalAlpha = alpha * 0.92
        ctx.drawImage(
          atlas.canvas,
          atlas.widths.slice(0, p.sprite).reduce((a, b) => a + b, 0) * dpr,
          0,
          atlas.widths[p.sprite] * dpr,
          atlas.height * dpr,
          x - w / 2,
          y - h / 2,
          w,
          h,
        )
      }

      ctx.globalAlpha = 1
      if (alive > 0 && now - start < MAX_MS) {
        frame = requestAnimationFrame(tick)
      } else {
        cancelAnimationFrame(frame)
        ctx.clearRect(0, 0, window.innerWidth, window.innerHeight)
        canvas.remove()
        resolve()
      }
    }

    frame = requestAnimationFrame(tick)
  })
}

/** Peel a line: the ink stays readable while its letters drift off in the wind. */
export function peel(element: HTMLElement | null, options: WeatherOptions = {}) {
  if (!element || reducedMotion()) return
  // Slower and longer than a switch: this is the page's own weather, and the
  // letters should still be legible as letters while they cross it.
  weather(element, { wind: 130, life: 2.8, budget: 1100, ...options })
}
