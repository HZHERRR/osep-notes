<script setup lang="ts">
// The weather front: how far the reader has moved through the sheet, and which
// sheets are already spent. Spent grammar recedes to rain grey — the world's own
// rule, doing real work for a reader who returns mid-module for weeks.
import { nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute } from 'vitepress'

const route = useRoute()
const progress = ref(0)
const visible = ref(false)

const SPENT_KEY = 'osep:spent'

let frame = 0
let observer: ResizeObserver | undefined

function articleElement() {
  return document.querySelector<HTMLElement>('.VPDoc .vp-doc')
}

function readSpent(): string[] {
  try {
    const raw = localStorage.getItem(SPENT_KEY)
    const parsed = raw ? JSON.parse(raw) : []
    return Array.isArray(parsed) ? parsed : []
  } catch {
    return []
  }
}

function markSpent(path: string) {
  try {
    const spent = new Set(readSpent())
    spent.add(path)
    localStorage.setItem(SPENT_KEY, JSON.stringify([...spent].slice(-60)))
  } catch {
    /* a reader with storage disabled simply gets no spent marking */
  }
}

function paintSpent() {
  const spent = new Set(readSpent())
  document.querySelectorAll<HTMLAnchorElement>('.VPSidebarItem .link').forEach((link) => {
    const url = new URL(link.href, window.location.origin)
    link.classList.toggle('is-spent', spent.has(url.pathname) && url.pathname !== route.path)
  })
}

function update() {
  cancelAnimationFrame(frame)
  frame = requestAnimationFrame(() => {
    const article = articleElement()
    visible.value = Boolean(article)
    if (!article) {
      progress.value = 0
      return
    }
    const top = window.scrollY + article.getBoundingClientRect().top
    const distance = Math.max(article.scrollHeight - window.innerHeight * 0.6, 1)
    progress.value = Math.min(Math.max((window.scrollY - top) / distance, 0), 1)
  })
}

function enhanceTables(article: HTMLElement) {
  article.querySelectorAll<HTMLTableElement>('table:not([data-scroll-table])').forEach((table) => {
    const wrapper = document.createElement('div')
    wrapper.className = 'table-scroll'
    table.dataset.scrollTable = 'true'
    table.parentNode?.insertBefore(wrapper, table)
    wrapper.appendChild(table)
  })
}

function compactOutlineLabel(label: string) {
  const text = label.replace(/\s+/g, ' ').trim()
  const scenario = text.match(/^(?:\d+\.\s*)?Scenario\s+(\d+)/i)
  if (scenario) return `Scenario ${scenario[1]}`

  const zhScenario = text.match(/^(?:\d+\.\s*)?场景\s*(\d+)/)
  if (zhScenario) return `场景 ${zhScenario[1]}`

  if (/^Background\b/i.test(text)) return 'Background'
  if (/^背景(?:速览)?/.test(text)) return '背景'

  return text
}

function compactOutline() {
  document.querySelectorAll<HTMLAnchorElement>('.VPDocAsideOutline .outline-link').forEach((link) => {
    const original = link.dataset.outlineLabel || link.textContent?.trim() || ''
    if (!original) return

    link.dataset.outlineLabel = original
    link.textContent = compactOutlineLabel(original)
    link.title = original
    link.setAttribute('aria-label', original)
  })
}

function sync() {
  const article = articleElement()
  if (article) {
    enhanceTables(article)
    observer?.observe(article)
  }
  update()
  paintSpent()
  compactOutline()
}

onMounted(() => {
  observer = new ResizeObserver(update)
  window.addEventListener('scroll', update, { passive: true })
  window.addEventListener('resize', update, { passive: true })
  if (route.path !== '/') markSpent(route.path)
  sync()
})

watch(
  () => route.path,
  () => nextTick(sync),
)

onBeforeUnmount(() => {
  cancelAnimationFrame(frame)
  observer?.disconnect()
  window.removeEventListener('scroll', update)
  window.removeEventListener('resize', update)
})
</script>

<template>
  <div v-if="visible" class="weather-front" aria-hidden="true">
    <span :style="{ transform: `scaleX(${progress})` }" />
  </div>
</template>

<style scoped>
.weather-front {
  position: fixed;
  z-index: 40;
  top: var(--vp-nav-height, 64px);
  right: 0;
  left: 0;
  height: 2px;
  overflow: hidden;
  pointer-events: none;
}

.weather-front span {
  display: block;
  width: 100%;
  height: 100%;
  background: var(--tac-accent);
  box-shadow: 0 0 8px var(--tac-accent);
  transform: scaleX(0);
  transform-origin: left center;
  transition: transform 90ms linear;
}
</style>
