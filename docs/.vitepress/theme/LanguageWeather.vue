<script setup lang="ts">
// The signature interaction: changing language is a weather event.
//
// This site's one real control is its bilingualism, and the world's own control
// is "type, split, conjugate, recombine language while physical consequences
// remain reversible". So the locale switch is the moment: the heading on screen
// is sampled into letter-mass, blown across the field, and the other language
// forms behind it. Under prefers-reduced-motion it is an honest hard cut.
import { computed, ref } from 'vue'
import { useRoute, useRouter } from 'vitepress'
import { reducedMotion, weather } from './weather'

const route = useRoute()
const router = useRouter()
const busy = ref(false)

const zh = computed(() => route.path === '/zh' || route.path.startsWith('/zh/'))

const target = computed(() => {
  const path = route.path
  if (zh.value) {
    const stripped = path.replace(/^\/zh/, '')
    return stripped === '' || stripped === '/' ? '/' : stripped
  }
  return path === '/' ? '/zh/' : `/zh${path}`
})

const label = computed(() => (zh.value ? 'English' : '中文'))

async function go() {
  if (busy.value) return
  busy.value = true

  if (!reducedMotion()) {
    // Blow the page's own heading apart, then land the other language.
    const heading =
      document.querySelector<HTMLElement>('.storm-title, .vp-doc h1') ||
      document.querySelector<HTMLElement>('.VPDoc h1')
    const run = weather(heading, { wind: 300, life: 2.1, budget: 1400 })
    document.documentElement.classList.add('is-weathering')
    window.setTimeout(() => router.go(target.value), 460)
    await run
    document.documentElement.classList.remove('is-weathering')
  } else {
    await router.go(target.value)
  }

  busy.value = false
}
</script>

<template>
  <button
    type="button"
    class="language-weather"
    :aria-label="zh ? 'Switch to English' : '切换到中文'"
    :lang="zh ? 'en' : 'zh-CN'"
    :disabled="busy"
    @click="go"
  >
    {{ label }}
  </button>
</template>

<style scoped>
.language-weather {
  padding: 0.3rem 0.62rem;
  border: 1px solid var(--storm-hair-strong);
  background: transparent;
  color: var(--storm-mass);
  font-family: inherit;
  font-size: 0.78rem;
  font-weight: 600;
  letter-spacing: 0.04em;
  cursor: pointer;
  transition:
    background-color 160ms ease-out,
    color 160ms ease-out;
}

.language-weather:hover:not(:disabled) {
  background: var(--storm-mass);
  color: var(--storm-field);
}

.language-weather:disabled {
  color: var(--storm-rain);
  cursor: progress;
}
</style>
