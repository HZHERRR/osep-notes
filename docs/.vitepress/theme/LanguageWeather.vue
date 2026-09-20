<script setup lang="ts">
import { computed } from 'vue'
import { useData, useRoute } from 'vitepress'

const { site } = useData()
const route = useRoute()

const base = computed(() => site.value.base || '/')

const cleanPath = computed(() => {
  let p = route.path
  const b = base.value
  if (b !== '/' && p.startsWith(b)) {
    p = p.slice(b.length - 1)
  }
  return p.startsWith('/') ? p : `/${p}`
})

const zh = computed(() => cleanPath.value === '/zh' || cleanPath.value.startsWith('/zh/'))

const targetRelative = computed(() => {
  const p = cleanPath.value
  if (zh.value) {
    const en = p.replace(/^\/zh(\/|$)/, '/')
    return en === '' ? '/' : en
  }
  return p === '/' ? '/zh/' : `/zh${p}`
})

const targetHref = computed(() => {
  const b = base.value.replace(/\/$/, '')
  return `${b}${targetRelative.value}`
})

const label = computed(() => (zh.value ? 'English' : '中文'))
</script>

<template>
  <a
    class="language-weather"
    :href="targetHref"
    :aria-label="zh ? 'Switch to English' : '切换到中文'"
    :lang="zh ? 'en' : 'zh-CN'"
  >
    {{ label }}
  </a>
</template>

<style scoped>
.language-weather {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  height: 28px;
  padding: 0 0.65rem;
  border: 1px solid var(--tac-border);
  border-radius: 6px;
  background: var(--tac-card);
  color: var(--tac-text-2);
  font-family: var(--tac-mono);
  font-size: 0.74rem;
  font-weight: 600;
  letter-spacing: 0.04em;
  text-decoration: none !important;
  cursor: pointer;
  white-space: nowrap;
  transition: all 120ms ease-out;
}

.language-weather:hover {
  border-color: var(--tac-accent);
  color: var(--tac-accent);
  background: var(--tac-card-hover);
}
</style>
