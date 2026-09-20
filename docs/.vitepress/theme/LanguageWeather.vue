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
  padding: 0 0.6rem;
  border: 1px solid var(--storm-hair-strong);
  border-radius: 2px;
  background: transparent;
  color: var(--storm-mass);
  font-family: inherit;
  font-size: 0.76rem;
  font-weight: 600;
  letter-spacing: 0.04em;
  text-decoration: none !important;
  cursor: pointer;
  white-space: nowrap;
  transition:
    background-color 140ms ease-out,
    color 140ms ease-out,
    border-color 140ms ease-out;
}

.language-weather:hover {
  background: var(--storm-mass);
  color: var(--storm-field);
  border-color: var(--storm-mass);
}
</style>
