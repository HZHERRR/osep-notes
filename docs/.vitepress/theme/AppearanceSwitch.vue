<script setup lang="ts">
import { computed } from 'vue'
import { useData, useRoute } from 'vitepress'

const { isDark } = useData()
const route = useRoute()
const zh = computed(() => route.path === '/zh' || route.path.startsWith('/zh/'))

const label = computed(() => {
  if (isDark.value) {
    return zh.value ? '浅色' : 'Light'
  }
  return zh.value ? '深色' : 'Dark'
})

function toggle() {
  const next = !isDark.value
  isDark.value = next
  try {
    localStorage.setItem('vitepress-theme-appearance', next ? 'dark' : 'light')
  } catch {
    /* storage disabled: the switch still works for this page view */
  }
}
</script>

<template>
  <button
    type="button"
    class="appearance-switch"
    role="switch"
    :aria-checked="isDark"
    :aria-label="isDark ? 'Switch to light appearance' : 'Switch to dark appearance'"
    @click="toggle"
  >
    {{ label }}
  </button>
</template>

<style scoped>
.appearance-switch {
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
  cursor: pointer;
  white-space: nowrap;
  transition:
    background-color 140ms ease-out,
    color 140ms ease-out,
    border-color 140ms ease-out;
}

.appearance-switch:hover {
  background: var(--storm-mass);
  color: var(--storm-field);
  border-color: var(--storm-mass);
}
</style>
