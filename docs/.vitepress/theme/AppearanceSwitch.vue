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
  padding: 0 0.65rem;
  border: 1px solid var(--tac-border);
  border-radius: 6px;
  background: var(--tac-card);
  color: var(--tac-text-2);
  font-family: var(--tac-mono);
  font-size: 0.74rem;
  font-weight: 600;
  letter-spacing: 0.04em;
  cursor: pointer;
  white-space: nowrap;
  transition: all 120ms ease-out;
}

.appearance-switch:hover {
  border-color: var(--tac-accent);
  color: var(--tac-accent);
  background: var(--tac-card-hover);
}
</style>
