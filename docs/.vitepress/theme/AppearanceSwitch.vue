<script setup lang="ts">
// The appearance control, rebuilt in the world's own vocabulary: a hairline
// square that names the appearance it will switch to, exactly like the language
// control beside it. The built-in switch is a rounded pill with a sun glyph,
// which belongs to no part of this page.
import { computed } from 'vue'
import { useData } from 'vitepress'

const { isDark } = useData()
const label = computed(() => (isDark.value ? 'Light' : 'Dark'))

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

.appearance-switch:hover {
  background: var(--storm-mass);
  color: var(--storm-field);
}
</style>
